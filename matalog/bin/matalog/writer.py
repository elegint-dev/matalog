"""The summary index write path and KV writes with the baseline roll rule.

Summary rows become stash lines (slot timestamp, then name="value" pairs,
repeated for string[] values). A batch of lines is saved to the
matalog_write_buffer collection and copied to the index by one
`| inputlookup ... | collect sourcetype=stash` job, then removed from the
buffer; makeresults inline data is capped at 30000 characters, which would
make the write path cost a job per 28 KB. KV documents are merged onto the
stored document, rolling cur_* into base_* under the rule in
docs/data-model.md, so no step rolls on its own.
"""
import collections
import json
import re

from . import keys
from . import rows as rows_mod

PROFILES_INDEX = "matalog_profiles"
STASH_SOURCETYPE = "stash"
BUFFER_COLLECTION = "matalog_write_buffer"


class WriteError(Exception):
    """A collect job or a KV batch failed; the report says which."""

    def __init__(self, message, report=None):
        Exception.__init__(self, message)
        self.report = report


class WriteReport(object):
    """What a summary write did: rows and bytes sent, collect jobs issued, failures."""

    def __init__(self):
        self.rows = 0
        self.write_bytes = 0
        self.write_searches = 0
        self.rows_by_kind = collections.OrderedDict()
        self.failed = []
        self.sids = []

    def __repr__(self):
        return "WriteReport(rows=%d, bytes=%d, searches=%d, failed=%d)" % (self.rows, self.write_bytes, self.write_searches, len(self.failed))


def kv_pair(name, value):
    """One name="value" pair, escaped the way collect writes stash lines."""
    text = "" if value is None else value
    if isinstance(text, float):
        text = repr(text)
    elif not isinstance(text, str):
        text = str(text)
    return '%s="%s"' % (name, text.replace("\\", "\\\\").replace('"', '\\"'))


def encode_line(row, slot_epoch):
    """The stash line for one summary row: timestamp, then pairs; string[] values repeat the name."""
    parts = [keys.stamp(slot_epoch)]
    for name, value in row.items():
        if isinstance(value, list):
            parts.extend(kv_pair(name, v) for v in value)
        else:
            parts.append(kv_pair(name, value))
    return ", ".join(parts)


def spl_quote(text):
    return text.replace("\\", "\\\\").replace('"', '\\"')


def parse_line(line):
    """The exact inverse of encode_line over a stash line read back as _raw: name -> value, repeated names as lists.

    The stamp is skipped; every pair is name="value" with backslash and
    double quote escaped as kv_pair writes them, so values keep their
    surrounding whitespace, trailing "=" and quotes, which auto-kv trims.
    Returns None for text that is not a stash line.
    """
    if not isinstance(line, str):
        return None
    text = line
    pos = text.find(", ")
    if pos < 0 or not _STAMP_RE.match(text[:pos]):
        return None
    pos += 2
    out = collections.OrderedDict()
    length = len(text)
    while pos < length:
        eq = text.find('="', pos)
        if eq < 0:
            return None
        name = text[pos:eq]
        if not name or not _NAME_RE.match(name):
            return None
        pos = eq + 2
        chars = []
        while True:
            if pos >= length:
                return None
            ch = text[pos]
            if ch == "\\" and pos + 1 < length and text[pos + 1] in ('"', "\\"):
                chars.append(text[pos + 1])
                pos += 2
                continue
            if ch == '"':
                pos += 1
                break
            chars.append(ch)
            pos += 1
        value = "".join(chars)
        if name in out:
            if isinstance(out[name], list):
                out[name].append(value)
            else:
                out[name] = [out[name], value]
        else:
            out[name] = value
        if pos >= length:
            break
        if not text.startswith(", ", pos):
            return None
        pos += 2
    return out


_STAMP_RE = re.compile(r"^\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} [+-]\d{4}$")
_NAME_RE = re.compile(r"^[^\s\"=,]+$")


def batch_payload(lines):
    """A batch of lines as compact JSON, the payload write_batch_bytes caps and write_bytes counts."""
    return json.dumps([{"r": line} for line in lines], separators=(",", ":"), ensure_ascii=False)


def payload_bytes(line):
    return len(json.dumps({"r": line}, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) + 1


def collect_spl(run_id, attempt, first_seq, last_seq, index=PROFILES_INDEX, buffer=BUFFER_COLLECTION):
    """The collect job for one staged batch: buffer rows of this attempt with seq in [first_seq, last_seq]."""
    return ('| inputlookup %s where run_id="%s" attempt=%d seq>=%d seq<=%d | eval _raw=r | fields _raw | collect index=%s sourcetype=%s'
            % (buffer, spl_quote(run_id), int(attempt), int(first_seq), int(last_seq), index, STASH_SOURCETYPE))


def row_id_of(row):
    """The content id of a summary row: profile_id for kind=field, row_id for the other kinds."""
    return row["profile_id"] if row.get("kind") == "field" else row["row_id"]


def clear_buffer(client, run_id, attempt, buffer=BUFFER_COLLECTION):
    """Drop staged lines left by earlier runs and attempts that stopped before collecting them."""
    client.kv_delete(buffer, {"run_id": {"$lt": run_id}})
    client.kv_delete(buffer, {"run_id": run_id, "attempt": {"$lt": int(attempt)}})


def make_batches(lines, max_rows, max_bytes):
    """Split lines into batches closing at max_rows rows or max_bytes payload bytes, whichever first."""
    batches = []
    current = []
    size = 2
    for line in lines:
        cost = payload_bytes(line)
        if current and (len(current) >= int(max_rows) or size + cost > int(max_bytes)):
            batches.append(current)
            current = []
            size = 2
        current.append(line)
        size += cost
    if current:
        batches.append(current)
    return batches


class SummaryWriter(object):
    """Writes validated summary rows to matalog_profiles through the KV buffer and the client's budget.

    run_id and attempt tag the buffer rows; every collect job reads only its
    own attempt's rows, so a buffer left by an earlier attempt is never copied.
    """

    def __init__(self, client, settings, slot_epoch, index=PROFILES_INDEX, run_id="", attempt=1, buffer=BUFFER_COLLECTION):
        self.client = client
        self.settings = settings
        self.slot_epoch = int(slot_epoch)
        self.index = index
        self.run_id = run_id or keys.run_id_of(self.slot_epoch)
        self.attempt = int(attempt)
        self.buffer = buffer
        self.seq = 0

    def write(self, rows, step="S10"):
        """Write rows in batches, in order; returns a WriteReport.

        Batches close at write.write_batch_rows rows or write.write_batch_bytes
        JSON bytes. The first failed batch stops the write and raises
        WriteError, so nothing after it (the commit row in particular) is
        written. write_bytes counts the JSON payload of every batch sent.
        """
        report = WriteReport()
        entries = []
        for row in rows:
            rows_mod.validate(row)
            entries.append((row, encode_line(row, self.slot_epoch)))
        lines = [line for _, line in entries]
        start = 0
        for batch in make_batches(lines, self.settings.write.write_batch_rows, self.settings.write.write_batch_bytes):
            batch_rows = [row for row, _ in entries[start:start + len(batch)]]
            start += len(batch)
            first = self.seq + 1
            docs = []
            for row, line in zip(batch_rows, batch):
                self.seq += 1
                docs.append(collections.OrderedDict([
                    ("_key", keys.k(self.run_id, self.attempt, row_id_of(row))), ("run_id", self.run_id),
                    ("attempt", self.attempt), ("seq", self.seq), ("kind", row["kind"]), ("r", line)]))
            payload_size = len(batch_payload(batch).encode("utf-8"))
            try:
                self.client.kv_batch_save(self.buffer, docs, batch_size=self.settings.write.kv_batch_size)
            except Exception as exc:
                report.failed.append({"sid": "", "status": "failed", "rows": len(batch), "messages": ["buffer save: %s" % exc]})
                break
            spl = collect_spl(self.run_id, self.attempt, first, self.seq, self.index, self.buffer)
            result = self.client.search(spl, step=step, subject_key="write", write=True,
                                        timeout=self.settings.budget.search_timeout_seconds, max_rows=len(batch) + 1)
            report.write_searches += 1
            report.write_bytes += payload_size
            report.sids.append(result.sid)
            # Rows with the same content id share one buffer doc, so a batch copies one row per distinct key.
            expected = len(set(d["_key"] for d in docs))
            if result.status == "ok" and result.result_count != expected:
                result.status = "failed"
                result.messages = list(result.messages) + [{"type": "ERROR", "text": "collect copied %d of %d buffer rows" % (result.result_count, expected)}]
            if result.status != "ok":
                report.failed.append({"sid": result.sid, "status": result.status, "rows": len(batch),
                                      "messages": [m.get("text", "") for m in result.messages][:3]})
                break
            report.rows += len(batch)
            for row in batch_rows:
                report.rows_by_kind[row["kind"]] = report.rows_by_kind.get(row["kind"], 0) + 1
            try:
                self.client.kv_delete(self.buffer, {"run_id": self.run_id, "attempt": self.attempt, "seq": {"$gte": first, "$lte": self.seq}})
            except Exception:
                # Leftover buffer rows are cleared at the next run start and never re-collected.
                pass
        if self.client.budget is not None:
            self.client.budget.rows_written(step, report.rows)
        if report.failed:
            raise WriteError("collect batch failed after %d rows in %d jobs" % (report.rows, report.write_searches), report)
        return report


# KV writes.

# Run id columns that only move forward, and the one that only moves back.
LATEST_RUN_COLUMNS = ("last_seen_run", "updated_run_id", "last_discovered_run", "last_profiled_run")
EARLIEST_RUN_COLUMNS = ("first_seen_run",)


def _empty(value):
    return value is None or value == "" or value == []


def snapshot_columns(collection, cur_prefix):
    """Every column of a collection under one cur_* prefix, the snapshot replaced as a whole."""
    return [c for c in rows_mod.COLLECTIONS.get(collection, {}) if c.startswith(cur_prefix)]


def apply_roll(collection, new_doc, existing):
    """Merge a staged document onto the stored one under the baseline roll rule.

    For each snapshot group of the collection: a newer cur run_id moves the
    stored cur_* to base_*, then the new snapshot replaces every cur_* column
    of the group (columns it does not carry are cleared); an equal run_id
    replaces cur_* only; an older one is ignored. On matalog_field_types an
    outgoing cur_* with source=reclassify keeps the stored base_*.

    Outside the groups: first_seen_run keeps the earliest value and
    LATEST_RUN_COLUMNS the latest; a document whose updated_run_id is older
    than the stored one only fills columns the stored document lacks, so
    replaying an old run never regresses newer values.
    """
    merged = collections.OrderedDict(existing or {})
    new_doc = collections.OrderedDict(new_doc)
    for cur, base, suffixes in rows_mod.SNAPSHOT_GROUPS.get(collection, []):
        new_run = new_doc.get(cur + "run_id")
        old_run = merged.get(cur + "run_id")
        if _empty(new_run):
            continue
        columns = snapshot_columns(collection, cur)
        if not _empty(old_run) and str(new_run) < str(old_run):
            for column in columns:
                new_doc.pop(column, None)
            continue
        if not _empty(old_run) and str(new_run) > str(old_run):
            keep_base = collection == "matalog_field_types" and merged.get("source") == "reclassify"
            if not keep_base:
                for suffix in suffixes:
                    merged[base + suffix] = merged.get(cur + suffix)
        for column in columns:
            if column not in new_doc:
                merged.pop(column, None)
    new_updated = new_doc.get("updated_run_id")
    old_updated = merged.get("updated_run_id")
    older = not _empty(new_updated) and not _empty(old_updated) and str(new_updated) < str(old_updated)
    for column, value in new_doc.items():
        stored = merged.get(column)
        if column in EARLIEST_RUN_COLUMNS and not _empty(stored) and not _empty(value):
            merged[column] = min(str(stored), str(value))
        elif column in LATEST_RUN_COLUMNS and not _empty(stored) and not _empty(value):
            merged[column] = max(str(stored), str(value))
        elif older and not _empty(stored):
            continue
        else:
            merged[column] = value
    return merged


def merge_snapshots(collection, docs):
    """Fold documents of one _key, oldest first, through apply_roll: the newest supplies cur_*, the one before base_*."""
    merged = collections.OrderedDict()
    for doc in docs:
        merged = apply_roll(collection, doc, merged)
    return merged


def kv_encode(doc):
    """A document ready for batch_save: None values dropped, lists kept, numbers kept."""
    out = collections.OrderedDict()
    for column, value in doc.items():
        if value is None:
            continue
        out[column] = value
    return out


class KVWriter(object):
    """Merges staged documents onto stored ones and saves them in kv_batch_size batches."""

    def __init__(self, client, settings):
        self.client = client
        self.settings = settings

    def write(self, collection, docs):
        """Upsert docs (partial documents with _key) with the roll rule applied. Returns the count saved."""
        docs = list(docs)
        if not docs:
            return 0
        for doc in docs:
            rows_mod.validate(doc, collection=collection, partial=True)
        existing = self.client.kv_get_many(collection, [d["_key"] for d in docs])
        merged = [kv_encode(apply_roll(collection, doc, existing.get(doc["_key"]))) for doc in docs]
        saved = self.client.kv_batch_save(collection, merged, batch_size=self.settings.write.kv_batch_size)
        if len(saved) != len(merged):
            raise WriteError("%s: saved %d of %d documents" % (collection, len(saved), len(merged)))
        return len(merged)

    def delete(self, collection, keys_list):
        keys_list = list(keys_list)
        if keys_list:
            self.client.kv_delete_keys(collection, keys_list)
        return len(keys_list)


# Reading committed rows back.

def committed_subsearch(index=PROFILES_INDEX):
    """Subsearch yielding the (run_id, attempt) pairs that have a kind=commit row."""
    return "[search index=%s kind=commit | stats max(attempt) as attempt by run_id | fields run_id attempt]" % index


def committed_rows_spl(kinds, extra="", index=PROFILES_INDEX):
    """SPL selecting committed rows of the given kinds; extra is appended inside the base search."""
    kind_filter = "kind=%s" % kinds[0] if len(kinds) == 1 else "kind IN (%s)" % ", ".join(kinds)
    return "search index=%s %s %s %s" % (index, kind_filter, extra, committed_subsearch(index))


SUBJECT_COLUMN = {"source": "source_key", "stratum": "stratum_key", "field": "field_key"}


# Rows read back for rebuild, replay and reclassify come as _raw and are parsed with parse_line: auto-kv trims
# values ending in "=" or whitespace and values wrapped in double quotes. The SPL names only the extracted terms it filters on.
RAW_ONLY = "| table _raw"
# A collect job that timed out can have indexed its batch before the retry, so a committed attempt can hold a row
# twice; readers that count or fold rows take one row per (run_id, attempt, row id).
DEDUP_ROWS = '| eval matalog_rid=coalesce(profile_id, row_id) | dedup run_id attempt matalog_rid'


def latest_rows_spl(kind, max_rows, per_subject=2, index=PROFILES_INDEX):
    """Newest committed rows per subject (and per mode) for rebuild, as _raw."""
    subject = SUBJECT_COLUMN[kind]
    by = subject if kind == "source" else "%s mode" % subject
    return "%s %s | dedup %d %s | head %d %s" % (committed_rows_spl([kind], index=index), DEDUP_ROWS, per_subject, by, int(max_rows), RAW_ONLY)


def latest_full_rows_spl(max_rows, index=PROFILES_INDEX):
    """The newest committed full kind=field row per field, of either mode, as _raw."""
    return "%s %s | dedup 1 field_key | head %d %s" % (committed_rows_spl(["field"], extra="shape=full", index=index), DEDUP_ROWS, int(max_rows), RAW_ONLY)


def first_seen_spl(max_rows, index=PROFILES_INDEX):
    """The oldest committed run_id per subject of kind source, stratum (listings included) and field."""
    return ("%s | eval matalog_subject=case(kind=\"field\", field_key, kind=\"stratum\", stratum_key, true(), source_key)"
            " | stats min(run_id) as first_seen_run by kind matalog_subject | head %d"
            % (committed_rows_spl(list(SUBJECT_COLUMN), index=index), int(max_rows)))


def run_rows_spl(run_id, attempt, kinds, max_rows, index=PROFILES_INDEX):
    """Rows of one committed attempt, for crash replay, as _raw."""
    kind_filter = "kind IN (%s)" % ", ".join(kinds)
    return "search index=%s %s run_id=%s attempt=%s %s | head %d %s" % (index, kind_filter, run_id, int(attempt), DEDUP_ROWS, int(max_rows), RAW_ONLY)


def committed_attempt_spl(run_id, index=PROFILES_INDEX):
    return "search index=%s kind=commit run_id=%s | stats max(attempt) as attempt" % (index, run_id)


def committed_attempts_spl(run_ids, index=PROFILES_INDEX):
    """The highest attempt with a commit row, per run_id, for several runs in one job."""
    return "search index=%s kind=commit run_id IN (%s) | stats max(attempt) as attempt by run_id" % (index, ", ".join('"%s"' % spl_quote(r) for r in run_ids))


def summary_row_from_result(result_row):
    """Keep the contract columns of a summary row read back from the index.

    A result carrying a stash line in _raw is parsed with parse_line, so every
    value is exactly what encode_line wrote; otherwise the extracted fields are used.
    """
    parsed = parse_line(result_row.get("_raw"))
    if parsed:
        result_row = parsed
    kind = result_row.get("kind")
    if kind not in rows_mod.SUMMARY_KINDS:
        return None
    shape = result_row.get("shape") if kind == "field" else None
    table = rows_mod.columns_for(kind=kind, shape=shape)
    out = collections.OrderedDict()
    for column in table:
        if column in result_row:
            value = result_row[column]
            if table[column] == rows_mod.STRING_LIST:
                value = value if isinstance(value, list) else [value]
            elif isinstance(value, list):
                value = value[0]
            out[column] = value
    return out
