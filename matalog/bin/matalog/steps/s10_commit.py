"""S10 commit.

Order of work, every part on the merged view (the staged doc over the stored
one) so a row this run changed is judged as S10 will write it:

1. Retention deletes through ctx.delete_kv:
   - level=stratum matalog_strata rows with state=retired whose older of
     retired_run and last_seen_run (updated_run_id when both are empty) is
     retention.stratum_retire_days before the slot, and every matalog_fields
     row of those strata;
   - matalog_fields rows with presence unobserved or declared_only,
     no matalog_meanings row for their source-level field_key, no usage, and
     last_seen_run (updated_run_id when empty) older than
     retention.unobserved_field_days. A row staged this run has
     updated_run_id this run, as runner.commit stamps it, and a row whose
     stratum is reactivated this run (stored presence retired) is kept;
   - matalog_runs beyond retention.run_retention_count, oldest run_id first,
     never this run's record and never one awaiting replay (status running,
     or committed_attempt set without committed=1).
2. matalog_meanings, normal runs only (rebuild never writes it): revisions
   beyond retention.meaning_revisions per field_key are deleted, oldest first;
   the highest revision gets status orphaned when its field_key has no
   matalog_fields row after this run, and current again when an orphaned one
   has a row; a removed revision keeps its status. Only status is staged.
3. The human mirror, read from matalog_meanings: every staged
   matalog_fields row and every stored row sharing a source-level field_key
   with a meaning, or still carrying a mirror, gets meaning_human,
   meaning_human_author, meaning_human_time and meaning_human_revision (0 and
   empty when there is no meaning). A stored row is staged only when its
   mirror differs.
4. runner.commit(ctx): summary rows, the commit row, the KV batches and the
   deletes, then committed=1. The mirror columns of the staged rows are read
   again from matalog_meanings immediately before the first KV batch.

A KV read that fails in parts 1 to 3 is recorded in ctx.errors and that part
is skipped; the commit still happens. Ages are measured from ctx.slot_start.

ctx.state written: "retention": OrderedDict collection -> rows deleted;
"human_layer": {"mirrored", "orphaned", "current", "revisions_deleted"}.

Also holds the rebuild derivations runner.RebuildStep calls: listing_strata
and rollup_fields.
"""
import collections

from .. import keys
from .. import rows as rows_mod
from .. import runner
from .. import writer as writer_mod
from ..runner import Step

FIELDS = "matalog_fields"
STRATA = "matalog_strata"
MEANINGS = "matalog_meanings"
RUNS = "matalog_runs"

MIRROR_COLUMNS = ("meaning_human", "meaning_human_author", "meaning_human_time", "meaning_human_revision")
RETAINABLE_PRESENCE = ("unobserved", "declared_only")
IDENTITY_COLUMNS = ("_key", "src_index", "src_sourcetype", "field_name")
CHUNK = 500


def _int(value):
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return 1 if value.lower() == "true" else 0
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _float(value):
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _empty(value):
    return value is None or value == "" or value == []


def _chunks(items, size=CHUNK):
    items = list(items)
    for start in range(0, len(items), size):
        yield items[start:start + size]


def view(ctx, collection, key, stored):
    """The document S10 will write for key: the staged doc merged onto stored under the roll rule.

    A staged doc gets updated_run_id this run, as runner.commit stamps it.
    """
    staged = ctx.kv[collection].get(key)
    if staged is None:
        return stored
    merged = writer_mod.apply_roll(collection, staged, stored)
    if "updated_run_id" in rows_mod.COLLECTIONS[collection]:
        merged["updated_run_id"] = ctx.run_id
    return merged


def source_key_of(doc):
    """The source-level field_key of a matalog_fields doc, or None when its identity is incomplete."""
    if not doc:
        return None
    try:
        return keys.source_field_key(doc["src_index"], doc["src_sourcetype"], doc["field_name"])
    except (KeyError, keys.IdentityError):
        return None


def read_meanings(client):
    """matalog_meanings revisions by field_key, highest revision first."""
    by_field = collections.OrderedDict()
    for doc in client.kv_query(MEANINGS):
        if doc.get("field_key"):
            by_field.setdefault(doc["field_key"], []).append(doc)
    for docs in by_field.values():
        docs.sort(key=lambda d: -(_int(d.get("revision")) or 0))
    return by_field


def mirror_of(meaning):
    """The meaning_human_* columns for a meaning revision; revision 0 and empty columns for none or a removed one."""
    if meaning is None or meaning.get("status") == "removed":
        return collections.OrderedDict([("meaning_human", None), ("meaning_human_author", None),
                                        ("meaning_human_time", None), ("meaning_human_revision", 0)])
    return collections.OrderedDict([
        ("meaning_human", None if meaning.get("text") is None else str(meaning.get("text"))),
        ("meaning_human_author", None if meaning.get("author") is None else str(meaning.get("author"))),
        ("meaning_human_time", _float(meaning.get("created_at"))),
        ("meaning_human_revision", _int(meaning.get("revision")) or 0),
    ])


def _same_mirror(doc, mirror):
    for column, wanted in mirror.items():
        have = doc.get(column)
        if column == "meaning_human_revision":
            if (_int(have) or 0) != wanted:
                return False
        elif column == "meaning_human_time":
            if _float(have) != wanted:
                return False
        elif (None if _empty(have) else str(have)) != (None if _empty(wanted) else wanted):
            return False
    return True


class Commit(Step):
    """Retention, the human layer, then runner.commit(ctx); see the module docstring."""

    name = "S10"
    label = "commit"
    required = True

    def run(self, ctx):
        self.deleted = collections.OrderedDict((c, 0) for c in (STRATA, FIELDS, RUNS, MEANINGS))
        self.human = collections.OrderedDict([("mirrored", 0), ("orphaned", 0), ("current", 0), ("revisions_deleted", 0)])
        ctx.state["retention"] = self.deleted
        ctx.state["human_layer"] = self.human
        meanings = self.guarded(ctx, "matalog_meanings", lambda: read_meanings(ctx.client))
        self.guarded(ctx, "retention:strata", lambda: self.retire_strata(ctx))
        if meanings is not None:
            self.guarded(ctx, "retention:fields", lambda: self.unobserved_fields(ctx, meanings))
        self.guarded(ctx, "retention:runs", lambda: self.run_records(ctx))
        if meanings is not None and ctx.run_mode != "rebuild":
            self.guarded(ctx, "meanings", lambda: self.meaning_status(ctx, meanings))
        self.mirror_sources = {}
        fresh = self.guarded(ctx, "mirror", lambda: read_meanings(ctx.client))
        if fresh is not None:
            self.guarded(ctx, "mirror", lambda: self.mirror(ctx, fresh))
        kv_writer = ctx.kv_writer
        ctx.kv_writer = MirrorRefresh(kv_writer, lambda: self.guarded(ctx, "mirror", lambda: self.refresh_mirror(ctx)))
        try:
            runner.commit(ctx, type_versions_hash=(ctx.run_record or {}).get("type_versions_hash") or "")
        finally:
            ctx.kv_writer = kv_writer

    def guarded(self, ctx, subject, fn):
        try:
            return fn()
        except Exception as exc:
            ctx.error(self.name, subject, "%s: %s" % (exc.__class__.__name__, exc))
            return None

    def delete(self, ctx, collection, key):
        if key in ctx.kv_deletes[collection]:
            return
        ctx.delete_kv(collection, key)
        self.deleted[collection] += 1

    # Retention.

    def cutoff_run(self, ctx, days):
        return keys.run_id_of(ctx.slot_start - int(days) * 86400)

    def candidates(self, ctx, collection, query, wanted, fields=None):
        """Stored rows matching query plus staged rows that pass wanted: {_key: (merged view, stored doc)}."""
        stored = dict((d["_key"], d) for d in ctx.client.kv_query(collection, query=query, fields=fields))
        extra = [k for k, d in ctx.kv[collection].items() if k not in stored and wanted(d)]
        if extra:
            stored.update(ctx.client.kv_get_many(collection, extra))
        out = collections.OrderedDict()
        for key in list(stored) + [k for k in extra if k not in stored]:
            merged = view(ctx, collection, key, stored.get(key))
            if merged:
                out[key] = (merged, stored.get(key) or {})
        return out

    def retire_strata(self, ctx):
        cutoff = self.cutoff_run(ctx, ctx.settings.retention.stratum_retire_days)
        gone = []
        for key, (doc, _) in self.candidates(ctx, STRATA, {"state": "retired"}, lambda d: d.get("state") == "retired").items():
            if doc.get("state") != "retired" or doc.get("level") == "source" or doc.get("stratum_value") == keys.ALL:
                continue
            runs = [str(doc[c]) for c in ("retired_run", "last_seen_run") if not _empty(doc.get(c))]
            since = min(runs) if runs else doc.get("updated_run_id")
            if not _empty(since) and str(since) < cutoff:
                self.delete(ctx, STRATA, key)
                gone.append(key)
        if not gone:
            return
        wanted = set(gone)
        field_keys = [k for k, d in ctx.kv[FIELDS].items() if d.get("stratum_key") in wanted]
        for chunk in _chunks(sorted(wanted)):
            field_keys.extend(d["_key"] for d in ctx.client.kv_query(FIELDS, query={"stratum_key": {"$in": chunk}}, fields=["_key"]))
        for key in field_keys:
            self.delete(ctx, FIELDS, key)

    def unobserved_fields(self, ctx, meanings):
        cutoff = self.cutoff_run(ctx, ctx.settings.retention.unobserved_field_days)
        columns = list(IDENTITY_COLUMNS) + ["presence", "last_seen_run", "updated_run_id", "usage_count", "level", "stratum_key"]
        found = self.candidates(ctx, FIELDS, {"presence": {"$in": list(RETAINABLE_PRESENCE)}},
                                lambda d: d.get("presence") in RETAINABLE_PRESENCE, fields=columns)
        for key, (doc, stored) in found.items():
            if doc.get("presence") not in RETAINABLE_PRESENCE or (_int(doc.get("usage_count")) or 0) > 0:
                continue
            if stored.get("presence") == "retired":
                continue
            source_key = source_key_of(doc)
            if source_key is None or source_key in meanings:
                continue
            since = doc.get("last_seen_run")
            if _empty(since):
                since = doc.get("updated_run_id")
            if not _empty(since) and str(since) < cutoff:
                self.delete(ctx, FIELDS, key)

    def run_records(self, ctx):
        keep = max(1, int(ctx.settings.retention.run_retention_count))
        columns = ["_key", "run_id", "status", "committed", "committed_attempt"]
        others = sorted((str(d.get("run_id") or d["_key"]), d["_key"], d) for d in ctx.client.kv_query(RUNS, fields=columns)
                        if d["_key"] != ctx.run_id)
        excess = len(others) + 1 - keep
        for _, key, doc in others:
            if excess <= 0:
                break
            if awaits_replay(doc):
                continue
            self.delete(ctx, RUNS, key)
            excess -= 1

    # Human layer.

    def field_survives(self, ctx, keys_list):
        """The field_keys among keys_list that have a matalog_fields row after this run."""
        live = set(k for k in keys_list if k in ctx.kv[FIELDS])
        rest = [k for k in keys_list if k not in live and k not in ctx.kv_deletes[FIELDS]]
        for chunk in _chunks(rest):
            live.update(ctx.client.kv_get_many(FIELDS, chunk))
        return set(k for k in live if k not in ctx.kv_deletes[FIELDS])

    def meaning_status(self, ctx, meanings):
        keep = max(1, int(ctx.settings.retention.meaning_revisions))
        for docs in meanings.values():
            for doc in docs[keep:]:
                if doc["_key"] not in ctx.kv_deletes[MEANINGS]:
                    ctx.delete_kv(MEANINGS, doc["_key"])
                    self.deleted[MEANINGS] += 1
                    self.human["revisions_deleted"] += 1
        live = self.field_survives(ctx, list(meanings))
        for field_key, docs in meanings.items():
            if not docs or docs[0]["_key"] in ctx.kv_deletes[MEANINGS]:
                continue
            current = docs[0]
            status = current.get("status")
            if status == "removed":
                continue
            if field_key not in live and status != "orphaned":
                ctx.stage_kv(MEANINGS, rows_mod.kv_doc(MEANINGS, current["_key"], status="orphaned"))
                self.human["orphaned"] += 1
            elif field_key in live and status == "orphaned":
                ctx.stage_kv(MEANINGS, rows_mod.kv_doc(MEANINGS, current["_key"], status="current"))
                self.human["current"] += 1

    def mirror(self, ctx, meanings):
        current = dict((field_key, docs[0]) for field_key, docs in meanings.items() if docs)
        staged = ctx.kv[FIELDS]
        lacking = [k for k, d in staged.items() if source_key_of(d) is None]
        stored_identity = {}
        for chunk in _chunks(lacking):
            stored_identity.update(ctx.client.kv_get_many(FIELDS, chunk))
        for key in list(staged):
            doc = staged[key]
            source_key = source_key_of(doc) or source_key_of(stored_identity.get(key))
            if source_key is None:
                continue
            ctx.stage_kv(FIELDS, rows_mod.kv_doc(FIELDS, key, **mirror_of(current.get(source_key))))
            self.mirror_sources[key] = source_key
            self.human["mirrored"] += 1
        columns = list(IDENTITY_COLUMNS) + list(MIRROR_COLUMNS)
        stored = collections.OrderedDict()
        names = sorted(set(str(d.get("field_name")) for d in current.values() if d.get("field_name")))
        for chunk in _chunks(names):
            for doc in ctx.client.kv_query(FIELDS, query={"field_name": {"$in": chunk}}, fields=columns):
                stored[doc["_key"]] = doc
        for doc in ctx.client.kv_query(FIELDS, query={"meaning_human_revision": {"$gt": 0}}, fields=columns):
            stored[doc["_key"]] = doc
        for key, doc in stored.items():
            if key in staged or key in ctx.kv_deletes[FIELDS]:
                continue
            source_key = source_key_of(doc)
            if source_key is None:
                continue
            meaning = current.get(source_key)
            if meaning is None and (_int(doc.get("meaning_human_revision")) or 0) == 0 and _empty(doc.get("meaning_human")):
                continue
            values = mirror_of(meaning)
            if _same_mirror(doc, values):
                continue
            ctx.stage_kv(FIELDS, rows_mod.kv_doc(FIELDS, key, **values))
            self.mirror_sources[key] = source_key
            self.human["mirrored"] += 1

    def refresh_mirror(self, ctx):
        """Rewrite the mirror columns of the staged rows from a new read of matalog_meanings.

        Rows not staged are left to the UI, which writes their mirror with the revision.
        """
        if not self.mirror_sources:
            return
        current = dict((field_key, docs[0]) for field_key, docs in read_meanings(ctx.client).items() if docs)
        for key, source_key in self.mirror_sources.items():
            doc = ctx.kv[FIELDS].get(key)
            if doc is not None:
                doc.update(mirror_of(current.get(source_key)))


def awaits_replay(run):
    """True for a run record S1 may still replay: status running, or committed_attempt set without committed=1."""
    if run.get("status") == "running":
        return True
    return (_int(run.get("committed_attempt")) or 0) > 0 and _int(run.get("committed")) != 1


class MirrorRefresh(object):
    """A KV writer that calls refresh once, before its first write or delete, then forwards to the wrapped writer."""

    def __init__(self, inner, refresh):
        self.inner = inner
        self.refresh = refresh
        self.done = False

    def _before(self):
        if not self.done:
            self.done = True
            self.refresh()

    def write(self, collection, docs):
        self._before()
        return self.inner.write(collection, docs)

    def delete(self, collection, keys_list):
        self._before()
        return self.inner.delete(collection, keys_list)

    def __getattr__(self, name):
        return getattr(self.inner, name)


# Rebuild derivation.

def listing_strata(settings, listing_rows):
    """matalog_strata docs derived from committed kind=stratum mode=listing rows: OrderedDict(_key -> doc).

    Each stratum takes its figures from its newest listing row. Within one
    listing run of a source the values rank by listed_events, then
    stratum_value; the first discovery.max_strata_per_source are active, the
    rest deferred; rate_per_hour is listed_events * sample_ratio * 3600 /
    discovery.stratum_list_window_seconds (over the row's own bounds for an
    anchored listing, window_anchor=last_event) and share_of_source is rate
    over that run's sum. A value absent
    from the source's newest listing keeps the figures of its own last
    listing, and is retired (retired_run the newest listing run) once that is
    retention.stratum_retire_days older. A value of a stratum_field other than
    the newest listing's is retired (stratum key change), with retired_run the
    first visible listing under the new field.
    """
    by_source = collections.OrderedDict()
    for row in listing_rows:
        by_source.setdefault(row["source_key"], []).append(row)
    cap = int(settings.discovery.max_strata_per_source)
    retire_seconds = int(settings.retention.stratum_retire_days) * 86400
    window = float(settings.discovery.stratum_list_window_seconds)

    def events_of(row):
        return rows_mod._int_or_none(row.get("events_seen")) or 0

    def rate(row):
        ratio = rows_mod._int_or_none(row.get("sample_ratio")) or 1
        span = window
        if row.get("window_anchor") == rows_mod.ANCHOR_LAST_EVENT:
            # An anchored listing's window is discovery-sized; the row's own bounds give the span S2 used.
            earliest, latest = rows_mod._float_or_none(row.get("earliest")), rows_mod._float_or_none(row.get("latest"))
            if earliest is not None and latest is not None and latest > earliest:
                span = latest - earliest
        return float(events_of(row)) * ratio * 3600.0 / span if span > 0 else 0.0

    out = collections.OrderedDict()
    for source_rows in by_source.values():
        source_rows = [r for r in source_rows if r.get("stratum_value") != keys.ALL]
        if not source_rows:
            continue
        newest = collections.OrderedDict()
        runs = collections.defaultdict(list)
        by_run = collections.defaultdict(list)
        for row in sorted(source_rows, key=lambda r: str(r["run_id"])):
            newest[row["stratum_key"]] = row
            runs[row["stratum_key"]].append(str(row["run_id"]))
            by_run[str(row["run_id"])].append(row)
        latest_run = max(by_run)
        field = by_run[latest_run][0]["stratum_field"]
        rekey_run = min(str(r["run_id"]) for r in source_rows if r["stratum_field"] == field)
        standing = {}
        for run_id, run_rows in by_run.items():
            ranked = sorted(run_rows, key=lambda r: (-events_of(r), str(r["stratum_value"])))
            total = sum(rate(r) for r in ranked)
            for position, row in enumerate(ranked):
                standing[(run_id, row["stratum_key"])] = ("active" if position < cap else "deferred", (rate(row) / total) if total > 0 else 0.0)
        for key, row in newest.items():
            run_id = str(row["run_id"])
            state, share = standing[(run_id, key)]
            retired_run = None
            if row["stratum_field"] != field:
                state, retired_run = "retired", rekey_run
            elif keys.slot_start_of(latest_run) - keys.slot_start_of(run_id) >= retire_seconds:
                state, retired_run = "retired", latest_run
            out[key] = _listing_doc(row, runs, state=state, listed_events=events_of(row), rate_per_hour=rate(row),
                                    share_of_source=share, retired_run=retired_run)
    return out


def _listing_doc(row, runs, **values):
    key_runs = runs[row["stratum_key"]]
    values.update(listed_sample_ratio=rows_mod._int_or_none(row.get("sample_ratio")) or 1, first_seen_run=min(key_runs),
                  last_seen_run=max(key_runs), updated_run_id=max(key_runs))
    if values.get("prunable") is None and row.get("prunable") not in (None, ""):
        values["prunable"] = rows_mod._int_or_none(row.get("prunable"))
    return rows_mod.strata_doc(row["src_index"], row["src_sourcetype"], row["stratum_field"], row["stratum_value"], **values)


ROLLUP_STATES = ("active",)


def _num(value):
    return rows_mod._float_or_none(value)


def rollup_fields(settings, field_docs, strata_docs, stored_states=None):
    """level=source is_rollup=1 field docs recomputed from level=stratum children: OrderedDict(_key -> doc).

    Children are the present field docs of strata whose state is active (or
    unknown); deferred and retired strata are left out. Per
    snapshot (cur_disc_*, cur_prof_*) counts are summed over the children
    carrying it, events over every active stratum of the source: the stratum's
    current discovery for cur_disc_*, its profile of the rollup's run for
    cur_prof_* (read off any field row of that stratum and run), a stratum
    without the field counting in full. coverage is their ratio, distinct and
    distinct_exact follow rows.rollup_distinct without a probe figure: the
    whole-source dc() S4 probes is not in the summary index, so a rebuilt
    rollup over more than one child is inexact until the source's next
    profile. run_id is the newest child run. top_values merge children by summed counts, sample_values is
    the union (children by cur_disc_count descending) capped like a stored
    sample set, identifier is 1 when any child is, type_guess is the
    children's majority or mixed, numeric stats combine the children's.
    absent_strata lists the active strata profiled in the rollup's run
    without the field (without a profile, those discovered without it), as
    the strata table orders them.
    """
    stored_states = stored_states or {}

    def active(stratum_key):
        stratum = strata_docs.get(stratum_key) or {}
        state = stratum.get("state") or stored_states.get(stratum_key)
        return not state or state in ROLLUP_STATES

    groups = collections.OrderedDict()
    profile_events = {}
    for doc in field_docs.values():
        if doc.get("stratum_value") in (None, keys.ALL) or doc.get("level") == "source":
            continue
        if doc.get("cur_prof_run_id") and doc.get("cur_prof_events") is not None:
            profile_events[(doc.get("stratum_key"), str(doc["cur_prof_run_id"]))] = rows_mod._int_or_none(doc.get("cur_prof_events")) or 0
        if doc.get("presence") != "present" or not active(doc.get("stratum_key")):
            continue
        groups.setdefault((doc["src_index"], doc["src_sourcetype"], doc["field_name"]), []).append(doc)
    strata_by_source = collections.defaultdict(list)
    for key, stratum in strata_docs.items():
        if stratum.get("level") == "stratum" and stratum.get("stratum_value") not in (None, keys.ALL) and active(key):
            strata_by_source[stratum.get("source_key")].append(dict(stratum, _key=key))
    p = settings.profile

    def num(doc, column):
        return rows_mod._int_or_none(doc.get(column)) or 0

    out = collections.OrderedDict()
    for (src_index, src_sourcetype, field_name), kids in groups.items():
        kids = sorted(kids, key=lambda k: (-num(k, "cur_disc_count"), str(k.get("stratum_key", ""))))
        stratum_field = any(field_name == k.get("stratum_field") for k in kids)
        strata = sorted(strata_by_source.get(keys.source_key(src_index, src_sourcetype), []),
                        key=lambda d: (-num(d, "listed_events"), str(d.get("stratum_value"))))
        values = collections.OrderedDict([("is_rollup", 1), ("rollup_strata", len(kids)), ("presence", "present"), ("observed", 1),
                                          ("consecutive_unseen", 0), ("is_stratum_field", 1 if stratum_field else 0)])
        absent = None
        for prefix, extra in (("cur_disc_", False), ("cur_prof_", True)):
            snap = [k for k in kids if k.get(prefix + "run_id")]
            if not snap:
                continue
            count = sum(num(k, prefix + "count") for k in snap)
            run_id = max(str(k[prefix + "run_id"]) for k in snap)
            child_events = dict((k.get("stratum_key"), num(k, prefix + "events")) for k in snap)
            if extra:
                known = dict((d["_key"], profile_events.get((d["_key"], run_id))) for d in strata)
            else:
                known = dict((d["_key"], rows_mod._int_or_none(d.get("cur_events_seen")) if d.get("cur_run_id") else None) for d in strata)
            events = sum(child_events.get(k, 0) if v is None else v for k, v in known.items()) if strata else sum(child_events.values())
            carrying = set(k.get("stratum_key") for k in snap if num(k, prefix + "count") > 0)
            if not extra:
                carrying |= set(k.get("stratum_key") for k in kids if not k.get(prefix + "run_id"))
            if extra or absent is None:
                absent = [d.get("stratum_value") for d in strata if known.get(d["_key"]) is not None and d["_key"] not in carrying]
            values[prefix + "run_id"] = run_id
            values[prefix + "count"] = count
            values[prefix + "events"] = events
            values[prefix + "coverage"] = rows_mod.coverage(count, events)
            distinct, exact = rows_mod.rollup_distinct(
                [(num(k, prefix + "distinct"), num(k, prefix + "distinct_exact"), k.get("stratum_value")) for k in snap], stratum_field)
            values[prefix + "distinct"] = distinct
            if extra:
                values[prefix + "distinct_exact"] = exact
                values[prefix + "sample_ratio"] = max(rows_mod._int_or_none(k.get(prefix + "sample_ratio")) or 1 for k in snap)
        identifier = 1 if any(num(k, "identifier") == 1 for k in kids) else 0
        summed = collections.OrderedDict()
        for kid in kids:
            for value, count in zip(kid.get("top_values") or [], kid.get("top_counts") or []):
                summed[str(value)] = summed.get(str(value), 0) + (rows_mod._int_or_none(count) or 0)
        merged_top = sorted(summed.items(), key=lambda item: (-item[1], item[0]))
        values["identifier"] = identifier
        values["top_values"] = [] if identifier else [v for v, _ in merged_top[:p.top_values]]
        values["top_counts"] = [] if identifier else [str(c) for _, c in merged_top[:p.top_values]]
        union = [v for kid in kids for v in (kid.get("sample_values") or [])]
        values["sample_values"], values["samples_truncated"] = rows_mod.cap_sample_values(union, p.sample_values, p.sample_values_max_bytes, p.max_value_chars)
        values["values_hash"] = rows_mod.values_hash([v for v, _ in merged_top])
        guesses = collections.Counter(k.get("type_guess") for k in kids if k.get("type_guess"))
        if guesses:
            guess, top = sorted(guesses.items(), key=lambda item: (-item[1], item[0]))[0]
            values["type_guess"] = guess if top * 2 > sum(guesses.values()) else "mixed"
        numeric = [k for k in kids if num(k, "numeric_count") > 0]
        values["numeric_count"] = sum(num(k, "numeric_count") for k in numeric)
        mins = [_num(k.get("num_min")) for k in numeric if _num(k.get("num_min")) is not None]
        maxs = [_num(k.get("num_max")) for k in numeric if _num(k.get("num_max")) is not None]
        means = [(_num(k.get("num_mean")), num(k, "numeric_count")) for k in numeric if _num(k.get("num_mean")) is not None]
        weight = sum(w for _, w in means)
        values["num_min"] = min(mins) if mins else None
        values["num_max"] = max(maxs) if maxs else None
        values["num_mean"] = (sum(m * w for m, w in means) / weight) if weight > 0 else None
        for column, pick in (("first_seen_run", min), ("last_seen_run", max), ("updated_run_id", max)):
            runs_seen = [str(k[column]) for k in kids if k.get(column)]
            if runs_seen:
                values[column] = pick(runs_seen)
        times = [_num(k.get("last_seen_time")) for k in kids if _num(k.get("last_seen_time")) is not None]
        if times:
            values["last_seen_time"] = max(times)
        origins = collections.Counter(k.get("origin") for k in kids if k.get("origin"))
        values["origin"] = sorted(origins.items(), key=lambda item: (-item[1], item[0]))[0][0] if origins else "unknown"
        if absent is not None:
            values["absent_strata"] = absent
            values["absent_strata_count"] = len(absent)
        doc = rows_mod.fields_doc(src_index, src_sourcetype, keys.ALL, keys.ALL, field_name, **values)
        out[doc["_key"]] = doc
    return out

