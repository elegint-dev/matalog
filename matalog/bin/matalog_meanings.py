#!/usr/bin/env python3
"""GET and POST /services/matalog/meanings: the catalog's field meanings as a sheet, out and back in.

GET returns every catalogued field with its human meaning, as CSV (default) or JSON: format=csv|json,
level=source|all, the optional filters index=<name> and sourcetype=<name>, and defaults=1 to include Splunk
default fields (is_default=1), which are left out otherwise.
POST takes a CSV or JSON body of field_key, meaning and meaning_note rows; each changed meaning becomes a new
matalog_meanings revision mirrored onto the field rows, exactly as the field page writes it. A meaning of "-"
(one hyphen) removes the current meaning: a revision with empty text and status=removed, the mirror cleared.

The collections are read and written with the system session after the capability check; the export is narrowed
to the indexes the caller's roles can search and import rows of other indexes are rejected (matalog_access.py).
The columns and the import rules are documented in docs/data-model.md, "Agent surface".
"""
import csv
import io
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from matalog.keys import k  # noqa: E402
from matalog_access import (IN_CHUNK, KvStore, RequestError, ScopedReader, caller_from_request, chunks, request_params,  # noqa: E402
                            require_primary, text)
from matalog_summary import inum, listing, num, type_name  # noqa: E402

try:
    from splunk.persistconn.application import PersistentServerConnectionApplication
except ImportError:
    PersistentServerConnectionApplication = object

MEANINGS_COLUMNS = ("field_key", "src_index", "src_sourcetype", "level", "stratum_field", "stratum_value", "field_name",
                    "type_guess", "semantic_type", "coverage", "distinct", "top_values", "cim_fields", "meaning",
                    "meaning_author", "meaning_revision", "meaning_note")
MEANINGS_READ_COLUMNS = ("field_key", "src_index", "src_sourcetype", "level", "stratum_field", "stratum_value", "field_name",
                         "type_guess", "best_type_id", "cur_prof_coverage", "cur_prof_distinct", "top_values", "cim_fields",
                         "meaning_human", "meaning_human_author", "meaning_human_revision")
REMOVE = "-"
IMPORT_COLUMNS = ("field_key", "source_key", "src_index", "src_sourcetype", "field_name", "level", "meaning_human")
EXPORT_PRESENCE = ("present", "declared_only")
MAX_BODY = 8 * 1024 * 1024
BATCH = 500
LIST_SEP = " | "
CSV_FILENAME = "matalog-meanings.csv"


def meaning_row(row):
    return {
        "field_key": text(row.get("field_key")),
        "src_index": text(row.get("src_index")),
        "src_sourcetype": text(row.get("src_sourcetype")),
        "level": text(row.get("level")),
        "stratum_field": text(row.get("stratum_field")),
        "stratum_value": text(row.get("stratum_value")),
        "field_name": text(row.get("field_name")),
        "type_guess": text(row.get("type_guess")),
        "semantic_type": type_name(row.get("best_type_id")),
        "coverage": num(row.get("cur_prof_coverage")),
        "distinct": num(row.get("cur_prof_distinct")),
        "top_values": LIST_SEP.join(listing(row.get("top_values"))),
        "cim_fields": LIST_SEP.join(listing(row.get("cim_fields"))),
        "meaning": text(row.get("meaning_human")),
        "meaning_author": text(row.get("meaning_human_author")),
        "meaning_revision": inum(row.get("meaning_human_revision")),
        "meaning_note": "",
    }


def export_query(params):
    level = params.get("level") or "source"
    if level not in ("source", "all"):
        raise RequestError(400, "level must be source or all")
    query = {"presence": {"$in": list(EXPORT_PRESENCE)}}
    if level == "source":
        query["level"] = "source"
    if text(params.get("defaults")).strip().lower() not in ("1", "true", "yes"):
        query["is_default"] = {"$ne": 1}
    if params.get("index"):
        query["src_index"] = params["index"].lower()
    if params.get("sourcetype"):
        query["src_sourcetype"] = params["sourcetype"]
    return query


def export_rows(params, read):
    rows = read("matalog_fields", export_query(params), fields=MEANINGS_READ_COLUMNS)
    rows.sort(key=lambda r: (text(r.get("src_index")), text(r.get("src_sourcetype")), text(r.get("field_name")),
                             text(r.get("level")) != "source", text(r.get("stratum_value"))))
    return [meaning_row(r) for r in rows]


def render_csv(rows):
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=MEANINGS_COLUMNS, lineterminator="\r\n")
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue()


def export_meanings(params, read):
    rows = export_rows(params, read)
    if (params.get("format") or "csv") == "json":
        return {"status": 200, "payload": {"columns": list(MEANINGS_COLUMNS), "rows": rows, "n": len(rows)},
                "headers": {"Content-Type": "application/json"}}
    if params.get("format") != "csv":
        raise RequestError(400, "format must be csv or json")
    return {"status": 200, "payload": render_csv(rows),
            "headers": {"Content-Type": "text/csv; charset=utf-8",
                        "Content-Disposition": "attachment; filename=%s" % CSV_FILENAME}}


def parse_import(body, content_type):
    body = body.lstrip("﻿")
    stripped = body.lstrip()
    if "json" in content_type.lower() or stripped[:1] in ("{", "["):
        try:
            data = json.loads(body)
        except ValueError:
            raise RequestError(400, "body is not JSON")
        rows = data.get("rows") if isinstance(data, dict) else data
        if not isinstance(rows, list):
            raise RequestError(400, 'JSON body must be {"rows": [{"field_key": ..., "meaning": ..., "meaning_note": ...}]}')
        return [r for r in rows if isinstance(r, dict)]
    reader = csv.DictReader(io.StringIO(body))
    names = reader.fieldnames or []
    if "field_key" not in names or "meaning" not in names:
        raise RequestError(400, "CSV needs field_key and meaning columns")
    return list(reader)


def revision_doc(row, revision, meaning, note, user, now):
    """A new matalog_meanings revision; a removal carries empty text and status=removed."""
    return {
        "_key": k(text(row.get("field_key")), revision),
        "field_key": text(row.get("field_key")),
        "src_index": text(row.get("src_index")),
        "src_sourcetype": text(row.get("src_sourcetype")),
        "field_name": text(row.get("field_name")),
        "revision": revision,
        "is_current": 1,
        "text": "" if meaning == REMOVE else meaning,
        "author": user,
        "created_at": now,
        "note": note,
        "status": "removed" if meaning == REMOVE else "current",
    }


def mirror_columns(meaning, revision, user, now):
    """The meaning_human_* columns of the field rows after the revision; cleared by a removal."""
    if meaning == REMOVE:
        return {"meaning_human": "", "meaning_human_author": "", "meaning_human_time": None, "meaning_human_revision": 0}
    return {"meaning_human": meaning, "meaning_human_author": user, "meaning_human_time": now, "meaning_human_revision": revision}


def import_meanings(rows, user, read, write, now=None):
    """Apply the rows; returns the counts and the rejected rows."""
    now = int(now or time.time())
    result = {"written": 0, "unchanged": 0, "skipped": 0, "rejected": [], "rows": len(rows)}
    wanted = []
    seen = set()
    for r in rows:
        key = text(r.get("field_key")).strip()
        meaning = text(r.get("meaning")).strip()
        note = text(r.get("meaning_note")).strip()
        if not meaning:
            result["skipped"] += 1
            continue
        if key in seen:
            result["rejected"].append({"field_key": key, "reason": "duplicate field_key"})
            continue
        seen.add(key)
        wanted.append((key, meaning, note))
    fields = {}
    unscoped = getattr(read, "unscoped", read)
    for chunk in chunks([w[0] for w in wanted if w[0]], IN_CHUNK):
        for row in unscoped("matalog_fields", {"field_key": {"$in": chunk}}, fields=IMPORT_COLUMNS):
            fields[text(row.get("field_key"))] = row
    readable = getattr(read, "can_read_index", lambda name: True)
    changes = []
    for key, meaning, note in wanted:
        row = fields.get(key)
        if row is None:
            result["rejected"].append({"field_key": key, "reason": "unknown field_key"})
        elif not readable(row.get("src_index")):
            result["rejected"].append({"field_key": key, "reason": "index not readable"})
        elif text(row.get("level")) != "source":
            result["rejected"].append({"field_key": key, "reason": "stratum row, use the source-level key"})
        elif meaning == text(row.get("meaning_human")) or (meaning == REMOVE and not text(row.get("meaning_human"))):
            result["unchanged"] += 1
        else:
            changes.append((row, meaning, note))
    if not changes:
        return result
    existing = {}
    for chunk in chunks([text(c[0].get("field_key")) for c in changes], IN_CHUNK):
        for m in read("matalog_meanings", {"field_key": {"$in": chunk}}):
            existing.setdefault(text(m.get("field_key")), []).append(m)
    docs = []
    mirror = {}
    for row, meaning, note in changes:
        key = text(row.get("field_key"))
        prior = existing.get(key, [])
        revision = max([inum(m.get("revision")) for m in prior] + [0]) + 1
        for m in prior:
            if inum(m.get("is_current")) == 1:
                flipped = dict(m)
                flipped.pop("_user", None)
                flipped["is_current"] = 0
                flipped["status"] = "superseded"
                docs.append(flipped)
        docs.append(revision_doc(row, revision, meaning, note, user, now))
        mirror[(text(row.get("source_key")), text(row.get("field_name")))] = mirror_columns(meaning, revision, user, now)
    for chunk in chunks(docs, BATCH):
        write("matalog_meanings", chunk)
    updates = []
    for chunk in chunks(list(mirror), IN_CHUNK):
        query = {"$or": [{"source_key": sk, "field_name": fn} for sk, fn in chunk]}
        for row in read("matalog_fields", query):
            hit = mirror.get((text(row.get("source_key")), text(row.get("field_name"))))
            if hit is None:
                continue
            doc = dict(row)
            doc.pop("_user", None)
            doc.update(hit)
            updates.append(doc)
    for chunk in chunks(updates, BATCH):
        write("matalog_fields", chunk)
    result["written"] = len(changes)
    return result


def request_header(request, name):
    headers = request.get("headers") or []
    if isinstance(headers, dict):
        headers = headers.items()
    for item in headers:
        if isinstance(item, (list, tuple)) and len(item) == 2 and text(item[0]).lower() == name.lower():
            return text(item[1])
    return ""


class MeaningsHandler(PersistentServerConnectionApplication):
    def __init__(self, command_line=None, command_arg=None):
        if PersistentServerConnectionApplication is not object:
            PersistentServerConnectionApplication.__init__(self)

    def handle(self, in_string):
        try:
            request = json.loads(in_string)
        except ValueError:
            return {"status": 400, "payload": {"error": "request is not JSON"}}
        method = text(request.get("method")).upper()
        if method not in ("GET", "POST"):
            return {"status": 405, "payload": {"error": "GET or POST only"}}
        try:
            caller, system_key = caller_from_request(request)
            store = KvStore(system_key)
            read = ScopedReader(store, caller)
            if method == "GET":
                return export_meanings(request_params(request), read)
            body = text(request.get("payload"))
            if len(body.encode("utf-8")) > MAX_BODY:
                raise RequestError(413, "body over %d MB; split the file" % (MAX_BODY // (1024 * 1024)))
            require_primary(store)
            rows = parse_import(body, request_header(request, "Content-Type"))
            payload = import_meanings(rows, caller.user, read, store.write)
        except RequestError as exc:
            return {"status": exc.status, "payload": {"error": str(exc)}}
        except Exception as exc:
            return {"status": 500, "payload": {"error": "%s: %s" % (exc.__class__.__name__, str(exc)[:500])}}
        return {"status": 200, "payload": payload, "headers": {"Content-Type": "application/json"}}
