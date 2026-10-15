#!/usr/bin/env python3
"""GET and POST /services/matalog/catalog: the catalog collections for the pages, read with the system session
and filtered by the caller's index access.

GET collection=<name> with query=<json>, fields=<csv>, sort=<column[:dir]>, limit=<n>, skip=<n>, as the KV data
endpoint takes them, returns the rows; key=<_key> returns one row or 404. Requires matalog_catalog_read.
POST batch=1 with a JSON body {"collection": <name>, "docs": [...]} writes the human layer: matalog_meanings rows
and the meaning_human_* mirror columns of matalog_fields (matalog_meanings_write), matalog_semantic_types and
matalog_stratum_config rows with origin=user (matalog_types_write). Every other collection and column is refused.
A removed meaning is a revision with empty text and status=removed; its mirror is cleared and carries no author.
Rules in docs/data-model.md, "Agent surface", "Catalog endpoint".
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from matalog_access import (CAP_CATALOG_READ, CAP_MEANINGS_WRITE, CAP_TYPES_WRITE, IN_CHUNK, READABLE, KvStore,  # noqa: E402
                            RequestError, ScopedReader, caller_from_request, chunks, request_params, text)

try:
    from splunk.persistconn.application import PersistentServerConnectionApplication
except ImportError:
    PersistentServerConnectionApplication = object

MAX_BODY = 8 * 1024 * 1024
BATCH = 500
MAX_DOCS = 5000
MIRROR_COLUMNS = ("meaning_human", "meaning_human_author", "meaning_human_time", "meaning_human_revision")
MEANING_COLUMNS = ("_key", "field_key", "src_index", "src_sourcetype", "field_name", "revision", "is_current", "text",
                   "author", "created_at", "note", "status")
WRITABLE = {
    "matalog_meanings": CAP_MEANINGS_WRITE,
    "matalog_fields": CAP_MEANINGS_WRITE,
    "matalog_semantic_types": CAP_TYPES_WRITE,
    "matalog_stratum_config": CAP_TYPES_WRITE,
}


def parse_query(raw):
    if not raw:
        return None
    try:
        query = json.loads(raw)
    except ValueError:
        raise RequestError(400, "query is not JSON")
    if not isinstance(query, dict):
        raise RequestError(400, "query must be a JSON object")
    return query


def parse_int(raw, name):
    if raw in (None, ""):
        return 0
    try:
        value = int(raw)
    except ValueError:
        raise RequestError(400, "%s must be an integer" % name)
    if value < 0:
        raise RequestError(400, "%s must not be negative" % name)
    return value


def read_catalog(params, reader):
    collection = params.get("collection") or ""
    if collection not in READABLE:
        raise RequestError(400, "collection must be one of %s" % ", ".join(READABLE))
    if params.get("key"):
        row = reader.get(collection, params["key"])
        if row is None:
            raise RequestError(404, "no %s row %s" % (collection, params["key"]))
        return row
    fields = [f.strip() for f in (params.get("fields") or "").split(",") if f.strip()]
    return reader(collection, parse_query(params.get("query")), fields=fields or None, limit=parse_int(params.get("limit"), "limit"),
                  sort=params.get("sort") or None, skip=parse_int(params.get("skip"), "skip"))


def parse_batch(body):
    try:
        data = json.loads(body)
    except ValueError:
        raise RequestError(400, "body is not JSON")
    if not isinstance(data, dict) or not isinstance(data.get("docs"), list):
        raise RequestError(400, 'body must be {"collection": <name>, "docs": [...]}')
    docs = [d for d in data["docs"] if isinstance(d, dict)]
    if len(docs) != len(data["docs"]):
        raise RequestError(400, "every doc must be a JSON object")
    if len(docs) > MAX_DOCS:
        raise RequestError(413, "at most %d docs per batch" % MAX_DOCS)
    for doc in docs:
        if not text(doc.get("_key")):
            raise RequestError(400, "every doc needs a _key")
    return text(data.get("collection")), docs


def stored_by_key(store, collection, keys):
    out = {}
    for chunk in chunks(sorted(set(keys)), IN_CHUNK):
        for row in store.read(collection, {"_key": {"$in": chunk}}):
            out[text(row.get("_key"))] = row
    return out


def meaning_docs(docs, caller):
    out = []
    for doc in docs:
        if set(doc) - set(MEANING_COLUMNS):
            raise RequestError(400, "matalog_meanings takes the contract columns only: %s" % ", ".join(sorted(set(doc) - set(MEANING_COLUMNS))))
        if not caller.can_read_index(doc.get("src_index")):
            raise RequestError(403, "index not readable: %s" % text(doc.get("src_index")))
        clean = dict(doc)
        clean["author"] = caller.user
        out.append(clean)
    return out


def mirror_docs(docs, caller, store):
    stored = stored_by_key(store, "matalog_fields", [text(d.get("_key")) for d in docs])
    out = []
    for doc in docs:
        row = stored.get(text(doc.get("_key")))
        if row is None:
            raise RequestError(404, "no matalog_fields row %s" % text(doc.get("_key")))
        if not caller.can_read_index(row.get("src_index")):
            raise RequestError(403, "index not readable: %s" % text(row.get("src_index")))
        merged = dict(row)
        merged.pop("_user", None)
        for column in MIRROR_COLUMNS:
            if column in doc:
                merged[column] = doc[column]
        # A cleared mirror (a removed meaning) carries no author.
        merged["meaning_human_author"] = caller.user if text(merged.get("meaning_human")) else ""
        out.append(merged)
    return out


def user_docs(collection, docs, caller, store, author_column):
    stored = stored_by_key(store, collection, [text(d.get("_key")) for d in docs])
    out = []
    for doc in docs:
        if text(doc.get("origin")) != "user":
            raise RequestError(400, "%s takes origin=user rows only" % collection)
        row = stored.get(text(doc.get("_key")))
        if row is not None and text(row.get("origin")) != "user":
            raise RequestError(403, "%s is a %s row" % (text(doc.get("_key")), text(row.get("origin")) or "shipped"))
        clean = dict(doc)
        clean.pop("_user", None)
        clean[author_column] = caller.user
        out.append(clean)
    return out


def write_catalog(collection, docs, caller, store, now=None):
    capability = WRITABLE.get(collection)
    if capability is None:
        raise RequestError(403, "%s is not writable through this endpoint" % (collection or "the collection"))
    caller.require(capability)
    if collection == "matalog_meanings":
        clean = meaning_docs(docs, caller)
    elif collection == "matalog_fields":
        clean = mirror_docs(docs, caller, store)
    elif collection == "matalog_semantic_types":
        clean = user_docs(collection, docs, caller, store, "author")
        for doc in clean:
            doc.setdefault("updated_at", int(now or time.time()))
    else:
        clean = user_docs(collection, docs, caller, store, "set_by")
        for doc in clean:
            doc.setdefault("set_at", int(now or time.time()))
    keys = []
    for chunk in chunks(clean, BATCH):
        result = store.write(collection, chunk)
        keys.extend(result if isinstance(result, list) else [])
    return keys


class CatalogHandler(PersistentServerConnectionApplication):
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
            params = request_params(request)
            if method == "GET":
                caller.require(CAP_CATALOG_READ)
                payload = read_catalog(params, ScopedReader(store, caller))
            else:
                if params.get("batch") != "1":
                    raise RequestError(400, "POST takes batch=1")
                body = text(request.get("payload"))
                if len(body.encode("utf-8")) > MAX_BODY:
                    raise RequestError(413, "body over %d MB" % (MAX_BODY // (1024 * 1024)))
                collection, docs = parse_batch(body)
                payload = write_catalog(collection, docs, caller, store)
        except RequestError as exc:
            return {"status": exc.status, "payload": {"error": str(exc)}}
        except Exception as exc:
            return {"status": 500, "payload": {"error": "%s: %s" % (exc.__class__.__name__, str(exc)[:500])}}
        return {"status": 200, "payload": json.dumps(payload), "headers": {"Content-Type": "application/json"}}
