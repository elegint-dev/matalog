#!/usr/bin/env python3
"""Shared pieces of the app's REST handlers: the KV store read and written with the system session, the caller
(user, roles, capabilities, readable indexes) and the index filter every catalog read goes through.

Rows of an index-scoped collection (one with a src_index column) are returned only when the caller's roles,
with inheritance, can search that index; the filter is applied inside the KV query, so limit and skip count
readable rows only. The usage graph is scoped through the rows it resolves to: a usage edge is readable when one
of its resolved_field_keys belongs to a readable index, a declaration when one of its applies_to_source_keys
does, a knowledge object only by object_key and only when a readable edge names it, and a run record is cut to
the columns that carry no source or search text. The semantic types and the stratum configuration pass through.
A caller who can search every catalog index sees everything. Rules in docs/data-model.md, "Agent surface",
"Access".
"""
import json
import re

try:
    import splunk.rest
except ImportError:
    splunk = None

APP = "matalog"
KV_PAGE = 1000
IN_CHUNK = 200

INDEX_SCOPED = ("matalog_sources", "matalog_strata", "matalog_fields", "matalog_cim_coverage", "matalog_meanings",
                "matalog_field_types")
EDGE_SCOPED = ("matalog_usage", "matalog_declarations", "matalog_objects")
RUNS = "matalog_runs"
PASS_THROUGH = ("matalog_stratum_config", "matalog_semantic_types")
READABLE = INDEX_SCOPED + EDGE_SCOPED + (RUNS,) + PASS_THROUGH

# matalog_runs columns a caller who cannot search every catalog index gets: identity, state, timing, the budget
# the windows are computed from, and counts. Not served: errors, per_step, type_versions, reclassified_types,
# profiled_as, app_context, config_hash, type_versions_hash.
RUN_READER_COLUMNS = (
    "_key", "run_id", "attempt", "committed", "committed_attempt", "run_mode", "status", "started_at", "finished_at",
    "budget", "searches_issued", "searches_failed", "write_searches", "write_reserve", "write_bytes", "events_scanned",
    "events_matched", "search_seconds", "wall_seconds", "peak_concurrency", "budget_exhausted", "rows_written",
    "sources_total", "sources_due", "sources_profiled", "sources_deferred", "strata_total", "strata_due",
    "strata_discovered", "strata_deferred", "strata_over_cap", "strata_profile_due", "strata_profiled", "fields_present", "fields_new", "indexes_total",
    "indexes_scanned", "indexes_sourceless", "objects_total",
    "objects_parsed", "objects_partial", "objects_failed", "cim_datasets", "cim_datasets_unresolved", "cim_mapped",
    "scan_ratio_max", "audit_watermark",
)
# The column that scopes an edge collection and the collection its keys point at.
EDGE_RULES = {
    "matalog_usage": ("resolved_field_keys", "matalog_fields"),
    "matalog_declarations": ("applies_to_source_keys", "matalog_sources"),
}

CAP_CATALOG_READ = "matalog_catalog_read"
CAP_SUMMARY_READ = "matalog_summary_read"
CAP_MEANINGS_WRITE = "matalog_meanings_write"
CAP_TYPES_WRITE = "matalog_types_write"


class RequestError(Exception):
    def __init__(self, status, message):
        Exception.__init__(self, message)
        self.status = status


def text(value):
    return "" if value is None else str(value)


def request_params(request):
    params = {}
    for item in request.get("query") or []:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            params[text(item[0])] = text(item[1])
    return params


def chunks(items, size):
    for start in range(0, len(items), size):
        yield items[start:start + size]


# Index patterns as srchIndexesAllowed carries them: * is the wildcard, and a pattern that does not start with an
# underscore never matches an internal index.

def index_pattern(pattern):
    body = ".*".join(re.escape(part) for part in text(pattern).split("*"))
    return re.compile("^%s$" % body, re.IGNORECASE)


def index_allowed(patterns, name):
    name = text(name)
    if not name:
        return False
    for pattern in patterns:
        if name.startswith("_") and not text(pattern).startswith("_"):
            continue
        if index_pattern(pattern).match(name):
            return True
    return False


class KvStore(object):
    """The app's collections through storage/collections/data with one session key."""

    def __init__(self, session_key):
        self.session_key = session_key

    def path(self, collection, tail=None):
        base = "/servicesNS/nobody/%s/storage/collections/data/%s" % (APP, collection)
        return base + ("/" + tail if tail else "")

    def read(self, collection, query=None, fields=None, limit=0, sort=None, skip=0):
        out = []
        skip = int(skip or 0)
        limit = int(limit or 0)
        page = min(limit, KV_PAGE) if limit else KV_PAGE
        while True:
            args = {"output_mode": "json", "limit": page, "skip": skip}
            if query:
                args["query"] = json.dumps(query)
            if fields:
                args["fields"] = ",".join(fields)
            if sort:
                args["sort"] = sort
            _, body = splunk.rest.simpleRequest(self.path(collection), sessionKey=self.session_key, getargs=args,
                                                raiseAllErrors=True)
            rows = json.loads(body)
            out.extend(rows)
            if len(rows) < page or (limit and len(out) >= limit):
                break
            skip += page
        return out[:limit] if limit else out

    def get(self, collection, key):
        try:
            _, body = splunk.rest.simpleRequest(self.path(collection, key), sessionKey=self.session_key,
                                                getargs={"output_mode": "json"}, raiseAllErrors=True)
        except Exception as exc:
            if "404" in str(exc):
                return None
            raise
        return json.loads(body)

    def write(self, collection, docs):
        if not docs:
            return []
        _, body = splunk.rest.simpleRequest(self.path(collection, "batch_save"), sessionKey=self.session_key,
                                            jsonargs=json.dumps(docs), method="POST", raiseAllErrors=True)
        try:
            return json.loads(body)
        except ValueError:
            return []


class Caller(object):
    """The calling user: name, roles, capabilities and the index patterns the roles allow, with inheritance."""

    def __init__(self, user, roles, capabilities, index_patterns):
        self.user = user or "unknown"
        self.roles = list(roles)
        self.capabilities = set(capabilities)
        self.index_patterns = list(index_patterns)

    def has(self, capability):
        return capability in self.capabilities

    def require(self, capability):
        if not self.has(capability):
            raise RequestError(403, "capability %s required" % capability)

    def can_read_index(self, name):
        return index_allowed(self.index_patterns, name)


def _entries(session_key, path):
    _, body = splunk.rest.simpleRequest(path, sessionKey=session_key, getargs={"output_mode": "json", "count": 0},
                                        raiseAllErrors=True)
    return json.loads(body).get("entry") or []


def load_caller(session_key, system_key):
    """The caller from authentication/current-context (as the caller) and authorization/roles (system session)."""
    entries = _entries(session_key, "/services/authentication/current-context")
    content = (entries[0].get("content") or {}) if entries else {}
    user = text(content.get("username"))
    roles = [text(r) for r in (content.get("roles") or [])]
    capabilities = [text(c) for c in (content.get("capabilities") or [])]
    patterns = []
    for role in roles:
        for entry in _entries(system_key or session_key, "/services/authorization/roles/%s" % role):
            body = entry.get("content") or {}
            for column in ("srchIndexesAllowed", "imported_srchIndexesAllowed"):
                for pattern in body.get(column) or []:
                    if text(pattern) and text(pattern) not in patterns:
                        patterns.append(text(pattern))
    return Caller(user, roles, capabilities, patterns)


def caller_from_request(request):
    session = request.get("session") or {}
    session_key = text(session.get("authtoken"))
    if not session_key:
        raise RequestError(401, "no session")
    system_key = text(request.get("system_authtoken")) or session_key
    return load_caller(session_key, system_key), system_key


class ScopedReader(object):
    """Reads with the system session, narrowed to the indexes the caller can search.

    Callable as read(collection, query, fields=, limit=, sort=, skip=) for the summary and meanings code.
    """

    def __init__(self, store, caller):
        self.store = store
        self.caller = caller
        self._readable = None
        self._key_index = {}

    def readable_indexes(self):
        """The catalog's indexes the caller can read, or None when every one of them is readable."""
        if self._readable is None:
            names = sorted(set(text(r.get("src_index")) for r in self.store.read("matalog_sources", fields=("src_index",))))
            allowed = [n for n in names if self.caller.can_read_index(n)]
            self._readable = allowed if len(allowed) < len(names) else "all"
        return None if self._readable == "all" else self._readable

    def can_read_index(self, name):
        return self.caller.can_read_index(name)

    def scope(self, collection, query):
        if collection not in INDEX_SCOPED:
            return query
        readable = self.readable_indexes()
        if readable is None:
            return query
        constraint = {"src_index": {"$in": readable}}
        if not query:
            return constraint
        return {"$and": [query, constraint]}

    # Edge rules.

    def _indexes_of(self, collection, keys):
        """{key: src_index} for the rows of an index-scoped collection, read once per key."""
        cache = self._key_index.setdefault(collection, {})
        wanted = sorted(set(k for k in keys if k and k not in cache))
        for chunk in chunks(wanted, IN_CHUNK):
            for row in self.store.read(collection, {"_key": {"$in": chunk}}, fields=("_key", "src_index")):
                cache[text(row.get("_key"))] = text(row.get("src_index"))
            for key in chunk:
                cache.setdefault(key, "")
        return cache

    def edge_readable(self, collection, rows):
        """The rows of matalog_usage or matalog_declarations whose key column names a row of a readable index."""
        column, target = EDGE_RULES[collection]
        keys = []
        for row in rows:
            keys.extend(text(k) for k in (row.get(column) or []) if isinstance(row.get(column), list))
        indexes = self._indexes_of(target, keys)
        out = []
        for row in rows:
            values = row.get(column) if isinstance(row.get(column), list) else []
            if any(self.can_read_index(indexes.get(text(k), "")) for k in values):
                out.append(row)
        return out

    def readable_object_keys(self, object_keys):
        """The object keys among those given that a readable usage edge names."""
        allowed = set()
        for chunk in chunks(sorted(set(object_keys)), IN_CHUNK):
            edges = self.store.read("matalog_usage", {"object_key": {"$in": chunk}}, fields=("object_key", "resolved_field_keys"))
            allowed.update(text(e.get("object_key")) for e in self.edge_readable("matalog_usage", edges))
        return allowed

    def _read_edges(self, collection, query, fields, limit, sort, skip):
        column = EDGE_RULES[collection][0]
        wanted = list(fields) if fields else None
        if wanted and column not in wanted:
            wanted.append(column)
        rows = self.edge_readable(collection, self.store.read(collection, query, fields=wanted, sort=sort))
        if fields and column not in fields:
            for row in rows:
                row.pop(column, None)
        rows = rows[int(skip or 0):]
        return rows[:limit] if limit else rows

    def _read_objects(self, query, fields, limit, sort, skip):
        keys = object_keys_of(query)
        if keys is None:
            raise RequestError(403, "matalog_objects is read by object_key only (a key or {\"object_key\": {\"$in\": [...]}})")
        allowed = sorted(self.readable_object_keys(keys))
        rows = []
        for chunk in chunks(allowed, IN_CHUNK):
            rows.extend(self.store.read("matalog_objects", {"$and": [query, {"object_key": {"$in": chunk}}]}, fields=fields, sort=sort))
        rows = rows[int(skip or 0):]
        return rows[:limit] if limit else rows

    def __call__(self, collection, query=None, fields=None, limit=0, sort=None, skip=0):
        if self.readable_indexes() is not None:
            if collection in EDGE_RULES:
                return self._read_edges(collection, query, fields, limit, sort, skip)
            if collection == "matalog_objects":
                return self._read_objects(query or {}, fields, limit, sort, skip)
            if collection == RUNS:
                return [run_reader_row(r) for r in self.store.read(collection, query, fields=fields, limit=limit, sort=sort, skip=skip)]
        return self.store.read(collection, self.scope(collection, query), fields=fields, limit=limit, sort=sort, skip=skip)

    def unscoped(self, collection, query=None, fields=None, limit=0, sort=None, skip=0):
        return self.store.read(collection, query, fields=fields, limit=limit, sort=sort, skip=skip)

    def get(self, collection, key):
        row = self.store.get(collection, key)
        if row is None:
            return None
        if collection in INDEX_SCOPED and not self.can_read_index(row.get("src_index")):
            return None
        if self.readable_indexes() is not None:
            if collection in EDGE_RULES and not self.edge_readable(collection, [row]):
                return None
            if collection == "matalog_objects" and text(key) not in self.readable_object_keys([text(key)]):
                return None
            if collection == RUNS:
                return run_reader_row(row)
        return row


def run_reader_row(row):
    return dict((k, v) for k, v in row.items() if k in RUN_READER_COLUMNS)


def object_keys_of(query):
    """The object keys a matalog_objects query names: object_key as a string or {"$in": [...]}, at the top level
    or inside a top-level $and; None when the query does not name any."""
    if not isinstance(query, dict):
        return None
    terms = [query] + [t for t in (query.get("$and") or []) if isinstance(t, dict)]
    for term in terms:
        value = term.get("object_key")
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict) and isinstance(value.get("$in"), list):
            return [text(k) for k in value["$in"]]
    return None
