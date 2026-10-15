"""A SplunkClient that serves recorded fixtures and keeps KV in memory.

Searches are matched against the fixtures' match regexes (the run comment is
stripped first); an unmatched search raises FakeClientError naming the SPL, so
a step author registers the fixture the step needs with add_search(). KV
queries support equality, $in, $nin, $ne, $lt, $lte, $gt, $gte, plus fields,
limit and sort. Every call is recorded in calls.
"""
import collections
import copy
import json
import os
import re

from matalog import client as client_mod

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
COMMENT_RE = re.compile(r"\s*`comment\(\"[^\"]*\"\)`\s*$")


class FakeClientError(Exception):
    pass


def load_fixture(name):
    with open(os.path.join(FIXTURES, name + ".json"), "r", encoding="utf-8") as handle:
        return json.load(handle)


def fixture_names():
    return sorted(f[:-5] for f in os.listdir(FIXTURES) if f.endswith(".json"))


class FakeClient(client_mod.SplunkClient):
    """Serves the fixtures under tests/fixtures; no network."""

    def __init__(self, settings=None, budget=None, load_all=True, username="svc_matalog"):
        client_mod.SplunkClient.__init__(self, "https://fake:8089", username=username, password="x", app="matalog", budget=budget, settings=settings)
        self.calls = []
        self.routes = []
        self.kv = collections.defaultdict(collections.OrderedDict)
        self.conf = {}
        self.pools = []
        self.fail_next_batch_save = 0
        self.collect_failures = 0
        self.collected = []
        self.job_counter = 0
        if load_all:
            self.load_fixtures()

    # Fixture registration.

    def load_fixtures(self):
        for name in fixture_names():
            data = load_fixture(name)
            if isinstance(data, dict) and "results" in data:
                self.add_search(data["match"], data, name=name)
            elif name.startswith("conf_"):
                self.conf[name[5:]] = data
            elif name.startswith("ko_"):
                self.conf[name] = data
            elif name == "datamodels":
                self.conf["datamodels"] = data
            elif name == "apps_local":
                self.conf["apps_local"] = data
            elif name == "licence_pools":
                self.pools = data

    def add_search(self, match, fixture, name=""):
        """Serve fixture for every search whose SPL matches all regexes in match.

        fixture is a dict with results and a job dict (scanCount, eventCount,
        resultCount, runDuration), or a plain list of result rows. A callable
        fixture receives the spec and returns a JobResult.
        """
        patterns = [re.compile(m) for m in ([match] if isinstance(match, str) else match)]
        self.routes.insert(0, (patterns, fixture, name))

    def add_results(self, match, results, scan_count=None, event_count=None, run_duration=0.01):
        rows = list(results)
        self.add_search(match, {"results": rows, "job": {"scanCount": scan_count if scan_count is not None else len(rows),
                                                          "eventCount": event_count if event_count is not None else len(rows),
                                                          "resultCount": len(rows), "runDuration": run_duration}})

    # Search transport.

    def _execute(self, spec):
        self.calls.append(("search", spec))
        spl = COMMENT_RE.sub("", spec["spl"]).strip()
        self.job_counter += 1
        sid = "fake.%d" % self.job_counter
        if "| collect " in spl and "| inputlookup matalog_write_buffer " in spl:
            return self._collect(spec, spl, sid)
        for patterns, fixture, name in self.routes:
            if all(p.search(spl) for p in patterns):
                if callable(fixture):
                    result = fixture(spec)
                    result.sid = result.sid or sid
                    return result
                job = fixture.get("job", {}) if isinstance(fixture, dict) else {}
                results = fixture["results"] if isinstance(fixture, dict) else fixture
                return client_mod.JobResult(
                    sid=sid, status=job.get("status", "ok"), scan_count=job.get("scanCount", len(results)), event_count=job.get("eventCount", len(results)),
                    result_count=job.get("resultCount", len(results)), run_duration=job.get("runDuration", 0.01), results=copy.deepcopy(results),
                    spl=spec["spl"], spl_hash=spec.get("spl_hash"), earliest=spec["earliest"], latest=spec["latest"], sample_ratio=spec["sample_ratio"])
        raise FakeClientError("no fixture matches search: %s" % spl[:300])

    def _collect(self, spec, spl, sid):
        """Record the buffer lines the collect job selects; fails when collect_failures is set."""
        match = re.search(r'where run_id="([^"]*)" attempt=(\d+) seq>=(\d+) seq<=(\d+) \|', spl)
        if not match:
            raise FakeClientError("collect without a buffer filter: %s" % spl[:300])
        run_id, attempt, first, last = match.group(1), int(match.group(2)), int(match.group(3)), int(match.group(4))
        docs = [d for d in self.kv["matalog_write_buffer"].values()
                if d.get("run_id") == run_id and d.get("attempt") == attempt and first <= d.get("seq", 0) <= last]
        lines = [d["r"] for d in sorted(docs, key=lambda d: d["seq"])]
        if self.collect_failures > 0:
            self.collect_failures -= 1
            return client_mod.JobResult(sid=sid, status="failed", messages=[{"type": "ERROR", "text": "collect failed (fake)"}], spl=spec["spl"])
        self.collected.extend(lines)
        return client_mod.JobResult(sid=sid, status="ok", scan_count=0, event_count=0, result_count=len(lines), run_duration=0.02, spl=spec["spl"], spl_hash=spec.get("spl_hash"))

    def collected_rows(self):
        """The collected lines parsed back as rows: name -> value or list of values."""
        return [parse_stash_line(line) for line in self.collected]

    # KV transport.

    def kv_get(self, collection, key):
        self.calls.append(("kv_get", collection, key))
        doc = self.kv[collection].get(key)
        return copy.deepcopy(doc) if doc is not None else None

    def kv_query(self, collection, query=None, fields=None, limit=0, sort=None):
        self.calls.append(("kv_query", collection, query))
        docs = [copy.deepcopy(d) for d in self.kv[collection].values() if _matches(d, query or {})]
        if sort:
            field, _, direction = sort.partition(":")
            docs.sort(key=lambda d: _sort_key(d.get(field)), reverse=(direction.strip() == "-1"))
        if limit:
            docs = docs[:limit]
        if fields:
            keep = set(fields) | {"_key"}
            docs = [collections.OrderedDict((k, v) for k, v in d.items() if k in keep) for d in docs]
        return docs

    def _kv_batch_save(self, collection, docs):
        self.calls.append(("kv_batch_save", collection, len(docs)))
        if len(docs) > 1000:
            raise client_mod.ClientError("batch_save over 1000 documents", status=400)
        if self.fail_next_batch_save > 0:
            self.fail_next_batch_save -= 1
            raise client_mod.ClientError("batch_save failed (fake)", status=500)
        saved = []
        for doc in docs:
            doc = copy.deepcopy(doc)
            key = doc.get("_key") or ("auto%d" % (len(self.kv[collection]) + 1))
            doc["_key"] = key
            self.kv[collection][key] = doc
            saved.append(key)
        return saved

    def kv_delete(self, collection, query=None):
        self.calls.append(("kv_delete", collection, query))
        for key in [k for k, d in self.kv[collection].items() if _matches(d, query or {})]:
            del self.kv[collection][key]

    # Config transport.

    def conf_entries(self, conf_name, app="-", owner="-"):
        self.calls.append(("conf", conf_name, app, owner))
        if conf_name not in self.conf:
            raise client_mod.ClientError("no fixture for conf-%s" % conf_name, status=404)
        return copy.deepcopy(self.conf[conf_name])

    def datamodels(self):
        return copy.deepcopy(self.conf.get("datamodels", []))

    def apps_local(self):
        return copy.deepcopy(self.conf.get("apps_local", []))

    def _knowledge_objects(self, path):
        name = "ko_" + path.replace("/", "_")
        self.calls.append(("ko", path))
        if name not in self.conf:
            raise client_mod.ClientError("no fixture for %s" % path, status=404)
        return copy.deepcopy(self.conf[name])

    def licence_pools(self):
        return copy.deepcopy(self.pools)

    def current_user(self):
        return self.username

    def server_info(self):
        return {"version": "10.4.3", "serverName": "fake"}


def _sort_key(value):
    return (value is None, value if isinstance(value, (int, float)) else str(value))


def _matches(doc, query):
    for field, cond in query.items():
        value = doc.get(field)
        if isinstance(cond, dict):
            for op, arg in cond.items():
                if op == "$in" and value not in arg:
                    return False
                if op == "$nin" and value in arg:
                    return False
                if op == "$ne" and value == arg:
                    return False
                if op in ("$lt", "$lte", "$gt", "$gte"):
                    if value is None:
                        return False
                    if op == "$lt" and not value < arg:
                        return False
                    if op == "$lte" and not value <= arg:
                        return False
                    if op == "$gt" and not value > arg:
                        return False
                    if op == "$gte" and not value >= arg:
                        return False
        elif value != cond:
            return False
    return True


PAIR_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_.{}]*)="((?:[^"\\]|\\.)*)"')


def parse_stash_line(line):
    """A stash line back into a row, the way auto-kv reads it: repeated names become lists."""
    head, _, rest = line.partition(", ")
    row = collections.OrderedDict([("_stamp", head)])
    for name, raw in PAIR_RE.findall(rest):
        value = raw.replace('\\"', '"').replace("\\\\", "\\")
        if name in row:
            if not isinstance(row[name], list):
                row[name] = [row[name]]
            row[name].append(value)
        else:
            row[name] = value
    return row
