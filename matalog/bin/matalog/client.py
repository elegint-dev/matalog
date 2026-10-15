"""Splunk REST client over urllib: search jobs, KV store, config reads, metadata and licence helpers.

Every search job goes through the budget pool when one is attached, so each
job is counted and gets a kind=search_cost row. Subclasses replace the
transport methods (_execute, _kv_*, _get_json) to serve recorded fixtures.
"""
import base64
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from . import keys

DEFAULT_APP = "matalog"
JOB_POLL_START = 0.2
JOB_POLL_MAX = 2.0
FINALIZE_WAIT_SECONDS = 120
RESULTS_PAGE = 50000
PERMISSION_WARNINGS = ("insufficient permission",)
KV_PAGE = 5000
KV_INIT_RETRIES = 24
KV_INIT_WAIT = 5.0


class ClientError(Exception):
    """A REST call failed; status and body are kept for the error list."""

    def __init__(self, message, status=None, body=None):
        Exception.__init__(self, message)
        self.status = status
        self.body = body


class JobResult(object):
    """What a finished search job reports."""

    def __init__(self, sid="", status="ok", scan_count=0, event_count=0, result_count=0, run_duration=0.0,
                 results=None, messages=None, spl="", earliest=None, latest=None, sample_ratio=1, spl_hash=None):
        self.sid = sid
        self.status = status
        self.scan_count = int(scan_count or 0)
        self.event_count = int(event_count or 0)
        self.result_count = int(result_count or 0)
        self.run_duration = float(run_duration or 0.0)
        self.results = results if results is not None else []
        self.messages = messages if messages is not None else []
        self.spl = spl
        self.spl_hash = spl_hash if spl_hash is not None else (keys.spl_hash(spl) if spl else "")
        self.earliest = earliest
        self.latest = latest
        self.sample_ratio = int(sample_ratio or 1)
        self.step = ""
        self.subject_key = ""
        self.error = ""

    @property
    def ok(self):
        return self.status == "ok"

    def __repr__(self):
        return "JobResult(sid=%r, status=%r, scanned=%d, matched=%d, rows=%d, seconds=%.3f)" % (
            self.sid, self.status, self.scan_count, self.event_count, self.result_count, self.run_duration)


def run_comment(run_id, step):
    """The SPL comment every search carries."""
    return '`comment("matalog run_id=%s step=%s")`' % (run_id, step)


def normalize_spl(spl):
    """The SPL a job is created with: a leading `search` unless it starts with a generating pipe."""
    spl = spl.strip()
    if spl.startswith("|") or spl.lower().startswith("search ") or spl.lower() == "search":
        return spl
    return "search " + spl


def tag_spl(spl, run_id, step):
    """Append the run comment to a search string."""
    spl = spl.rstrip()
    return "%s %s" % (spl, run_comment(run_id, step))


class SplunkClient(object):
    """REST client. Authenticate with username and password, or with a session key."""

    def __init__(self, base_url, username=None, password=None, session_key=None, app=DEFAULT_APP, owner=None,
                 verify=False, http_timeout=600, budget=None, run_id="", settings=None):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.app = app
        self.owner = owner or username or "nobody"
        self.http_timeout = http_timeout
        self.budget = budget
        self.run_id = run_id
        self.settings = settings
        self.ssl_context = ssl.create_default_context()
        if not verify:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
        if session_key:
            self._auth = "Splunk " + session_key
        elif username is not None and password is not None:
            self._auth = "Basic " + base64.b64encode(("%s:%s" % (username, password)).encode("utf-8")).decode("ascii")
        else:
            raise ClientError("username and password, or a session key, are required")

    # Transport.

    def request(self, method, path, params=None, data=None, json_body=None, raw=False):
        """One REST call. Returns parsed JSON unless raw. Raises ClientError on HTTP errors."""
        url = self.base_url + path
        query = dict(params or {})
        if not raw:
            query.setdefault("output_mode", "json")
        if query:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(query, doseq=True)
        body = None
        headers = {"Authorization": self._auth}
        if json_body is not None:
            body = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif data is not None:
            body = urllib.parse.urlencode(data, doseq=True).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        for attempt in range(KV_INIT_RETRIES + 1):
            try:
                with urllib.request.urlopen(req, context=self.ssl_context, timeout=self.http_timeout) as resp:
                    text = resp.read().decode("utf-8")
                break
            except urllib.error.HTTPError as exc:
                text = exc.read().decode("utf-8", "replace")
                # KV store answers 503 while it starts; it is the only error worth waiting for.
                if exc.code == 503 and "KV Store is initializing" in text and attempt < KV_INIT_RETRIES:
                    self._sleep(KV_INIT_WAIT)
                    continue
                raise ClientError("%s %s -> HTTP %s: %s" % (method, path, exc.code, text[:500]), status=exc.code, body=text)
            except urllib.error.URLError as exc:
                raise ClientError("%s %s -> %s" % (method, path, exc.reason))
        if raw or not text:
            return text
        return json.loads(text)

    def _sleep(self, seconds):
        time.sleep(seconds)

    def _get_json(self, path, params=None):
        return self.request("GET", path, params=params)

    def ns(self, owner=None, app=None):
        return "/servicesNS/%s/%s" % (owner or self.owner, app or self.app)

    def current_user(self):
        entry = self._get_json("/services/authentication/current-context")["entry"][0]
        return entry["content"]["username"]

    def server_info(self):
        return self._get_json("/services/server/info")["entry"][0]["content"]

    # Search jobs.

    def search(self, spl, earliest=None, latest=None, sample_ratio=1, timeout=None, step="", subject_key="",
               write=False, tag=True, max_rows=None):
        """Run a blocking search job through the budget and return its JobResult.

        earliest and latest are epoch seconds or Splunk time strings; sample_ratio
        1 means unsampled; timeout defaults to budget.search_timeout_seconds and a
        job past it is finalized and reported as status timeout. max_rows sets the
        job's max_count, which bounds the events a non-transforming search keeps
        (Splunk keeps 10000 without it); results are read in pages. SPL without a
        leading pipe gets `search` prepended. spl_hash is taken before the run
        comment is added. Raises BudgetExhausted before dispatch when a ceiling is hit.
        """
        spl = normalize_spl(spl)
        spl_hash = keys.spl_hash(spl)
        if tag and self.run_id:
            spl = tag_spl(spl, self.run_id, step or "S0")
        if timeout is None and self.settings is not None:
            timeout = self.settings.budget.search_timeout_seconds
        spec = {"spl": spl, "spl_hash": spl_hash, "earliest": earliest, "latest": latest, "sample_ratio": int(sample_ratio or 1),
                "timeout": timeout, "step": step, "subject_key": subject_key, "max_rows": max_rows}
        if self.budget is None:
            return self._execute(spec)
        return self.budget.run_job(step, subject_key or (WRITE_SUBJECT if write else ""), lambda: self._execute(spec), write=write, job=spec)

    def _execute(self, spec):
        """Create the job, poll it, finalize on timeout, read its results."""
        data = {"search": spec["spl"], "exec_mode": "normal", "output_mode": "json"}
        if spec["earliest"] is not None:
            data["earliest_time"] = str(spec["earliest"])
        if spec["latest"] is not None:
            data["latest_time"] = str(spec["latest"])
        if spec["sample_ratio"] and spec["sample_ratio"] > 1:
            data["sample_ratio"] = str(spec["sample_ratio"])
        if spec["timeout"]:
            data["timeout"] = str(int(spec["timeout"]) + 600)
        if spec.get("max_rows"):
            data["max_count"] = str(int(spec["max_rows"]))
        path = self.ns() + "/search/jobs"
        try:
            sid = self.request("POST", path, data=data)["sid"]
        except ClientError as exc:
            return JobResult(status="failed", messages=[{"type": "ERROR", "text": str(exc)}], spl=spec["spl"], spl_hash=spec.get("spl_hash"),
                             earliest=spec["earliest"], latest=spec["latest"], sample_ratio=spec["sample_ratio"])
        try:
            return self._finish(sid, spec)
        except ClientError as exc:
            self._control(sid, "cancel")
            return JobResult(sid=sid, status="failed", messages=[{"type": "ERROR", "text": str(exc)}], spl=spec["spl"], spl_hash=spec.get("spl_hash"),
                             earliest=spec["earliest"], latest=spec["latest"], sample_ratio=spec["sample_ratio"])

    def _finish(self, sid, spec):
        """Poll a created job to completion, finalize it on timeout, and read its results."""
        status = "ok"
        started = time.time()
        delay = JOB_POLL_START
        content = {}
        while True:
            content = self._job_content(sid)
            if content.get("isDone") in (True, "1", 1):
                break
            if content.get("isFailed") in (True, "1", 1):
                status = "failed"
                break
            if spec["timeout"] and time.time() - started >= float(spec["timeout"]):
                status = "timeout"
                self._control(sid, "finalize")
                # A finalized job stays FINALIZING until its results are written; only isDone means they are readable.
                waited = time.time()
                while time.time() - waited < FINALIZE_WAIT_SECONDS:
                    content = self._job_content(sid)
                    if content.get("isDone") in (True, "1", 1) or content.get("isFailed") in (True, "1", 1):
                        break
                    time.sleep(0.5)
                break
            time.sleep(delay)
            delay = min(JOB_POLL_MAX, delay * 1.5)
        if status == "ok" and content.get("isFailed") in (True, "1", 1):
            status = "failed"
        messages = content.get("messages") or []
        if status == "ok" and any(m.get("type") in ("FATAL", "ERROR") for m in messages):
            status = "failed"
        if status == "ok" and permission_denied(messages):
            status = "failed"
        results = []
        if status != "failed":
            try:
                results = self._job_results(sid, content.get("resultCount"))
            except ClientError as exc:
                status = "failed"
                messages = messages + [{"type": "ERROR", "text": str(exc)}]
        return JobResult(sid=sid, status=status, scan_count=content.get("scanCount", 0),
                         event_count=content.get("eventCount", 0), result_count=content.get("resultCount", len(results)),
                         run_duration=content.get("runDuration", 0.0), results=results, messages=messages,
                         spl=spec["spl"], spl_hash=spec.get("spl_hash"), earliest=spec["earliest"], latest=spec["latest"],
                         sample_ratio=spec["sample_ratio"])

    def _job_content(self, sid):
        return self._get_json(self.ns() + "/search/jobs/" + urllib.parse.quote(sid, safe=""))["entry"][0]["content"]

    def _control(self, sid, action):
        try:
            self.request("POST", self.ns() + "/search/jobs/" + urllib.parse.quote(sid, safe="") + "/control", data={"action": action})
        except ClientError:
            pass

    def _job_results(self, sid, result_count=None):
        """Every result of a finished job, read RESULTS_PAGE at a time; an empty body is no results."""
        path = self.ns() + "/search/jobs/" + urllib.parse.quote(sid, safe="") + "/results"
        total = int(float(result_count)) if result_count not in (None, "") else None
        out = []
        while True:
            page = self._get_json(path, params={"count": RESULTS_PAGE, "offset": len(out)})
            rows = page.get("results", []) if isinstance(page, dict) else []
            out.extend(rows)
            if not rows or (total is not None and len(out) >= total) or (total is None and len(rows) < RESULTS_PAGE):
                break
        return out

    # KV store.

    def _kv_path(self, collection, suffix=""):
        return "%s/storage/collections/data/%s%s" % (self.ns(owner="nobody"), collection, suffix)

    def kv_get(self, collection, key):
        """One document by _key, or None."""
        try:
            return self._get_json(self._kv_path(collection, "/" + urllib.parse.quote(key, safe="")))
        except ClientError as exc:
            if exc.status == 404:
                return None
            raise

    def kv_query(self, collection, query=None, fields=None, limit=0, sort=None):
        """Documents matching a Mongo-style query dict; limit 0 pages through everything."""
        out = []
        skip = 0
        page_size = KV_PAGE if not limit else min(limit, KV_PAGE)
        while True:
            params = {"limit": page_size, "skip": skip}
            if query:
                params["query"] = json.dumps(query)
            if fields:
                params["fields"] = ",".join(fields)
            if sort:
                params["sort"] = sort
            page = self._get_json(self._kv_path(collection), params=params)
            out.extend(page)
            if len(page) < page_size or (limit and len(out) >= limit):
                break
            skip += page_size
        return out[:limit] if limit else out

    def kv_get_many(self, collection, keys_list):
        """Documents for a list of keys, as {_key: doc}; missing keys are absent."""
        out = {}
        keys_list = [k for k in keys_list if k]
        for start in range(0, len(keys_list), 500):
            chunk = keys_list[start:start + 500]
            for doc in self.kv_query(collection, query={"_key": {"$in": chunk}}):
                out[doc["_key"]] = doc
        return out

    def kv_batch_save(self, collection, docs, batch_size=None):
        """Upsert documents in batches of write.kv_batch_size; returns the saved keys."""
        if batch_size is None:
            batch_size = self.settings.write.kv_batch_size if self.settings is not None else 500
        saved = []
        docs = list(docs)
        for start in range(0, len(docs), batch_size):
            saved.extend(self._kv_batch_save(collection, docs[start:start + batch_size]))
        return saved

    def _kv_batch_save(self, collection, docs):
        return self.request("POST", self._kv_path(collection, "/batch_save"), json_body=docs)

    def kv_delete(self, collection, query=None):
        """Delete documents matching the query; the whole collection when query is None."""
        params = {"query": json.dumps(query)} if query else None
        self.request("DELETE", self._kv_path(collection), params=params, raw=True)

    def kv_delete_keys(self, collection, keys_list):
        keys_list = [k for k in keys_list if k]
        for start in range(0, len(keys_list), 500):
            self.kv_delete(collection, {"_key": {"$in": keys_list[start:start + 500]}})

    # Config reads. Entries keep name, content and acl in the order the endpoint returns.

    def conf_entries(self, conf_name, app="-", owner="-"):
        """Stanzas of a conf file through configs/conf-<name>; app '-' lists every app's own stanza."""
        page = self._get_json("/servicesNS/%s/%s/configs/conf-%s" % (owner, app, conf_name), params={"count": 0})
        return [_entry(e) for e in page.get("entry", [])]

    def props(self):
        return self.conf_entries("props")

    def transforms(self):
        return self.conf_entries("transforms")

    def fields_conf(self):
        return self.conf_entries("fields")

    def eventtypes(self):
        return self.conf_entries("eventtypes")

    def tags(self):
        return self.conf_entries("tags")

    def datamodels(self):
        page = self._get_json("/servicesNS/-/-/datamodel/model", params={"count": 0})
        return [_entry(e) for e in page.get("entry", [])]

    # Knowledge objects, every app and owner the account sees.

    def _knowledge_objects(self, path):
        page = self._get_json("/servicesNS/-/-/" + path, params={"count": 0})
        return [_entry(e) for e in page.get("entry", [])]

    def saved_searches(self):
        return self._knowledge_objects("saved/searches")

    def views(self):
        return self._knowledge_objects("data/ui/views")

    def macros(self):
        return self._knowledge_objects("data/macros")

    def lookup_definitions(self):
        return self._knowledge_objects("data/transforms/lookups")

    def apps_local(self):
        page = self._get_json("/services/apps/local", params={"count": 0})
        return [_entry(e) for e in page.get("entry", [])]

    # Metadata and licence helpers.

    def metadata_sourcetypes(self, index, earliest=None, latest=None, step="S1", subject_key=""):
        """| metadata type=sourcetypes for one index: rows with sourcetype, firstTime, lastTime, recentTime, totalCount."""
        return self.search("| metadata type=sourcetypes index=%s" % keys._spl_quote(index), earliest=earliest, latest=latest,
                           step=step, subject_key=subject_key or index)

    def licence_usage(self, earliest, latest, step="S1"):
        """Licensed bytes by index and sourcetype from license_usage.log: rows idx, st, b."""
        spl = ("search index=_internal source=*license_usage.log* type=Usage"
               " | stats sum(b) as b by idx st")
        return self.search(spl, earliest=earliest, latest=latest, step=step, subject_key="licence")

    def licence_pools(self):
        """Pool usage from the licenser endpoint: name, used_bytes, quota."""
        page = self._get_json("/services/licenser/pools", params={"count": 0})
        return [{"name": e["name"], "used_bytes": int(e["content"].get("used_bytes") or 0),
                 "quota": e["content"].get("effective_quota")} for e in page.get("entry", [])]


WRITE_SUBJECT = "write"


def permission_denied(messages):
    """True when a job's messages say the user may not run it; Splunk reports this as a WARN with no results."""
    for message in messages or []:
        text = str(message.get("text", "")).lower()
        if any(w in text for w in PERMISSION_WARNINGS):
            return True
    return False


def _entry(entry):
    acl = entry.get("acl", {})
    return {
        "name": entry.get("name"),
        "content": dict(entry.get("content", {})),
        "acl": {"app": acl.get("app"), "owner": acl.get("owner"), "sharing": acl.get("sharing")},
    }
