"""S6 parse_usage: the _audit watermark every run, and the knowledge object pass every usage.usage_interval_seconds.

_audit part: one search per run over [watermark, slot start less
budget.window_lag_seconds) gives last_human_search_time and _user per source.
Each search text is expanded (macros) and resolved (eventtypes, tags, data
model datasets) through ScopeKnowledge before its scope is read, and source=
and host= terms narrow the scope to sources whose known values match. A
search constrained on index alone stamps no source.

Knowledge object part (a usage pass): saved searches, views, macros, lookup
definitions, eventtypes and data models are listed through REST as the
service account, their SPL parsed with matalog.spl into field references, and
the references resolved to source-level field keys. Outputs: matalog_objects,
matalog_usage, the usage_* columns of the source-level matalog_fields rows and
of matalog_sources, deletion of stale objects and edges, and the objects_*
counts of the run record. One search over the trailing 30 days (the scheduler
log and _audit) supplies last_run_time and run_count_30d.
"""
import collections
import json
import re
try:
    from urllib.parse import unquote as url_unquote
except ImportError:  # Python 2 on older Splunk
    from urllib import unquote as url_unquote

from .. import keys
from .. import rows as rows_mod
from .. import spl
from ..budget import BudgetExhausted
from ..runner import Step
from . import s5_read_config as s5
from . import s8_derive_meaning as s8

STEP = "S6"
AUDIT_SUBJECT = "audit"
RUNS_SUBJECT = "runs"
WATERMARK_COLUMN = "audit_watermark"
# Distinct (user, app, search text) rows read per run; the oldest are kept when more exist.
AUDIT_MAX_ROWS = 50000
RUNS_MAX_ROWS = 200000
RUN_HISTORY_DAYS = 30
OBJECTS = "matalog_objects"
USAGE = "matalog_usage"
FIELDS = "matalog_fields"
SOURCES = "matalog_sources"
COVERAGE = "matalog_cim_coverage"
RUNS = "matalog_runs"
KO_ORDER = ("alert", "report", "savedsearch", "dashboard", "datamodel", "eventtype", "macro", "lookup")
FIELD_USAGE_COLUMNS = ("usage_count", "usage_alert_count", "usage_objects", "usage_last_run_time", "usage_unscoped_count")
SOURCE_USAGE_COLUMNS = ("usage_count", "usage_alert_count")
EDGE_COLUMNS = ("_key", "object_key", "field_name", "ref_kind", "resolution", "scope", "scope_text", "resolved_field_keys", "confidence",
                "last_seen_run", "expanded", "macros", "scope_via")
SOURCE_SCOPE_COLUMNS = ("source_key", "src_index", "src_sourcetype", "search_sourcetype", "sources_top", "hosts_top",
                        "last_human_search_time", "last_human_search_user")
FIELD_COLUMNS = ("_key", "source_key", "field_name", "level", "stratum_value") + FIELD_USAGE_COLUMNS
EXPORTED_SHARING = ("system", "global")
# The datamodel endpoint returns fresh UUID calculation ids on every read of a model that stores none.
UUID_RE = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")

# The constraint reader lives in matalog.spl; these names stay for the audit part and its callers.
MAX_GROUPS = spl.MAX_GROUPS
spl_text = spl.spl_text
constraint_groups = spl.constraint_groups
constraints = spl.constraints
touches = spl.touches
touches_any = spl.touches_any


def _quote_list(values):
    return ", ".join('"%s"' % v.replace("\\", "\\\\").replace('"', '\\"') for v in values)


def audit_spl(exclude_users, exclude_apps, max_rows=AUDIT_MAX_ROWS):
    """The one _audit search: human search texts with their latest time, oldest first."""
    parts = ["search index=_audit action=search (info=granted OR info=completed) search=*"]
    if exclude_users:
        parts.append("NOT user IN (%s)" % _quote_list(exclude_users))
    if exclude_apps:
        parts.append("NOT app IN (%s)" % _quote_list(exclude_apps))
    return ("%s | stats max(_time) as last_time by user app search"
            ' | where match(search, "(?i)(index|sourcetype|eventtype|tag)\\s*(=|in\\s*\\()|datamodel|\\x60")'
            " | sort 0 last_time | head %d" % (" ".join(parts), int(max_rows)))


def runs_spl(max_rows=RUNS_MAX_ROWS):
    """The run history search: completed runs per saved search (scheduler log and _audit) and per dashboard (_audit provenance)."""
    return ("search (index=_audit action=search info=completed (savedsearch_name=* OR provenance=UI:Dashboard:*))"
            " OR (index=_internal sourcetype=scheduler status=success savedsearch_name=*)"
            ' | eval matalog_kind=case(index="_internal", "scheduler", savedsearch_name!="", "savedsearch",'
            ' like(provenance, "UI:Dashboard:%"), "dashboard")'
            " | where isnotnull(matalog_kind)"
            ' | eval matalog_name=if(matalog_kind="dashboard", replace(provenance, "^UI:Dashboard:", ""), savedsearch_name)'
            " | stats count as runs max(_time) as last_time by app matalog_kind matalog_name"
            " | head " + str(int(max_rows)))


def _epoch(value):
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _int(value, default=0):
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return 1 if value.strip().lower() == "true" else 0
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _list(value):
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def truthy(value):
    return s5.truthy(value)


def object_hash(text):
    """spl_hash of an object: the parser version and the SPL, so a parser change reparses unchanged objects once."""
    return keys.spl_hash("%s\n%s" % (spl.PARSER_VERSION, text))


# Watermark.

def watermark_column_exists():
    return WATERMARK_COLUMN in rows_mod.COLLECTIONS[RUNS]


def stored_watermark(ctx):
    """audit_watermark of the newest committed run before this one that carries it, or None.

    Runs whose record never reached finalize carry none, so the watermark is
    read past them. A rebuild run carries the lookback floor, since rebuild
    leaves last_human_search_* empty. A run that finalized as failed is skipped
    too: when crash replay later marks it committed, its matalog_sources writes
    were rebuilt from summary rows, which do not carry last_human_search_*.
    """
    query = {"committed": 1, "run_id": {"$lt": ctx.run_id}, WATERMARK_COLUMN: {"$gt": 0}, "status": {"$ne": "failed"}}
    docs = ctx.client.kv_query(RUNS, query=query, fields=["run_id", WATERMARK_COLUMN], sort="run_id:-1", limit=1)
    return _epoch(docs[0].get(WATERMARK_COLUMN)) if docs else None


def audit_bounds(ctx):
    """(earliest, latest) of this run's _audit read.

    earliest is the newest committed audit_watermark, or ctx.audit_window()'s
    earliest when no committed run carries one; never more than
    usage.audit_initial_lookback_days before latest.
    """
    fallback, latest = ctx.audit_window()
    floor = latest - ctx.settings.usage.audit_initial_lookback_days * 86400
    stored = stored_watermark(ctx)
    earliest = stored if stored is not None else fallback
    earliest = min(max(earliest, floor), latest)
    return float(earliest), float(latest)


def set_watermark(ctx, value):
    value = float(value)
    ctx.state[WATERMARK_COLUMN] = value
    if watermark_column_exists():
        ctx.counts[WATERMARK_COLUMN] = value


def held_watermark(results, earliest, latest):
    """Where the next run starts after a truncated read: the newest kept text's time.

    The search keeps the oldest texts, so every text the row cap dropped has
    its latest time at or after this one and is read again from here. When
    that time does not move past earliest, the window end, so the read cannot stall.
    """
    times = [t for t in (_epoch(r.get("last_time")) for r in results) if t is not None and earliest <= t < latest]
    newest = max(times) if times else None
    return newest if newest is not None and newest > earliest else latest


# The usage pass cadence.

def usage_passes(ctx):
    """run_ids of the committed normal runs before this one that did a usage pass (their record carries objects_total)."""
    query = {"committed": 1, "run_mode": "normal", "objects_total": {"$gte": 0}, "run_id": {"$lt": ctx.run_id}}
    return sorted(str(d["run_id"]) for d in ctx.client.kv_query(RUNS, query=query, fields=["run_id"]) if d.get("run_id"))


def usage_pass_due(ctx):
    """True when no committed normal run within usage.usage_interval_seconds before this slot did a usage pass."""
    cached = ctx.state.get("usage_pass_due")
    if cached is not None:
        return cached
    passes = usage_passes(ctx)
    due = True
    if passes:
        due = ctx.slot_start - keys.slot_start_of(passes[-1]) >= int(ctx.settings.usage.usage_interval_seconds)
    ctx.state["usage_pass_due"] = due
    return due


def searches_held(ctx):
    """Searches S6 needs: the _audit read, plus the run history read on a usage pass."""
    try:
        return 2 if usage_pass_due(ctx) else 1
    except Exception as exc:
        ctx.error(STEP, "usage_pass", "could not read the previous passes: %s" % exc)
        return 2


# Knowledge objects.

class KnowledgeObject(object):
    """One listed object before it becomes a matalog_objects document."""

    def __init__(self, ko_type, app, owner, name, sharing="", is_scheduled=0, is_alert=0, disabled=0):
        self.ko_type = ko_type
        self.app = app or ""
        self.owner = owner or ""
        self.name = name or ""
        self.sharing = sharing or ""
        self.is_scheduled = int(is_scheduled)
        self.is_alert = int(is_alert)
        self.disabled = int(disabled)
        self.is_matalog_own = 0
        self.key = keys.k(ko_type, self.app, self.owner, self.name)
        self.text = ""
        self.queries = []
        self.fragments = []
        self.model_refs = []
        self.pre_gaps = []
        self.parse = None
        self.skipped = False
        self.references = []
        self.macros = []

    @property
    def label(self):
        return "%s:%s:%s" % (self.ko_type, self.app, self.name)


def saved_search_objects(entries):
    out = []
    for entry in entries:
        acl = entry.get("acl") or {}
        content = entry.get("content") or {}
        scheduled = truthy(content.get("is_scheduled"))
        alert_type = str(content.get("alert_type") or "always").strip().lower()
        has_action = bool(str(content.get("actions") or "").strip()) or truthy(content.get("alert.track"))
        has_condition = alert_type not in ("", "always") or bool(str(content.get("alert_condition") or "").strip())
        if scheduled and (has_action or has_condition):
            ko_type = "alert"
        elif scheduled:
            ko_type = "report"
        else:
            ko_type = "savedsearch"
        obj = KnowledgeObject(ko_type, acl.get("app"), acl.get("owner"), entry.get("name"), acl.get("sharing"),
                              is_scheduled=1 if scheduled else 0, is_alert=1 if ko_type == "alert" else 0,
                              disabled=1 if truthy(content.get("disabled")) else 0)
        obj.text = str(content.get("search") or "")
        obj.queries = [obj.text] if obj.text.strip() else []
        out.append(obj)
    return out


def view_objects(entries):
    out = []
    for entry in entries:
        acl = entry.get("acl") or {}
        content = entry.get("content") or {}
        obj = KnowledgeObject("dashboard", acl.get("app"), acl.get("owner"), entry.get("name"), acl.get("sharing"),
                              disabled=1 if truthy(content.get("disabled")) else 0)
        queries, gaps = spl.dashboard_queries(content.get("eai:data"))
        obj.queries = queries
        obj.pre_gaps = gaps
        obj.text = "\n".join(queries)
        out.append(obj)
    return out


def macro_objects(entries):
    out = []
    for entry in entries:
        acl = entry.get("acl") or {}
        content = entry.get("content") or {}
        obj = KnowledgeObject("macro", acl.get("app"), acl.get("owner"), entry.get("name"), acl.get("sharing"),
                              disabled=1 if truthy(content.get("disabled")) else 0)
        definition = str(content.get("definition") or "")
        obj.text = definition
        if truthy(content.get("iseval")):
            obj.pre_gaps = ["iseval"]
        elif definition.strip():
            obj.queries = [command_fragment(definition)]
        out.append(obj)
    return out


def command_fragment(text):
    """A macro definition as a search text: a definition that starts with a command is a pipe segment."""
    stripped = text.strip()
    first = stripped.split(None, 1)[0].lower() if stripped else ""
    if stripped.startswith("|") or first == "search" or first not in spl.KNOWN_COMMANDS:
        return stripped
    return "| " + stripped


def lookup_objects(entries):
    out = []
    for entry in entries:
        acl = entry.get("acl") or {}
        content = entry.get("content") or {}
        obj = KnowledgeObject("lookup", acl.get("app"), acl.get("owner"), entry.get("name"), acl.get("sharing"),
                              disabled=1 if truthy(content.get("disabled")) else 0)
        obj.text = json.dumps([str(content.get(c) or "") for c in ("filename", "collection", "external_type", "fields_list")])
        out.append(obj)
    return out


def eventtype_objects(entries):
    out = []
    for entry in entries:
        acl = entry.get("acl") or {}
        content = entry.get("content") or {}
        obj = KnowledgeObject("eventtype", acl.get("app"), acl.get("owner"), entry.get("name"), acl.get("sharing"),
                              disabled=1 if truthy(content.get("disabled")) else 0)
        obj.text = str(content.get("search") or "")
        obj.queries = [obj.text] if obj.text.strip() else []
        out.append(obj)
    return out


def datamodel_objects(entries):
    """One object per model; its references are the dataset fields, the constraint terms and the calculation inputs."""
    out = []
    for entry in entries:
        acl = entry.get("acl") or {}
        content = entry.get("content") or {}
        description = str(content.get("description") or "")
        name = str(entry.get("name") or "")
        accelerated = 0
        try:
            acceleration = json.loads(content.get("acceleration") or "{}")
            accelerated = 1 if isinstance(acceleration, dict) and truthy(acceleration.get("enabled")) else 0
        except (TypeError, ValueError):
            pass
        obj = KnowledgeObject("datamodel", acl.get("app"), acl.get("owner"), name, acl.get("sharing"), is_scheduled=accelerated)
        obj.text = UUID_RE.sub("uuid", description)
        try:
            model = json.loads(description or "{}")
            objects = collections.OrderedDict()
            for item in model.get("objects") or []:
                if isinstance(item, dict) and item.get("objectName"):
                    objects.setdefault(str(item["objectName"]), item)
            model_name = str(model.get("modelName") or name)
            stanza = s5.model_stanza(entry, model)
            for object_name, item in objects.items():
                dataset = s8.build_dataset(model_name, object_name, objects, obj.app, stanza, {})
                scope = spl.Scope(spl.DATAMODEL, dataset=dataset.name)
                for field_name in dataset.fields:
                    obj.model_refs.append((field_name, scope))
                for constraint in item.get("constraints") or []:
                    if isinstance(constraint, dict) and str(constraint.get("search") or "").strip():
                        obj.fragments.append((str(constraint["search"]), scope))
                for calc in item.get("calculations") or []:
                    if s5.calculation_attribute(item, calc) is None:
                        continue
                    obj.fragments.append((calculation_fragment(calc), scope))
        except (TypeError, ValueError, AttributeError):
            obj.pre_gaps = ["definition"]
        out.append(obj)
    return out


def calculation_fragment(calc):
    """A data model calculation as a pipe segment the reference parser reads."""
    kind = str(calc.get("calculationType") or "").lower()
    outputs = [str(f.get("fieldName")) for f in calc.get("outputFields") or [] if f.get("fieldName")]
    if kind == "eval":
        return "| eval %s=%s" % (outputs[0] if outputs else "matalog_calc", calc.get("expression") or "")
    if kind == "lookup":
        parts = ["| lookup", str(calc.get("lookupName") or "matalog_lookup")]
        for pair in calc.get("lookupInputs") or []:
            if isinstance(pair, dict) and pair.get("inputField"):
                parts.append("%s AS %s" % (pair.get("lookupField") or pair["inputField"], pair["inputField"]))
        if not any(isinstance(p, dict) and p.get("inputField") for p in calc.get("lookupInputs") or []) and calc.get("inputField"):
            parts.append(str(calc["inputField"]))
        if outputs:
            parts.append("OUTPUT " + " ".join(outputs))
        return " ".join(parts)
    source = str(calc.get("inputField") or "_raw")
    return "| rex field=%s \"%s\"" % (source, "".join("(?<%s>.)" % o for o in outputs))


def root_datasets(entries):
    """model name -> root object name, from the model definitions."""
    out = {}
    for entry in entries:
        content = entry.get("content") or {}
        try:
            model = json.loads(content.get("description") or "{}")
        except (TypeError, ValueError):
            continue
        objects = [o for o in model.get("objects") or [] if isinstance(o, dict) and o.get("objectName")]
        names = set(str(o["objectName"]) for o in objects)
        roots = [str(o["objectName"]) for o in objects if str(o.get("parentName") or "") not in names]
        model_name = str(model.get("modelName") or entry.get("name") or "")
        if model_name and roots:
            out[model_name] = model_name if model_name in roots else roots[0]
    return out


def macro_lookup(entries):
    """lookup_for(app) -> lookup(name, argc): the macro the referencing app sees, same app first, then an exported one."""
    by_key = collections.OrderedDict()
    for entry in entries:
        content = entry.get("content") or {}
        if truthy(content.get("disabled")):
            continue
        by_key.setdefault(spl.macro_key(entry.get("name")), []).append(entry)

    def lookup_for(app):
        def lookup(name, argc):
            candidates = by_key.get((name, argc))
            if not candidates:
                return None
            chosen = None
            for entry in candidates:
                if (entry.get("acl") or {}).get("app") == app:
                    chosen = entry
                    break
            if chosen is None:
                for entry in candidates:
                    if (entry.get("acl") or {}).get("sharing") in EXPORTED_SHARING:
                        chosen = entry
                        break
            chosen = chosen or candidates[0]
            content = chosen.get("content") or {}
            return {"definition": content.get("definition") or "", "args": content.get("args") or "", "iseval": truthy(content.get("iseval"))}
        return lookup
    return lookup_for


class ScopeKnowledge(object):
    """What scope terms resolve through, read once per run and only when a text needs it.

    Eventtypes and tags come from the config S5 read this run, else from
    REST; a read that fails is recorded and leaves those terms unresolved
    (a gap on the object, nothing stamped from the term). A data model
    dataset resolves to the source keys of its class in the stored
    matalog_cim_coverage. Macros are the run's listing, as the referencing
    app sees them.
    """

    def __init__(self, ctx):
        self.ctx = ctx
        self._eventtypes = None
        self._tags = None
        self._datasets = None
        self._roots = None
        self._lookup_for = None

    def _config(self, name):
        config = self.ctx.state.get("config") or {}
        if config.get(name + "_ok") and config.get(name) is not None:
            return list(config[name])
        try:
            return list(getattr(self.ctx.client, name)())
        except Exception as exc:
            self.ctx.error(STEP, name, "conf-%s unreadable: %s; %s terms stay unresolved" % (name, exc, name))
            return None

    def eventtypes(self, pattern):
        if self._eventtypes is None:
            entries = self._config("eventtypes")
            self._eventtypes = False if entries is None else [
                (str(e.get("name")), str((e.get("content") or {}).get("search") or ""))
                for e in entries if e.get("name") and not truthy((e.get("content") or {}).get("disabled"))]
        if self._eventtypes is False:
            return None
        matcher = spl.pattern_re(pattern.lower())
        return [(name, search) for name, search in self._eventtypes if matcher.match(name.lower())]

    def tags(self, pattern, field=None):
        if self._tags is None:
            entries = self._config("tags")
            if entries is None:
                self._tags = False
            else:
                self._tags = []
                for entry in entries:
                    name = url_unquote(str(entry.get("name") or ""))
                    if "=" not in name:
                        continue
                    tag_field, value = name.split("=", 1)
                    for tag, state in (entry.get("content") or {}).items():
                        if tag.startswith("eai:") or tag == "disabled":
                            continue
                        if str(state or "").strip().lower() == "enabled":
                            self._tags.append((tag, tag_field, value))
        if self._tags is False:
            return None
        matcher = spl.pattern_re(pattern.lower())
        return [(tag, tag_field, value) for tag, tag_field, value in self._tags
                if matcher.match(tag.lower()) and (field is None or tag_field.lower() == field.lower())]

    def dataset_keys(self, dataset):
        if self._datasets is None:
            self._datasets = {}
            try:
                for doc in self.ctx.client.kv_query(COVERAGE, fields=["cim_dataset", "source_key"]):
                    if doc.get("cim_dataset") and doc.get("source_key"):
                        self._datasets.setdefault(str(doc["cim_dataset"]), set()).add(str(doc["source_key"]))
            except Exception as exc:
                self.ctx.error(STEP, "datamodels", "%s unreadable: %s; datamodel references stay unresolved" % (COVERAGE, exc))
        found = self._datasets.get(dataset)
        return frozenset(found) if found else None

    def root_dataset(self, model):
        if self._roots is None:
            config = self.ctx.state.get("config") or {}
            entries = config.get("datamodels") if config.get("datamodels_ok") else None
            if entries is None:
                try:
                    entries = list(self.ctx.client.datamodels())
                except Exception as exc:
                    self.ctx.error(STEP, "datamodels", "datamodel endpoint unreadable: %s; models named without a dataset take their own name" % exc)
                    entries = []
            self._roots = root_datasets(entries)
        return self._roots.get(model)

    def macros_listed(self, entries):
        self._lookup_for = macro_lookup(entries)

    def macro_lookup_for(self, app):
        def lookup(name, argc):
            if self._lookup_for is None:
                try:
                    self.macros_listed(list(self.ctx.client.macros()))
                except Exception as exc:
                    self.ctx.error(STEP, "data/macros", "data/macros unreadable: %s; macros in search texts stay unexpanded" % exc)
                    self.macros_listed([])
            return self._lookup_for(app)(name, argc)
        return lookup


def parse_object(obj, lookup_for, roots, knowledge=None):
    """Parse one object's SPL into references; a failed parse is recorded on the object, never raised."""
    parse = spl.Parse()
    for gap in obj.pre_gaps:
        parse.gap(gap)
    lookup = lookup_for(obj.app)
    root = roots.get
    for query in obj.queries:
        part = spl.parse_search(query, lookup, root, knowledge)
        for gap in part.gaps:
            parse.gap(gap)
        parse.expanded(part.macros)
        if part.failed:
            parse.failed = True
        for field_name, ref_kind, scope, confidence, via in part.references():
            parse.add(field_name, ref_kind, [scope], confidence, via)
    for text, scope in obj.fragments:
        spl.parse_fragment(text, parse, [scope], lookup)
    for field_name, scope in obj.model_refs:
        parse.add(field_name, spl.DATAMODEL_FIELD, [scope], spl.EXACT)
    obj.parse = parse
    obj.references = parse.references()
    obj.macros = list(parse.macros)
    return parse


# Resolution.

class Resolver(object):
    """Resolves a scope to the source-level field keys it covers.

    sources is candidate_sources(): source_key -> (src_index, src_sourcetype,
    names searches see, known source values, known host values). A scope's
    source or host pattern keeps only the sources with a matching known
    value; when none matches, the edge resolves as partial.
    """

    def __init__(self, sources, fields_by_source, coverage):
        self.sources = sources
        self.fields_by_source = fields_by_source
        self.coverage = coverage
        self._matches = {}

    @staticmethod
    def narrows(scope, entry):
        if scope.source_pattern and not spl.any_match([scope.source_pattern], entry[3] or []):
            return False
        if scope.host_pattern and not spl.any_match([scope.host_pattern], entry[4] or []):
            return False
        return True

    def source_keys(self, scope):
        cached = self._matches.get(scope)
        if cached is not None:
            return cached
        found = []
        if scope.resolution == spl.EXACT_SOURCE:
            for key, entry in self.sources.items():
                src_index, _, names = entry[0], entry[1], entry[2]
                if src_index == scope.index_pattern and any(n.lower() == scope.sourcetype_pattern for n in names) and self.narrows(scope, entry):
                    found.append(key)
        elif scope.resolution == spl.SOURCETYPE_PATTERN:
            group = spl.scope_group(scope)
            for key, entry in self.sources.items():
                if spl.group_touches(group, entry[0], entry[2], entry[3], entry[4]):
                    found.append(key)
        self._matches[scope] = found
        return found

    def resolution(self, scope):
        """The edge's resolution: partial when the scope's source or host pattern matches no known source."""
        if scope.narrowed and scope.resolution in (spl.EXACT_SOURCE, spl.SOURCETYPE_PATTERN) and not self.source_keys(scope):
            return spl.PARTIAL
        return scope.resolution

    def scope_key(self, scope):
        resolution = self.resolution(scope)
        if resolution == spl.PARTIAL:
            return keys.k("partial", scope.index_pattern, scope.sourcetype_pattern, scope.source_pattern, scope.host_pattern)
        if resolution == spl.EXACT_SOURCE:
            found = self.source_keys(scope)
            return found[0] if found else keys.source_key(scope.index_pattern, scope.sourcetype_pattern)
        if resolution == spl.SOURCETYPE_PATTERN:
            if scope.narrowed:
                return keys.k("stpattern", scope.index_pattern, scope.sourcetype_pattern, scope.source_pattern, scope.host_pattern)
            return keys.k("stpattern", scope.index_pattern, scope.sourcetype_pattern)
        if resolution == spl.DATAMODEL:
            return keys.k("dm", scope.dataset)
        if resolution == spl.INDEX_ONLY:
            return keys.k("index", scope.index_pattern)
        return "*"

    def field_keys(self, scope, field_name):
        if scope.resolution == spl.DATAMODEL:
            return list(self.coverage.get((scope.dataset, field_name), []))
        if scope.resolution in (spl.UNSCOPED, spl.INDEX_ONLY):
            return []
        out = []
        for source_key in self.source_keys(scope):
            key = self.fields_by_source.get(source_key, {}).get(field_name)
            if key:
                out.append(key)
        return out


def summarize(settings, edges, objects, field_index):
    """Usage summary per source-level field and per source.

    edges are matalog_usage docs, objects matalog_objects docs by key,
    field_index field_key -> (source_key, field_name). Returns
    (field_values by field_key, source_values by source_key); objects with
    is_matalog_own=1 count nowhere.
    """
    per_field = collections.defaultdict(set)
    per_source = collections.defaultdict(set)
    unscoped = collections.Counter()
    for edge in edges:
        obj = objects.get(edge.get("object_key"))
        if obj is None or _int(obj.get("is_matalog_own")) == 1:
            continue
        if edge.get("resolution") == spl.UNSCOPED:
            unscoped[str(edge.get("field_name") or "")] += 1
            continue
        for field_key in _list(edge.get("resolved_field_keys")):
            entry = field_index.get(field_key)
            if entry is None:
                continue
            per_field[field_key].add(edge["object_key"])
            per_source[entry[0]].add(edge["object_key"])
    shown = int(settings.usage.usage_objects_shown)

    def ordered(object_keys):
        docs = [objects[k] for k in object_keys]
        docs.sort(key=lambda d: (0 if _int(d.get("is_alert")) == 1 else 1, -(_epoch(d.get("last_run_time")) or 0.0),
                                 str(d.get("ko_type")), str(d.get("app")), str(d.get("name"))))
        return docs

    field_values = collections.OrderedDict()
    for field_key, (source_key, field_name) in field_index.items():
        docs = ordered(per_field.get(field_key, set()))
        times = [_epoch(d.get("last_run_time")) for d in docs if _epoch(d.get("last_run_time")) is not None]
        field_values[field_key] = collections.OrderedDict([
            ("usage_count", len(docs)),
            ("usage_alert_count", sum(1 for d in docs if _int(d.get("is_alert")) == 1)),
            ("usage_objects", ["%s:%s:%s" % (d.get("ko_type"), d.get("app"), d.get("name")) for d in docs[:shown]]),
            ("usage_last_run_time", max(times) if times else None),
            ("usage_unscoped_count", unscoped.get(field_name, 0)),
        ])
    source_values = collections.OrderedDict()
    for source_key in sorted(set(v[0] for v in field_index.values()) | set(per_source)):
        docs = ordered(per_source.get(source_key, set()))
        source_values[source_key] = collections.OrderedDict([
            ("usage_count", len(docs)), ("usage_alert_count", sum(1 for d in docs if _int(d.get("is_alert")) == 1))])
    return field_values, source_values


def usage_differs(stored, values):
    for column, value in values.items():
        have = (stored or {}).get(column)
        if isinstance(value, list):
            if _list(have) != value:
                return True
        elif column == "usage_last_run_time":
            if _epoch(have) != value:
                return True
        elif _int(have) != _int(value):
            return True
    return False


def rebuild_usage(ctx, field_docs, source_docs):
    """Rebuild: the usage summary columns from the stored objects and edges onto rebuilt field and source docs."""
    objects = dict((d["_key"], d) for d in ctx.client.kv_query(OBJECTS) if d.get("_key"))
    edges = ctx.client.kv_query(USAGE)
    field_index = collections.OrderedDict()
    for key, doc in field_docs.items():
        if doc.get("level") == "source" and doc.get("source_key") and doc.get("field_name"):
            field_index[key] = (doc["source_key"], doc["field_name"])
    field_values, source_values = summarize(ctx.settings, edges, objects, field_index)
    for key, values in field_values.items():
        field_docs[key].update(values)
    for key, values in source_values.items():
        if key in source_docs:
            source_docs[key].update(values)
    return len(field_values)


class ParseUsage(Step):
    """The _audit watermark every run and the knowledge object pass when due; see the module docstring.

    _audit: one search over [watermark, slot start less
    budget.window_lag_seconds) of action=search events with info granted or
    completed, excluding settings.exclude_users() and settings.exclude_apps(),
    grouped by user, app and search text. Each text's alternatives
    (spl.constraint_groups(), macros expanded and eventtype, tag and data
    model references resolved through ScopeKnowledge) are matched against
    every known source: the staged and stored matalog_sources rows and
    ctx.state["sources"], with source= and host= terms matched against the
    sources' sources_top and hosts_top.
    Outputs last_human_search_time and _user where newer than the stored and
    staged value, the window end as audit_watermark (the window start when the
    search failed, the newest kept text's time when the row cap was hit), and
    ctx.state["audit"]. A full read (the window starts at the
    usage.audit_initial_lookback_days floor: the first run, or the run after a
    rebuild rewound the watermark) rebuilds the two columns instead: every
    known source gets the newest matching search of the window, or empty when
    none matches, unless the row cap truncated the read.

    Usage pass (usage_pass_due): ctx.state["usage"] holds the counts; the
    objects_* run record counters are set on pass runs only, with an object
    skipped on an unchanged hash counted under its stored parse_status.
    """

    name = STEP
    label = "parse_usage"

    def run(self, ctx):
        knowledge = ScopeKnowledge(ctx)
        self.audit(ctx, knowledge)
        if usage_pass_due(ctx):
            self.usage_pass(ctx, knowledge)

    # _audit.

    def audit(self, ctx, knowledge=None):
        knowledge = knowledge or ScopeKnowledge(ctx)
        earliest, latest = audit_bounds(ctx)
        set_watermark(ctx, earliest)
        full = earliest <= latest - ctx.settings.usage.audit_initial_lookback_days * 86400
        summary = collections.OrderedDict([("earliest", earliest), ("latest", latest), ("full", 1 if full else 0), ("searches", 0),
                                           ("constraining", 0), ("expanded", 0), ("sources_touched", 0), ("cleared", 0), ("truncated", 0)])
        ctx.state["audit"] = summary
        if latest <= earliest:
            set_watermark(ctx, latest)
            return
        users = ctx.settings.exclude_users()
        apps = ctx.settings.exclude_apps()
        result = ctx.client.search(audit_spl(users, apps), earliest=earliest, latest=latest, step=self.name,
                                   subject_key=AUDIT_SUBJECT, max_rows=AUDIT_MAX_ROWS)
        if not result.ok:
            ctx.error(self.name, AUDIT_SUBJECT, "_audit read failed: %s; the watermark stays at %s" % (result.status, earliest))
            return
        end = latest
        if len(result.results) >= AUDIT_MAX_ROWS:
            summary["truncated"] = 1
            end = held_watermark(result.results, earliest, latest)
            ctx.error(self.name, AUDIT_SUBJECT, "_audit read hit %d search texts; the watermark is held at %s so older texts are read again"
                      % (AUDIT_MAX_ROWS, end))
        latest_by_source, sources = self.match(ctx, result.results, users, apps, earliest, latest, summary, knowledge)
        self.stage(ctx, latest_by_source, summary, sources if full and not summary["truncated"] else None)
        set_watermark(ctx, end)

    def candidate_sources(self, ctx):
        """source_key -> (src_index, src_sourcetype, [names searches see], known sources, known hosts, stamp time, stamp user).

        The known values are sources_top and hosts_top, None for a source
        never probed; the staged row of this run wins over the stored one. The
        stamp is the stored or staged last_human_search_time and _user.
        """
        found = collections.OrderedDict()

        def add(doc):
            key = doc.get("source_key") or doc.get("_key")
            index, sourcetype = doc.get("src_index"), doc.get("src_sourcetype")
            if not key or not index or not sourcetype:
                return
            entry = found.setdefault(key, [index, sourcetype, [sourcetype], None, None, None, ""])
            alias = doc.get("search_sourcetype")
            if alias and alias not in entry[2]:
                entry[2].append(alias)
            for position, column in ((3, "sources_top"), (4, "hosts_top")):
                values = _list(doc.get(column))
                if values:
                    entry[position] = values
            when = _epoch(doc.get("last_human_search_time"))
            if when is not None and (entry[5] is None or when > entry[5]):
                entry[5], entry[6] = when, str(doc.get("last_human_search_user") or "")

        for doc in ctx.client.kv_query(SOURCES, fields=list(SOURCE_SCOPE_COLUMNS)):
            add(doc)
        for doc in ctx.kv[SOURCES].values():
            add(doc)
        for doc in ctx.state.get("sources") or []:
            add(doc)
        return collections.OrderedDict((key, tuple(entry)) for key, entry in found.items())

    def match(self, ctx, results, users, apps, earliest, latest, summary, knowledge=None):
        """(source_key -> (time, user, identity) of the newest search in results that touches it, candidate_sources())."""
        knowledge = knowledge or ScopeKnowledge(ctx)
        sources = self.candidate_sources(ctx)
        skip_users = set(u.lower() for u in users)
        skip_apps = set(a.lower() for a in apps)
        best = {}
        for row in results:
            user = str(row.get("user") or "")
            app = str(row.get("app") or "")
            when = _epoch(row.get("last_time"))
            if not user or when is None or user.lower() in skip_users or app.lower() in skip_apps:
                continue
            if when < earliest or when >= latest:
                continue
            summary["searches"] += 1
            trace = spl.Trace()
            groups = constraint_groups(spl_text(row.get("search")), knowledge, knowledge.macro_lookup_for(app), trace)
            if trace.macros:
                summary["expanded"] += 1
            if not groups:
                continue
            summary["constraining"] += 1
            for key, entry in sources.items():
                if not touches_any(groups, entry[0], entry[2], entry[3], entry[4], key):
                    continue
                current = best.get(key)
                if current is None or when > current[0] or (when == current[0] and user < current[1]):
                    best[key] = (when, user, sources[key])
        return best, sources

    def stage(self, ctx, latest_by_source, summary, rebuild_from=None):
        """Stage last_human_search_time and _user where newer than the stored and staged values.

        With rebuild_from (candidate_sources() of a full read) the columns are
        rebuilt instead: every source in it takes this read's match, and one
        with a stamp that no search of the window reproduces is cleared.
        """
        by_key = {}
        for doc in ctx.state.get("sources") or []:
            key = doc.get("source_key") or doc.get("_key")
            if key:
                by_key.setdefault(key, []).append(doc)

        def put(key, identity, when, user):
            ctx.stage_kv(SOURCES, rows_mod.sources_doc(identity[0], identity[1], last_human_search_time=when, last_human_search_user=user))
            for entry in by_key.get(key, []):
                entry["last_human_search_time"] = when
                entry["last_human_search_user"] = user

        if rebuild_from is not None:
            for key, identity in rebuild_from.items():
                stamped = (identity[5], identity[6])
                match = latest_by_source.get(key)
                if match is None:
                    if stamped[0] is not None:
                        put(key, identity, None, None)
                        summary["cleared"] += 1
                elif (match[0], match[1]) != stamped:
                    put(key, identity, match[0], match[1])
                    summary["sources_touched"] += 1
            return
        for key, (when, user, identity) in latest_by_source.items():
            if identity[5] is not None and when <= identity[5]:
                continue
            put(key, identity, when, user)
            summary["sources_touched"] += 1

    # The usage pass.

    def usage_pass(self, ctx, knowledge=None):
        knowledge = knowledge or ScopeKnowledge(ctx)
        state = collections.OrderedDict([
            ("listed", 0), ("over_cap", 0), ("parsed", 0), ("partial", 0), ("failed", 0), ("skipped", 0), ("own", 0),
            ("edges", 0), ("edges_deleted", 0), ("objects_deleted", 0), ("fields_staged", 0), ("sources_staged", 0),
            ("history_rows", 0)])
        ctx.state["usage"] = state
        listed, macros, models, listed_types = self.list_objects(ctx)
        listed.sort(key=lambda o: (KO_ORDER.index(o.ko_type) if o.ko_type in KO_ORDER else len(KO_ORDER), o.app, o.owner, o.name))
        own_account = str(ctx.settings.usage.service_account or "")
        own_apps = set(a.lower() for a in ctx.settings.exclude_apps())
        for obj in listed:
            obj.is_matalog_own = 1 if (obj.owner == own_account or obj.app.lower() in own_apps) else 0
        cap = int(ctx.settings.usage.max_objects)
        state["listed"] = len(listed)
        parsed_set = listed[:cap]
        state["over_cap"] = len(listed) - len(parsed_set)
        if state["over_cap"]:
            ctx.error(STEP, "objects", "%d knowledge objects over usage.max_objects (%d) were not parsed" % (state["over_cap"], cap))
        history = self.run_history(ctx, state)
        stored_objects = dict((d["_key"], d) for d in ctx.client.kv_query(OBJECTS) if d.get("_key"))
        stored_edges = collections.defaultdict(list)
        for doc in ctx.client.kv_query(USAGE, fields=list(EDGE_COLUMNS)):
            if doc.get("_key") and doc.get("object_key"):
                stored_edges[doc["object_key"]].append(doc)
        sources = self.candidate_sources(ctx)
        field_index, fields_by_source, stored_usage = self.field_rows(ctx)
        resolver = Resolver(sources, fields_by_source, self.coverage(ctx))
        lookup_for = macro_lookup(macros)
        knowledge.macros_listed(macros)
        roots = root_datasets(models)
        edges = collections.OrderedDict()
        objects = dict(stored_objects)
        touched = set()
        for obj in parsed_set:
            touched.add(obj.key)
            stored = stored_objects.get(obj.key)
            spl_hash = object_hash(obj.text)
            values = collections.OrderedDict([
                ("sharing", obj.sharing), ("is_scheduled", obj.is_scheduled), ("is_alert", obj.is_alert), ("disabled", obj.disabled),
                ("is_matalog_own", obj.is_matalog_own), ("spl_hash", spl_hash), ("last_seen_run", ctx.run_id)])
            run = history.get((obj.ko_type, obj.app, obj.name))
            values["last_run_time"] = run[1] if run else _epoch((stored or {}).get("last_run_time"))
            values["run_count_30d"] = run[0] if run else 0
            if stored and stored.get("spl_hash") == spl_hash and stored.get("parse_status") in ("parsed", "partial"):
                obj.skipped = True
                obj.references = [(e.get("field_name"), e.get("ref_kind"), spl.scope_from_text(e.get("resolution"), e.get("scope_text")),
                                   e.get("confidence") or spl.EXACT, _list(e.get("scope_via"))) for e in stored_edges.get(obj.key, []) if e.get("field_name")]
                obj.macros = sorted(set(m for e in stored_edges.get(obj.key, []) for m in _list(e.get("macros"))))
                state["skipped"] += 1
                # A skipped object counts on the record under its stored outcome, so objects_total less the three is the over-cap count.
                state[stored["parse_status"]] += 1
            else:
                parse = parse_object(obj, lookup_for, roots, knowledge)
                values.update(parse_status=parse.status, parse_gaps=list(parse.gaps), last_parsed_run=ctx.run_id)
                state[parse.status] += 1
            doc = rows_mod.objects_doc(obj.ko_type, obj.app, obj.owner, obj.name, **values)
            ctx.stage_kv(OBJECTS, doc)
            merged = dict(stored or {})
            merged.update(doc)
            objects[obj.key] = merged
            if obj.is_matalog_own:
                state["own"] += 1
                continue
            for field_name, ref_kind, scope, confidence, via in obj.references:
                edge = rows_mod.usage_doc(obj.key, resolver.scope_key(scope), field_name, ref_kind, ko_type=obj.ko_type, app=obj.app, name=obj.name,
                                          is_alert=obj.is_alert, resolution=resolver.resolution(scope), scope_text=scope.text,
                                          resolved_field_keys=resolver.field_keys(scope, field_name), confidence=confidence,
                                          expanded=1 if obj.macros else 0, macros=list(obj.macros), scope_via=list(via))
                if not obj.skipped:
                    edge["last_seen_run"] = ctx.run_id
                edges[edge["_key"]] = edge
        for obj in parsed_set:
            for stored_edge in stored_edges.get(obj.key, []):
                if stored_edge["_key"] not in edges:
                    ctx.delete_kv(USAGE, stored_edge["_key"])
                    state["edges_deleted"] += 1
        for key, doc in edges.items():
            ctx.stage_kv(USAGE, doc)
        state["edges"] = len(edges)
        self.delete_stale(ctx, stored_objects, stored_edges, touched, listed_types, state, objects)
        summary_edges = list(edges.values())
        for object_key, docs in stored_edges.items():
            if object_key not in touched and object_key in objects:
                summary_edges.extend(docs)
        field_values, source_values = summarize(ctx.settings, summary_edges, objects, field_index)
        state["fields_staged"] = self.stage_field_usage(ctx, field_values, field_index, stored_usage)
        state["sources_staged"] = self.stage_source_usage(ctx, source_values, sources)
        for status in ("parsed", "partial", "failed"):
            ctx.counts["objects_" + status] = int(state[status])
        ctx.counts["objects_total"] = int(state["listed"])

    def list_objects(self, ctx):
        """Every knowledge object the service account sees; a listing that fails is recorded and its type left out."""
        config = ctx.state.get("config") or {}
        listed = []
        macros = []
        models = []
        listed_types = set()

        def read(label, reader, builder, types):
            try:
                entries = list(reader())
            except Exception as exc:
                ctx.error(STEP, label, "%s unreadable: %s" % (label, exc))
                return None
            listed.extend(builder(entries))
            listed_types.update(types)
            return entries

        read("saved/searches", ctx.client.saved_searches, saved_search_objects, ("alert", "report", "savedsearch"))
        read("data/ui/views", ctx.client.views, view_objects, ("dashboard",))
        macros = read("data/macros", ctx.client.macros, macro_objects, ("macro",)) or []
        read("data/transforms/lookups", ctx.client.lookup_definitions, lookup_objects, ("lookup",))
        if config.get("eventtypes_ok") and config.get("eventtypes") is not None:
            listed.extend(eventtype_objects(config["eventtypes"]))
            listed_types.add("eventtype")
        else:
            read("conf-eventtypes", ctx.client.eventtypes, eventtype_objects, ("eventtype",))
        if config.get("datamodels_ok") and config.get("datamodels") is not None:
            models = list(config["datamodels"])
            listed.extend(datamodel_objects(models))
            listed_types.add("datamodel")
        else:
            models = read("datamodel/model", ctx.client.datamodels, datamodel_objects, ("datamodel",)) or []
        return listed, macros, models, listed_types

    def run_history(self, ctx, state):
        """(ko_type, app, name) -> (runs in the trailing 30 days, latest run time), from one search ending at the audit window end."""
        latest = ctx.audit_window()[1]
        earliest = latest - RUN_HISTORY_DAYS * 86400
        try:
            result = ctx.client.search(runs_spl(), earliest=float(earliest), latest=float(latest), step=STEP, subject_key=RUNS_SUBJECT, max_rows=RUNS_MAX_ROWS)
        except BudgetExhausted as exc:
            ctx.error(STEP, RUNS_SUBJECT, "budget ceiling %s; last_run_time and run_count_30d keep their stored values" % exc.ceiling)
            return {}
        except Exception as exc:
            ctx.error(STEP, RUNS_SUBJECT, "run history search raised %s: %s" % (exc.__class__.__name__, exc))
            return {}
        if not result.ok:
            ctx.error(STEP, RUNS_SUBJECT, "run history search %s" % result.status)
            return {}
        by_name = {}
        for row in result.results:
            kind = str(row.get("matalog_kind") or "")
            app = str(row.get("app") or "")
            name = str(row.get("matalog_name") or "")
            runs = _int(row.get("runs"))
            last = _epoch(row.get("last_time"))
            if not name or not kind:
                continue
            ko_types = ("dashboard",) if kind == "dashboard" else ("alert", "report", "savedsearch")
            for ko_type in ko_types:
                current = by_name.get((ko_type, app, name))
                if current is None:
                    by_name[(ko_type, app, name)] = (runs, last)
                else:
                    by_name[(ko_type, app, name)] = (max(current[0], runs), max(v for v in (current[1], last) if v is not None) if (current[1] is not None or last is not None) else None)
        state["history_rows"] = len(result.results)
        return by_name

    def field_rows(self, ctx):
        """Source-level field rows after this run's staging: (field_key -> (source_key, field_name), source_key -> {name: key}, stored usage by key)."""
        field_index = collections.OrderedDict()
        stored_usage = {}
        for doc in ctx.client.kv_query(FIELDS, query={"level": "source"}, fields=list(FIELD_COLUMNS)):
            if doc.get("_key") and doc.get("source_key") and doc.get("field_name"):
                field_index[doc["_key"]] = (doc["source_key"], doc["field_name"])
                stored_usage[doc["_key"]] = doc
        for key, doc in ctx.kv[FIELDS].items():
            if key in field_index:
                continue
            if (doc.get("level") == "source" or doc.get("stratum_value") == keys.ALL) and doc.get("source_key") and doc.get("field_name"):
                field_index[key] = (doc["source_key"], doc["field_name"])
        for key in ctx.kv_deletes[FIELDS]:
            field_index.pop(key, None)
        fields_by_source = collections.defaultdict(dict)
        for key, (source_key, field_name) in field_index.items():
            fields_by_source[source_key][field_name] = key
        return field_index, fields_by_source, stored_usage

    def coverage(self, ctx):
        """(Model.Dataset, field) -> source-level field keys mapped by S8."""
        out = collections.defaultdict(list)
        for doc in ctx.client.kv_query(COVERAGE, query={"mapped": 1}, fields=["cim_dataset", "cim_field", "field_key"]):
            if doc.get("field_key") and doc.get("cim_dataset") and doc.get("cim_field"):
                out[(str(doc["cim_dataset"]), str(doc["cim_field"]))].append(str(doc["field_key"]))
        return out

    def delete_stale(self, ctx, stored_objects, stored_edges, touched, listed_types, state, objects):
        """Objects of a listed type not seen for retention.object_stale_runs passes are deleted with their edges."""
        passes = usage_passes(ctx)
        limit = int(ctx.settings.retention.object_stale_runs)
        for key, doc in stored_objects.items():
            if key in touched or doc.get("ko_type") not in listed_types:
                continue
            last = str(doc.get("last_seen_run") or "")
            missed = 1 + sum(1 for r in passes if r > last)
            if missed < limit:
                continue
            ctx.delete_kv(OBJECTS, key)
            objects.pop(key, None)
            state["objects_deleted"] += 1
            for edge in stored_edges.get(key, []):
                ctx.delete_kv(USAGE, edge["_key"])
                state["edges_deleted"] += 1

    def stage_field_usage(self, ctx, field_values, field_index, stored_usage):
        staged = 0
        for key, values in field_values.items():
            stored = stored_usage.get(key)
            current = dict(stored or {})
            current.update(ctx.staged(FIELDS, key) or {})
            if not usage_differs(current, values):
                continue
            source_key, field_name = field_index[key]
            ctx.stage_kv(FIELDS, rows_mod.kv_doc(FIELDS, key, source_key=source_key, field_name=field_name, **values))
            staged += 1
        return staged

    def stage_source_usage(self, ctx, source_values, sources):
        staged = 0
        stored = ctx.existing(SOURCES, list(source_values)) if source_values else {}
        for key, values in source_values.items():
            current = dict(stored.get(key) or {})
            current.update(ctx.staged(SOURCES, key) or {})
            if not usage_differs(current, values):
                continue
            identity = sources.get(key)
            if identity is None:
                continue
            ctx.stage_kv(SOURCES, rows_mod.sources_doc(identity[0], identity[1], **values))
            staged += 1
        return staged
