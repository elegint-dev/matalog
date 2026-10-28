"""S5 read_config."""
import collections
import json
import re

from .. import keys
from .. import rows as rows_mod
from ..budget import BudgetExhausted
from ..runner import Step, StepFailed

STEP = "S5"
MAX_RAW_CHARS = 4096
# Indexed-field candidates probed per index; a tstats run with 438 dc() aggregations takes 0.14 s, the same as one with 200.
PROBE_MAX_FIELDS = 1000
PROBE_MAX_VALUES = 1000
# Source and host values kept per source on matalog_sources (sources_top, hosts_top), from the probe.
SOURCE_VALUES_KEPT = 20
KV_QUERY_CHUNK = 200
EXPORTED_SHARING = ("system", "global")
TRUE_VALUES = ("1", "true", "t", "yes", "y", "on")

# Names a tstats probe can carry in dc("...") and in its alias.
SAFE_PROBE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.{}@-]*$")
MODULAR_REF = re.compile(r"\[\[([^\[\]:]+)(?::([^\[\]]*))?\]\]")
GROUP_OPEN = re.compile(r"\(\?(?:P?<(?![=!])([^>]*)>|'([^']*)')")
DYNAMIC_GROUP = re.compile(r"^_(?:KEY|VAL)_")
UUID_SHAPE = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
EXTRACT_IN_FIELD = re.compile(r"\s+in\s+([A-Za-z_][A-Za-z0-9_.{}-]*)\s*$")

PREFIX_CLASSES = (
    ("EXTRACT-", "EXTRACT"), ("REPORT-", "REPORT"), ("FIELDALIAS-", "FIELDALIAS"), ("EVAL-", "EVAL"),
    ("LOOKUP-", "LOOKUP"), ("TRANSFORMS-", "TRANSFORMS"),
)
EXACT_CLASSES = {"TRANSFORMS": "TRANSFORMS", "KV_MODE": "KV_MODE", "INDEXED_EXTRACTIONS": "INDEXED_EXTRACTIONS", "rename": "rename"}
# Attributes applied before search time: their sourcetype stanza matches the indexed sourcetype, not the renamed one.
INDEX_TIME_CLASSES = ("TRANSFORMS", "INDEXED_EXTRACTIONS", "rename")

PROBE_PREFIX = "matalog_dc:"
FIELD_COLUMNS = ["_key", "source_key", "src_index", "src_sourcetype", "stratum_field", "stratum_value", "field_name", "level",
                 "presence", "declared", "origin", "origin_app", "origin_stanza", "origin_decl_key", "origin_candidates",
                 "origin_conflict", "origin_changed_run"]
S5_FIELD_COLUMNS = ("declared", "origin", "origin_app", "origin_stanza", "origin_decl_key", "origin_candidates", "origin_conflict")
# Columns rows.fields_doc fills by default that belong to other steps; dropped before S5 restages an existing row.
FOREIGN_DEFAULT_COLUMNS = ("stratum_label", "level", "is_stratum_field")
# KV_MODE is one setting per event: a source:: stanza overrides host::, which overrides the sourcetype, then [default].
KV_MODE_KIND_RANK = {"source": 0, "host": 1, "sourcetype": 2, "default": 3}
# Search-time operation sequence: index-time fields, then EXTRACT, REPORT, KV_MODE, FIELDALIAS, EVAL, LOOKUP. A later stage that
# writes the field is its winner. FIELDALIAS ASNEW and LOOKUP OUTPUTNEW never overwrite, so they rank below every writing stage;
# a data model calculation writes nothing outside its model and ranks just above them.
STAGE_RANK = {"TRANSFORMS": 10, "INDEXED_EXTRACTIONS": 10, "INDEXED": 10, "EXTRACT": 20, "REPORT": 30, "KV_MODE": 40,
              "FIELDALIAS": 50, "EVAL": 60, "LOOKUP": 70}
DATAMODEL_RANK = 1
NEW_ONLY_RANK = 0


def new_only_fields(cls, value):
    """Field names a declaration only fills when absent: FIELDALIAS ASNEW targets, every output of a LOOKUP with OUTPUTNEW."""
    tokens = tokenize(value)
    if cls == "FIELDALIAS":
        return set(tokens[i + 2] for i in range(len(tokens) - 2) if tokens[i + 1].upper() == "ASNEW")
    if cls == "LOOKUP" and any(t.upper() == "OUTPUTNEW" for t in tokens):
        return set(lookup_fields(value, None)[0])
    return set()


def stage_rank(decl, name):
    """Precedence of one declaration for one field: higher wins, ties fall to endpoint order."""
    if name in decl.new_only:
        return NEW_ONLY_RANK
    if decl.conf_file == "datamodels":
        return DATAMODEL_RANK
    return STAGE_RANK.get(decl.cls, DATAMODEL_RANK + 1)


# Parsing of declaration values. Every function returns field names in the
# order they appear and whether the parse is complete.

def truthy(value):
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in TRUE_VALUES


def _dedupe(names):
    out = []
    seen = set()
    for name in names:
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def status_of(names, complete):
    """parsed when every part resolved to names, partial when some did, opaque when none did."""
    if not names:
        return "opaque"
    return "parsed" if complete else "partial"


def scan_regex(regex):
    """Named groups and [[transform]] references of a Splunk regex, in order, without compiling it.

    Returns tokens ("group", name) and ("ref", transform, field_or_None).
    Escaped characters and character classes are skipped, so (?<= and \\(? are not groups.
    """
    tokens = []
    text = regex or ""
    i, n = 0, len(text)
    in_class = False
    while i < n:
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if in_class:
            if ch == "]":
                in_class = False
            i += 1
            continue
        if ch == "[":
            ref = MODULAR_REF.match(text, i)
            if ref:
                tokens.append(("ref", ref.group(1).strip(), ref.group(2)))
                i = ref.end()
                continue
            in_class = True
            i += 1
            if i < n and text[i] == "^":
                i += 1
            if i < n and text[i] == "]":
                i += 1
            continue
        if ch == "(":
            group = GROUP_OPEN.match(text, i)
            if group:
                tokens.append(("group", group.group(1) if group.group(1) is not None else group.group(2)))
                i = group.end()
                continue
        i += 1
    return tokens


def regex_fields(regex, lookup, stack=()):
    """Field names a regex yields, expanding [[name]] and [[name:field]] through lookup(name) -> transform content.

    A reference with a field name yields that name for a referenced regex
    without named groups, and the field name as a prefix of each group
    otherwise; (?<>...) takes the name of the reference. _KEY_n and _VAL_n
    groups are dynamic and make the parse incomplete; other names starting
    with an underscore are internal and dropped.
    """
    names = []
    complete = True
    for token in scan_regex(regex):
        if token[0] == "group":
            name = token[1]
            if name == "":
                continue
            if DYNAMIC_GROUP.match(name):
                complete = False
                continue
            if name.startswith("_"):
                continue
            names.append(name)
            continue
        _, target, field = token
        content = lookup(target) if target not in stack else None
        if content is None:
            complete = False
            if field:
                names.append(field)
            continue
        inner, ok = regex_fields(content.get("REGEX", ""), lookup, stack + (target,))
        complete = complete and ok
        if field is None:
            names.extend(inner)
        elif inner:
            names.extend(field + name for name in inner)
        else:
            names.append(field)
    return _dedupe(names), complete


def format_fields(fmt):
    """Field names of a FORMAT string of name::value pairs; a name holding a $n capture is dynamic."""
    names = []
    complete = True
    for token in (fmt or "").split():
        if "::" not in token:
            continue
        name = token.split("::", 1)[0].strip().strip('"')
        if not name:
            continue
        if "$" in name:
            complete = False
            continue
        names.append(name)
    return _dedupe(names), complete


def split_list(value):
    """A comma or space separated list, quotes removed."""
    return [p.strip().strip('"').strip("'") for p in re.split(r"[,\s]+", value or "") if p.strip().strip('"').strip("'")]


def transform_fields(content, lookup, name=""):
    """Fields a search-time transform yields: REGEX named groups or FORMAT names, or FIELDS with DELIMS."""
    if content is None:
        return [], False
    delims = (content.get("DELIMS") or "").strip()
    fields_attr = (content.get("FIELDS") or "").strip()
    fmt = (content.get("FORMAT") or "").strip()
    regex = content.get("REGEX") or ""
    if delims:
        if fields_attr:
            return _dedupe(split_list(fields_attr)), True
        return [], False
    if fmt:
        return format_fields(fmt)
    if regex:
        return regex_fields(regex, lookup, (name,) if name else ())
    return [], True


def is_index_time_meta(content):
    """An index-time transform that writes fields: WRITE_META true or DEST_KEY=_meta."""
    if content is None:
        return False
    return truthy(content.get("WRITE_META")) or (content.get("DEST_KEY") or "").strip() == "_meta"


def tokenize(value):
    """Whitespace tokens with double-quoted runs kept together and quotes removed; commas separate too."""
    out = []
    for match in re.finditer(r'"((?:[^"\\]|\\.)*)"|([^\s,]+)', value or ""):
        out.append(match.group(1) if match.group(1) is not None else match.group(2))
    return out


def fieldalias_fields(value):
    """New names of a FIELDALIAS value: `a AS b c ASNEW d` yields b, d."""
    tokens = tokenize(value)
    names = []
    complete = True
    i = 0
    while i < len(tokens):
        if i + 2 < len(tokens) and tokens[i + 1].upper() in ("AS", "ASNEW"):
            names.append(tokens[i + 2])
            i += 3
            continue
        complete = False
        i += 1
    return _dedupe(names), complete and bool(names)


def _field_specs(tokens):
    """`f [AS g]` specs: list of (lookup_field, event_field)."""
    specs = []
    i = 0
    while i < len(tokens):
        if i + 2 < len(tokens) and tokens[i + 1].upper() == "AS":
            specs.append((tokens[i], tokens[i + 2]))
            i += 3
        else:
            specs.append((tokens[i], tokens[i]))
            i += 1
    return specs


def lookup_fields(value, lookup_content):
    """Output names of a LOOKUP value; without OUTPUT or OUTPUTNEW, the lookup's fields_list less its inputs."""
    tokens = tokenize(value)
    if not tokens:
        return [], False
    rest = tokens[1:]
    split = None
    for i, token in enumerate(rest):
        if token.upper() in ("OUTPUT", "OUTPUTNEW"):
            split = i
            break
    if split is not None:
        outputs = _field_specs(rest[split + 1:])
        return _dedupe([event for _, event in outputs]), bool(outputs)
    inputs = set(lookup for lookup, _ in _field_specs(rest))
    if lookup_content is None or not (lookup_content.get("fields_list") or "").strip():
        return [], False
    names = [f for f in split_list(lookup_content.get("fields_list")) if f not in inputs and f != "_key"]
    return _dedupe(names), True


def kv_mode_origin(value):
    mode = (value or "").strip().lower()
    if mode == "json":
        return "json_auto"
    if mode in ("auto", "auto_escaped"):
        return "kv_auto"
    return None


# Stanza kinds and patterns.

def stanza_kind(name):
    """sourcetype, source, host or default; None for stanzas that declare no fields (rule::, delayedrule::)."""
    if name == "default":
        return "default"
    bare = name[4:] if name.startswith("(?i)") else name
    if bare.startswith("source::"):
        return "source"
    if bare.startswith("host::"):
        return "host"
    if bare.startswith("rule::") or bare.startswith("delayedrule::"):
        return None
    return "sourcetype"


def pattern_regex(stanza):
    """Compiled matcher for a source:: or host:: stanza: ... is any run, * any run without a path separator, . literal.

    A (?i) anywhere makes the whole match case-insensitive. The match is anchored at both ends.
    """
    flags = 0
    body = stanza
    if "(?i)" in body:
        flags = re.IGNORECASE
        body = body.replace("(?i)", "")
    body = body.split("::", 1)[1] if "::" in body else body
    out = []
    i, n = 0, len(body)
    while i < n:
        if body.startswith("...", i):
            out.append(".*")
            i += 3
        elif body[i] == "*":
            out.append("[^/\\\\]*")
            i += 1
        elif body[i] == "\\":
            out.append(body[i:i + 2])
            i += 2
        elif body[i] == ".":
            out.append("\\.")
            i += 1
        else:
            out.append(body[i])
            i += 1
    return re.compile("^(?:%s)$" % "".join(out), flags)


class Declaration(object):
    """One declaring attribute, before it becomes a matalog_declarations document."""

    def __init__(self, app, owner, sharing, conf_file, stanza, attribute, cls, raw_value, origin_class, fields, parse_status, kind, order):
        self.app = app or ""
        self.owner = owner or ""
        self.sharing = sharing or ""
        self.conf_file = conf_file
        self.stanza = stanza
        self.attribute = attribute
        self.cls = cls
        self.raw_value = raw_value
        self.origin_class = origin_class or ""
        self.fields = fields
        self.parse_status = parse_status
        self.kind = kind
        self.order = order
        self.key = keys.k(self.app, conf_file, stanza, attribute)
        self.sourcetype = ""
        self.matcher = None
        self.applies_all = False
        self.never_applies = False
        self.only_observed = False
        self.new_only = new_only_fields(cls, raw_value)

    @property
    def origin_stanza(self):
        return "%s:%s:%s" % (self.conf_file, self.stanza, self.attribute)

    @property
    def index_time(self):
        return self.cls in INDEX_TIME_CLASSES


class ReadConfig(Step):
    """Read props, transforms, fields and datamodels through the config endpoints and resolve each field's origin.

    Inputs: client.props(), client.transforms(), client.fields_conf(),
    client.datamodels(), each a list of {name, content, acl} in the order the
    endpoint returned, which is the precedence the service account sees;
    ctx.state["apps_local"] (the client.apps_local() entries S1 read, read
    here when absent) for app versions; ctx.state["sources"] and the
    enumerated sources in ctx.state["sources_all"] that are not gone; the staged and
    stored matalog_fields rows of those sources; the stored
    matalog_declarations and matalog_sources rows; committed matalog_runs for
    the stale count. Searches per index with sources this run, on
    ctx.windows["source_day"]: one `| walklex type=field`, then one `| tstats`
    probe carrying dc() of the candidate names (walklex-listed names that are
    field rows of the index and not declared in fields.conf) plus
    values(source) and values(host) by sourcetype for source:: and host::
    stanzas.

    Outputs: one matalog_declarations doc per declaring attribute; on
    matalog_fields: declared, origin, origin_app, origin_stanza,
    origin_decl_key, origin_candidates, origin_conflict, origin_changed_run,
    staged for every row S3 or S4 staged and for stored rows whose values
    change; level=source presence=declared_only rows for declared fields
    no row has; on matalog_sources: search_sourcetype, config_apps,
    config_apps_changed_run; deletion of declarations unseen for
    retention.object_stale_runs reads. The kind=source and full kind=field
    summary rows still unwritten get config_apps and origin, origin_app.
    ctx.state["config"] holds the raw entries for later steps and
    ctx.state["declarations"] the staged declaration docs by key.
    """

    name = "S5"
    label = "read_config"

    def run(self, ctx):
        try:
            config = self.read_config(ctx)
        except StepFailed:
            self.mark_unknown(ctx)
            raise
        ctx.state["config"] = config
        versions = self.app_versions(ctx, config["apps_local"])
        declarations = self.build_declarations(ctx, config)
        sources = self.sources_to_resolve(ctx)
        source_keys = [s["source_key"] for s in sources]
        rows_by_source = self.field_rows(ctx, source_keys)
        index_facts = self.search_indexes(ctx, sources, rows_by_source, declarations)
        ctx.state["index_facts"] = index_facts
        ctx.counts["indexes_scanned"] = sum(1 for f in index_facts.values() if f.get("searched"))
        stored_sources = ctx.existing("matalog_sources", source_keys) if source_keys else {}
        self.stored_declarations = dict((d["_key"], d) for d in ctx.client.kv_query("matalog_declarations"))
        applies = self.match_sources(ctx, declarations, sources, rows_by_source, index_facts, stored_sources)
        self.stage_sources(ctx, sources, declarations, applies, versions, stored_sources)
        self.stage_fields(ctx, sources, declarations, applies, rows_by_source, index_facts, stored_sources)
        self.stage_declarations(ctx, declarations, applies, versions, source_keys, config)
        self.amend_unwritten(ctx)

    def mark_unknown(self, ctx):
        """With the config unreadable, staged rows that have no stored origin get origin=unknown; stored origins stay."""
        staged = ctx.kv["matalog_fields"]
        if not staged:
            return
        stored = ctx.existing("matalog_fields", list(staged.keys()))
        marked = set()
        for key, doc in list(staged.items()):
            if doc.get("origin") or (stored.get(key) or {}).get("origin"):
                continue
            ctx.stage_kv("matalog_fields", restage_doc(doc, origin="unknown"))
            marked.add(key)
        pending = set(id(r) for r in ctx.unwritten)
        for row in ctx.summary.get("field", []):
            if row.get("shape") == "full" and row.get("field_key") in marked and id(row) in pending and not row.get("origin"):
                row["origin"] = "unknown"
                if rows_mod.row_bytes(row) > ctx.settings.profile.max_row_bytes:
                    row["origin"] = ""

    # Config reads.

    def read_config(self, ctx):
        """Every config read; a failed props, transforms or fields read stops the step before anything is staged."""
        out = collections.OrderedDict()
        for name, reader in (("props", ctx.client.props), ("transforms", ctx.client.transforms), ("fields", ctx.client.fields_conf)):
            try:
                out[name] = list(reader())
            except Exception as exc:
                raise StepFailed("conf-%s unreadable: %s" % (name, exc))
        out["datamodels_ok"] = True
        try:
            out["datamodels"] = list(ctx.client.datamodels())
        except Exception as exc:
            ctx.error(STEP, "datamodels", "datamodel endpoint unreadable: %s" % exc)
            out["datamodels"] = []
            out["datamodels_ok"] = False
        # Eventtypes and tags resolve data model constraints in S8; a failed read leaves tag and eventtype terms unresolved there.
        for name, reader in (("eventtypes", ctx.client.eventtypes), ("tags", ctx.client.tags)):
            out[name + "_ok"] = True
            try:
                out[name] = list(reader())
            except Exception as exc:
                ctx.error(STEP, name, "conf-%s unreadable: %s" % (name, exc))
                out[name] = []
                out[name + "_ok"] = False
        apps = ctx.state.get("apps_local")
        if apps is None:
            try:
                apps = list(ctx.client.apps_local())
            except Exception as exc:
                raise StepFailed("apps/local unreadable: %s" % exc)
        out["apps_local"] = apps
        return out

    def app_versions(self, ctx, apps):
        versions = {}
        for entry in apps or []:
            name = entry.get("name")
            if name:
                versions[name] = str((entry.get("content") or {}).get("version") or "")
        if "system" not in versions:
            try:
                versions["system"] = str(ctx.client.server_info().get("version") or "")
            except Exception as exc:
                ctx.error(STEP, "server_info", str(exc))
                versions["system"] = ""
        return versions

    # Declarations.

    def build_declarations(self, ctx, config):
        """Declarations in precedence order: props entries and their attributes as the endpoint returned them, then fields, then datamodels."""
        transforms = self.transform_index(config["transforms"])
        out = []
        out.extend(self.props_declarations(config["props"], transforms, len(out)))
        out.extend(self.fields_declarations(config["fields"], len(out)))
        out.extend(self.datamodel_declarations(config["datamodels"], len(out)))
        seen = collections.OrderedDict()
        for decl in out:
            if decl.key not in seen:
                seen[decl.key] = decl
        return list(seen.values())

    def transform_index(self, entries):
        by_name = collections.OrderedDict()
        for entry in entries:
            if truthy((entry.get("content") or {}).get("disabled")):
                continue
            by_name.setdefault(entry.get("name"), []).append(entry)
        return by_name

    def transform_lookup(self, transforms, app):
        """lookup(name) -> transform content, preferring the declaring app's entry, then an exported one, then the first."""
        def lookup(name):
            entries = transforms.get(name)
            if not entries:
                return None
            for entry in entries:
                if (entry.get("acl") or {}).get("app") == app:
                    return entry.get("content") or {}
            for entry in entries:
                if (entry.get("acl") or {}).get("sharing") in EXPORTED_SHARING:
                    return entry.get("content") or {}
            return entries[0].get("content") or {}
        return lookup

    def owned_attributes(self, entries):
        """For each entry index, the declaring attributes it owns.

        The configs endpoint returns each app's stanza merged with what that
        app inherits, so one attribute and value repeat across apps. A
        repeated (stanza, attribute, value) is owned by its system entry,
        else by its only globally shared entry, else by the first entry in
        endpoint order. Values from a [default] stanza repeated in another
        stanza of an app that sees it are inherited, not declared there.
        """
        defaults = []
        for entry in entries:
            if entry.get("name") == "default":
                acl = entry.get("acl") or {}
                for attr, value in (entry.get("content") or {}).items():
                    if declaring_class(attr) and str(value or "").strip():
                        defaults.append((attr, str(value), acl.get("app"), acl.get("sharing")))
        carriers = collections.OrderedDict()
        for index, entry in enumerate(entries):
            content = entry.get("content") or {}
            if truthy(content.get("disabled")):
                continue
            name = entry.get("name")
            acl = entry.get("acl") or {}
            for attr, value in content.items():
                if not declaring_class(attr):
                    continue
                text = str(value) if value is not None else ""
                if not text.strip():
                    continue
                if name != "default" and any(attr == d[0] and text == d[1] and (d[2] == acl.get("app") or d[3] in EXPORTED_SHARING) for d in defaults):
                    continue
                carriers.setdefault((name, attr, text), []).append(index)
        owned = collections.defaultdict(set)
        for (name, attr, text), indexes in carriers.items():
            owner = indexes[0]
            if len(indexes) > 1:
                sharing = [((entries[i].get("acl") or {}).get("sharing"), (entries[i].get("acl") or {}).get("app"), i) for i in indexes]
                system = [i for s, app, i in sharing if s == "system" or app == "system"]
                exported = [i for s, app, i in sharing if s == "global"]
                if system:
                    owner = system[0]
                elif len(exported) == 1:
                    owner = exported[0]
            owned[owner].add(attr)
        return owned

    def props_declarations(self, entries, transforms, start):
        out = []
        owned = self.owned_attributes(entries)
        for index, entry in enumerate(entries):
            if index not in owned:
                continue
            name = entry.get("name") or ""
            kind = stanza_kind(name)
            if kind is None:
                continue
            acl = entry.get("acl") or {}
            content = entry.get("content") or {}
            lookup = self.transform_lookup(transforms, acl.get("app"))
            for attr, value in content.items():
                if attr not in owned[index]:
                    continue
                parsed = parse_props_attribute(attr, str(value), content, lookup)
                if parsed is None:
                    continue
                cls, origin_class, fields, status = parsed
                decl = Declaration(acl.get("app"), acl.get("owner"), acl.get("sharing"), "props", name, attr, cls,
                                   str(value)[:MAX_RAW_CHARS], origin_class, fields, status, kind, start + len(out))
                if kind == "sourcetype":
                    decl.sourcetype = name
                elif kind == "default":
                    decl.applies_all = True
                else:
                    try:
                        decl.matcher = pattern_regex(name)
                    except re.error:
                        decl.matcher = None
                        decl.never_applies = True
                out.append(decl)
        return out

    def fields_declarations(self, entries, start):
        """fields.conf INDEXED=true: an index-time field, declared for every source (or one sourcetype for sourcetype:: stanzas)."""
        out = []
        for entry in entries:
            content = entry.get("content") or {}
            if truthy(content.get("disabled")) or not truthy(content.get("INDEXED")):
                continue
            name = entry.get("name") or ""
            acl = entry.get("acl") or {}
            kind = "default"
            sourcetype = ""
            field = name
            if name.startswith("sourcetype::") and name.count("::") >= 2:
                _, sourcetype, field = name.split("::", 2)
                kind = "sourcetype"
            if "*" in field or not field:
                fields, status = [], "opaque"
            else:
                fields, status = [field], "parsed"
            decl = Declaration(acl.get("app"), acl.get("owner"), acl.get("sharing"), "fields", name, "INDEXED", "INDEXED",
                               str(content.get("INDEXED")), "indexed", fields, status, kind, start + len(out))
            decl.sourcetype = sourcetype
            decl.applies_all = kind == "default"
            out.append(decl)
        return out

    def datamodel_declarations(self, entries, start):
        """Data model calculations: origin datamodel, applying to no source until datasets are matched to sources."""
        out = []
        for entry in entries:
            acl = entry.get("acl") or {}
            content = entry.get("content") or {}
            try:
                model = json.loads(content.get("description") or "{}")
            except (TypeError, ValueError):
                continue
            stanza = model_stanza(entry, model)
            seen = set()
            for obj in model.get("objects") or []:
                for calc in obj.get("calculations") or []:
                    parsed = calculation_attribute(obj, calc)
                    if parsed is None or parsed[0] in seen:
                        continue
                    attribute, fields, raw = parsed
                    seen.add(attribute)
                    decl = Declaration(acl.get("app"), acl.get("owner"), acl.get("sharing"), "datamodels", stanza, attribute, "DATAMODEL",
                                       str(raw)[:MAX_RAW_CHARS], "datamodel", fields, "parsed" if fields else "opaque", None, start + len(out))
                    decl.never_applies = True
                    out.append(decl)
        return out

    # Sources and their field rows.

    def sources_to_resolve(self, ctx):
        """The sources due this run, then every other enumerated source not gone, then the sources of staged field rows.

        Declarations apply whether or not a source had events this cycle, so a
        quiet source keeps its origin columns current too.
        """
        out = collections.OrderedDict()
        enumerated = [d for d in (ctx.state.get("sources_all") or {}).values() if d.get("state") != "gone"]
        for doc in list(ctx.state.get("sources") or []) + enumerated:
            out.setdefault(doc["source_key"], {"source_key": doc["source_key"], "src_index": doc["src_index"], "src_sourcetype": doc["src_sourcetype"]})
        for doc in ctx.kv["matalog_fields"].values():
            key = doc.get("source_key")
            if key and key not in out and doc.get("src_index") and doc.get("src_sourcetype"):
                out[key] = {"source_key": key, "src_index": doc["src_index"], "src_sourcetype": doc["src_sourcetype"]}
        return list(out.values())

    def field_rows(self, ctx, source_keys):
        """source_key -> OrderedDict(_key -> (staged doc or None, stored doc or None)) over staged and stored field rows."""
        out = collections.OrderedDict((k, collections.OrderedDict()) for k in source_keys)
        wanted = set(source_keys)
        stored = []
        for start in range(0, len(source_keys), KV_QUERY_CHUNK):
            chunk = source_keys[start:start + KV_QUERY_CHUNK]
            stored.extend(ctx.client.kv_query("matalog_fields", query={"source_key": {"$in": chunk}}, fields=FIELD_COLUMNS))
        for doc in stored:
            if doc.get("source_key") in wanted and doc.get("_key"):
                out[doc["source_key"]][doc["_key"]] = [None, doc]
        for key, doc in ctx.kv["matalog_fields"].items():
            if doc.get("source_key") in wanted:
                entry = out[doc["source_key"]].setdefault(key, [None, None])
                entry[0] = doc
        return out

    # Searches.

    def search_indexes(self, ctx, sources, rows_by_source, declarations):
        """Per index whose scan is due: walklex field names, then one tstats probe. Returns index -> facts.

        Without ctx.state["indexes_due"] every index with a source is scanned.
        facts: searched (both jobs ok), walklex (set), confirmed
        (sourcetype -> set of names with dc > 0), source_values and host_values
        (sourcetype -> list), candidates (the probed names), overflow (the
        candidates past PROBE_MAX_FIELDS, left unprobed).
        """
        fields_conf_names = set()
        for decl in declarations:
            if decl.conf_file == "fields":
                fields_conf_names.update(decl.fields)
        by_index = collections.OrderedDict()
        for source in sources:
            by_index.setdefault(source["src_index"], []).append(source)
        earliest, latest = ctx.windows["source_day"]
        facts = collections.OrderedDict()
        due = ctx.state.get("indexes_due")
        due = None if due is None else set(str(i).lower() for i in due)
        for index, members in by_index.items():
            fact = {"searched": False, "walklex": set(), "confirmed": {}, "source_values": {}, "host_values": {}, "candidates": [],
                    "overflow": set()}
            facts[index] = fact
            if due is not None and str(index).lower() not in due:
                continue
            walk = self._search(ctx, walklex_spl(index), earliest, latest, index)
            if walk is None:
                continue
            fact["walklex"] = set(str(r.get("field", "")).lstrip() for r in walk.results if str(r.get("field", "")).strip())
            observed = set()
            known_indexed = set()
            for source in members:
                for staged, stored in rows_by_source.get(source["source_key"], {}).values():
                    name = (staged or stored or {}).get("field_name")
                    if name:
                        observed.add(name)
                        if (stored or {}).get("origin") == "indexed":
                            known_indexed.add(name)
            # Names without a stored indexed origin are probed first, so a capped probe confirms new names before rechecking known ones.
            candidates = sorted((n for n in fact["walklex"] & observed if n not in fields_conf_names and SAFE_PROBE_NAME.match(n)),
                                key=lambda n: (n in known_indexed, n))
            if len(candidates) > PROBE_MAX_FIELDS:
                ctx.error(STEP, index, "%d indexed-field candidates, probing the first %d" % (len(candidates), PROBE_MAX_FIELDS))
                fact["overflow"] = set(candidates[PROBE_MAX_FIELDS:])
                candidates = candidates[:PROBE_MAX_FIELDS]
            fact["candidates"] = candidates
            probe = self._search(ctx, probe_spl(index, candidates), earliest, latest, index)
            if probe is None:
                continue
            for row in probe.results:
                sourcetype = row.get("sourcetype")
                if not sourcetype:
                    continue
                fact["confirmed"][sourcetype] = set(n for n in candidates if _positive(row.get(PROBE_PREFIX + n)))
                fact["source_values"][sourcetype] = _values(row.get("matalog_source"))
                fact["host_values"][sourcetype] = _values(row.get("matalog_host"))
            fact["searched"] = True
        return facts

    def _search(self, ctx, spl, earliest, latest, index):
        try:
            result = ctx.client.search(spl, earliest=earliest, latest=latest, step=STEP, subject_key=index)
        except BudgetExhausted as exc:
            ctx.error(STEP, index, "budget ceiling %s; config matching for this index uses stored state" % exc.ceiling)
            return None
        except Exception as exc:
            ctx.error(STEP, index, "search raised %s: %s" % (exc.__class__.__name__, exc))
            return None
        if not result.ok:
            ctx.error(STEP, index, "search %s: %s" % (result.status, "; ".join(str(m.get("text", "")) for m in result.messages[:3])))
            return None
        return result

    # Matching.

    def match_sources(self, ctx, declarations, sources, rows_by_source, index_facts, stored_sources):
        """decl.key -> list of source keys it applies to, and per source the search sourcetype.

        For a source whose index was not searched this run, a source:: or
        host:: declaration applies when its stored applies_to_source_keys
        already lists the source.
        """
        self.search_sourcetype = {}
        applies = collections.OrderedDict((d.key, []) for d in declarations)
        for source in sources:
            sourcetype = source["src_sourcetype"]
            facts = index_facts.get(source["src_index"]) or {}
            renamed = sourcetype
            for decl in declarations:
                if decl.cls == "rename" and decl.kind == "sourcetype" and decl.sourcetype == sourcetype:
                    renamed = decl.raw_value.strip() or sourcetype
                    break
            self.search_sourcetype[source["source_key"]] = renamed
            values = {"source": facts.get("source_values", {}).get(sourcetype, []), "host": facts.get("host_values", {}).get(sourcetype, [])}
            for decl in declarations:
                if decl.kind in ("source", "host") and not facts.get("searched"):
                    stored = self.stored_declarations.get(decl.key) or {}
                    hit = source["source_key"] in _values(stored.get("applies_to_source_keys"))
                else:
                    hit = self.applies(decl, sourcetype, renamed, values)
                if hit:
                    applies[decl.key].append(source["source_key"])
        return applies

    def applies(self, decl, sourcetype, renamed, values):
        if decl.never_applies:
            return False
        if decl.applies_all:
            return True
        if decl.kind == "sourcetype":
            if decl.conf_file == "fields" or decl.index_time:
                return decl.sourcetype == sourcetype
            return decl.sourcetype == renamed
        if decl.kind in ("source", "host") and decl.matcher is not None:
            return any(decl.matcher.match(v) for v in values[decl.kind])
        return False

    # Staging.

    def applying(self, declarations, applies, source_key):
        return [d for d in declarations if source_key in applies[d.key]]

    def stage_sources(self, ctx, sources, declarations, applies, versions, stored_sources):
        for source in sources:
            key = source["source_key"]
            apps = sorted(set("%s@%s" % (d.app, versions.get(d.app, "")) for d in self.applying(declarations, applies, key)))
            values = {"search_sourcetype": self.search_sourcetype.get(key, source["src_sourcetype"]), "config_apps": apps}
            facts = (ctx.state.get("index_facts") or {}).get(source["src_index"]) or {}
            if facts.get("searched"):
                values["sources_top"] = list(facts.get("source_values", {}).get(source["src_sourcetype"], []))[:SOURCE_VALUES_KEPT]
                values["hosts_top"] = list(facts.get("host_values", {}).get(source["src_sourcetype"], []))[:SOURCE_VALUES_KEPT]
                values["index_scan_run"] = ctx.run_id
            stored = stored_sources.get(key) or {}
            previous = stored.get("config_apps")
            if previous is not None and sorted(_values(previous)) != apps:
                values["config_apps_changed_run"] = ctx.run_id
            ctx.stage_kv("matalog_sources", rows_mod.sources_doc(source["src_index"], source["src_sourcetype"], **values))
        self.config_apps = dict((s["source_key"], ctx.kv["matalog_sources"][s["source_key"]]["config_apps"]) for s in sources)

    def stage_fields(self, ctx, sources, declarations, applies, rows_by_source, index_facts, stored_sources):
        self.origins = {}
        for source in sources:
            key = source["source_key"]
            applying = self.applying(declarations, applies, key)
            candidates = collections.OrderedDict()
            for decl in applying:
                for name in decl.fields:
                    candidates.setdefault(name, []).append(decl)
            kv_modes = sorted((d for d in applying if d.cls == "KV_MODE"), key=lambda d: KV_MODE_KIND_RANK.get(d.kind, len(KV_MODE_KIND_RANK)))
            auto = kv_mode_origin(kv_modes[0].raw_value if kv_modes else "auto")
            facts = index_facts.get(source["src_index"]) or {}
            confirmed = facts.get("confirmed", {}).get(source["src_sourcetype"], set())
            if facts.get("searched"):
                probed, unprobed = set(facts.get("candidates") or ()), facts.get("overflow") or set()
            else:
                probed, unprobed = set(), None
            rows = rows_by_source.get(key, {})
            names_with_rows = set()
            for field_key, (staged, stored) in rows.items():
                # A staged doc can be partial (an absence update carries no src_index), so identity reads through to the stored row.
                identity = dict(stored or {})
                identity.update(staged or {})
                name = identity.get("field_name")
                if not name:
                    continue
                names_with_rows.add(name)
                values = self.resolve(name, candidates, auto, probed, unprobed, confirmed, stored)
                self.stage_field(ctx, identity, staged, stored, values)
            for name, decls in candidates.items():
                if name in names_with_rows or name.startswith("_"):
                    continue
                if not any(d.conf_file == "props" for d in decls):
                    continue
                values = self.resolve(name, candidates, auto, probed, unprobed, confirmed, None)
                values.update(presence="declared_only", observed=0, level="source", is_rollup=0, rollup_strata=0, consecutive_unseen=0)
                doc = rows_mod.fields_doc(source["src_index"], source["src_sourcetype"], keys.ALL, keys.ALL, name, **values)
                ctx.stage_kv("matalog_fields", doc)
                self.origins[doc["_key"]] = (values.get("origin"), values.get("origin_app"))

    def resolve(self, name, candidates, auto, probed, unprobed, confirmed, stored):
        """The S5 columns of one field.

        Candidates are ordered by stage_rank, the last search-time stage that
        writes the field first, then by endpoint order; the first wins. Else
        indexed when the probe confirms it, or when its stored origin is
        indexed and it was not probed: its index was not searched (unprobed
        None) or it is in unprobed. Else json_auto or kv_auto from KV_MODE.
        Else unknown.
        """
        decls = sorted(candidates.get(name) or [], key=lambda d: (-stage_rank(d, name), d.order))
        if decls:
            winner = decls[0]
            return collections.OrderedDict([
                ("declared", 1), ("origin", winner.origin_class), ("origin_app", winner.app), ("origin_stanza", winner.origin_stanza),
                ("origin_decl_key", winner.key), ("origin_candidates", [d.key for d in decls]),
                ("origin_conflict", 1 if len(set(d.app for d in decls)) > 1 else 0)])
        values = collections.OrderedDict([("declared", 0), ("origin_app", ""), ("origin_stanza", ""), ("origin_decl_key", ""),
                                          ("origin_candidates", []), ("origin_conflict", 0)])
        if name in probed:
            indexed = name in confirmed
        elif unprobed is None or name in unprobed:
            indexed = bool(stored) and stored.get("origin") == "indexed"
        else:
            indexed = False
        if indexed:
            values["origin"] = "indexed"
        elif auto:
            values["origin"] = auto
        else:
            values["origin"] = "unknown"
        return values

    def stage_field(self, ctx, identity, staged, stored, values):
        # An empty stored side is not a change: a rebuilt row carries origin from its summary row but no declaration key.
        stored_decl = stored.get("origin_decl_key") if stored else ""
        if stored and stored.get("origin") and (stored.get("origin") != values["origin"] or (stored_decl and stored_decl != values["origin_decl_key"])):
            values["origin_changed_run"] = ctx.run_id
        if staged is None and not self.differs(stored, values):
            return
        doc = restage_doc(identity, **values)
        ctx.stage_kv("matalog_fields", doc)
        self.origins[doc["_key"]] = (values["origin"], values["origin_app"])

    def differs(self, stored, values):
        if not stored:
            return True
        for column in S5_FIELD_COLUMNS:
            new = values.get(column)
            old = stored.get(column)
            if column == "origin_candidates":
                if _values(old) != list(new or []):
                    return True
            elif column in ("declared", "origin_conflict"):
                if _int(old) != _int(new):
                    return True
            elif (old or "") != (new or ""):
                return True
        return "origin_changed_run" in values

    def stage_declarations(self, ctx, declarations, applies, versions, source_keys, config):
        processed = set(source_keys)
        stored = self.stored_declarations
        staged = collections.OrderedDict()
        for decl in declarations:
            keep = [k for k in _values((stored.get(decl.key) or {}).get("applies_to_source_keys")) if k not in processed]
            doc = rows_mod.declarations_doc(
                decl.app, decl.conf_file, decl.stanza, decl.attribute, app_version=versions.get(decl.app, ""), owner=decl.owner,
                sharing=decl.sharing, stanza_kind=decl.kind, src_sourcetype=decl.sourcetype, origin_class=decl.origin_class,
                raw_value=decl.raw_value, fields_declared=list(decl.fields), parse_status=decl.parse_status,
                applies_to_source_keys=applies[decl.key] + keep, first_seen_run=ctx.run_id, last_seen_run=ctx.run_id)
            staged[decl.key] = ctx.stage_kv("matalog_declarations", doc)
        ctx.state["declarations"] = staged
        unseen = [d for key, d in stored.items() if key not in staged]
        if not unseen:
            return
        # A run counts as an S5 read only when it did one: not a rebuild, no S5 failure, and not a crash replay (which restores no declarations).
        runs = [r.get("run_id") for r in ctx.client.kv_query("matalog_runs", query={"committed": 1, "run_id": {"$lt": ctx.run_id}},
                                                            fields=["run_id", "run_mode", "errors"])
                if r.get("run_id") and r.get("run_mode") not in rows_mod.REBUILD_MODES and not config_read_failed(r.get("errors"))
                and not replayed(r.get("errors"))]
        limit = ctx.settings.retention.object_stale_runs
        for doc in unseen:
            if doc.get("conf_file") == "datamodels" and not config.get("datamodels_ok"):
                continue
            last = str(doc.get("last_seen_run") or "")
            missed = 1 + sum(1 for r in runs if str(r) > last)
            if missed >= limit:
                ctx.delete_kv("matalog_declarations", doc["_key"])

    def amend_unwritten(self, ctx):
        """Set config_apps and origin on summary rows staged earlier this run and not yet written."""
        limit = ctx.settings.profile.max_row_bytes
        late = 0
        pending = set(id(r) for r in ctx.unwritten)
        for row in ctx.summary.get("source", []):
            apps = self.config_apps.get(row.get("source_key"))
            if apps is None:
                continue
            if id(row) in pending:
                row["config_apps"] = list(apps)
            else:
                late += 1
        for row in ctx.summary.get("field", []):
            if row.get("shape") != "full" or row.get("field_key") not in self.origins:
                continue
            if id(row) not in pending:
                late += 1
                continue
            origin, origin_app = self.origins[row["field_key"]]
            before = (row.get("origin"), row.get("origin_app"))
            row["origin"], row["origin_app"] = origin, origin_app or ""
            if rows_mod.row_bytes(row) > limit:
                row["origin"], row["origin_app"] = before
        if late:
            ctx.log.info("S5: %d summary rows were written before config was read and keep their staged origin and config_apps", late)


def model_stanza(entry, model):
    """The matalog_declarations stanza of a data model: the endpoint entry name, else the model name."""
    return entry.get("name") or model.get("modelName") or ""


def calculation_attribute(obj, calc):
    """(attribute, output fields, raw value) of a calculation the object declares itself; None for inherited or unnamed ones.

    The endpoint lists inherited calculations on every descendant with owner
    set to the declaring object's lineage, so a calculation is the object's own
    when owner is its objectName or its lineage.
    """
    calc_id = calc.get("calculationID") or ""
    object_name = obj.get("objectName") or ""
    if not calc_id or calc.get("owner", object_name) not in (object_name, obj.get("lineage") or object_name):
        return None
    fields = _dedupe([f.get("fieldName") for f in calc.get("outputFields") or [] if f.get("fieldName")])
    raw = calc.get("expression") or json.dumps({k: calc.get(k) for k in ("calculationType", "lookupName", "inputField") if calc.get(k)})
    calc_id = stable_calculation_id(calc_id, calc.get("calculationType"), object_name, fields, raw)
    return "%s:%s:%s" % (calc.get("calculationType") or "calculation", object_name, calc_id), fields, raw


def stable_calculation_id(calc_id, calc_type, object_name, fields, raw):
    """calculationID, or a content hash when it is UUID-shaped.

    The datamodel endpoint returns a new UUID calculationID on every read of a
    model that stores none, so such an id cannot be part of a content key.
    """
    if not UUID_SHAPE.match(str(calc_id)):
        return calc_id
    return "c" + keys.k(calc_type or "", object_name or "", "\x1f".join(fields), raw)[:16]


def restage_doc(identity, **values):
    """A partial matalog_fields doc for an existing row: identity plus values, without the defaults other steps own."""
    doc = rows_mod.fields_doc(identity["src_index"], identity["src_sourcetype"], identity["stratum_field"], identity["stratum_value"],
                              identity["field_name"], **values)
    for column in FOREIGN_DEFAULT_COLUMNS:
        if column not in values:
            doc.pop(column, None)
    return doc


def config_read_failed(errors, step=STEP):
    """True when a run record's errors show the step raised StepFailed, so that run did not do its read."""
    if isinstance(errors, str):
        try:
            errors = json.loads(errors)
        except ValueError:
            return False
    for entry in errors or []:
        if isinstance(entry, dict) and entry.get("step") == step and str(entry.get("message", "")).startswith("StepFailed"):
            return True
    return False


def replayed(errors):
    """True when a run record's errors carry the crash replay line, so its KV writes came from the replay, not its own steps."""
    if isinstance(errors, str):
        try:
            errors = json.loads(errors)
        except ValueError:
            return False
    for entry in errors or []:
        if isinstance(entry, dict) and entry.get("step") == "S1" and entry.get("subject") == "replay" \
                and str(entry.get("message", "")).startswith("replayed"):
            return True
    return False


def declaring_class(attr):
    """The declaration class of a props attribute name, or None when it declares nothing."""
    for prefix, cls in PREFIX_CLASSES:
        if attr.startswith(prefix) and len(attr) > len(prefix):
            return cls
    return EXACT_CLASSES.get(attr)


def parse_props_attribute(attr, value, content, lookup):
    """(class, origin_class, fields, parse_status) for one props attribute, or None when it declares nothing.

    TRANSFORMS that write no index-time field (routing, rewriting _raw or
    metadata) declare nothing.
    """
    cls = declaring_class(attr)
    if cls is None or not value.strip():
        return None
    if cls == "EXTRACT":
        regex = value
        match = EXTRACT_IN_FIELD.search(value)
        if match:
            regex = value[:match.start()]
        names, complete = regex_fields(regex, lookup)
        return cls, "regex_extract", names, status_of(names, complete)
    if cls == "REPORT":
        names, complete = [], True
        for name in split_list(value):
            content_t = lookup(name)
            got, ok = transform_fields(content_t, lookup, name)
            names.extend(got)
            complete = complete and ok
        names = _dedupe(names)
        return cls, "regex_report", names, status_of(names, complete)
    if cls == "FIELDALIAS":
        names, complete = fieldalias_fields(value)
        return cls, "alias", names, status_of(names, complete)
    if cls == "EVAL":
        target = attr[len("EVAL-"):]
        return cls, "eval", [target], "parsed"
    if cls == "LOOKUP":
        tokens = tokenize(value)
        names, complete = lookup_fields(value, lookup(tokens[0]) if tokens else None)
        return cls, "lookup", names, status_of(names, complete)
    if cls == "TRANSFORMS":
        names, complete, meta = [], True, False
        for name in split_list(value):
            content_t = lookup(name)
            if content_t is None:
                complete = False
                continue
            if not is_index_time_meta(content_t):
                continue
            meta = True
            got, ok = format_fields(content_t.get("FORMAT") or "")
            names.extend(got)
            complete = complete and ok
        if not meta:
            return None
        names = _dedupe(names)
        return cls, "indexed", names, status_of(names, complete)
    if cls == "KV_MODE":
        origin = kv_mode_origin(value)
        return cls, origin, [], "parsed" if value.strip().lower() == "none" else "opaque"
    if cls == "INDEXED_EXTRACTIONS":
        names = _dedupe(split_list(content.get("FIELD_NAMES") or ""))
        return cls, "indexed", names, "parsed" if names else "opaque"
    if cls == "rename":
        return cls, None, [], "parsed"
    return None


def walklex_spl(index):
    return "| walklex index=%s type=field | eval field=ltrim(field) | stats count by field" % keys._spl_quote(index)


def probe_spl(index, names):
    """One tstats job: dc() of each candidate name and the source and host values, by sourcetype."""
    aggs = "".join('dc("%s") as "%s%s" ' % (n, PROBE_PREFIX, n) for n in names)
    return ("| tstats %svalues(source) as matalog_source values(host) as matalog_host where index=%s by sourcetype"
            " | eval matalog_source=mvindex(matalog_source, 0, %d), matalog_host=mvindex(matalog_host, 0, %d)"
            % (aggs, keys._spl_quote(index), PROBE_MAX_VALUES - 1, PROBE_MAX_VALUES - 1))


def _positive(value):
    try:
        return float(value or 0) > 0
    except (TypeError, ValueError):
        return False


def _values(value):
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _int(value):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0
