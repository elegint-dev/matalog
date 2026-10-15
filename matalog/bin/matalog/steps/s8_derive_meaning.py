"""S8 derive_meaning.

Class membership. Every data model S5 read (ctx.state["config"]["datamodels"])
is a set of datasets; a dataset's constraint is the AND of its own
constraint searches and its ancestors'. The constraint is parsed into terms
and evaluated per enumerated source with three values. index, sourcetype,
source and host terms resolve against the source's identity and the S5
probe facts (ctx.state["index_facts"]: the source and host values seen per
sourcetype in the trailing day); eventtype and tag terms resolve through
the eventtypes and tags config S5 read, recursively; earliest and latest
are time bounds and always hold. Every other term (a test on another
field, a keyword, a comparison, a subsearch, a macro, a base search) is
unresolved, and so is a source term for a source whose probe facts are
missing or capped this run. A source is in the class when the whole
constraint is true; OR binds tighter than the implicit AND, as in the
search command. A dataset with a source left unresolved by a term is
counted in cim_datasets_unresolved and named, with its terms, in one error
per model; nothing is written for that source and dataset.

Mapping. Per dataset field and source in the class, the source-level
matalog_fields row of that name decides: a declared alias, eval or lookup
field maps through its declaration (cim_via its origin, via_decl_key its
origin_decl_key); a present field of another origin maps as same_name; a
calculation in the dataset's lineage that outputs the name maps as
datamodel_eval through the S5 datamodel declaration; else the row is
mapped=0. coverage is the row's cur_prof_coverage, else cur_disc_coverage,
empty when the field is not present. cim_description and
cim_expected_values come from the field's comment in the model definition
(a description string and an expected_values list in a comment object, or
a plain string as the description) and stay empty otherwise. Dataset
fields are the model's field list without objectCount and childCount
entries, plus the outputs of the lineage's calculations.

Outputs: matalog_cim_coverage rows with derived_run this run; deletion of
stored rows not confirmed for retention.cim_stale_runs S8 runs (runs where
S8 failed, and rebuild runs, do not count); cim_fields and cim_via on the
source-level field rows, cleared when the field no longer maps;
ctx.counts cim_datasets, cim_datasets_unresolved and cim_mapped. Issues no
search. Raises StepFailed, leaving every stored row untouched, when S5 did
not read the datamodel endpoint this run.
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
from ..runner import Step, StepFailed
from . import s5_read_config as s5

STEP = "S8"
COVERAGE = "matalog_cim_coverage"
FIELDS = "matalog_fields"
SOURCES = "matalog_sources"
RUNS = "matalog_runs"
VIA_DECLARED = ("alias", "eval", "lookup")
COUNT_TYPES = ("objectCount", "childCount")
# Root parents whose membership is a search or a transaction, not a constraint.
UNRESOLVED_ROOTS = ("BaseSearch", "BaseTransaction")
TIME_TERMS = ("earliest", "latest", "_index_earliest", "_index_latest")
MAX_DEPTH = 10
FIELD_COLUMNS = ("_key", "field_key", "source_key", "src_index", "src_sourcetype", "stratum_value", "field_name", "level", "presence",
                 "declared", "origin", "origin_decl_key", "cur_prof_coverage", "cur_disc_coverage", "cim_fields", "cim_via")
TOKEN = re.compile(r'\s*(?:(\()|(\))|"((?:[^"\\]|\\.)*)"|([^\s()"]+))')
QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
# Longest operator first, so != and >= are not read as = and >.
OPERATORS = ("!=", "::", ">=", "<=", "=", ">", "<")
TAG_PREFIX = "tag::"


def _empty(value):
    return value is None or value == "" or value == []


def _int(value, default=None):
    if _empty(value):
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return 1 if value.strip().lower() == "true" else 0
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _float(value):
    if _empty(value):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _list(value):
    if _empty(value):
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


# Constraint parsing.

def glob_regex(pattern):
    """Case-insensitive matcher for a search term value: * matches any run, a backslash escapes the next character."""
    out = []
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\" and i + 1 < n:
            out.append(re.escape(pattern[i + 1]))
            i += 2
        elif ch == "*":
            out.append(".*")
            i += 1
        else:
            out.append(re.escape(ch))
            i += 1
    return re.compile("^(?:%s)$" % "".join(out), re.IGNORECASE | re.DOTALL)


def split_term(word):
    """(field, operator, value) of a search term; a word without an operator is a keyword with empty field and operator."""
    if word.startswith(TAG_PREFIX):
        rest = word[len(TAG_PREFIX):]
        if "=" in rest:
            field, value = rest.split("=", 1)
            return TAG_PREFIX + field, "=", value
        return "", "", word
    best = None
    for op in OPERATORS:
        index = word.find(op)
        if index > 0 and (best is None or index < best[0]):
            best = (index, op)
    if best is None:
        return "", "", word
    index, op = best
    return word[:index], op, word[index + len(op):]


def tokenize(text):
    """Tokens of a constraint search: ("(",), (")",), ("AND",), ("OR",), ("NOT",) and ("term", field, op, value, text).

    Raises ValueError for SPL a constraint evaluator cannot read: pipes,
    subsearches and macros.
    """
    if any(c in text for c in "|[]`"):
        raise ValueError("pipe, subsearch or macro in constraint")
    out = []
    pos, n = 0, len(text)
    while pos < n:
        match = TOKEN.match(text, pos)
        if not match or match.end() == pos:
            break
        pos = match.end()
        if match.group(1):
            out.append(("(",))
        elif match.group(2):
            out.append((")",))
        elif match.group(3) is not None:
            out.append(("term", "", "", match.group(3), '"%s"' % match.group(3)))
        elif match.group(4) is not None:
            word = match.group(4)
            if word.upper() in ("AND", "OR", "NOT"):
                out.append((word.upper(),))
                continue
            field, op, value = split_term(word)
            raw = word
            if op and value == "" and pos < n and text[pos] == '"':
                quoted = QUOTED.match(text, pos)
                if quoted:
                    value = quoted.group(1)
                    raw = word + quoted.group(0)
                    pos = quoted.end()
            out.append(("term", field, op, value, raw))
    return out


class Parser(object):
    """Recursive descent over tokenize() output: parentheses, then NOT, then OR, then the implicit AND."""

    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def parse(self):
        if not self.tokens:
            raise ValueError("empty constraint")
        node = self.and_expr()
        if self.pos != len(self.tokens):
            raise ValueError("unbalanced parenthesis")
        return node

    def and_expr(self):
        parts = [self.or_expr()]
        while self.peek() is not None and self.peek()[0] != ")":
            if self.peek()[0] == "AND":
                self.pos += 1
            parts.append(self.or_expr())
        return ("and", parts) if len(parts) > 1 else parts[0]

    def or_expr(self):
        parts = [self.not_expr()]
        while self.peek() is not None and self.peek()[0] == "OR":
            self.pos += 1
            parts.append(self.not_expr())
        return ("or", parts) if len(parts) > 1 else parts[0]

    def not_expr(self):
        if self.peek() is not None and self.peek()[0] == "NOT":
            self.pos += 1
            return ("not", self.not_expr())
        return self.atom()

    def atom(self):
        token = self.peek()
        if token is None:
            raise ValueError("constraint ends inside an expression")
        if token[0] == "(":
            self.pos += 1
            node = self.and_expr()
            if self.peek() is None or self.peek()[0] != ")":
                raise ValueError("missing closing parenthesis")
            self.pos += 1
            return node
        if token[0] == "term":
            self.pos += 1
            return ("term", token)
        raise ValueError("unexpected %s" % token[0])


def parse_constraint(text):
    return Parser(tokenize(text)).parse()


# Evaluation.

class Resolver(object):
    """Evaluates constraint trees per source; holds the eventtype and tag config of the run.

    evaluate() returns (value, unresolved): value True, False or None, and
    the set of (kind, text) pairs behind a None, kind "term" for a term no
    source-level fact decides and "facts" for a source whose probe facts
    are missing or capped.
    """

    def __init__(self, config):
        self.eventtypes = collections.OrderedDict()
        self.eventtypes_ok = bool(config.get("eventtypes_ok"))
        for entry in config.get("eventtypes") or []:
            content = entry.get("content") or {}
            if s5.truthy(content.get("disabled")) or _empty(entry.get("name")):
                continue
            self.eventtypes.setdefault(str(entry["name"]), str(content.get("search") or ""))
        self.tags = []
        self.tags_ok = bool(config.get("tags_ok"))
        for entry in config.get("tags") or []:
            # conf-tags returns the stanza name URL-quoted (eventtype=cim%3Aauthentication).
            name = url_unquote(str(entry.get("name") or ""))
            if "=" not in name:
                continue
            field, value = name.split("=", 1)
            for tag, state in (entry.get("content") or {}).items():
                if tag.startswith("eai:") or tag == "disabled":
                    continue
                if str(state or "").strip().lower() == "enabled":
                    self.tags.append((tag, field, value))
        self.parsed = {}
        self.globs = {}

    def glob(self, pattern):
        if pattern not in self.globs:
            self.globs[pattern] = glob_regex(pattern)
        return self.globs[pattern]

    def tree(self, text):
        """The parsed tree of a search text, or a ValueError instance when it cannot be parsed."""
        if text not in self.parsed:
            try:
                self.parsed[text] = parse_constraint(text)
            except ValueError as exc:
                self.parsed[text] = exc
        return self.parsed[text]

    def evaluate(self, node, source, depth=0, stack=()):
        kind = node[0]
        if kind == "term":
            value, unresolved = self.term(node[1], source, depth, stack)
            return value, unresolved
        if kind == "not":
            value, unresolved = self.evaluate(node[1], source, depth, stack)
            return (None if value is None else (not value)), unresolved
        results = [self.evaluate(child, source, depth, stack) for child in node[1]]
        if kind == "and":
            if any(v is False for v, _ in results):
                return False, set()
            if any(v is None for v, _ in results):
                return None, set().union(*[u for v, u in results if v is None])
            return True, set()
        if any(v is True for v, _ in results):
            return True, set()
        if any(v is None for v, _ in results):
            return None, set().union(*[u for v, u in results if v is None])
        return False, set()

    def term(self, token, source, depth, stack):
        _, field, op, value, text = token
        if op == "":
            return (True, set()) if value == "*" else (None, {("term", text)})
        if op in (">", "<", ">=", "<="):
            return None, {("term", text)}
        # Field names are case-sensitive: eventType is an ordinary field, eventtype the special one.
        name = field
        negate = op == "!="
        facts = False
        if name == "index":
            result = self.glob(value).match(source["src_index"]) is not None
        elif name == "sourcetype":
            result = self.glob(value).match(source["search_sourcetype"]) is not None
        elif name in ("source", "host"):
            result = self.values_match(source[name + "s"], source[name + "s_capped"], value)
            facts = result is None
        elif name in TIME_TERMS:
            result = True
        elif name == "eventtype":
            result = self.eventtype(value, source, depth, stack)
        elif name == "tag" or name.startswith(TAG_PREFIX):
            result = self.tag(name, value, source, depth, stack)
        else:
            result = None
        if result is None:
            return None, {("facts" if facts else "term", text)}
        return (not result) if negate else result, set()

    def values_match(self, values, capped, pattern):
        if values is None:
            return None
        matcher = self.glob(pattern)
        if any(matcher.match(v) for v in values):
            return True
        return None if capped else False

    def eventtype(self, pattern, source, depth, stack):
        if not self.eventtypes_ok or depth >= MAX_DEPTH:
            return None
        matcher = self.glob(pattern)
        values = []
        for name, search in self.eventtypes.items():
            if not matcher.match(name):
                continue
            if name in stack:
                return None
            tree = self.tree(search)
            if isinstance(tree, ValueError):
                return None
            values.append(self.evaluate(tree, source, depth + 1, stack + (name,))[0])
        return _any3(values)

    def tag(self, name, pattern, source, depth, stack):
        if not self.tags_ok or depth >= MAX_DEPTH:
            return None
        only = name[len(TAG_PREFIX):] if name.startswith(TAG_PREFIX) else None
        matcher = self.glob(pattern)
        values = []
        for tag, field, value in self.tags:
            if not matcher.match(tag) or (only is not None and field != only):
                continue
            token = ("term", field, "=", value, "%s=%s" % (field, value))
            values.append(self.term(token, source, depth + 1, stack)[0])
        return _any3(values)


def _any3(values):
    if any(v is True for v in values):
        return True
    if any(v is None for v in values):
        return None
    return False


# Data model reading.

class Dataset(object):
    """One dataset of one model: its combined constraint and its fields."""

    def __init__(self, model_name, object_name):
        self.model = model_name
        self.object_name = object_name
        self.name = "%s.%s" % (model_name, object_name)
        self.constraints = []
        self.unresolved_root = ""
        self.fields = collections.OrderedDict()
        self.tree = None
        self.parse_error = ""


def comment_of(item):
    """(description, expected values) from a field's comment object; a plain string is the description."""
    comment = item.get("comment")
    if isinstance(comment, str) and comment.strip().startswith("{"):
        try:
            comment = json.loads(comment)
        except ValueError:
            pass
    if isinstance(comment, dict):
        description = comment.get("description")
        expected = comment.get("expected_values")
        return ("" if _empty(description) else str(description)), ([str(v) for v in expected if not _empty(v)] if isinstance(expected, list) else [])
    if isinstance(comment, str):
        return comment.strip(), []
    return "", []


def read_datasets(ctx, entries, declarations):
    """Datasets of every readable model in endpoint order, and the names of models whose definition did not parse."""
    datasets = []
    failed = []
    for entry in entries:
        acl = entry.get("acl") or {}
        content = entry.get("content") or {}
        try:
            model = json.loads(content.get("description") or "{}")
        except (TypeError, ValueError):
            failed.append(str(entry.get("name") or ""))
            ctx.error(STEP, entry.get("name") or "", "model definition unreadable")
            continue
        model_name = str(model.get("modelName") or entry.get("name") or "")
        if not model_name or not isinstance(model.get("objects"), list):
            failed.append(str(entry.get("name") or model_name))
            ctx.error(STEP, entry.get("name") or model_name, "model definition has no objects")
            continue
        stanza = s5.model_stanza(entry, model)
        objects = collections.OrderedDict()
        for obj in model["objects"]:
            if isinstance(obj, dict) and obj.get("objectName"):
                objects.setdefault(str(obj["objectName"]), obj)
        for object_name, obj in objects.items():
            datasets.append(build_dataset(model_name, object_name, objects, acl.get("app") or "", stanza, declarations))
    return datasets, failed


def lineage_chain(obj, objects):
    """The objects from the root ancestor down to obj, and the root's parent name."""
    chain = [obj]
    seen = {obj.get("objectName")}
    parent = obj.get("parentName")
    while parent in objects and parent not in seen:
        chain.append(objects[parent])
        seen.add(parent)
        parent = objects[parent].get("parentName")
    chain.reverse()
    return chain, str(parent or "")


def build_dataset(model_name, object_name, objects, app, stanza, declarations):
    dataset = Dataset(model_name, object_name)
    chain, root_parent = lineage_chain(objects[object_name], objects)
    if root_parent in UNRESOLVED_ROOTS or any(not _empty(o.get("baseSearch")) for o in chain):
        dataset.unresolved_root = "baseSearch" if root_parent == "BaseSearch" or any(o.get("baseSearch") for o in chain) else "transaction"
    seen = set()
    calc_outputs = collections.OrderedDict()
    for obj in chain:
        own = obj.get("objectName") or ""
        for constraint in obj.get("constraints") or []:
            if not isinstance(constraint, dict):
                continue
            search = str(constraint.get("search") or "").strip()
            owner = str(constraint.get("owner") or own)
            if not search or (owner, search) in seen:
                continue
            seen.add((owner, search))
            dataset.constraints.append(search)
        for calc in obj.get("calculations") or []:
            parsed = s5.calculation_attribute(obj, calc)
            if parsed is None:
                continue
            attribute = parsed[0]
            decl_key = keys.k(app, "datamodels", stanza, attribute)
            for output in calc.get("outputFields") or []:
                name = output.get("fieldName")
                if name and name not in calc_outputs:
                    calc_outputs[name] = (decl_key if decl_key in declarations else "", comment_of(output))
    for obj in chain:
        for field in obj.get("fields") or []:
            name = field.get("fieldName")
            if not name or field.get("type") in COUNT_TYPES:
                continue
            description, expected = comment_of(field)
            dataset.fields[name] = collections.OrderedDict([("description", description), ("expected_values", expected), ("calc_decl_key", None)])
    for name, (decl_key, (description, expected)) in calc_outputs.items():
        entry = dataset.fields.get(name)
        if entry is None:
            entry = dataset.fields[name] = collections.OrderedDict([("description", description), ("expected_values", expected), ("calc_decl_key", None)])
        entry["calc_decl_key"] = decl_key
    if dataset.constraints and not dataset.unresolved_root:
        try:
            dataset.tree = parse_constraint(" ".join("(%s)" % c for c in dataset.constraints))
        except ValueError as exc:
            dataset.parse_error = str(exc)
    return dataset


# Sources and field rows.

def source_facts(ctx):
    """Every enumerated source that is not gone, with the probe facts a constraint evaluator reads."""
    facts = ctx.state.get("index_facts") or {}
    search_sourcetypes = {}
    for doc in ctx.client.kv_query(SOURCES, fields=["_key", "search_sourcetype"]):
        if doc.get("_key") and not _empty(doc.get("search_sourcetype")):
            search_sourcetypes[doc["_key"]] = str(doc["search_sourcetype"])
    for key, doc in ctx.kv[SOURCES].items():
        if not _empty(doc.get("search_sourcetype")):
            search_sourcetypes[key] = str(doc["search_sourcetype"])
    out = []
    for source in s5.ReadConfig().sources_to_resolve(ctx):
        key = source["source_key"]
        entry = {"source_key": key, "src_index": source["src_index"], "src_sourcetype": source["src_sourcetype"],
                 "search_sourcetype": search_sourcetypes.get(key) or source["src_sourcetype"]}
        index_fact = facts.get(source["src_index"]) or {}
        for name in ("source", "host"):
            values = index_fact.get(name + "_values", {}).get(source["src_sourcetype"]) if index_fact.get("searched") else None
            entry[name + "s"] = list(values) if values is not None else None
            entry[name + "s_capped"] = values is not None and len(values) >= s5.PROBE_MAX_VALUES
        out.append(entry)
    return out


def read_field_rows(ctx):
    """Source-level matalog_fields docs after this run's staging, by key; rows deleted this run are left out."""
    out = collections.OrderedDict()
    for doc in ctx.client.kv_query(FIELDS, query={"level": "source"}, fields=list(FIELD_COLUMNS)):
        if doc.get("_key"):
            out[doc["_key"]] = collections.OrderedDict(doc)
    for key, doc in ctx.kv[FIELDS].items():
        stored = out.get(key)
        if stored is None:
            if doc.get("stratum_value") != keys.ALL and doc.get("level") != "source":
                continue
            stored = out[key] = collections.OrderedDict([("_key", key)])
        for column, value in doc.items():
            if value is not None:
                stored[column] = value
    for key in ctx.kv_deletes[FIELDS]:
        out.pop(key, None)
    return out


def coverage_of(doc):
    value = _float(doc.get("cur_prof_coverage"))
    return value if value is not None else _float(doc.get("cur_disc_coverage"))


def mapping_of(doc, field_entry):
    """The mapping columns of one dataset field on one source; mapped=0 when nothing supplies the name."""
    if doc is not None:
        present = doc.get("presence") == "present"
        origin = doc.get("origin") or ""
        if _int(doc.get("declared"), 0) == 1 and origin in VIA_DECLARED:
            return collections.OrderedDict([("mapped", 1), ("field_name", doc.get("field_name") or ""), ("field_key", doc["_key"]),
                                            ("cim_via", origin), ("via_decl_key", doc.get("origin_decl_key") or ""),
                                            ("coverage", coverage_of(doc) if present else None)])
        if present:
            return collections.OrderedDict([("mapped", 1), ("field_name", doc.get("field_name") or ""), ("field_key", doc["_key"]),
                                            ("cim_via", "same_name"), ("via_decl_key", ""), ("coverage", coverage_of(doc))])
    if field_entry.get("calc_decl_key") is not None:
        return collections.OrderedDict([("mapped", 1), ("field_name", field_entry["name"]), ("field_key", doc["_key"] if doc is not None else ""),
                                        ("cim_via", "datamodel_eval"), ("via_decl_key", field_entry["calc_decl_key"]), ("coverage", None)])
    return collections.OrderedDict([("mapped", 0), ("field_name", ""), ("field_key", ""), ("cim_via", ""), ("via_decl_key", ""), ("coverage", None)])


class DeriveMeaning(Step):
    """Data model class membership and field mapping; see the module docstring.

    ctx.state["meaning"]: {"models", "datasets", "datasets_unresolved", "sources", "rows", "mapped", "field_rows_staged", "stale_deleted"}.
    """

    name = STEP
    label = "derive_meaning"

    def run(self, ctx):
        config = ctx.state.get("config")
        if config is None or not config.get("datamodels_ok"):
            raise StepFailed("datamodel definitions were not read this run")
        declarations = ctx.state.get("declarations") or {}
        datasets, failed_models = read_datasets(ctx, config.get("datamodels") or [], declarations)
        sources = source_facts(ctx)
        field_rows = read_field_rows(ctx)
        by_name = {}
        for doc in field_rows.values():
            if doc.get("source_key") and doc.get("field_name"):
                by_name[(doc["source_key"], doc["field_name"])] = doc
        resolver = Resolver(config)
        state = collections.OrderedDict([
            ("models", len(set(d.model for d in datasets))), ("datasets", len(datasets)), ("datasets_unresolved", 0),
            ("sources", len(sources)), ("rows", 0), ("mapped", 0), ("field_rows_staged", 0), ("stale_deleted", 0)])
        ctx.state["meaning"] = state
        unresolved = collections.OrderedDict()
        field_maps = collections.defaultdict(list)
        for dataset in datasets:
            members, terms, without_facts = self.members(dataset, sources, resolver)
            if terms or without_facts:
                unresolved.setdefault(dataset.model, []).append((dataset.object_name, terms, without_facts))
                if terms:
                    state["datasets_unresolved"] += 1
            for source in members:
                for name, entry in dataset.fields.items():
                    entry = dict(entry, name=name)
                    values = mapping_of(by_name.get((source["source_key"], name)), entry)
                    values.update(cim_description=entry["description"], cim_expected_values=list(entry["expected_values"]), derived_run=ctx.run_id)
                    doc = rows_mod.cim_coverage_doc(dataset.name, name, source["src_index"], source["src_sourcetype"], **values)
                    ctx.stage_kv(COVERAGE, doc)
                    state["rows"] += 1
                    if values["mapped"]:
                        state["mapped"] += 1
                        if values["field_key"]:
                            field_maps[values["field_key"]].append(("%s.%s" % (dataset.name, name), values["cim_via"]))
        for model, items in unresolved.items():
            ctx.error(STEP, model, unresolved_message(items))
        state["field_rows_staged"] = self.stage_field_columns(ctx, field_rows, field_maps)
        state["stale_deleted"] = self.delete_stale(ctx, failed_models)
        ctx.counts["cim_datasets"] = len(datasets)
        ctx.counts["cim_datasets_unresolved"] = state["datasets_unresolved"]
        ctx.counts["cim_mapped"] = state["mapped"]

    def members(self, dataset, sources, resolver):
        """(sources in the class, unresolved term texts, count of sources without probe facts)."""
        members = []
        terms = set()
        without_facts = 0
        if dataset.unresolved_root:
            return members, {dataset.unresolved_root}, 0
        if dataset.tree is None:
            if dataset.parse_error:
                return members, {dataset.parse_error}, 0
            return list(sources), terms, 0
        for source in sources:
            value, reasons = resolver.evaluate(dataset.tree, source)
            if value is True:
                members.append(source)
            elif value is None:
                texts = set(text for kind, text in reasons if kind == "term")
                if texts:
                    terms.update(texts)
                else:
                    without_facts += 1
        return members, terms, without_facts

    def stage_field_columns(self, ctx, field_rows, field_maps):
        staged = 0
        for key, doc in field_rows.items():
            entries = field_maps.get(key, [])
            cim_fields = [name for name, _ in entries]
            cim_via = [via for _, via in entries]
            if _list(doc.get("cim_fields")) == cim_fields and _list(doc.get("cim_via")) == cim_via:
                continue
            ctx.stage_kv(FIELDS, rows_mod.kv_doc(FIELDS, key, cim_fields=cim_fields, cim_via=cim_via))
            staged += 1
        return staged

    def delete_stale(self, ctx, failed_models):
        """Delete stored coverage rows not confirmed for retention.cim_stale_runs S8 runs; rows of a model that failed to parse this run are kept."""
        stored = ctx.client.kv_query(COVERAGE, fields=["_key", "cim_dataset", "derived_run"])
        unseen = [d for d in stored if d.get("_key") and d["_key"] not in ctx.kv[COVERAGE]]
        if not unseen:
            return 0
        # A run counts only when its record carries cim_datasets: a rebuild, a config read failure or a crash replay wrote no coverage.
        runs = [r.get("run_id") for r in ctx.client.kv_query(RUNS, query={"committed": 1, "run_id": {"$lt": ctx.run_id}},
                                                            fields=["run_id", "run_mode", "errors", "cim_datasets"])
                if r.get("run_id") and r.get("run_mode") != "rebuild" and r.get("cim_datasets") is not None
                and not s5.config_read_failed(r.get("errors"), step=STEP)]
        limit = int(ctx.settings.retention.cim_stale_runs)
        failed = set(failed_models)
        deleted = 0
        for doc in unseen:
            if str(doc.get("cim_dataset") or "").split(".", 1)[0] in failed:
                continue
            last = str(doc.get("derived_run") or "")
            missed = 1 + sum(1 for r in runs if str(r) > last)
            if missed >= limit:
                ctx.delete_kv(COVERAGE, doc["_key"])
                deleted += 1
        return deleted


def unresolved_message(items):
    """One line per model: each unresolved dataset with its terms, and the sources without probe facts."""
    parts = []
    without_facts = 0
    for object_name, terms, missing in items:
        if terms:
            parts.append("%s [%s]" % (object_name, ", ".join(sorted(terms))))
        without_facts = max(without_facts, missing)
    message = "unresolved datasets: %s" % ("; ".join(parts) if parts else "none")
    if without_facts:
        message += "; sources without source or host values this run: %d" % without_facts
    return message
