"""SPL scanning for the usage graph: constraint alternatives, macro expansion, field references with their scope.

constraint_groups() reads the index and sourcetype alternatives of a search
text (S6 matches them against sources for last_human_search_*). parse_search()
reads the field references of a search text with the scope each resolves in
(exact_source, sourcetype_pattern, index_only, datamodel, unscoped) and
records every
construct it did not resolve as a parse gap, so an object is never claimed
complete. dashboard_queries() lifts the searches out of a view definition.
"""
import collections
import json
import re
import xml.etree.ElementTree as ET

# Folded into spl_hash, so a parser change reparses every object once.
PARSER_VERSION = "4"
# Alternatives one search text may expand to; past this its constraints are pooled into one.
MAX_GROUPS = 64
MAX_MACRO_DEPTH = 8
# Macro depth for _audit search texts.
AUDIT_MACRO_DEPTH = 4
# Eventtype and tag nesting followed when a scope term resolves through one.
MAX_KNOWLEDGE_DEPTH = 8
MAX_SUBSEARCH_DEPTH = 6
MAX_CHAIN_DEPTH = 12

TERM_RE = re.compile(r"(?<![\w.:{}!])(index|sourcetype|source|host)\s*(!=|==|=|\s+in\s*\()", re.IGNORECASE)
# eventtype=, tag= and tag::<field>= terms, resolved through the run's eventtypes and tags.
KNOWLEDGE_TERM_RE = re.compile(r"(?<![\w.:{}!])(eventtype|tag(?:::[\w.]+)?)\s*(!=|==|=|\s+in\s*\()", re.IGNORECASE)
# Group dimensions: index, sourcetype, source and host patterns, and source keys fixed by a data model dataset.
INDEX, SOURCETYPE, SOURCE, HOST, KEYS = range(5)
DIMENSIONS = {"index": INDEX, "sourcetype": SOURCETYPE, "source": SOURCE, "host": HOST}
# A key no source carries: a dataset whose class is unknown or empty touches nothing.
NO_SOURCE = "\x00no-source"
FIELD_TERM_RE = re.compile(r"(?<![\w.:{}!$])([A-Za-z_][\w.{}:-]*)\s*(!=|>=|<=|==|=|>|<|::|\s+in\s*\()", re.IGNORECASE)
OPERATOR_RE = re.compile(r"(OR|AND|NOT)(?=[\s(]|$)")
VALUE_END = set(" \t\r\n|()[],;")
# Commands whose index= or sourcetype= arguments name a destination or a field, not data read.
NON_READING_COMMANDS = frozenset([
    "collect", "mcollect", "tscollect", "eval", "rename", "fields", "table", "fieldformat", "fillnull",
    "rex", "lookup", "inputlookup", "outputlookup", "outputcsv", "sendemail"])
UNCONSTRAINED = (frozenset(), frozenset(), frozenset(), frozenset(), frozenset())

FILTER, BY, OUTPUT, EVAL_INPUT, LOOKUP_KEY, DATAMODEL_FIELD = "filter", "by", "output", "eval_input", "lookup_key", "datamodel_field"
EXACT, INFERRED = "exact", "inferred"
EXACT_SOURCE, SOURCETYPE_PATTERN, DATAMODEL, UNSCOPED, PARTIAL = "exact_source", "sourcetype_pattern", "datamodel", "unscoped", "partial"
# An alternative constrained on index alone: it names no sourcetype, source or host, so it resolves to no source.
INDEX_ONLY = "index_only"

# Search terms that name scope or time, never a field.
SCOPE_TERMS = frozenset(["index", "sourcetype", "earliest", "latest", "_index_earliest", "_index_latest", "splunk_server",
                         "splunk_server_group", "sid", "savedsearch", "eventtype", "tag", "nodename"])
EVAL_KEYWORDS = frozenset(["and", "or", "not", "xor", "like", "true", "false", "null"])
# Generating commands that read indexed events: the pipeline is scoped by their terms.
EVENT_GENERATORS = frozenset(["search", "metasearch", "walklex"])
# Generating commands whose output is not event data: the pipeline references no catalog field.
NON_DATA_GENERATORS = frozenset([
    "rest", "makeresults", "inputlookup", "inputcsv", "dbinspect", "metadata", "eventcount", "loadjob", "typeahead", "history",
    "gentimes", "mstats", "mcatalog", "mpreview", "msearch", "sendalert", "audit", "dbxquery", "ldapsearch", "script", "run"])
STATS_COMMANDS = frozenset(["stats", "eventstats", "streamstats", "sistats", "sichart", "sitimechart", "chart", "timechart",
                            "geostats", "tstats", "mstats", "contingency", "geom", "addtotals"])
# Commands that reference no field, or whose arguments are not field names.
NO_REF_COMMANDS = frozenset([
    "head", "tail", "reverse", "transpose", "localop", "collect", "outputlookup", "sendemail", "outputcsv", "addinfo", "delete",
    "export", "noop", "addcoltotals", "outputtelemetry", "append", "appendcols", "union", "multisearch", "set", "appendpipe", "join", "inputlookup",
    "inputcsv", "makeresults", "rest", "dbinspect", "metadata", "eventcount", "loadjob", "typeahead", "history", "gentimes",
    "savedsearch", "format", "return", "extract", "kv", "xmlkv", "kvform", "tags", "typer", "typelearner", "fieldsummary",
    "analyzefields", "af", "abstract", "highlight", "audit", "relevancy", "diff", "overlap", "localize", "uniq", "require",
    "sendalert", "outputtext", "cofilter", "findtypes", "iconify", "rtorder", "searchtxn", "sichart", "redistribute", "ctable",
    "counttable", "tscollect", "mcollect", "meventcollect", "datamodel", "from", "pivot", "makejson", "tojson", "fromjson",
    "spl1", "run", "script", "setfields", "nomv", "makecontinuous", "where_not", "anomalies", "cluster", "kmeans", "predict",
    "trendline", "x11", "arules", "associate", "correlate", "anomalousvalue", "anomalydetection", "outlier", "mvcombine",
    "erex", "multikv", "reltime", "strcat", "concurrency", "fillnull", "filldown", "dedup", "sort", "fields", "table", "rename",
    "eval", "where", "search", "regex", "rex", "lookup", "spath", "bin", "bucket", "mvexpand", "makemv", "convert", "transaction",
    "iplocation", "replace", "top", "rare", "xyseries", "untable", "autoregress", "delta", "accum", "foreach", "map", "tstats"])
BRACKET_COMMANDS = frozenset(["append", "appendcols", "union", "multisearch", "set", "join", "search", "appendpipe"])
KNOWN_COMMANDS = NO_REF_COMMANDS | STATS_COMMANDS | BRACKET_COMMANDS | NON_DATA_GENERATORS | EVENT_GENERATORS


# Scanning helpers.

def spl_text(raw):
    """The SPL of an _audit event: the search field without the single quotes _audit wraps it in."""
    text = str(raw or "").strip()
    if len(text) >= 2 and text[0] == "'" and text[-1] == "'":
        text = text[1:-1]
    return text.replace("\\'", "'")


TOKEN_RE = re.compile(r"\$[^\s$]*\$")


def token_end(text, pos):
    """End of a $token$ (a dashboard token, possibly with a |filter) starting at pos, or None."""
    match = TOKEN_RE.match(text, pos)
    return match.end() if match else None


def skip_quoted(text, pos):
    """Position just after the double-quoted string that starts at pos."""
    n = len(text)
    pos += 1
    while pos < n and text[pos] != '"':
        if text[pos] == "\\":
            pos += 1
        pos += 1
    return min(pos + 1, n)


def match_close(text, pos, open_ch, close_ch):
    """Position just after the close_ch that balances the open_ch at pos, or len(text) when unbalanced."""
    depth, n = 0, len(text)
    while pos < n:
        c = text[pos]
        if c == '"':
            pos = skip_quoted(text, pos)
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return pos + 1
        pos += 1
    return n


def inner_text(text, start, end, close_ch):
    """The text between the opener at start and its closer ending at end."""
    if end <= len(text) and end - 1 > start and text[end - 1] == close_ch:
        return text[start + 1:end - 1]
    return text[start + 1:]


def skip_space(text, pos):
    while pos < len(text) and text[pos] in " \t\r\n":
        pos += 1
    return pos


def read_value(text, pos):
    """One value at pos, quoted or bare: (value, end position)."""
    n = len(text)
    while pos < n and text[pos] in " \t":
        pos += 1
    if text.startswith('\\"', pos):
        end = text.find('\\"', pos + 2)
        end = n if end < 0 else end
        return text[pos + 2:end], min(end + 2, n)
    if pos < n and text[pos] == '"':
        out = []
        pos += 1
        while pos < n and text[pos] != '"':
            if text[pos] == "\\" and pos + 1 < n:
                pos += 1
            out.append(text[pos])
            pos += 1
        return "".join(out), pos + 1
    start = pos
    while pos < n and text[pos] not in VALUE_END and text[pos] != '"':
        token = token_end(text, pos) if text[pos] == "$" else None
        pos = token if token else pos + 1
    return text[start:pos], pos


def read_list(text, pos):
    """The values of a ( ... ) list starting after the opening parenthesis, comma or OR separated: (values, end position)."""
    values = []
    n = len(text)
    while pos < n:
        while pos < n and text[pos] in " \t\r\n,":
            pos += 1
        if pos >= n or text[pos] == ")":
            return values, pos + 1
        value, end = read_value(text, pos)
        if end == pos:
            return values, pos + 1
        if value and value != "OR":
            values.append(value)
        pos = end
    return values, pos


def word_end(text, pos):
    """End of a plain word at pos: up to whitespace outside quotes and balanced parentheses."""
    n = len(text)
    while pos < n and text[pos] not in " \t\r\n":
        if text[pos] == '"':
            pos = skip_quoted(text, pos)
        elif text[pos] == "(":
            pos = match_close(text, pos, "(", ")")
        elif text[pos] == ")":
            break
        elif text[pos] == "$" and token_end(text, pos):
            pos = token_end(text, pos)
        else:
            pos += 1
    return pos


def subsearches(text):
    """(text with each top-level [ ... ] blanked to spaces, [(start, end, inner text)])."""
    out, subs = [], []
    pos, n = 0, len(text)
    while pos < n:
        c = text[pos]
        if c == '"':
            end = skip_quoted(text, pos)
            out.append(text[pos:end])
            pos = end
        elif c == "[":
            end = match_close(text, pos, "[", "]")
            subs.append((pos, end, inner_text(text, pos, end, "]")))
            out.append(" " * (end - pos))
            pos = end
        else:
            out.append(c)
            pos += 1
    return "".join(out), subs


def pipes(text):
    """Pipe segments of a search outside quotes and parentheses: [(offset, text)]."""
    segments, start, depth, pos, n = [], 0, 0, 0, len(text)
    while pos < n:
        c = text[pos]
        if c == '"':
            pos = skip_quoted(text, pos)
            continue
        if c == "$" and token_end(text, pos):
            pos = token_end(text, pos)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        elif c == "|" and depth == 0:
            segments.append((start, text[start:pos]))
            start = pos + 1
        pos += 1
    segments.append((start, text[start:]))
    return segments


# Constraint alternatives.

class Trace(object):
    """What a scope computation went through: its gaps, the knowledge objects it resolved and the macros it expanded."""

    def __init__(self):
        self.gaps = []
        self.via = []
        self.macros = []

    def gap(self, text):
        if text not in self.gaps:
            self.gaps.append(text)

    def through(self, text):
        if text not in self.via:
            self.via.append(text)


def _dimension_group(dimension, patterns):
    group = list(UNCONSTRAINED)
    group[dimension] = frozenset(patterns)
    return tuple(group)


def _keys_group(source_keys):
    """A group fixed to the given source keys; an unknown or empty class touches nothing."""
    return _dimension_group(KEYS, source_keys or [NO_SOURCE])


def _term_values(text, match):
    """(operator, values, end position) of a term matched by TERM_RE or KNOWLEDGE_TERM_RE."""
    op = match.group(2).strip().lower()
    pos = match.end()
    if op in ("!=", "=="):
        _, end = read_value(text, pos)
        return op, [], end
    if op == "=":
        start = skip_space(text, pos)
        if start < len(text) and text[start] == "(":
            values, end = read_list(text, start + 1)
        else:
            value, end = read_value(text, pos)
            values = [value]
    else:
        values, end = read_list(text, pos)
    return op, values, end


def _patterns(values):
    """The lowercased patterns of a term's values; None when one of them is a bare * or none is given."""
    patterns = set()
    for value in values:
        value = value.strip().lower()
        if not value:
            continue
        if value.strip("*") == "":
            return None
        patterns.add(value)
    return patterns or None


def _term(text, match):
    """The alternatives one index, sourcetype, source or host term constrains, and the position after it."""
    dimension = DIMENSIONS[match.group(1).lower()]
    op, values, end = _term_values(text, match)
    patterns = _patterns(values) if op not in ("!=", "==") else None
    if patterns is None:
        return [UNCONSTRAINED], end
    return [_dimension_group(dimension, patterns)], end


def _knowledge_term(text, match, knowledge, depth, trace):
    """The alternatives an eventtype=, tag= or tag::<field>= term constrains, resolved through the knowledge objects."""
    name = match.group(1).lower()
    op, values, end = _term_values(text, match)
    patterns = _patterns(values) if op not in ("!=", "==") else None
    if patterns is None:
        return [UNCONSTRAINED], end
    alternatives = []
    for pattern in sorted(patterns):
        if name == "eventtype":
            alternatives.extend(eventtype_groups(pattern, knowledge, depth, trace))
        else:
            field = name[len("tag::"):] if name.startswith("tag::") else None
            alternatives.extend(tag_groups(pattern, field, knowledge, depth, trace))
    return _bounded(alternatives), end


def eventtype_groups(pattern, knowledge, depth, trace):
    """Alternatives of the eventtypes a pattern names, each through its own search; unconstrained, with a gap, when none is known."""
    found = knowledge.eventtypes(pattern) if knowledge is not None and depth < MAX_KNOWLEDGE_DEPTH else None
    if not found:
        trace.gap("eventtype:%s" % pattern)
        return [UNCONSTRAINED]
    out = []
    for name, search in found:
        trace.through("eventtype:%s" % name)
        out.extend(expression_groups(search, knowledge, depth + 1, trace))
    return _bounded(out)


def tag_groups(pattern, field, knowledge, depth, trace):
    """Alternatives of the tag assignments a pattern names: an eventtype through its search, a scope term as itself, any other field unconstrained."""
    found = knowledge.tags(pattern, field) if knowledge is not None and depth < MAX_KNOWLEDGE_DEPTH else None
    if not found:
        trace.gap("tag:%s" % pattern)
        return [UNCONSTRAINED]
    out = []
    for tag, tag_field, value in found:
        trace.through("tag:%s" % tag)
        lowered = str(tag_field).lower()
        patterns = _patterns([value])
        if lowered == "eventtype":
            out.extend(eventtype_groups(value, knowledge, depth + 1, trace))
        elif lowered in DIMENSIONS and patterns is not None:
            out.append(_dimension_group(DIMENSIONS[lowered], patterns))
        else:
            out.append(UNCONSTRAINED)
    return _bounded(out)


def _merge(left, right):
    return tuple(a | b for a, b in zip(left, right))


def _dedupe(groups):
    seen, out = set(), []
    for group in groups:
        if group not in seen:
            seen.add(group)
            out.append(group)
    return out


def _pool(groups):
    pooled = UNCONSTRAINED
    for group in groups:
        pooled = _merge(pooled, group)
    return [pooled]


def _bounded(groups):
    groups = _dedupe(groups)
    return groups if len(groups) <= MAX_GROUPS else _pool(groups)


def and_groups(left, right):
    """Both alternatives lists at once: each pair merged, pooled into one when the product grows past MAX_GROUPS."""
    return _bounded([_merge(a, b) for a in left for b in right])


def expression_groups(text, knowledge=None, depth=0, trace=None):
    """Alternatives of a boolean search expression.

    Implicit AND joins terms; OR binds tighter than AND, as in SPL; NOT and
    != negate one term or parenthesized group, which then constrains nothing.
    eventtype and tag terms resolve through knowledge (see constraint_groups).
    """
    trace = trace if trace is not None else Trace()
    clusters = []
    pending_or = negate = False
    pos, n = 0, len(text)
    while True:
        pos = skip_space(text, pos)
        if pos >= n:
            break
        operator = OPERATOR_RE.match(text, pos)
        if operator:
            word = operator.group(1)
            pending_or = word == "OR" or pending_or
            negate = word == "NOT" or negate
            pos = operator.end()
            continue
        if text[pos] == "(":
            end = match_close(text, pos, "(", ")")
            alternatives = expression_groups(inner_text(text, pos, end, ")"), knowledge, depth, trace)
        elif text[pos] == ")":
            alternatives, end = [UNCONSTRAINED], pos + 1
        else:
            match = TERM_RE.match(text, pos)
            reference = None if match else KNOWLEDGE_TERM_RE.match(text, pos)
            if match:
                alternatives, end = _term(text, match)
            elif reference:
                alternatives, end = _knowledge_term(text, reference, knowledge, depth, trace)
            else:
                alternatives, end = [UNCONSTRAINED], word_end(text, pos)
        pos = max(end, pos + 1)
        if negate:
            alternatives, negate = [UNCONSTRAINED], False
        if pending_or and clusters:
            clusters[-1] = _bounded(clusters[-1] + alternatives)
        else:
            clusters.append(alternatives)
        pending_or = False
    groups = [UNCONSTRAINED]
    for cluster in clusters:
        groups = and_groups(groups, cluster)
    return groups


DATAMODEL_FROM_RE = re.compile(r"\bfrom\s+datamodel\s*=\s*(\"[^\"]*\"|\S+)", re.IGNORECASE)
FROM_DATAMODEL_RE = re.compile(r'\s*datamodel\s*:?\s*("?)([^\s"]+)\1', re.IGNORECASE)


def dataset_name(text, root_dataset):
    """The Model.Dataset a datamodel reference names; a model alone takes its root dataset through root_dataset(model)."""
    text = unquote(text or "").strip()
    if not text:
        return ""
    parts = text.split(".")
    if len(parts) >= 2:
        return "%s.%s" % (parts[0], parts[1])
    root = root_dataset(parts[0]) if root_dataset else None
    return "%s.%s" % (parts[0], root or parts[0])


def generating_dataset(command, rest, root_dataset):
    """The dataset a datamodel, from datamodel: or tstats from datamodel= segment reads, and the tstats where text; ("", "") otherwise."""
    if command == "datamodel":
        tokens = [t for t in arg_tokens(rest) if t[0] != "," and not is_option(t[0])]
        names = [unquote(t[0]) for t in tokens if t[0].lower() not in ("search", "flat", "acceleration_search")]
        if not names:
            return "", ""
        return ("%s.%s" % (names[0], names[1]) if len(names) >= 2 else dataset_name(names[0], root_dataset)), ""
    if command == "from":
        match = FROM_DATAMODEL_RE.match(rest)
        return (dataset_name(match.group(2), root_dataset) if match else ""), ""
    if command == "tstats":
        match = DATAMODEL_FROM_RE.search(rest)
        if not match:
            return "", ""
        where = re.search(r"\bwhere\b", rest, re.IGNORECASE)
        by = re.search(r"\b(by|groupby)\b", rest, re.IGNORECASE)
        where_text = ""
        if where:
            where_end = by.start() if by and by.start() > where.start() else len(rest)
            where_text = rest[where.end():where_end]
        return dataset_name(match.group(1), root_dataset), where_text
    return "", ""


def constraint_groups(spl, knowledge=None, macro_lookup=None, trace=None):
    """The alternatives an SPL text reads: a list of groups (index, sourcetype, source, host patterns, source keys), lowercased.

    Each alternative is one branch the search may read: a top-level OR branch
    or a subsearch. Terms joined by AND or by later pipes are merged into one
    alternative. Negated terms, == comparisons, a bare * and the arguments of
    NON_READING_COMMANDS constrain nothing. Patterns keep * as a wildcard. An
    alternative with no dimension is left out.

    macro_lookup(name, argc) expands macros first, to AUDIT_MACRO_DEPTH.
    knowledge resolves eventtype and tag terms and data model datasets:
    knowledge.eventtypes(pattern) gives [(name, search)], knowledge.tags(pattern,
    field) gives [(tag, field, value)], knowledge.dataset_keys(Model.Dataset)
    gives the source keys of the dataset's class or None, and
    knowledge.root_dataset(model) the root dataset name. trace collects the
    gaps, the knowledge objects resolved and the macros expanded.
    """
    trace = trace if trace is not None else Trace()
    text = str(spl or "")
    if macro_lookup is not None and "`" in text:
        text, _ = expand_macros(text, macro_lookup, trace.gaps, names=trace.macros, max_depth=AUDIT_MACRO_DEPTH)
    root_dataset = knowledge.root_dataset if knowledge is not None else None
    outer, subs = subsearches(text)
    groups = [UNCONSTRAINED]
    for _, segment in pipes(outer):
        head = segment.strip().split(None, 1)
        command = head[0].lower() if head else ""
        rest = head[1] if len(head) > 1 else ""
        if command in NON_READING_COMMANDS:
            continue
        dataset, where_text = generating_dataset(command, rest, root_dataset)
        if dataset:
            source_keys = knowledge.dataset_keys(dataset) if knowledge is not None else None
            if source_keys is None:
                trace.gap("datamodel:%s" % dataset)
            trace.through("datamodel:%s" % dataset)
            groups = and_groups(groups, [_keys_group(source_keys)])
            if where_text:
                groups = and_groups(groups, expression_groups(where_text, knowledge, 0, trace))
            continue
        groups = and_groups(groups, expression_groups(segment, knowledge, 0, trace))
    found = [g for g in groups if any(g)]
    for _, _, sub in subs:
        found.extend(constraint_groups(sub, knowledge, macro_lookup, trace))
    return _dedupe(found)


def constraints(spl):
    """Every index and sourcetype pattern an SPL text constrains, pooled: (index_patterns, sourcetype_patterns)."""
    index_patterns, sourcetype_patterns = set(), set()
    for group in constraint_groups(spl):
        index_patterns |= group[INDEX]
        sourcetype_patterns |= group[SOURCETYPE]
    return index_patterns, sourcetype_patterns


_PATTERN_CACHE = {}


def pattern_re(pattern):
    """A pattern as a regex: * matches any run of characters, every other character is literal."""
    compiled = _PATTERN_CACHE.get(pattern)
    if compiled is None:
        compiled = re.compile("^%s$" % ".*".join(re.escape(p) for p in pattern.split("*")), re.DOTALL)
        _PATTERN_CACHE[pattern] = compiled
    return compiled


def any_match(patterns, names):
    for pattern in patterns:
        for name in names:
            if name and pattern_re(pattern).match(name.lower()):
                return True
    return False


def index_only(group):
    """True for an alternative whose only constraint is on index."""
    return bool(group[INDEX]) and not any(group[INDEX + 1:])


def group_touches(group, src_index, sourcetypes, sources=None, hosts=None, source_key=""):
    """True when a search alternative reads the source.

    A dimension with no pattern is unconstrained; an alternative with no
    dimension constrains nothing, and one constrained on index alone touches
    no source: a search counts for a source only when it names the sourcetype
    or narrows to it through source, host, a dataset or a resolved knowledge
    object. sourcetypes is the source's indexed name and its search-time name;
    sources and hosts are its known source and host values, and a source or
    host pattern matches nothing when they are unknown.
    """
    index_patterns, sourcetype_patterns, source_patterns, host_patterns, source_keys = group
    if not any(group) or index_only(group):
        return False
    if source_keys and source_key not in source_keys:
        return False
    if index_patterns and not any_match(index_patterns, [src_index]):
        return False
    if sourcetype_patterns and not any_match(sourcetype_patterns, sourcetypes):
        return False
    if source_patterns and not any_match(source_patterns, sources or []):
        return False
    if host_patterns and not any_match(host_patterns, hosts or []):
        return False
    return True


def touches(index_patterns, sourcetype_patterns, src_index, sourcetypes):
    """True when an alternative with only index and sourcetype patterns reads the source."""
    return group_touches(_merge(_dimension_group(INDEX, index_patterns), _dimension_group(SOURCETYPE, sourcetype_patterns)),
                         src_index, sourcetypes)


def scope_group(scope):
    """The constraint group an exact_source or sourcetype_pattern scope stands for; * is no constraint."""
    group = UNCONSTRAINED
    for dimension, pattern in ((INDEX, scope.index_pattern), (SOURCETYPE, scope.sourcetype_pattern),
                               (SOURCE, scope.source_pattern), (HOST, scope.host_pattern)):
        if pattern and pattern != "*":
            group = _merge(group, _dimension_group(dimension, {pattern}))
    return group


def touches_any(groups, src_index, sourcetypes, sources=None, hosts=None, source_key=""):
    """True when any alternative of constraint_groups() reads the source."""
    return any(group_touches(g, src_index, sourcetypes, sources, hosts, source_key) for g in groups)


# Macros.

MACRO_NAME_RE = re.compile(r"[A-Za-z_][\w.:-]*")


def macro_key(rest_name):
    """(name, argument count) of a macro as the macros endpoint names it: name or name(n)."""
    match = re.match(r"^(.*?)\((\d+)\)$", rest_name or "")
    if match:
        return match.group(1), int(match.group(2))
    return rest_name or "", 0


def split_args(text):
    """Macro call arguments split at depth-0 commas, quotes and parentheses respected, surrounding quotes removed."""
    args, depth, pos, start, n = [], 0, 0, 0, len(text)
    while pos < n:
        c = text[pos]
        if c == '"':
            pos = skip_quoted(text, pos)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        elif c == "," and depth == 0:
            args.append(text[start:pos])
            start = pos + 1
        pos += 1
    args.append(text[start:])
    out = []
    for arg in args:
        arg = arg.strip()
        if len(arg) >= 2 and arg[0] == '"' and arg[-1] == '"':
            arg = arg[1:-1]
        out.append(arg)
    return out


def macro_call(text, pos):
    """(name, args, end) of the macro call starting at the backtick at pos, or None."""
    n = len(text)
    name = MACRO_NAME_RE.match(text, pos + 1)
    if not name:
        return None
    end = name.end()
    args = []
    if end < n and text[end] == "(":
        close = match_close(text, end, "(", ")")
        args = split_args(inner_text(text, end, close, ")"))
        end = close
    if end >= n or text[end] != "`":
        return None
    return name.group(0), args, end + 1


STRING_LITERAL_RE = re.compile(r'^"((?:[^"\\]|\\.)*)"$', re.DOTALL)


def substitute(definition, arg_names, args):
    body = definition
    for name, value in zip(arg_names, args):
        body = body.replace("$%s$" % name, value)
    return body


def expand_macros(text, lookup, gaps, depth=0, names=None, max_depth=MAX_MACRO_DEPTH):
    """Expand macro calls outside quotes: (expanded text, [(start, end)] of macro-sourced spans in the expanded text).

    lookup(name, argc) returns {"definition", "args", "iseval"} or None. An
    eval macro whose definition is one string literal expands to that text;
    any other eval macro, an unknown macro and a macro past max_depth is
    removed and recorded as a gap macro:<name>. names, when given, collects
    the names of the macros expanded.
    """
    out, ranges, length = [], [], 0
    pos, n = 0, len(text)
    while pos < n:
        c = text[pos]
        if c == '"':
            end = skip_quoted(text, pos)
            out.append(text[pos:end])
            length += end - pos
            pos = end
            continue
        if c == "`":
            call = macro_call(text, pos)
            if call is not None:
                name, args, end = call
                body = macro_body(lookup, name, args, depth, max_depth)
                if body is None:
                    if "macro:%s" % name not in gaps:
                        gaps.append("macro:%s" % name)
                else:
                    if names is not None and name not in names:
                        names.append(name)
                    body, _ = expand_macros(body, lookup, gaps, depth + 1, names, max_depth)
                    piece = " %s " % body
                    out.append(piece)
                    ranges.append((length, length + len(piece)))
                    length += len(piece)
                pos = end
                continue
        out.append(c)
        length += 1
        pos += 1
    return "".join(out), ranges


def macro_body(lookup, name, args, depth, max_depth=MAX_MACRO_DEPTH):
    if depth >= max_depth:
        return None
    macro = lookup(name, len(args))
    if macro is None:
        return None
    definition = str(macro.get("definition") or "")
    arg_names = [a.strip() for a in str(macro.get("args") or "").split(",") if a.strip()]
    if macro.get("iseval"):
        literal = STRING_LITERAL_RE.match(definition.strip())
        if literal is None:
            return None
        return substitute(literal.group(1).replace('\\"', '"'), arg_names, args)
    return substitute(definition, arg_names, args)


# Scopes and references.

class Scope(object):
    """Where a field reference resolves: a source, a source pattern, a data model dataset, or nothing.

    source_pattern and host_pattern narrow an exact_source or
    sourcetype_pattern scope to the sources whose known source or host values
    match; they are empty when the search carries no such term. An index_only
    scope keeps its index pattern for display and resolves to no source.
    """

    __slots__ = ("resolution", "index_pattern", "sourcetype_pattern", "dataset", "source_pattern", "host_pattern")

    def __init__(self, resolution, index_pattern="", sourcetype_pattern="", dataset="", source_pattern="", host_pattern=""):
        self.resolution = resolution
        self.index_pattern = index_pattern
        self.sourcetype_pattern = sourcetype_pattern
        self.dataset = dataset
        self.source_pattern = source_pattern
        self.host_pattern = host_pattern

    @property
    def narrowed(self):
        return bool(self.source_pattern or self.host_pattern)

    @property
    def text(self):
        if self.resolution in (EXACT_SOURCE, SOURCETYPE_PATTERN, INDEX_ONLY):
            text = "index=%s sourcetype=%s" % (self.index_pattern, self.sourcetype_pattern)
            if self.source_pattern:
                text += " source=%s" % self.source_pattern
            if self.host_pattern:
                text += " host=%s" % self.host_pattern
            return text
        if self.resolution == DATAMODEL:
            return self.dataset
        return ""

    def identity(self):
        return (self.resolution, self.index_pattern, self.sourcetype_pattern, self.dataset, self.source_pattern, self.host_pattern)

    def __eq__(self, other):
        return isinstance(other, Scope) and self.identity() == other.identity()

    def __hash__(self):
        return hash(self.identity())

    def __repr__(self):
        return "Scope(%s %s)" % (self.resolution, self.text)


SCOPE_TEXT_RE = re.compile(r"^index=(\S+) sourcetype=(.*?)(?: source=(.*?))?(?: host=(.*?))?$", re.DOTALL)


def source_scope(index_pattern, sourcetype_pattern, source_pattern="", host_pattern=""):
    """The scope of one alternative's index, sourcetype, source and host patterns, * for a missing dimension.

    exact_source when index and sourcetype are literal, sourcetype_pattern when
    either carries a wildcard or a source or host pattern narrows a missing
    sourcetype, index_only when the index is the only constraint, unscoped
    when there is none.
    """
    if index_pattern == "*" and sourcetype_pattern == "*" and not source_pattern and not host_pattern:
        return Scope(UNSCOPED)
    if sourcetype_pattern == "*" and not source_pattern and not host_pattern:
        return Scope(INDEX_ONLY, index_pattern, "*")
    if "*" in index_pattern or "*" in sourcetype_pattern:
        return Scope(SOURCETYPE_PATTERN, index_pattern, sourcetype_pattern, source_pattern=source_pattern, host_pattern=host_pattern)
    return Scope(EXACT_SOURCE, index_pattern, sourcetype_pattern, source_pattern=source_pattern, host_pattern=host_pattern)


def scope_from_text(resolution, text):
    """The Scope a stored edge's resolution and scope_text describe; a partial edge's scope is resolved again."""
    if resolution in (EXACT_SOURCE, SOURCETYPE_PATTERN, INDEX_ONLY, PARTIAL):
        match = SCOPE_TEXT_RE.match(text or "")
        if not match:
            return Scope(UNSCOPED)
        return source_scope(match.group(1), match.group(2), match.group(3) or "", match.group(4) or "")
    if resolution == DATAMODEL:
        return Scope(DATAMODEL, dataset=text or "")
    return Scope(UNSCOPED)


def scopes_of_groups(groups, gaps):
    """Scopes for constraint alternatives, one source_scope() per combination of patterns.

    A source or host pattern rides on the scope and narrows it at resolution;
    a group with only such patterns is the pattern index=* sourcetype=*.
    """
    scopes = []
    for group in groups:
        indexes = sorted(group[INDEX]) or ["*"]
        sourcetypes = sorted(group[SOURCETYPE]) or ["*"]
        sources = sorted(group[SOURCE]) or [""]
        hosts = sorted(group[HOST]) or [""]
        for token in [p for p in indexes + sourcetypes + sources + hosts if "$" in p]:
            if "token:%s" % token not in gaps:
                gaps.append("token:%s" % token)
        indexes = [p for p in indexes if "$" not in p] or ["*"]
        sourcetypes = [p for p in sourcetypes if "$" not in p] or ["*"]
        sources = [p for p in sources if "$" not in p] or [""]
        hosts = [p for p in hosts if "$" not in p] or [""]
        for index_pattern in indexes:
            for sourcetype_pattern in sourcetypes:
                for source_pattern in sources:
                    for host_pattern in hosts:
                        scope = source_scope(index_pattern, sourcetype_pattern, source_pattern, host_pattern)
                        if scope not in scopes:
                            scopes.append(scope)
    return scopes or [Scope(UNSCOPED)]


class Parse(object):
    """The references and gaps of one object's SPL."""

    def __init__(self):
        self.refs = collections.OrderedDict()
        self.gaps = []
        self.macros = []
        self.failed = False

    def add(self, field_name, ref_kind, scopes, confidence, via=()):
        """Record a reference; via names the eventtypes and tags the scope was reached through."""
        for scope in scopes:
            key = (field_name, ref_kind, scope.identity())
            entry = self.refs.get(key)
            if entry is None:
                self.refs[key] = [field_name, ref_kind, scope, confidence, list(via)]
            else:
                if confidence == EXACT:
                    entry[3] = EXACT
                for item in via:
                    if item not in entry[4]:
                        entry[4].append(item)

    def expanded(self, names):
        for name in names:
            if name not in self.macros:
                self.macros.append(name)

    def gap(self, text):
        if text not in self.gaps:
            self.gaps.append(text)

    @property
    def status(self):
        if self.failed:
            return "failed"
        return "partial" if self.gaps else "parsed"

    def references(self):
        """[(field_name, ref_kind, Scope, confidence, via)]."""
        return [tuple(v) for v in self.refs.values()]


class Pipeline(object):
    """Parse state of one pipeline: its scopes, the names derived so far, and the macro spans for confidence."""

    def __init__(self, parse, ranges, base, root_dataset, depth, knowledge=None):
        self.parse = parse
        self.ranges = ranges
        self.base = base
        self.root_dataset = root_dataset
        self.depth = depth
        self.knowledge = knowledge
        self.groups = [UNCONSTRAINED]
        self.scopes = None
        self.none = False
        self.derived = {}
        self.via = []

    def constrain(self, text):
        """Narrow every alternative by a search expression; its gaps go to the parse and its knowledge objects to via."""
        trace = Trace()
        groups = expression_groups(text, self.knowledge, 0, trace)
        for gap in trace.gaps:
            self.parse.gap(gap)
        for item in trace.via:
            if item not in self.via:
                self.via.append(item)
        self.groups = and_groups(self.groups, groups)
        self.scopes = None

    def confidence(self, pos):
        absolute = self.base + pos
        for start, end in self.ranges:
            if start <= absolute < end:
                return INFERRED
        return EXACT

    def current_scopes(self):
        if self.scopes is None:
            self.scopes = scopes_of_groups(self.groups, self.parse.gaps)
        return self.scopes

    def add(self, name, kind, pos):
        """Record a reference, mapping a derived name back to the fields it was computed from."""
        if self.none or not name or "$" in name:
            return
        if "*" in name:
            self.parse.gap("wildcard:%s" % name)
            return
        if name.startswith("_"):
            return
        confidence = self.confidence(pos)
        name = strip_dataset(name, self)
        sources = self.derived.get(name)
        if sources is None:
            self.parse.add(name, kind, self.current_scopes(), confidence, self.via)
            return
        for source in sources:
            if source == name:
                self.parse.add(source, kind, self.current_scopes(), confidence, self.via)
            elif not source.startswith("_") and "$" not in source and "*" not in source:
                self.parse.add(source, kind, self.current_scopes(), INFERRED, self.via)

    def define(self, name, inputs):
        if not name or "$" in name:
            return
        expanded = set()
        for item in inputs:
            for source in self.derived.get(item, [item]):
                expanded.add(source)
        self.derived[name] = expanded


def parse_search(text, macro_lookup=None, root_dataset=None, knowledge=None):
    """Field references of a search text with their scopes: a Parse (see constraint_groups for knowledge)."""
    parse = Parse()
    lookup = macro_lookup or (lambda name, argc: None)
    try:
        expanded, ranges = expand_macros(str(text or ""), lookup, parse.gaps, names=parse.macros)
        parse_pipeline(expanded, parse, ranges, 0, root_dataset, 0, knowledge=knowledge)
    except Exception as exc:  # the object is reported failed, never the run
        parse.failed = True
        parse.gap("error:%s" % exc.__class__.__name__)
    return parse


def parse_fragment(text, parse, scopes, macro_lookup=None):
    """References of a search fragment (a constraint, a macro body) under fixed scopes, added to parse."""
    lookup = macro_lookup or (lambda name, argc: None)
    expanded, ranges = expand_macros(str(text or ""), lookup, parse.gaps, names=parse.macros)
    state = Pipeline(parse, ranges, 0, None, 0)
    state.scopes = list(scopes)
    try:
        run_pipeline(expanded, state, implicit_search=True)
    except Exception as exc:
        parse.failed = True
        parse.gap("error:%s" % exc.__class__.__name__)


def parse_pipeline(text, parse, ranges, base, root_dataset, depth, inherit=None, knowledge=None):
    state = Pipeline(parse, ranges, base, root_dataset, depth, knowledge=knowledge)
    if inherit is not None:
        state.groups, state.scopes, state.none, state.derived = inherit.groups, inherit.scopes, inherit.none, dict(inherit.derived)
        state.via = list(inherit.via)
    run_pipeline(text, state, implicit_search=True)
    return state


def run_pipeline(text, state, implicit_search=True):
    outer, subs = subsearches(text)
    generating = True
    for index, (offset, segment) in enumerate(pipes(outer)):
        stripped = segment.strip()
        if not stripped:
            continue
        seg_pos = offset + (len(segment) - len(segment.lstrip()))
        if index == 0 and implicit_search:
            command, rest, rest_pos = "search", stripped, seg_pos
            if rest.lower().startswith("search ") or rest.lower() == "search":
                rest = rest[6:]
                rest_pos += 6
        else:
            head = stripped.split(None, 1)
            command = head[0].lower()
            rest = head[1] if len(head) > 1 else ""
            rest_pos = seg_pos + (len(stripped) - len(rest))
            if command[-1:] in "+-" and command[:-1] in KNOWN_COMMANDS:
                # fields- x and fields+ x are written without the space.
                rest, rest_pos, command = command[-1] + " " + rest, rest_pos - 2, command[:-1]
        inner = [(s - rest_pos, e - rest_pos, body) for s, e, body in subs if offset <= s < offset + len(segment)]
        run_command(command, rest, rest_pos, inner, state, generating)
        generating = False


def run_command(command, rest, pos, subs, state, generating=False):
    """Apply one command: scope changes, subsearch descent, references."""
    parse = state.parse
    if "$" in command:
        parse.gap("token:%s" % command)
        return
    if command in ("map", "foreach"):
        parse.gap(command)
        return
    if command in BRACKET_COMMANDS:
        for start, end, body in subs:
            if command == "appendpipe":
                parse_pipeline(body, parse, state.ranges, state.base + pos + start + 1, state.root_dataset, state.depth + 1,
                               inherit=state, knowledge=state.knowledge)
            elif state.depth < MAX_SUBSEARCH_DEPTH:
                parse_pipeline(body, parse, state.ranges, state.base + pos + start + 1, state.root_dataset, state.depth + 1,
                               knowledge=state.knowledge)
            else:
                parse.gap("subsearch")
            if command == "search":
                parse.gap("subsearch")
        if command == "join":
            for name, position in join_fields(rest):
                state.add(name, BY, pos + position)
        if command != "search":
            return
    elif subs:
        parse.gap("subsearch")
    if command in ("search", "metasearch"):
        if state.none:
            return
        state.constrain(rest)
        for name, position in filter_fields(rest):
            state.add(name, FILTER, pos + position)
        return
    if command == "tstats":
        tstats(rest, pos, state)
        return
    if command == "datamodel":
        datamodel_command(rest, state)
        return
    if command == "from":
        from_command(rest, state)
        return
    if command in NON_DATA_GENERATORS:
        if generating:
            state.none = True
        return
    if command == "where":
        for name, position in eval_identifiers(rest):
            state.add(name, EVAL_INPUT, pos + position)
        return
    if command in ("eval", "fieldformat"):
        eval_command(rest, pos, state)
        return
    if command in STATS_COMMANDS:
        stats_command(command, rest, pos, state)
        return
    if command in ("top", "rare"):
        top_command(rest, pos, state)
        return
    if command in ("fields", "table"):
        for token, position in arg_tokens(rest):
            if token in ("+", "-", ","):
                continue
            state.add(unquote(token), OUTPUT, pos + position)
        return
    if command == "rename":
        rename_command(rest, pos, state)
        return
    if command in ("dedup", "sort", "transaction"):
        sort_like(command, rest, pos, state)
        return
    if command == "rex":
        rex_command(rest, pos, state)
        return
    if command == "regex":
        for token, position in arg_tokens(rest):
            if "=" in token and not token.startswith('"'):
                name = token.split("=", 1)[0]
                if "!" in name:
                    name = name.rstrip("!")
                state.add(unquote(name), FILTER, pos + position)
            break
        return
    if command == "lookup":
        lookup_command(rest, pos, state)
        return
    if command == "spath":
        spath_command(rest, pos, state)
        return
    if command in ("bin", "bucket"):
        bin_command(rest, pos, state)
        return
    if command in ("fillnull", "filldown"):
        for token, position in arg_tokens(rest):
            if "=" in token or token == ",":
                continue
            state.add(unquote(token), OUTPUT, pos + position)
        return
    if command in ("mvexpand", "makemv", "nomv", "mvcombine", "iplocation", "autoregress", "delta", "accum", "convert", "untable", "xyseries"):
        for token, position in arg_tokens(rest):
            if token == ",":
                continue
            if "=" in token and not token.startswith('"'):
                continue
            name, inner = call_parts(token)
            if inner is not None:
                for part, part_pos in split_fields(inner, position + len(name) + 1):
                    state.add(unquote(part), EVAL_INPUT, pos + part_pos)
                continue
            if token.lower() == "as":
                break
            state.add(unquote(token), EVAL_INPUT, pos + position)
        return
    if command == "replace":
        tokens = arg_tokens(rest)
        seen_in = False
        for token, position in tokens:
            if seen_in and token != ",":
                state.add(unquote(token), EVAL_INPUT, pos + position)
            elif token.lower() == "in":
                seen_in = True
        return
    if command == "pivot":
        parse.gap("pivot")
        return
    if command in NO_REF_COMMANDS:
        return
    parse.gap("command:%s" % command)


# Argument tokenizers.

def arg_tokens(text):
    """Command arguments as (token, position): quoted strings whole, function calls whole, commas on their own."""
    tokens, pos, n = [], 0, len(text)
    while pos < n:
        c = text[pos]
        if c in " \t\r\n":
            pos += 1
            continue
        if c == ",":
            tokens.append((",", pos))
            pos += 1
            continue
        start = pos
        if c == '"':
            pos = skip_quoted(text, pos)
        elif c == "'":
            end = text.find("'", pos + 1)
            pos = n if end < 0 else end + 1
        while pos < n and text[pos] not in " \t\r\n,":
            if text[pos] == '"':
                pos = skip_quoted(text, pos)
            elif text[pos] == "(":
                pos = match_close(text, pos, "(", ")")
            else:
                pos += 1
        tokens.append((text[start:pos], start))
    return tokens


def unquote(token):
    token = token.strip()
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return token[1:-1]
    return token


def call_parts(token):
    """(name, inner) for a function call token name(inner); (token, None) otherwise."""
    match = re.match(r"^([A-Za-z_][\w.]*)\((.*)\)$", token, re.DOTALL)
    if not match:
        return token, None
    return match.group(1), match.group(2)


def split_fields(text, base):
    """Comma or space separated field names inside a function call: [(name, position)]."""
    out = []
    for token, position in arg_tokens(text):
        if token != ",":
            out.append((token, base + position))
    return out


def is_option(token):
    return bool(re.match(r"^[A-Za-z_][\w.]*=", token)) and not token.lower().startswith("eval(")


EVAL_TOKEN_RE = re.compile(r'"(?:[^"\\]|\\.)*"|\'((?:[^\'\\]|\\.)*)\'|([A-Za-z_][\w.]*)(\s*\()?|\$[^$\s]*\$|\d[\w.]*|.', re.DOTALL)


def eval_identifiers(text):
    """Field names an eval expression reads: [(name, position)]; function names, strings, numbers and keywords are not fields."""
    out = []
    for match in EVAL_TOKEN_RE.finditer(text):
        if match.group(1) is not None:
            out.append((match.group(1), match.start()))
        elif match.group(2) is not None and match.group(3) is None:
            name = match.group(2)
            if name.lower() in EVAL_KEYWORDS:
                continue
            out.append((name, match.start()))
    return out


def split_assignments(text):
    """eval assignments at depth-0 commas: [(target, expression, expression position)]."""
    parts, depth, pos, start, n = [], 0, 0, 0, len(text)
    while pos < n:
        c = text[pos]
        if c == '"':
            pos = skip_quoted(text, pos)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        elif c == "," and depth == 0:
            parts.append((start, text[start:pos]))
            start = pos + 1
        pos += 1
    parts.append((start, text[start:]))
    out = []
    for offset, part in parts:
        match = re.match(r'\s*(\'[^\']*\'|"[^"]*"|[^\s=]+)\s*=(?!=)', part)
        if not match:
            continue
        out.append((unquote(match.group(1)), part[match.end():], offset + match.end()))
    return out


def eval_command(rest, pos, state):
    for target, expression, offset in split_assignments(rest):
        inputs = eval_identifiers(expression)
        for name, position in inputs:
            state.add(name, EVAL_INPUT, pos + offset + position)
        state.define(target, [n for n, _ in inputs])


def filter_fields(text):
    """Field names a search expression tests, with positions; scope and time terms are left out."""
    out = []
    pos, n = 0, len(text)
    while pos < n:
        pos = skip_space(text, pos)
        if pos >= n:
            break
        c = text[pos]
        if c == '"':
            pos = skip_quoted(text, pos)
            continue
        if c == "(":
            end = match_close(text, pos, "(", ")")
            for name, position in filter_fields(inner_text(text, pos, end, ")")):
                out.append((name, pos + 1 + position))
            pos = max(end, pos + 1)
            continue
        if c == ")":
            pos += 1
            continue
        operator = OPERATOR_RE.match(text, pos)
        if operator:
            pos = operator.end()
            continue
        if re.match(r"(TERM|PREFIX|CASE)\(", text[pos:pos + 7]):
            pos = word_end(text, pos)
            continue
        match = FIELD_TERM_RE.match(text, pos)
        if match:
            name = match.group(1)
            op = match.group(2).strip().lower()
            if name.lower() not in SCOPE_TERMS and not name.startswith("$"):
                out.append((name, pos))
            end = match.end()
            if op == "in":
                _, end = read_list(text, end)
            else:
                start = skip_space(text, end)
                if start < n and text[start] == "(":
                    _, end = read_list(text, start + 1)
                else:
                    _, end = read_value(text, end)
            pos = max(end, pos + 1)
            continue
        pos = max(word_end(text, pos), pos + 1)
    return out


def stats_command(command, rest, pos, state):
    if command == "addtotals":
        return
    tokens = arg_tokens(rest)
    mode = "agg"
    last_inputs = []
    i = 0
    while i < len(tokens):
        token, position = tokens[i]
        low = token.lower()
        if token == ",":
            i += 1
            continue
        if low in ("by", "over", "groupby"):
            mode = "by"
            i += 1
            continue
        if is_option(token):
            i += 1
            continue
        if mode == "by":
            state.add(unquote(token), BY, pos + position)
            i += 1
            continue
        if low == "as" and i + 1 < len(tokens):
            alias = unquote(tokens[i + 1][0])
            state.define(alias, last_inputs)
            i += 2
            continue
        name, inner = call_parts(token)
        if inner is None:
            last_inputs = []
            i += 1
            continue
        if name.lower() == "eval":
            inputs = eval_identifiers(inner)
            for field, field_pos in inputs:
                state.add(field, EVAL_INPUT, pos + position + len(name) + 1 + field_pos)
            last_inputs = [n for n, _ in inputs]
        else:
            last_inputs = []
            for field, field_pos in split_fields(inner, position + len(name) + 1):
                inner_name, inner_body = call_parts(field)
                if inner_body is not None and inner_name.lower() == "eval":
                    for sub_field, sub_pos in eval_identifiers(inner_body):
                        state.add(sub_field, EVAL_INPUT, pos + field_pos + len(inner_name) + 1 + sub_pos)
                        last_inputs.append(sub_field)
                    continue
                field = unquote(field)
                state.add(field, EVAL_INPUT, pos + field_pos)
                last_inputs.append(field)
        i += 1


def top_command(rest, pos, state):
    for token, position in arg_tokens(rest):
        if token == "," or is_option(token) or token.lower() == "by":
            continue
        state.add(unquote(token), BY, pos + position)


def rename_command(rest, pos, state):
    tokens = [t for t in arg_tokens(rest) if t[0] != ","]
    i = 0
    while i < len(tokens):
        token, position = tokens[i]
        if i + 2 < len(tokens) and tokens[i + 1][0].lower() == "as":
            source, target = unquote(token), unquote(tokens[i + 2][0])
            state.add(source, EVAL_INPUT, pos + position)
            state.define(target, [source])
            i += 3
            continue
        i += 1


def sort_like(command, rest, pos, state):
    for token, position in arg_tokens(rest):
        if token == "," or is_option(token):
            continue
        if command == "sort" and re.match(r"^-?\d+$", token):
            continue
        if command == "dedup" and re.match(r"^\d+$", token):
            continue
        if token.lower() in ("sortby", "d", "desc", "a", "asc"):
            continue
        name = token.lstrip("+-")
        func, inner = call_parts(name)
        if inner is not None:
            name = inner
        state.add(unquote(name), BY, pos + position)


def rex_command(rest, pos, state):
    source = "_raw"
    source_pos = None
    regex = ""
    mode_sed = False
    for token, position in arg_tokens(rest):
        if token.lower().startswith("field="):
            source = unquote(token[6:])
            source_pos = position + 6
        elif token.lower().startswith("mode=sed"):
            mode_sed = True
        elif token.startswith('"'):
            regex = unquote(token)
    if source_pos is not None:
        state.add(source, EVAL_INPUT, pos + source_pos)
    if mode_sed:
        return
    for group in re.findall(r"\(\?P?<([A-Za-z_][\w]*)>", regex):
        state.define(group, [source])


def lookup_command(rest, pos, state):
    tokens = [t for t in arg_tokens(rest) if t[0] != ","]
    tokens = [t for t in tokens if not is_option(t[0])]
    if not tokens:
        return
    specs = tokens[1:]
    outputs = []
    for i, (token, _) in enumerate(specs):
        if token.lower() in ("output", "outputnew"):
            outputs = specs[i + 1:]
            specs = specs[:i]
            break
    keys_used = []
    for name, position in field_specs(specs):
        state.add(name, LOOKUP_KEY, pos + position)
        keys_used.append(name)
    for name, _ in field_specs(outputs):
        state.define(name, keys_used)


def field_specs(tokens):
    """`a [AS b]` specs: the event-side name with its position."""
    out = []
    i = 0
    while i < len(tokens):
        if i + 2 < len(tokens) and tokens[i + 1][0].lower() == "as":
            out.append((unquote(tokens[i + 2][0]), tokens[i + 2][1]))
            i += 3
        else:
            out.append((unquote(tokens[i][0]), tokens[i][1]))
            i += 1
    return out


def join_fields(rest):
    out = []
    for token, position in arg_tokens(rest):
        if token == "," or is_option(token) or token.startswith("["):
            continue
        out.append((unquote(token), position))
    return out


def spath_command(rest, pos, state):
    source, output, path = None, None, None
    for token, position in arg_tokens(rest):
        low = token.lower()
        if low.startswith("input="):
            source = (unquote(token[6:]), position + 6)
        elif low.startswith("output="):
            output = unquote(token[7:])
        elif low.startswith("path="):
            path = unquote(token[5:])
        elif not is_option(token) and token != ",":
            path = unquote(token)
    if source is not None:
        state.add(source[0], EVAL_INPUT, pos + source[1])
    target = output or path
    if target:
        state.define(target, [source[0]] if source else ["_raw"])


def bin_command(rest, pos, state):
    tokens = [t for t in arg_tokens(rest) if t[0] != "," and not is_option(t[0])]
    if not tokens:
        return
    source = unquote(tokens[0][0])
    state.add(source, EVAL_INPUT, pos + tokens[0][1])
    if len(tokens) >= 3 and tokens[1][0].lower() == "as":
        state.define(unquote(tokens[2][0]), [source])


def dataset_of(text, state):
    """The Model.Dataset a datamodel reference names; a model alone takes its root dataset."""
    return dataset_name(text, state.root_dataset)


def set_datamodel_scope(dataset, state):
    state.groups = [UNCONSTRAINED]
    state.scopes = [Scope(DATAMODEL, dataset=dataset)] if dataset else [Scope(UNSCOPED)]
    state.none = False


def strip_dataset(name, state):
    """Dataset-prefixed field names (Object.field or Model.field) in a datamodel pipeline become the dataset field name."""
    scopes = state.scopes or []
    if len(scopes) == 1 and scopes[0].resolution == DATAMODEL and "." in name:
        model_name, _, object_name = scopes[0].dataset.partition(".")
        for prefix in (object_name + ".", model_name + "."):
            if len(prefix) > 1 and name.startswith(prefix):
                return name[len(prefix):]
    return name


def tstats(rest, pos, state):
    match = re.search(r"\bfrom\s+datamodel\s*=\s*(\"[^\"]*\"|\S+)", rest, re.IGNORECASE)
    where = re.search(r"\bwhere\b", rest, re.IGNORECASE)
    by = re.search(r"\b(by|groupby)\b", rest, re.IGNORECASE)
    agg_end = min([m.start() for m in (match, where, by) if m] or [len(rest)])
    if match:
        set_datamodel_scope(dataset_of(match.group(1), state), state)
    where_text = ""
    if where:
        where_end = by.start() if by and by.start() > where.start() else len(rest)
        where_text = rest[where.end():where_end]
        if not match:
            state.constrain(where_text)
    for name, position in filter_fields(where_text):
        state.add(name, FILTER, pos + (where.end() if where else 0) + position)
    stats_command("stats", rest[:agg_end], pos, state)
    if by:
        for token, position in arg_tokens(rest[by.end():]):
            if token == "," or is_option(token):
                continue
            state.add(unquote(token), BY, pos + by.end() + position)


def datamodel_command(rest, state):
    tokens = [t for t in arg_tokens(rest) if t[0] != "," and not is_option(t[0])]
    names = [unquote(t[0]) for t in tokens if t[0].lower() not in ("search", "flat", "acceleration_search")]
    if not names:
        state.none = True
        return
    dataset = "%s.%s" % (names[0], names[1]) if len(names) >= 2 else dataset_of(names[0], state)
    set_datamodel_scope(dataset, state)


def from_command(rest, state):
    match = re.match(r'\s*datamodel\s*:?\s*("?)([^\s"]+)\1', rest, re.IGNORECASE)
    if match:
        set_datamodel_scope(dataset_of(match.group(2), state), state)
        return
    state.none = True


# Dashboards.

def dashboard_queries(data):
    """(queries, gaps) of a view definition: Simple XML search elements, or Dashboard Studio dataSources.

    A chained search (base= in Simple XML, extend in Studio) is prefixed with
    its base query. A search that references a saved search is left to that
    object. A definition that does not parse is one gap.
    """
    text = str(data or "").strip()
    if not text:
        return [], []
    if text.startswith("{"):
        return studio_queries(text)
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return [], ["xml"]
    definition = root.find("definition")
    if root.get("version") == "2" and definition is not None:
        return studio_queries(definition.text or "")
    queries, chained, gaps = [], {}, []
    for element in root.iter():
        tag = element.tag.split("}")[-1]
        if tag == "search":
            query = element.findtext("query")
            if query is None:
                continue
            entry = {"query": query.strip(), "base": element.get("base")}
            if element.get("id"):
                chained[element.get("id")] = entry
            queries.append(entry)
        elif tag in ("searchString", "searchTemplate", "populatingSearch"):
            if element.text and element.text.strip():
                queries.append({"query": element.text.strip(), "base": None})
        elif tag == "searchPostProcess":
            if element.text and element.text.strip():
                queries.append({"query": element.text.strip(), "base": None})
                gaps.append("postprocess")
    return resolve_chains(queries, chained, gaps), gaps


def studio_queries(text):
    try:
        definition = json.loads(text)
    except ValueError:
        return [], ["json"]
    sources = definition.get("dataSources") if isinstance(definition, dict) else None
    if not isinstance(sources, dict):
        return [], []
    queries, chained, gaps = [], {}, []
    for source_id, source in sources.items():
        if not isinstance(source, dict):
            continue
        options = source.get("options") if isinstance(source.get("options"), dict) else {}
        kind = str(source.get("type") or "")
        if kind == "ds.savedSearch":
            continue
        query = options.get("query")
        if not isinstance(query, str) or not query.strip():
            continue
        entry = {"query": query.strip(), "base": options.get("extend") if kind == "ds.chain" else None}
        chained[str(source_id)] = entry
        queries.append(entry)
    return resolve_chains(queries, chained, gaps), gaps


def resolve_chains(queries, chained, gaps):
    out = []
    for entry in queries:
        query, base, depth = entry["query"], entry["base"], 0
        while base:
            parent = chained.get(base)
            depth += 1
            if parent is None or depth > MAX_CHAIN_DEPTH:
                if "chain" not in gaps:
                    gaps.append("chain")
                break
            query = "%s | %s" % (parent["query"].rstrip(), query.lstrip().lstrip("|").lstrip())
            base = parent["base"]
        if query and query not in out:
            out.append(query)
    return out
