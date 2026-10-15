"""Content keys, stratum sentinels, identity normalization, run ids and search windows.

Every rule here is the Conventions section of docs/data-model.md.
"""
import datetime
import hashlib
import math
import re

SEP = "\u001f"
SEP_REPLACEMENT = "�"

ALL = "__all__"
EMPTY = "__empty__"
MISSING = "__missing__"
MULTI = "__multi__"

RUN_ID_FORMAT = "%Y%m%dT%H%MZ"

_FORBIDDEN_IDENTITY = ("", "*")


class IdentityError(ValueError):
    """An identity part is empty, null or a wildcard."""


def sha32(text):
    """First 32 hex characters of SHA-256 over text as UTF-8."""
    if isinstance(text, str):
        text = text.encode("utf-8")
    return hashlib.sha256(text).hexdigest()[:32]


def k(*parts):
    """Content key: SHA-256 over the parts joined with U+001F, first 32 hex characters.

    A U+001F inside a part is replaced by U+FFFD before hashing. Parts are
    stringified; None is not a valid part.
    """
    if not parts:
        raise IdentityError("k() needs at least one part")
    cleaned = []
    for part in parts:
        if part is None:
            raise IdentityError("k() part is None")
        cleaned.append(str(part).replace(SEP, SEP_REPLACEMENT))
    return sha32(SEP.join(cleaned))


def num_text(value):
    """Canonical text of a number inside a key: whole numbers without a fraction, others in shortest round-trip form.

    Matches JavaScript String(n), so the UI and the profiler hash the same text; None is "".
    """
    if value is None or value == "":
        return ""
    if isinstance(value, str):
        value = float(value)
    number = float(value)
    if number.is_integer():
        return str(int(number))
    return repr(number)


def spl_hash(spl):
    """First 32 hex of SHA-256 over the SPL text as written."""
    return sha32(spl)


def check_identity(value, name="identity"):
    """Reject an identity value that is empty, None or '*'."""
    if value is None or not isinstance(value, str) or value in _FORBIDDEN_IDENTITY:
        raise IdentityError("%s must be a non-empty string other than '*': %r" % (name, value))
    return value


def norm_index(index):
    """src_index: the index name lowercased."""
    return check_identity(index, "src_index").lower()


def norm_sourcetype(sourcetype):
    """src_sourcetype: exactly as metadata and tstats report it."""
    return check_identity(sourcetype, "src_sourcetype")


def norm_field_name(field_name):
    """field_name: verbatim, case kept, no trimming."""
    return check_identity(field_name, "field_name")


def norm_stratum_field(stratum_field):
    """stratum_field: the field name verbatim, or __all__."""
    if stratum_field is None or stratum_field == "":
        return ALL
    return check_identity(stratum_field, "stratum_field")


def multi_value(values):
    """The __multi__ sentinel for a multivalued stratum field: sorted distinct values."""
    distinct = sorted(set(str(v) for v in values))
    return MULTI + SEP + SEP.join(distinct)


def multi_values(stratum_value):
    """The distinct values encoded in a __multi__ sentinel."""
    if not is_multi(stratum_value):
        raise ValueError("not a __multi__ sentinel: %r" % (stratum_value,))
    body = stratum_value[len(MULTI) + len(SEP):]
    return body.split(SEP) if body else []


def is_multi(stratum_value):
    return isinstance(stratum_value, str) and stratum_value.startswith(MULTI + SEP)


def stratum_value_of(raw):
    """Stratum value for one event's stratum field value, as S2 computes it.

    raw is None when the event lacks the field, a list when it is multivalued,
    otherwise the value as text.
    """
    if raw is None:
        return MISSING
    if isinstance(raw, (list, tuple)):
        values = [str(v) for v in raw]
        if len(values) == 0:
            return MISSING
        if len(values) > 1:
            return multi_value(values)
        raw = values[0]
    raw = str(raw)
    if raw == "":
        return EMPTY
    return raw


def value_kind(stratum_value):
    """all, value, empty, missing or multi."""
    if stratum_value == ALL:
        return "all"
    if stratum_value == EMPTY:
        return "empty"
    if stratum_value == MISSING:
        return "missing"
    if is_multi(stratum_value):
        return "multi"
    check_identity(stratum_value, "stratum_value")
    return "value"


def stratum_label(stratum_field, stratum_value):
    """Display form of a stratum."""
    kind = value_kind(stratum_value)
    if kind == "all":
        return "all events"
    if kind == "empty":
        return "%s is empty" % stratum_field
    if kind == "missing":
        return "%s is missing" % stratum_field
    if kind == "multi":
        return "%s in {%s}" % (stratum_field, ", ".join(multi_values(stratum_value)))
    return "%s=%s" % (stratum_field, stratum_value)


def prunable(stratum_value):
    """1 when the discovery filter is a plain field=value the lexicon prunes."""
    return 1 if value_kind(stratum_value) == "value" else 0


def _spl_quote(text):
    return '"' + str(text).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _eval_field(name):
    return "'" + str(name).replace("'", "\\'") + "'"


# Field names usable as the left side of a search term; any other name is matched by the where clause alone, without lexicon pruning.
SEARCH_TERM_FIELD = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.{}@:-]*$")
PLAIN_FIELD = re.compile(r"^[A-Za-z0-9_]+$")


def _term_field(name):
    """A field name as the left side of a search term: double-quoted unless it is [A-Za-z0-9_] only.

    The search command reads a single-quoted name as literal text, never as a field.
    """
    name = str(name)
    return name if PLAIN_FIELD.match(name) else _spl_quote(name)


def _where_only_filter(kind, f, stratum_value):
    """stratum_filter for a field name a search term cannot carry."""
    if kind == "value":
        return "| where mvcount(%s)=1 AND %s==%s" % (f, f, _spl_quote(stratum_value))
    if kind == "missing":
        return "| where isnull(%s)" % f
    if kind == "empty":
        return "| where mvcount(%s)=1 AND %s==\"\"" % (f, f)
    values = multi_values(stratum_value)
    present = " AND ".join("isnotnull(mvfilter(%s==%s))" % (f, _spl_quote(v)) for v in values)
    return "| where mvcount(%s)>1 AND mvcount(mvdedup(%s))=%d AND %s" % (f, f, len(values), present)


def stratum_filter(stratum_field, stratum_value):
    """SPL filter selecting exactly one stratum, appended to the source search.

    The search terms keep lexicon pruning; the where clause makes the match
    exact, since search terms are case-insensitive and treat * as a wildcard,
    and applies the multivalue rule of stratum_value_of (a value stratum is
    single-valued, a multi stratum is its distinct set).
    """
    kind = value_kind(stratum_value)
    if kind == "all":
        return ""
    f = _eval_field(stratum_field)
    if not SEARCH_TERM_FIELD.match(str(stratum_field)):
        return _where_only_filter(kind, f, stratum_value)
    t = _term_field(stratum_field)
    if kind == "value":
        return "%s=%s | where mvcount(%s)=1 AND %s==%s" % (t, _spl_quote(stratum_value), f, f, _spl_quote(stratum_value))
    if kind == "missing":
        return "NOT %s=*" % t
    if kind == "empty":
        return "%s=\"\" | where mvcount(%s)=1 AND %s==\"\"" % (t, f, f)
    values = multi_values(stratum_value)
    conj = " ".join("%s=%s" % (t, _spl_quote(v)) for v in values)
    present = " AND ".join("isnotnull(mvfilter(%s==%s))" % (f, _spl_quote(v)) for v in values)
    return "%s | where mvcount(%s)>1 AND mvcount(mvdedup(%s))=%d AND %s" % (conj, f, f, len(values), present)


def source_key(src_index, src_sourcetype):
    return k(norm_index(src_index), norm_sourcetype(src_sourcetype))


def stratum_key(src_index, src_sourcetype, stratum_field, stratum_value):
    check_identity(stratum_value, "stratum_value")
    return k(norm_index(src_index), norm_sourcetype(src_sourcetype), norm_stratum_field(stratum_field), stratum_value)


def field_key(src_index, src_sourcetype, stratum_field, stratum_value, field_name):
    check_identity(stratum_value, "stratum_value")
    return k(norm_index(src_index), norm_sourcetype(src_sourcetype), norm_stratum_field(stratum_field), stratum_value, norm_field_name(field_name))


def source_field_key(src_index, src_sourcetype, field_name):
    """The source-level field key: the __all__ stratum."""
    return field_key(src_index, src_sourcetype, ALL, ALL, field_name)


# Run identity and slot arithmetic.

def slot_start(now, cycle_seconds):
    """UTC start of the cycle slot containing now."""
    cycle_seconds = int(cycle_seconds)
    if cycle_seconds <= 0:
        raise ValueError("cycle_seconds must be positive")
    return int(math.floor(float(now) / cycle_seconds) * cycle_seconds)


def run_id_of(slot_epoch):
    """run_id text for a slot start epoch: YYYYMMDDTHHMMZ."""
    return datetime.datetime.fromtimestamp(int(slot_epoch), datetime.timezone.utc).strftime(RUN_ID_FORMAT)


def slot_start_of(run_id):
    """Slot start epoch of a run_id."""
    dt = datetime.datetime.strptime(run_id, RUN_ID_FORMAT).replace(tzinfo=datetime.timezone.utc)
    return int(dt.timestamp())


def run_id_for(now, cycle_seconds):
    return run_id_of(slot_start(now, cycle_seconds))


def run_id_add(run_id, slots, cycle_seconds):
    """run_id a number of slots after (or before, when negative) run_id."""
    return run_id_of(slot_start_of(run_id) + int(slots) * int(cycle_seconds))


def slots_between(earlier_run_id, later_run_id, cycle_seconds):
    """Whole slots from earlier_run_id to later_run_id; negative when reversed."""
    return (slot_start_of(later_run_id) - slot_start_of(earlier_run_id)) // int(cycle_seconds)


def stamp(epoch):
    """Timestamp prefix of a stash line: MM/DD/YYYY HH:MM:SS +0000."""
    return datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc).strftime("%m/%d/%Y %H:%M:%S +0000")


# Window table.

WINDOW_NAMES = ("discovery", "profile", "stratum_list", "source_day", "source_cycle")


def windows(settings, slot_epoch):
    """Every search window of a run, pinned to the slot: name -> (earliest, latest)."""
    latest = int(slot_epoch) - settings.budget.window_lag_seconds
    return {
        "discovery": (latest - settings.discovery.discovery_window_seconds, latest),
        "profile": (latest - settings.profile.profile_window_seconds, latest),
        "stratum_list": (latest - settings.discovery.stratum_list_window_seconds, latest),
        "source_day": (latest - 86400, latest),
        "source_cycle": (latest - settings.budget.cycle_seconds, latest),
    }


def anchored_window(settings, last_event_time):
    """The window of an anchored first discovery: discovery.discovery_window_seconds long, ending after the second of last_event_time.

    latest is exclusive, so the window ends one second past the floor of
    last_event_time and the newest event is inside it.
    """
    latest = int(math.floor(float(last_event_time))) + 1
    return (latest - settings.discovery.discovery_window_seconds, latest)
