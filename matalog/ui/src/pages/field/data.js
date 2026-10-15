// The field page's reads: the row, its siblings across levels, meaning layers, declarations,
// usage edges with their objects, type edges, the source's stratum rows, the run records behind the
// snapshot windows, and the committed profile history from the index.
import { kvGet, kvQuery, valuesStored } from '../../lib/kv';
import { oneshot, splQuote } from '../../lib/search';
import { loadRuns } from '../../lib/window';
import { bool, list } from '../../lib/format';

const HISTORY_EARLIEST = '-30d@d';
// The index pattern of an index_only edge (scope_text index=<pattern> sourcetype=*), * a wildcard.
const INDEX_ONLY_RE = /^index=(\S+) sourcetype=\*$/;

function indexOnlyMatches(scopeText, index) {
    const m = INDEX_ONLY_RE.exec(scopeText || '');
    if (!m || !index) return false;
    const re = new RegExp(`^${m[1].split('*').map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`, 'i');
    return re.test(index);
}
// Slots can sit ahead of the clock when a run was pinned, so the window reaches forward too.
const HISTORY_LATEST = '+7d@d';

// A rollup's history row has the headline's basis: the whole source as the merged rollup of that run reports it.
// The rows come back per run and stratum (the field's count and the stratum's events in that run); each stratum's
// latest snapshot is carried forward, a run counts only when it searched a stratum that carries the field, and a
// run in which some active stratum has no snapshot yet is left out rather than shown on the slice's basis.
// A value can hold a newline, so a row can span a few lines; what is left out is an event that merged several
// rows (a second stash timestamp after a newline), whose counts are not one row's. linecount<=64 prunes the
// large merges before field extraction, since one row never reaches that many lines.
const MERGED = ' | regex _raw!="\\n\\d\\d/\\d\\d/\\d{4} \\d\\d:\\d\\d:\\d\\d \\+0000 "';

export function historySPL(row) {
    const committed = '[search index=matalog_profiles kind=commit | stats max(attempt) as attempt by run_id | fields run_id attempt]';
    if (bool(row.is_rollup)) {
        return (
            `search index=matalog_profiles linecount<=64 source_key=${splQuote(row.source_key)} ((kind=field field_name=${splQuote(row.field_name)}) OR (kind=stratum mode!=listing)) ${committed}` +
            MERGED +
            ' | eval fcount=if(kind=="field", count, null()), fdistinct=if(kind=="field", distinct, null()), fexact=if(kind=="field", distinct_exact, null()), sevents=if(kind=="stratum", events_seen, null())' +
            ' | stats min(_time) as _time max(fcount) as count max(fdistinct) as distinct max(fexact) as distinct_exact max(sevents) as events by run_id mode stratum_key' +
            ' | sort run_id stratum_key'
        );
    }
    return (
        `search index=matalog_profiles linecount<=64 kind=field field_key=${splQuote(row.field_key)} ${committed}` +
        MERGED +
        ' | stats max(count) as count max(events_in_stratum) as events max(distinct) as distinct max(coverage) as coverage by _time run_id mode' +
        ' | sort run_id'
    );
}

function point(r, count, events, distinct, distinctExact = null) {
    return {
        time: Date.parse(r._time) / 1000,
        runId: r.run_id,
        mode: r.mode,
        count,
        events,
        distinct,
        // false when the distinct is a maximum over several strata, or a capped single stratum; null when not a rollup
        distinctExact,
        coverage: events > 0 ? Math.round((count / events) * 10000) / 10000 : 0,
    };
}

// Per mode, the latest snapshot of every stratum as of each run; a run's row sums the active strata. The distinct is
// the maximum over the strata carrying the field, exact only when one stratum carries it with an exact count.
export function mergeRollupHistory(rows, carriers, active) {
    const runs = new Map();
    rows.forEach((r) => {
        const key = `${r.mode}|${r.run_id}`;
        if (!runs.has(key)) runs.set(key, { first: r, rows: [] });
        runs.get(key).rows.push(r);
    });
    const latest = {};
    const points = [];
    const skipped = [];
    runs.forEach(({ first, rows: own }) => {
        const snapshots = latest[first.mode] || (latest[first.mode] = new Map());
        let carried = false;
        own.forEach((r) => {
            if (r.events === '' || r.events == null || !r.stratum_key) return;
            snapshots.set(r.stratum_key, { count: Number(r.count) || 0, events: Number(r.events) || 0, distinct: Number(r.distinct) || 0, exact: Number(r.distinct_exact) === 1 });
            if (carriers.includes(r.stratum_key)) carried = true;
        });
        if (!carried) return;
        if (active.some((k) => !snapshots.has(k))) {
            skipped.push(first.run_id);
            return;
        }
        let count = 0;
        let events = 0;
        let distinct = 0;
        let carrying = 0;
        let exact = false;
        active.forEach((k) => {
            const snap = snapshots.get(k);
            count += snap.count;
            events += snap.events;
            distinct = Math.max(distinct, snap.distinct);
            if (snap.count > 0) {
                carrying += 1;
                exact = snap.exact;
            }
        });
        points.push(point(first, count, events, distinct, carrying === 1 && exact));
    });
    return { points, skipped };
}

export async function loadHistory(row) {
    const spl = historySPL(row);
    if (!bool(row.is_rollup)) {
        const results = await oneshot(spl, { earliest: HISTORY_EARLIEST, latest: HISTORY_LATEST });
        return { points: results.map((r) => point(r, Number(r.count) || 0, Number(r.events) || 0, Number(r.distinct) || 0)), spl, skipped: [] };
    }
    const [results, carrierRows, activeRows] = await Promise.all([
        oneshot(spl, { earliest: HISTORY_EARLIEST, latest: HISTORY_LATEST }),
        kvQuery('matalog_fields', { query: { source_key: row.source_key, field_name: row.field_name, level: 'stratum' }, fields: ['stratum_key'] }),
        kvQuery('matalog_strata', { query: { source_key: row.source_key, level: 'stratum', state: 'active' }, fields: ['stratum_key'] }),
    ]);
    const carriers = carrierRows.map((r) => r.stratum_key).filter(Boolean);
    const active = activeRows.map((r) => r.stratum_key).filter(Boolean);
    const merged = mergeRollupHistory(results, carriers, active);
    return { points: merged.points, spl, skipped: merged.skipped };
}

export async function loadField(fieldKey) {
    const row = await kvGet('matalog_fields', fieldKey);
    if (!row) return null;
    const siblings = await kvQuery('matalog_fields', { query: { source_key: row.source_key, field_name: row.field_name } });
    const sourceRow = siblings.find((r) => r.level === 'source') || row;
    const strata = siblings.filter((r) => r.level === 'stratum');
    const declKeys = Array.from(new Set(list(sourceRow.origin_candidates).concat(list(row.origin_candidates))));
    const runIds = siblings.flatMap((r) => [r.cur_prof_run_id, r.cur_disc_run_id]);
    const [source, cim, meanings, declarations, usage, types, typeDefs, stored, strataRows, runs] = await Promise.all([
        kvGet('matalog_sources', row.source_key),
        kvQuery('matalog_cim_coverage', { query: { field_key: sourceRow.field_key } }),
        kvQuery('matalog_meanings', { query: { field_key: sourceRow.field_key } }),
        declKeys.length ? kvQuery('matalog_declarations', { query: { decl_key: { $in: declKeys } } }) : [],
        kvQuery('matalog_usage', { query: { field_name: row.field_name } }),
        kvQuery('matalog_field_types', { query: { field_key: row.field_key } }),
        kvQuery('matalog_semantic_types', { fields: ['type_id', 'label', 'description', 'specificity', 'origin', 'match_threshold', 'min_distinct'] }),
        valuesStored(),
        kvQuery('matalog_strata', {
            query: { source_key: row.source_key },
            fields: ['stratum_key', 'stratum_value', 'stratum_label', 'level', 'state', 'listed_events', 'cur_run_id', 'cur_earliest', 'cur_latest', 'cur_truncated', 'cur_events_seen', 'last_profiled_run'],
        }),
        loadRuns(runIds),
    ]);
    const scoped = usage.filter((e) => list(e.resolved_field_keys).includes(sourceRow.field_key));
    const unscoped = usage.filter((e) => e.resolution === 'unscoped');
    // Edges whose search names an index this field lives in but no sourcetype: listed, never counted.
    const indexOnly = usage.filter((e) => e.resolution === 'index_only' && indexOnlyMatches(e.scope_text, sourceRow.src_index || source?.src_index));
    const objectKeys = Array.from(new Set(scoped.map((e) => e.object_key)));
    const objects = objectKeys.length
        ? await kvQuery('matalog_objects', { query: { object_key: { $in: objectKeys } } })
        : [];
    return { row, sourceRow, strata, source, cim, meanings, declarations, scoped, unscoped, indexOnly, objects, types, typeDefs, stored, strataRows, runs };
}
