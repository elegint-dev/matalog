// The lookup's reads: sources whose sourcetype, search name, source paths or config apps contain the text, field
// rows by name, sourcetype or data model field, plus the rows a card needs, the run records behind the snapshot
// windows, and the most used fields for the empty state.
import { kvQuery, regexEscape, valuesStored } from '../../lib/kv';
import { loadRuns } from '../../lib/window';

const CARD_LIMIT = 40;
const MOST_USED = 5;

function runsOf(rows, sources = []) {
    return loadRuns(rows.flatMap((r) => [r.cur_prof_run_id, r.cur_disc_run_id]).concat(sources.map((s) => s.updated_run_id)));
}

// The five most used source-level fields, Splunk default fields left out, for the empty lookup.
export async function mostUsed() {
    return kvQuery('matalog_fields', {
        query: { level: 'source', presence: 'present', is_default: { $ne: 1 }, usage_count: { $gt: 0 } },
        fields: ['field_key', 'field_name', 'src_index', 'src_sourcetype', 'usage_count', 'usage_alert_count'],
        sort: 'usage_count:-1',
        limit: MOST_USED,
    });
}

function unique(values) {
    return Array.from(new Set(values.filter(Boolean)));
}

async function sourcesFor(rows) {
    const keys = unique(rows.map((r) => r.source_key));
    if (!keys.length) return {};
    const sources = await kvQuery('matalog_sources', {
        query: { source_key: { $in: keys } },
        fields: ['source_key', 'src_index', 'src_sourcetype', 'search_sourcetype', 'strata_count', 'strata_deferred', 'daily_events', 'usage_alert_count'],
    });
    const map = {};
    sources.forEach((s) => {
        map[s.source_key] = s;
    });
    return map;
}

async function losersFor(rows) {
    const keys = unique(
        rows.flatMap((r) => (Array.isArray(r.origin_candidates) ? r.origin_candidates : []).filter((key) => key !== r.origin_decl_key))
    );
    if (!keys.length) return {};
    const decls = await kvQuery('matalog_declarations', {
        query: { decl_key: { $in: keys } },
        fields: ['decl_key', 'app', 'app_version', 'conf_file', 'stanza', 'attribute', 'sharing'],
    });
    const map = {};
    decls.forEach((d) => {
        map[d.decl_key] = d;
    });
    return map;
}

async function strataFor(cards) {
    if (!cards.length) return [];
    const names = unique(cards.map((r) => r.field_name));
    const sourceKeys = unique(cards.map((r) => r.source_key));
    return kvQuery('matalog_fields', {
        query: { level: 'stratum', field_name: { $in: names }, source_key: { $in: sourceKeys } },
        fields: [
            'field_key', 'source_key', 'field_name', 'stratum_value', 'stratum_label', 'presence',
            'cur_prof_run_id', 'cur_prof_coverage', 'cur_prof_count', 'cur_prof_events', 'cur_prof_distinct', 'cur_prof_distinct_exact', 'cur_prof_sample_ratio',
            'cur_disc_run_id', 'cur_disc_coverage', 'cur_disc_count', 'cur_disc_events', 'cur_disc_distinct',
        ],
    });
}

const SOURCE_MATCH_COLUMNS = [
    'source_key', 'src_index', 'src_sourcetype', 'search_sourcetype', 'sources_top', 'config_apps', 'state', 'daily_events',
    'field_count', 'usage_count', 'usage_alert_count', 'last_human_search_time', 'last_human_search_user', 'updated_run_id',
];

function nameRank(name, lower) {
    const value = (name || '').toLowerCase();
    if (value === lower) return 0;
    if (value.startsWith(lower)) return 1;
    return 2;
}

// Sources whose sourcetype, search sourcetype, source paths (sources_top) or config app names contain the text:
// exact sourcetype first, then prefix, substring, a source path, an app; then usage and daily events.
export async function sourceMatches(q) {
    const pattern = { $regex: regexEscape(q), $options: 'i' };
    const rows = await kvQuery('matalog_sources', {
        query: { $or: [{ src_sourcetype: pattern }, { search_sourcetype: pattern }, { sources_top: pattern }, { config_apps: pattern }] },
        fields: SOURCE_MATCH_COLUMNS,
        limit: 2000,
    });
    const lower = q.toLowerCase();
    return rows
        .map((row) => {
            const via = [];
            let rank = 5;
            const st = row.src_sourcetype || '';
            const sst = row.search_sourcetype || '';
            if (st.toLowerCase().includes(lower)) {
                via.push('sourcetype');
                rank = Math.min(rank, nameRank(st, lower));
            }
            if (sst && sst !== st && sst.toLowerCase().includes(lower)) {
                via.push('search sourcetype');
                rank = Math.min(rank, nameRank(sst, lower));
            }
            if ((Array.isArray(row.sources_top) ? row.sources_top : []).some((v) => String(v).toLowerCase().includes(lower))) {
                via.push('source');
                rank = Math.min(rank, 3);
            }
            if ((Array.isArray(row.config_apps) ? row.config_apps : []).some((a) => String(a).split('@')[0].toLowerCase().includes(lower))) {
                via.push('app');
                rank = Math.min(rank, 4);
            }
            return { row, via, rank };
        })
        .filter((m) => m.via.length)
        .sort(
            (a, b) =>
                a.rank - b.rank ||
                (Number(b.row.usage_count) || 0) - (Number(a.row.usage_count) || 0) ||
                (Number(b.row.daily_events) || 0) - (Number(a.row.daily_events) || 0) ||
                a.row.src_index.localeCompare(b.row.src_index) ||
                a.row.src_sourcetype.localeCompare(b.row.src_sourcetype)
        );
}

// Words of a field name: split on separators and on camel case, so client.ipAddress gives client, ip, address.
export function nameWords(name) {
    return name
        .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
        .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
        .split(/[^A-Za-z0-9]+| /)
        .filter(Boolean)
        .map((w) => w.toLowerCase());
}

export async function lookupByText(q) {
    const pattern = regexEscape(q);
    const rows = await kvQuery('matalog_fields', {
        query: {
            level: 'source',
            $or: [{ field_name: { $regex: pattern, $options: 'i' } }, { src_sourcetype: { $regex: pattern, $options: 'i' } }],
        },
        limit: 2000,
    });
    const cards = rows.filter((r) => r.field_name === q).slice(0, CARD_LIMIT);
    const lower = q.toLowerCase();
    const others = rows
        .filter((r) => r.field_name !== q)
        .map((r) => {
            const name = r.field_name.toLowerCase();
            const words = nameWords(r.field_name);
            let kind = 'sourcetype';
            if (name === lower) kind = 'name, other case';
            else if (name.startsWith(lower)) kind = 'prefix';
            else if (words.includes(lower)) kind = 'word';
            else if (words.some((w) => w.startsWith(lower))) kind = 'word prefix';
            else if (name.includes(lower)) kind = 'substring';
            return { row: r, kind };
        });
    const matched = await sourceMatches(q);
    const [sources, losers, strata, cim, stored, runs] = await Promise.all([
        sourcesFor(rows),
        losersFor(cards),
        strataFor(cards),
        kvQuery('matalog_cim_coverage', {
            query: { cim_field: { $regex: pattern, $options: 'i' } },
            fields: ['cim_dataset', 'cim_field', 'mapped', 'source_key', 'src_index', 'src_sourcetype', 'field_key', 'field_name'],
        }),
        valuesStored(),
        runsOf(rows, matched.map((m) => m.row)),
    ]);
    return { cards, others, matched, sources, losers, strata, cim, unmapped: [], stored, runs };
}

export async function lookupByDataModelField(dataset, field) {
    const cim = await kvQuery('matalog_cim_coverage', {
        query: { cim_dataset: dataset, cim_field: field },
        fields: ['cim_dataset', 'cim_field', 'mapped', 'source_key', 'src_index', 'src_sourcetype', 'field_key', 'field_name', 'cim_via', 'coverage'],
    });
    const mappedKeys = unique(cim.filter((r) => Number(r.mapped) === 1).map((r) => r.field_key));
    const cards = mappedKeys.length
        ? await kvQuery('matalog_fields', { query: { field_key: { $in: mappedKeys } }, limit: CARD_LIMIT })
        : [];
    const [sources, losers, strata, stored, runs] = await Promise.all([sourcesFor(cards.concat(cim)), losersFor(cards), strataFor(cards), valuesStored(), runsOf(cards)]);
    return {
        cards,
        others: [],
        matched: [],
        sources,
        losers,
        strata,
        cim,
        unmapped: cim.filter((r) => Number(r.mapped) !== 1),
        stored,
        runs,
    };
}
