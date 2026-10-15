// The source page's reads: the source row, its strata, every field row of the source,
// the declarations that apply to it and the run records behind its windows.
import { kvGet, kvQuery } from '../../lib/kv';
import { loadRuns } from '../../lib/window';

const FIELD_COLUMNS = [
    'field_key', 'source_key', 'stratum_key', 'field_name', 'level', 'is_rollup', 'rollup_strata', 'is_stratum_field', 'is_default',
    'stratum_value', 'stratum_label', 'presence', 'observed', 'declared', 'origin', 'origin_app', 'origin_conflict',
    'identifier', 'type_guess', 'best_type_id', 'best_type_rate', 'cim_fields', 'cim_via',
    'meaning_human', 'meaning_human_author', 'usage_count', 'usage_alert_count', 'last_seen_time',
    'cur_prof_run_id', 'cur_prof_coverage', 'cur_prof_count', 'cur_prof_events', 'cur_prof_distinct', 'cur_prof_distinct_exact', 'cur_prof_sample_ratio',
    'cur_disc_run_id', 'cur_disc_coverage', 'cur_disc_count', 'cur_disc_events', 'cur_disc_distinct',
];

const DECL_COLUMNS = ['decl_key', 'app', 'app_version', 'conf_file', 'stanza', 'attribute', 'origin_class', 'raw_value', 'fields_declared', 'sharing', 'last_seen_run'];

export async function loadSource(sourceKey) {
    const source = await kvGet('matalog_sources', sourceKey);
    if (!source) return null;
    const [strata, fields, declarations] = await Promise.all([
        kvQuery('matalog_strata', { query: { source_key: sourceKey } }),
        kvQuery('matalog_fields', { query: { source_key: sourceKey }, fields: FIELD_COLUMNS }),
        kvQuery('matalog_declarations', { query: { applies_to_source_keys: sourceKey }, fields: DECL_COLUMNS }),
    ]);
    const runs = await loadRuns([source.updated_run_id, source.last_profiled_run, source.last_discovered_run].concat(strata.map((s) => s.last_seen_run)));
    return { source, strata, fields, declarations, runs };
}

// Declaration counts the config box shows: KV_MODE value, aliases, evals, extracts, reports, lookups, indexed fields.
export function declarationSummary(declarations) {
    const summary = { kvMode: '', aliases: 0, evals: 0, extracts: 0, reports: 0, lookups: 0, indexed: 0, apps: {} };
    declarations.forEach((d) => {
        const attr = d.attribute || '';
        if (attr === 'KV_MODE') summary.kvMode = d.raw_value || '';
        else if (attr.startsWith('FIELDALIAS-')) summary.aliases += 1;
        else if (attr.startsWith('EVAL-')) summary.evals += 1;
        else if (attr.startsWith('EXTRACT-')) summary.extracts += 1;
        else if (attr.startsWith('REPORT-')) summary.reports += 1;
        else if (attr.startsWith('LOOKUP-')) summary.lookups += 1;
        else if (attr === 'INDEXED') summary.indexed += 1;
        const app = `${d.app}${d.app_version ? `@${d.app_version}` : ''}`;
        summary.apps[app] = (summary.apps[app] || 0) + 1;
    });
    return summary;
}
