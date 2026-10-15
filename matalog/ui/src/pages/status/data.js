// The status page's reads: run records newest first and the settings in force from matalog.conf.
import { kvQuery } from '../../lib/kv';
import { restGet } from '../../lib/rest';

export const RUN_COLUMNS = [
    'run_id', 'attempt', 'committed', 'committed_attempt', 'run_mode', 'status', 'started_at', 'finished_at', 'config_hash',
    'searches_issued', 'searches_failed', 'write_searches', 'events_scanned', 'events_matched', 'search_seconds', 'wall_seconds',
    'peak_concurrency', 'budget_exhausted', 'rows_written', 'per_step', 'errors', 'budget', 'scan_ratio_max',
    'sources_total', 'sources_due', 'sources_profiled', 'sources_deferred', 'strata_total', 'strata_due', 'strata_discovered', 'strata_deferred', 'strata_over_cap',
    'strata_profile_due', 'strata_profiled', 'indexes_total', 'indexes_scanned', 'indexes_sourceless',
    'fields_present', 'fields_new', 'objects_total', 'objects_parsed', 'objects_partial', 'objects_failed',
    'cim_datasets', 'cim_datasets_unresolved', 'cim_mapped', 'audit_watermark', 'type_versions_hash', 'reclassified_types',
];

// Settings stanzas the page lays out as tables; stratum stanzas are listed after them.
export const SETTING_GROUPS = ['budget', 'discovery', 'profile', 'classify', 'usage', 'write', 'rebuild', 'retention'];

// The conf read needs read access to matalog.conf, which the admin roles have; a reader without it gets
// confError and the run records.
export async function loadStatus() {
    const [runs, conf] = await Promise.all([
        kvQuery('matalog_runs', { fields: RUN_COLUMNS, sort: 'started_at:-1', limit: 500 }),
        restGet('configs/conf-matalog').then(
            (body) => ({ body, error: null }),
            (error) => ({ body: { entry: [] }, error })
        ),
    ]);
    const settings = {};
    const strata = [];
    (conf.body.entry || []).forEach((entry) => {
        const content = {};
        Object.entries(entry.content || {}).forEach(([key, value]) => {
            if (key.startsWith('eai:') || key === 'disabled') return;
            content[key] = value;
        });
        if (entry.name.startsWith('stratum:')) strata.push({ sourcetype: entry.name.slice('stratum:'.length), ...content });
        else settings[entry.name] = content;
    });
    runs.sort((a, b) => (Number(b.started_at) || 0) - (Number(a.started_at) || 0));
    return { runs, settings, strata, confError: conf.error };
}

// Rows the index received and documents the collections received, from a run's rows_written map.
export function rowsWritten(run) {
    const map = run.rows_written && typeof run.rows_written === 'object' ? run.rows_written : {};
    let index = 0;
    let kv = 0;
    Object.entries(map).forEach(([key, value]) => {
        if (key.startsWith('matalog_')) kv += Number(value) || 0;
        else index += Number(value) || 0;
    });
    return { index, kv };
}

export function errorCount(run) {
    return Array.isArray(run.errors) ? run.errors.length : 0;
}
