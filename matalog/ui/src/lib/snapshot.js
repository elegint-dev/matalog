// The newest measured snapshot of a field row: the profile when one exists, else the discovery.
import { bool } from './format';

export function snapshot(row) {
    if (!row) return null;
    if (row.cur_prof_run_id) {
        return {
            mode: 'profile',
            runId: row.cur_prof_run_id,
            count: Number(row.cur_prof_count) || 0,
            events: Number(row.cur_prof_events) || 0,
            coverage: Number(row.cur_prof_coverage) || 0,
            distinct: Number(row.cur_prof_distinct) || 0,
            exact: bool(row.cur_prof_distinct_exact),
            ratio: Number(row.cur_prof_sample_ratio) || 1,
        };
    }
    if (row.cur_disc_run_id) {
        return {
            mode: 'discovery',
            runId: row.cur_disc_run_id,
            count: Number(row.cur_disc_count) || 0,
            events: Number(row.cur_disc_events) || 0,
            coverage: Number(row.cur_disc_coverage) || 0,
            distinct: Number(row.cur_disc_distinct) || 0,
            exact: null,
            ratio: 1,
        };
    }
    return null;
}

export function coverageOf(row) {
    const s = snapshot(row);
    return s ? s.coverage : 0;
}
