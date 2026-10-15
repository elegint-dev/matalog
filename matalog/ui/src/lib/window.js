// The search windows behind the counts on a row. Field and source rows carry run ids, not bounds; the bounds come
// from the run record of that run (matalog_runs.budget: budget.window_lag_seconds with profile.profile_window_seconds,
// discovery.discovery_window_seconds, discovery.stratum_list_window_seconds, budget.cycle_seconds or 86400 for the
// trailing day). Stratum rows carry their discovery window in cur_earliest and cur_latest.
import { kvQuery } from './kv';
import { dateTime, num, slot, slotEpoch } from './format';

export const WINDOW_SOURCE =
    'Window bounds are computed from the run record (matalog_runs.budget of the run named: budget.window_lag_seconds and ' +
    'profile.profile_window_seconds, discovery.discovery_window_seconds, discovery.stratum_list_window_seconds, budget.cycle_seconds or 86,400 s for a day); ' +
    'stratum rows carry their discovery window in cur_earliest and cur_latest.';

// Run records by run_id, for the runs the rows name.
export async function loadRuns(runIds) {
    const ids = Array.from(new Set(runIds.filter(Boolean)));
    if (!ids.length) return {};
    const rows = await kvQuery('matalog_runs', { query: { run_id: { $in: ids } }, fields: ['run_id', 'budget', 'committed'] });
    const map = {};
    rows.forEach((r) => {
        map[r.run_id] = r;
    });
    return map;
}

function setting(run, group, key) {
    const budget = run && run.budget && typeof run.budget === 'object' ? run.budget : null;
    const values = budget && budget[group];
    const v = values ? Number(values[key]) : NaN;
    return Number.isNaN(v) ? null : v;
}

const LENGTHS = {
    profile: ['profile', 'profile_window_seconds'],
    discovery: ['discovery', 'discovery_window_seconds'],
    listing: ['discovery', 'stratum_list_window_seconds'],
    cycle: ['budget', 'cycle_seconds'],
};

// {earliest, latest} of the profile, discovery, cycle or day window of a run; null when the run record is gone.
export function runWindow(runId, kind, runs) {
    const start = slotEpoch(runId);
    const run = runs ? runs[runId] : null;
    if (start === null || !run) return null;
    const lag = setting(run, 'budget', 'window_lag_seconds');
    const length = LENGTHS[kind] ? setting(run, LENGTHS[kind][0], LENGTHS[kind][1]) : 86400;
    if (lag === null || length === null) return null;
    const latest = start - lag;
    return { earliest: latest - length, latest };
}

export function span(w) {
    return `${dateTime(w.earliest)} to ${dateTime(w.latest)}`;
}

const LABELS = { profile: 'the profile window', discovery: 'the discovery window', listing: 'the listing window', cycle: 'the cycle', day: 'the day' };

// "the profile window (2026-10-12 20:55Z to 2026-10-13 20:55Z)", or the run when its record is gone.
export function windowText(runId, kind, runs) {
    const w = runWindow(runId, kind, runs);
    if (!w) return `${LABELS[kind]} of run ${slot(runId)} (bounds unknown, no run record)`;
    return `${LABELS[kind]} (${span(w)})`;
}

// A snapshot's count against its denominator with the window it was measured in:
// "1,938 of 20,846 events in the profile window (a to b)", "... in a 1 in 10 sample of the profile window (...)".
export function countText(snap, runs, { anchored = false, truncated = false } = {}) {
    if (!snap) return 'not measured';
    const sample = snap.ratio > 1 ? `a 1 in ${num(snap.ratio)} sample of ` : '';
    const where = anchored
        ? `the discovery window anchored at the source's last event (run ${slot(snap.runId)})`
        : windowText(snap.runId, snap.mode, runs);
    const head = truncated ? ' (the search stopped at its head cap before the window ended)' : '';
    return `${num(snap.count)} of ${num(snap.events)} events in ${sample}${where}${head}`;
}
