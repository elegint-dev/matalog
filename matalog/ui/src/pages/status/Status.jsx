import React, { useEffect, useMemo, useRef, useState } from 'react';
import Table from '@splunk/react-ui/Table';
import Chip from '@splunk/react-ui/Chip';
import Link from '@splunk/react-ui/Link';
import { errorCount, loadStatus, rowsWritten, SETTING_GROUPS } from './data';
import { age, bool, dateTime, list, num, pct, plural, seconds, slot } from '../../lib/format';
import { sourcesURL } from '../../lib/links';
import { Box, Code, H, Kpi, Mono, Muted, NoWrap, Row, Wrap } from '../../components/styles';
import { Failure, Loading } from '../../components/Page';
import { Frame, PAD, Panel, Tip, useWidth } from '../../components/HistoryChart';

const CHART_RUNS = 30;
const STEPS = ['S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7', 'S8', 'S10'];
const STEP_NAMES = {
    S1: 'sources',
    S2: 'strata',
    S3: 'discovery',
    S4: 'profile',
    S5: 'declarations',
    S6: 'usage',
    S7: 'classify',
    S8: 'data models',
    S10: 'commit',
};

function CostChart({ runs, budget }) {
    const ref = useRef(null);
    const width = useWidth(ref);
    const [hover, setHover] = useState(null);
    const points = useMemo(
        () =>
            runs
                .slice(0, CHART_RUNS)
                .map((r) => ({
                    time: Number(r.started_at) || 0,
                    runId: r.run_id,
                    mode: r.run_mode,
                    status: r.status,
                    searches: Number(r.searches_issued) || 0,
                    scanned: Number(r.events_scanned) || 0,
                    searchSeconds: Number(r.search_seconds) || 0,
                    wallSeconds: Number(r.wall_seconds) || 0,
                    exhausted: r.budget_exhausted || '',
                }))
                .sort((a, b) => a.time - b.time),
        [runs]
    );
    if (!points.length) return <Muted>no run records</Muted>;
    const p = hover !== null ? points[hover] : null;
    const panel = (title, key, format, ceiling) => (
        <Panel
            title={`${title}${ceiling ? `, ceiling ${format(ceiling)}` : ''}`}
            points={points}
            valueOf={(d) => d[key]}
            format={format}
            max={Math.max(1, ...points.map((d) => d[key]))}
            width={width}
            height={110}
            hover={hover}
            onHover={setHover}
        />
    );
    return (
        <Frame ref={ref}>
            {panel('searches issued', 'searches', num, budget.max_searches_per_cycle)}
            {panel('events scanned', 'scanned', num, budget.max_events_scanned_per_cycle)}
            {panel('search seconds', 'searchSeconds', seconds, budget.max_search_seconds_per_cycle)}
            {panel('wall seconds', 'wallSeconds', seconds, budget.max_wall_seconds_per_cycle)}
            {p ? (
                <Tip style={{ left: Math.min(width - 320, Math.max(0, PAD.left + 8)) }}>
                    run {slot(p.runId)}, {p.mode}, {p.status}: <b>{num(p.searches)}</b> searches, <b>{num(p.scanned)}</b> scanned,{' '}
                    <b>{seconds(p.searchSeconds)}</b> search, <b>{seconds(p.wallSeconds)}</b> wall{p.exhausted ? `, ceiling hit: ${p.exhausted}` : ''}
                </Tip>
            ) : null}
        </Frame>
    );
}

// A setting as text: numbers with thousands separators, lists broken at commas so a cell can wrap there.
function settingText(value) {
    if (value === undefined || value === null) return '';
    const text = String(value);
    if (/^-?\d+(\.\d+)?$/.test(text)) return num(text);
    return text.replace(/,/g, ', ');
}

function budgetOf(run) {
    const b = run && run.budget && typeof run.budget === 'object' ? run.budget : {};
    return b.budget || {};
}

function ratioCell(value, ceiling) {
    const v = Number(value) || 0;
    const c = Number(ceiling) || 0;
    return (
        <Muted>
            this run, of {num(c)} allowed per cycle{c ? ` (${pct(v / c)})` : ''}
        </Muted>
    );
}

export default function Status() {
    const [state, setState] = useState({ loading: true, error: null, data: null });
    useEffect(() => {
        let live = true;
        loadStatus().then(
            (data) => live && setState({ loading: false, error: null, data }),
            (error) => live && setState({ loading: false, error, data: null })
        );
        return () => {
            live = false;
        };
    }, []);

    if (state.loading) {
        return (
            <Wrap>
                <Loading what="reading matalog_runs and matalog.conf" />
            </Wrap>
        );
    }
    if (!state.data) {
        return (
            <Wrap>
                <Failure error={state.error} />
            </Wrap>
        );
    }
    const { runs, settings, strata, confError } = state.data;
    const newest = runs[0];
    const usageRun = runs.find((r) => r.objects_total !== undefined && r.objects_total !== '');
    const cimRun = runs.find((r) => r.cim_datasets !== undefined && r.cim_datasets !== '');
    const budget = newest ? budgetOf(newest) : settings.budget || {};
    const confBudget = settings.budget || {};
    const perStep = newest && newest.per_step && typeof newest.per_step === 'object' ? newest.per_step : {};
    const newestWritten = newest ? rowsWritten(newest) : { index: 0, kv: 0 };
    const unparsed = usageRun ? Math.max(0, (Number(usageRun.objects_total) || 0) - (Number(usageRun.objects_parsed) || 0)) : null;
    const runBudget = newest && newest.budget && typeof newest.budget === 'object' ? newest.budget : {};

    return (
        <Wrap>
            <Row align="center">
                <Muted>status: {plural(runs.length, 'run record')} in <Mono>matalog_runs</Mono>, newest first. <Link to={sourcesURL()}>Sources</Link></Muted>
            </Row>
            {newest ? (
                <Box flex="1 1 100%">
                    <Row style={{ gap: 28 }}>
                        <Kpi>
                            <Muted>newest run</Muted>
                            <b>{slot(newest.run_id)}</b>
                            <Muted>
                                {newest.status}, {newest.run_mode}, attempt {num(newest.attempt)}{bool(newest.committed) ? ', committed' : ', not committed'}; started {age(newest.started_at)} ago
                            </Muted>
                        </Kpi>
                        <Kpi>
                            <Muted>searches issued</Muted>
                            <b>{num(newest.searches_issued || 0)}</b>
                            {ratioCell(newest.searches_issued, budget.max_searches_per_cycle)}
                        </Kpi>
                        <Kpi>
                            <Muted>events scanned</Muted>
                            <b>{num(newest.events_scanned || 0)}</b>
                            {ratioCell(newest.events_scanned, budget.max_events_scanned_per_cycle)}
                        </Kpi>
                        <Kpi>
                            <Muted>search seconds</Muted>
                            <b>{seconds(newest.search_seconds || 0)}</b>
                            {ratioCell(newest.search_seconds, budget.max_search_seconds_per_cycle)}
                        </Kpi>
                        <Kpi>
                            <Muted>wall seconds</Muted>
                            <b>{seconds(newest.wall_seconds || 0)}</b>
                            {ratioCell(newest.wall_seconds, budget.max_wall_seconds_per_cycle)}
                        </Kpi>
                        <Kpi>
                            <Muted>rows written</Muted>
                            <b>{num(newestWritten.index)}</b>
                            <Muted>summary index rows this run; {num(newestWritten.kv)} collection documents</Muted>
                        </Kpi>
                        <Kpi>
                            <Muted>unparsed objects</Muted>
                            <b>{unparsed === null ? 'none' : num(unparsed)}</b>
                            <Muted>
                                {usageRun
                                    ? `of ${num(usageRun.objects_total)} listed: ${num(usageRun.objects_partial || 0)} partial, ${num(usageRun.objects_failed || 0)} failed, run ${slot(usageRun.run_id)}`
                                    : 'no usage pass recorded'}
                            </Muted>
                        </Kpi>
                        <Kpi>
                            <Muted>unresolved data model constraints</Muted>
                            <b>{cimRun ? num(cimRun.cim_datasets_unresolved || 0) : 'none'}</b>
                            <Muted>{cimRun ? `of ${num(cimRun.cim_datasets)} datasets, ${num(cimRun.cim_mapped || 0)} mapped rows, run ${slot(cimRun.run_id)}` : 'no data model pass recorded'}</Muted>
                        </Kpi>
                        <Kpi>
                            <Muted>config hash</Muted>
                            <b><Mono>{newest.config_hash}</Mono></b>
                            <Muted>
                                types {newest.type_versions_hash ? <Mono>{newest.type_versions_hash}</Mono> : 'none'}; budget exhausted: {newest.budget_exhausted || 'no'}
                            </Muted>
                        </Kpi>
                    </Row>
                </Box>
            ) : (
                <Muted>no run record yet</Muted>
            )}
            <Row>
                <Box flex="3 1 560px">
                    <H>Cost per run, last {num(Math.min(CHART_RUNS, runs.length))} runs</H>
                    <CostChart runs={runs} budget={budget} />
                </Box>
                <Box flex="2 1 440px">
                    <H>Steps of {newest ? slot(newest.run_id) : 'the newest run'}</H>
                    <Table>
                        <Table.Head>
                            <Table.HeadCell width={130}>step</Table.HeadCell>
                            <Table.HeadCell width={80} align="right">searches</Table.HeadCell>
                            <Table.HeadCell width={90} align="right">scanned</Table.HeadCell>
                            <Table.HeadCell width={80} align="right">search s</Table.HeadCell>
                            <Table.HeadCell width={70} align="right">rows</Table.HeadCell>
                            <Table.HeadCell width={70} align="right">wall s</Table.HeadCell>
                        </Table.Head>
                        <Table.Body>
                            {STEPS.filter((s) => perStep[s]).map((s) => (
                                <Table.Row key={s}>
                                    <Table.Cell>
                                        <span>{s} <Muted>{STEP_NAMES[s]}</Muted></span>
                                    </Table.Cell>
                                    <Table.Cell align="right">{num(perStep[s].searches || 0)}</Table.Cell>
                                    <Table.Cell align="right">{num(perStep[s].scanned || 0)}</Table.Cell>
                                    <Table.Cell align="right">{seconds(perStep[s].seconds || 0)}</Table.Cell>
                                    <Table.Cell align="right">{num(perStep[s].rows_written || 0)}</Table.Cell>
                                    <Table.Cell align="right">{seconds(perStep[s].wall_seconds || 0)}</Table.Cell>
                                </Table.Row>
                            ))}
                        </Table.Body>
                    </Table>
                    {newest ? (
                        <Muted>
                            {num(newest.sources_due || 0)} of {num(newest.sources_total || 0)} sources due, {num(newest.sources_profiled || 0)} profiled, {num(newest.sources_deferred || 0)} deferred;{' '}
                            {num(newest.strata_discovered || 0)} of {num(newest.strata_due || 0)} strata discovered, {num(newest.strata_deferred || 0)} deferred, {num(newest.strata_over_cap || 0)} over cap;{' '}
                            {num(newest.strata_profiled || 0)} of {num(newest.strata_profile_due || 0)} strata due profiled;{' '}
                            {num(newest.indexes_scanned || 0)} of {num(newest.indexes_total || 0)} indexes scanned{list(newest.indexes_sourceless).length ? ` (${list(newest.indexes_sourceless).join(', ')} without a sourcetype)` : ''};{' '}
                            {num(newest.fields_present || 0)} field rows present over the sources discovered this run, {num(newest.fields_new || 0)} first seen this run; worst scan ratio {Number(newest.scan_ratio_max || 0).toFixed(2)}; peak concurrency {num(newest.peak_concurrency || 0)};{' '}
                            audit watermark {dateTime(newest.audit_watermark)}
                        </Muted>
                    ) : null}
                    {newest && list(newest.errors).length ? (
                        <Table>
                            <Table.Head>
                                <Table.HeadCell width={60}>step</Table.HeadCell>
                                <Table.HeadCell width={140}>subject</Table.HeadCell>
                                <Table.HeadCell>message</Table.HeadCell>
                            </Table.Head>
                            <Table.Body>
                                {list(newest.errors).map((e, i) => (
                                    <Table.Row key={`${e.step}:${e.subject}:${i}`}>
                                        <Table.Cell>{e.step}</Table.Cell>
                                        <Table.Cell>{e.subject}</Table.Cell>
                                        <Table.Cell><Mono>{e.message}</Mono></Table.Cell>
                                    </Table.Row>
                                ))}
                            </Table.Body>
                        </Table>
                    ) : null}
                </Box>
            </Row>
            <Box flex="1 1 100%">
                <H>Runs</H>
                <Table stripeRows>
                    <Table.Head>
                        <Table.HeadCell width={170}>run</Table.HeadCell>
                        <Table.HeadCell width={90}>status</Table.HeadCell>
                        <Table.HeadCell width={80}>mode</Table.HeadCell>
                        <Table.HeadCell width={100} align="right">searches</Table.HeadCell>
                        <Table.HeadCell width={120} align="right">events scanned</Table.HeadCell>
                        <Table.HeadCell width={90} align="right">search s</Table.HeadCell>
                        <Table.HeadCell width={80} align="right">wall s</Table.HeadCell>
                        <Table.HeadCell width={150} align="right">rows written</Table.HeadCell>
                        <Table.HeadCell width={110}>budget exhausted</Table.HeadCell>
                        <Table.HeadCell width={70} align="right">errors</Table.HeadCell>
                        <Table.HeadCell>started</Table.HeadCell>
                    </Table.Head>
                    <Table.Body>
                        {runs.map((r) => {
                            const written = rowsWritten(r);
                            return (
                                <Table.Row key={r.run_id + ':' + r.attempt}>
                                    <Table.Cell>
                                        <NoWrap>
                                            {slot(r.run_id)}
                                            {Number(r.attempt) > 1 ? <Muted> attempt {num(r.attempt)}</Muted> : null}
                                        </NoWrap>
                                    </Table.Cell>
                                    <Table.Cell>
                                        {r.status}
                                        {!bool(r.committed) ? <Chip appearance="outline">uncommitted</Chip> : null}
                                    </Table.Cell>
                                    <Table.Cell>{r.run_mode}</Table.Cell>
                                    <Table.Cell align="right">
                                        <span>
                                            {num(r.searches_issued || 0)}
                                            {Number(r.searches_failed) ? <Muted> {num(r.searches_failed)} failed</Muted> : null}
                                        </span>
                                    </Table.Cell>
                                    <Table.Cell align="right">{num(r.events_scanned || 0)}</Table.Cell>
                                    <Table.Cell align="right">{seconds(r.search_seconds || 0)}</Table.Cell>
                                    <Table.Cell align="right">{seconds(r.wall_seconds || 0)}</Table.Cell>
                                    <Table.Cell align="right">
                                        <span>{num(written.index)} <Muted>+ {num(written.kv)} kv</Muted></span>
                                    </Table.Cell>
                                    <Table.Cell>{r.budget_exhausted || <Muted>no</Muted>}</Table.Cell>
                                    <Table.Cell align="right">{num(errorCount(r))}</Table.Cell>
                                    <Table.Cell>
                                        <NoWrap>{dateTime(r.started_at)} <Muted>{r.config_hash ? r.config_hash.slice(0, 8) : ''}</Muted></NoWrap>
                                    </Table.Cell>
                                </Table.Row>
                            );
                        })}
                    </Table.Body>
                </Table>
                <Muted>Every count in a run row is that run&apos;s own: searches issued (failed among them), events scanned by them, their search and wall seconds, rows written to the summary index and documents to the collections, errors recorded.</Muted>
                <Code>| inputlookup matalog_runs | table run_id status run_mode searches_issued events_scanned search_seconds wall_seconds budget_exhausted</Code>
            </Box>
            <Box flex="1 1 100%">
                <H>Settings in force</H>
                {confError ? (
                    <Muted>
                        <Mono>matalog.conf</Mono> is not readable by your role; the admin roles see it here. The newest run&apos;s budget table above carries the values that run used.
                    </Muted>
                ) : (
                    <Muted>
                        Values from <Mono>matalog.conf</Mono> through the conf endpoint; the run column shows the value the newest run copied into its record, and differs when the conf changed after it started.
                    </Muted>
                )}
                <Row>
                    {SETTING_GROUPS.filter((g) => settings[g]).map((g) => (
                        <Box key={g} flex="1 1 400px">
                            <Table>
                                <Table.Head>
                                    <Table.HeadCell width={230}>{g}</Table.HeadCell>
                                    <Table.HeadCell align="right">conf</Table.HeadCell>
                                    <Table.HeadCell width={120} align="right">run</Table.HeadCell>
                                </Table.Head>
                                <Table.Body>
                                    {Object.keys(settings[g])
                                        .sort()
                                        .map((key) => {
                                            const conf = settings[g][key];
                                            const run = runBudget[g] ? runBudget[g][key] : undefined;
                                            const numeric = run !== undefined && !Number.isNaN(Number(run)) && !Number.isNaN(Number(conf));
                                            const differs = run !== undefined && (numeric ? Number(run) !== Number(conf) : String(run) !== String(conf));
                                            return (
                                                <Table.Row key={key}>
                                                    <Table.Cell><Mono>{key}</Mono></Table.Cell>
                                                    <Table.Cell align="right"><Mono>{settingText(conf)}</Mono></Table.Cell>
                                                    <Table.Cell align="right">
                                                        {run === undefined ? <Muted>none</Muted> : differs ? <strong><Mono>{settingText(run)}</Mono></strong> : <Muted>{settingText(run)}</Muted>}
                                                    </Table.Cell>
                                                </Table.Row>
                                            );
                                        })}
                                </Table.Body>
                            </Table>
                        </Box>
                    ))}
                </Row>
                {strata.length ? (
                    <Table>
                        <Table.Head>
                            <Table.HeadCell width={260}>stratum stanza</Table.HeadCell>
                            <Table.HeadCell width={120}>index pattern</Table.HeadCell>
                            <Table.HeadCell width={200}>stratum field</Table.HeadCell>
                            <Table.HeadCell>version field</Table.HeadCell>
                        </Table.Head>
                        <Table.Body>
                            {strata.map((s) => (
                                <Table.Row key={s.sourcetype}>
                                    <Table.Cell>{s.sourcetype}</Table.Cell>
                                    <Table.Cell>{s.index_pattern}</Table.Cell>
                                    <Table.Cell><Mono>{s.stratum_field}</Mono></Table.Cell>
                                    <Table.Cell>{s.version_field ? <Mono>{s.version_field}</Mono> : <Muted>none</Muted>}</Table.Cell>
                                </Table.Row>
                            ))}
                        </Table.Body>
                    </Table>
                ) : null}
                <Muted>
                    Ceiling in force for the chart: {num(confBudget.max_searches_per_cycle)} searches, {num(confBudget.max_events_scanned_per_cycle)} events scanned,{' '}
                    {num(confBudget.max_search_seconds_per_cycle)} search seconds, {num(confBudget.max_wall_seconds_per_cycle)} wall seconds per cycle of {num(confBudget.cycle_seconds)} seconds.
                </Muted>
            </Box>
        </Wrap>
    );
}
