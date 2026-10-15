import React, { useEffect, useMemo, useState } from 'react';
import Link from '@splunk/react-ui/Link';
import Message from '@splunk/react-ui/Message';
import Select from '@splunk/react-ui/Select';
import Table from '@splunk/react-ui/Table';
import Text from '@splunk/react-ui/Text';
import { kvQuery } from '../../lib/kv';
import { restPost, restURL } from '../../lib/rest';
import { age, bytes, daysSince, dateTime, num, plural, slot } from '../../lib/format';
import { WINDOW_SOURCE, loadRuns, windowText } from '../../lib/window';
import { pageParams, replaceParams, sourceURL, wasteURL } from '../../lib/links';
import { Mono, Muted, NoWrap, Row, Wrap } from '../../components/styles';
import { Failure, Loading } from '../../components/Page';

const COLUMNS = [
    'source_key', 'src_index', 'src_sourcetype', 'search_sourcetype', 'state', 'daily_events', 'daily_bytes', 'daily_bytes_status',
    'last_event_time', 'last_human_search_time', 'last_human_search_user', 'strata_count', 'strata_deferred', 'field_count',
    'usage_count', 'usage_alert_count', 'stratum_field', 'profile_mode', 'last_discovered_run', 'updated_run_id',
];

// Sort keys map to a comparable value per row; empty values sort last in either direction.
const SORT = {
    index: (r) => r.src_index,
    sourcetype: (r) => r.src_sourcetype,
    events: (r) => Number(r.daily_events) || 0,
    bytes: (r) => (r.daily_bytes === '' || r.daily_bytes === undefined || r.daily_bytes === null ? null : Number(r.daily_bytes)),
    last_event: (r) => Number(r.last_event_time) || null,
    last_search: (r) => Number(r.last_human_search_time) || null,
    idle: (r) => (r.last_human_search_time ? daysSince(r.last_human_search_time) : Infinity),
    strata: (r) => Number(r.strata_count) || 0,
    fields: (r) => Number(r.field_count) || 0,
    used: (r) => Number(r.usage_count) || 0,
    state: (r) => r.state,
};

const MEANINGS = 'matalog/meanings';

// Export link and import control for the meanings sheet; the import posts the chosen file and shows the counts.
function MeaningsTransfer({ indexFilter }) {
    const [state, setState] = useState({ busy: false, result: null, error: null, name: '' });
    const onFile = async (e) => {
        const file = e.target.files && e.target.files[0];
        e.target.value = '';
        if (!file) return;
        setState({ busy: true, result: null, error: null, name: file.name });
        try {
            const body = await file.text();
            const type = /\.json$/i.test(file.name) ? 'application/json' : 'text/csv';
            const result = await restPost(MEANINGS, body, type);
            setState({ busy: false, result, error: null, name: file.name });
        } catch (error) {
            setState({ busy: false, result: null, error, name: file.name });
        }
    };
    const { result } = state;
    return (
        <>
            <Row align="center">
                <Muted>meanings</Muted>
                <Link to={restURL(MEANINGS, { format: 'csv', index: indexFilter })}>export CSV</Link>
                <Muted>one row per source-level field{indexFilter ? ` of ${indexFilter}` : ''}; fill the meaning column and upload the file</Muted>
                <label>
                    <Muted>import CSV </Muted>
                    <input type="file" accept=".csv,.json,text/csv,application/json" onChange={onFile} disabled={state.busy} aria-label="import meanings" />
                </label>
                {state.busy ? <Loading what={`importing ${state.name}`} /> : null}
            </Row>
            <Failure error={state.error} />
            {result ? (
                <Message type={result.rejected.length ? 'warning' : 'success'}>
                    {state.name}: {plural(result.rows, 'row')}, {num(result.written)} written, {num(result.unchanged)} unchanged, {num(result.skipped)} skipped (empty meaning),{' '}
                    {num(result.rejected.length)} rejected.
                </Message>
            ) : null}
            {result && result.rejected.length ? (
                <Table>
                    <Table.Head>
                        <Table.HeadCell width={300}>rejected field_key</Table.HeadCell>
                        <Table.HeadCell>reason</Table.HeadCell>
                    </Table.Head>
                    <Table.Body>
                        {result.rejected.map((r, i) => (
                            <Table.Row key={`${r.field_key}-${i}`}>
                                <Table.Cell>
                                    <Mono>{r.field_key || '(empty)'}</Mono>
                                </Table.Cell>
                                <Table.Cell>{r.reason}</Table.Cell>
                            </Table.Row>
                        ))}
                    </Table.Body>
                </Table>
            ) : null}
        </>
    );
}

function compare(a, b, key, dir) {
    const va = SORT[key](a);
    const vb = SORT[key](b);
    if (va === null && vb === null) return 0;
    if (va === null) return 1;
    if (vb === null) return -1;
    let out = 0;
    if (typeof va === 'string') out = va.localeCompare(vb);
    else out = va - vb;
    return dir === 'asc' ? out : -out;
}

export default function Sources() {
    const params = pageParams();
    const [state, setState] = useState({ loading: true, error: null, rows: [], runs: {} });
    const [indexFilter, setIndexFilter] = useState(params.get('index') || '');
    const [stateFilter, setStateFilter] = useState(params.get('state') || '');
    const [text, setText] = useState(params.get('q') || '');
    const [sortKey, setSortKey] = useState(SORT[params.get('sort')] ? params.get('sort') : 'events');
    const [sortDir, setSortDir] = useState(params.get('dir') === 'asc' ? 'asc' : 'desc');

    useEffect(() => {
        let live = true;
        kvQuery('matalog_sources', { fields: COLUMNS })
            .then((rows) => loadRuns(rows.map((r) => r.updated_run_id)).then((runs) => ({ rows, runs })))
            .then(
                ({ rows, runs }) => live && setState({ loading: false, error: null, rows, runs }),
                (error) => live && setState({ loading: false, error, rows: [], runs: {} })
            );
        return () => {
            live = false;
        };
    }, []);

    useEffect(() => {
        replaceParams({ index: indexFilter, state: stateFilter, q: text, sort: sortKey === 'events' ? '' : sortKey, dir: sortDir === 'desc' ? '' : sortDir });
    }, [indexFilter, stateFilter, text, sortKey, sortDir]);

    const indexes = useMemo(() => Array.from(new Set(state.rows.map((r) => r.src_index))).sort(), [state.rows]);
    const states = useMemo(() => Array.from(new Set(state.rows.map((r) => r.state))).sort(), [state.rows]);
    const needle = text.trim().toLowerCase();
    const rows = useMemo(
        () =>
            state.rows
                .filter((r) => !indexFilter || r.src_index === indexFilter)
                .filter((r) => !stateFilter || r.state === stateFilter)
                .filter((r) => !needle || r.src_sourcetype.toLowerCase().includes(needle) || (r.search_sourcetype || '').toLowerCase().includes(needle))
                .sort((a, b) => compare(a, b, sortKey, sortDir) || a.src_index.localeCompare(b.src_index) || a.src_sourcetype.localeCompare(b.src_sourcetype)),
        [state.rows, indexFilter, stateFilter, needle, sortKey, sortDir]
    );
    const totals = useMemo(
        () => ({
            events: rows.reduce((n, r) => n + (Number(r.daily_events) || 0), 0),
            bytes: rows.reduce((n, r) => n + (r.daily_bytes_status === 'ok' ? Number(r.daily_bytes) || 0 : 0), 0),
            unreadable: rows.filter((r) => r.daily_bytes_status && r.daily_bytes_status !== 'ok').length,
            readable: rows.filter((r) => r.daily_bytes_status === 'ok').length,
            fields: rows.reduce((n, r) => n + (Number(r.field_count) || 0), 0),
            used: rows.reduce((n, r) => n + (Number(r.usage_count) || 0), 0),
        }),
        [rows]
    );

    const newestRun = state.rows.map((r) => r.updated_run_id || '').sort().pop() || '';
    const dayWindow = newestRun ? windowText(newestRun, 'day', state.runs) : '';

    const onSort = (e, { sortKey: key }) => {
        if (key === sortKey) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
        else {
            setSortKey(key);
            setSortDir(key === 'index' || key === 'sourcetype' || key === 'state' ? 'asc' : 'desc');
        }
    };
    const head = (key, label, extra = {}) => (
        <Table.HeadCell onSort={onSort} sortKey={key} sortDir={sortKey === key ? sortDir : 'none'} {...extra}>
            {label}
        </Table.HeadCell>
    );

    return (
        <Wrap>
            <Row align="center">
                <Muted>sources</Muted>
                <div style={{ width: 260 }}>
                    <Text value={text} onChange={(e, { value }) => setText(value)} placeholder="sourcetype contains" aria-label="filter sourcetypes" />
                </div>
                <Select value={indexFilter} onChange={(e, { value }) => setIndexFilter(value)} prefixLabel="index" appearance="subtle" inline filter>
                    <Select.Option label="all" value="" />
                    {indexes.map((i) => (
                        <Select.Option key={i} label={i} value={i} />
                    ))}
                </Select>
                <Select value={stateFilter} onChange={(e, { value }) => setStateFilter(value)} prefixLabel="state" appearance="subtle" inline>
                    <Select.Option label="all" value="" />
                    {states.map((s) => (
                        <Select.Option key={s} label={s} value={s} />
                    ))}
                </Select>
                {!state.loading ? (
                    <Muted>
                        {plural(rows.length, 'source')} of {num(state.rows.length)}; {num(totals.events)} events and {totals.readable ? `${bytes(totals.bytes)} licensed` : 'licensed bytes unavailable'} in {dayWindow || 'the trailing day'}
                        {totals.readable && totals.unreadable ? ` (${num(totals.unreadable)} without a readable figure)` : ''}, {num(totals.fields)} present fields, {num(totals.used)} knowledge objects using them.{' '}
                        <Link to={wasteURL()}>Waste view</Link>
                    </Muted>
                ) : null}
            </Row>
            <Failure error={state.error} />
            {state.loading ? <Loading what="reading matalog_sources" /> : null}
            {!state.loading ? <MeaningsTransfer indexFilter={indexFilter} /> : null}
            {!state.loading ? (
                <Table stripeRows>
                    <Table.Head>
                        {head('index', 'index', { width: 110 })}
                        {head('sourcetype', 'sourcetype', { width: 270 })}
                        {head('events', 'events, 1 day', { width: 115, align: 'right' })}
                        {head('bytes', 'bytes, 1 day', { width: 110, align: 'right' })}
                        {head('last_event', 'last event', { width: 90 })}
                        {head('last_search', 'last human search', { width: 150 })}
                        {head('idle', 'days idle', { width: 85, align: 'right' })}
                        {head('strata', 'strata', { width: 95, align: 'right' })}
                        {head('fields', 'fields', { width: 70, align: 'right' })}
                        {head('used', 'used by', { width: 100, align: 'right' })}
                        {head('state', 'state')}
                    </Table.Head>
                    <Table.Body>
                        {rows.map((r) => {
                            const idle = r.last_human_search_time ? daysSince(r.last_human_search_time) : null;
                            return (
                                <Table.Row key={r.source_key}>
                                    <Table.Cell>{r.src_index}</Table.Cell>
                                    <Table.Cell>
                                        <span>
                                            <Link to={sourceURL(r.source_key)}>{r.src_sourcetype}</Link>
                                            {r.search_sourcetype && r.search_sourcetype !== r.src_sourcetype ? <Muted> as {r.search_sourcetype}</Muted> : null}
                                            {r.stratum_field && r.stratum_field !== '__all__' ? <Muted> by {r.stratum_field}</Muted> : null}
                                        </span>
                                    </Table.Cell>
                                    <Table.Cell align="right">
                                        <NoWrap title={`events in ${windowText(r.updated_run_id, 'day', state.runs)}`}>{num(r.daily_events || 0)}</NoWrap>
                                    </Table.Cell>
                                    <Table.Cell align="right">
                                        <NoWrap title={`licensed bytes in ${windowText(r.updated_run_id, 'day', state.runs)}`}>
                                            {r.daily_bytes_status === 'ok' ? bytes(r.daily_bytes || 0) : <Muted>{r.daily_bytes_status || 'unknown'}</Muted>}
                                        </NoWrap>
                                    </Table.Cell>
                                    <Table.Cell>
                                        <NoWrap title={r.last_event_time ? dateTime(r.last_event_time) : ''}>{r.last_event_time ? age(r.last_event_time) : 'none'}</NoWrap>
                                    </Table.Cell>
                                    <Table.Cell>
                                        {r.last_human_search_time ? (
                                            <NoWrap title={dateTime(r.last_human_search_time)}>
                                                {age(r.last_human_search_time)} <Muted>{r.last_human_search_user}</Muted>
                                            </NoWrap>
                                        ) : (
                                            <Muted>none</Muted>
                                        )}
                                    </Table.Cell>
                                    <Table.Cell align="right">{idle === null ? <Muted>never</Muted> : num(idle)}</Table.Cell>
                                    <Table.Cell align="right">
                                        <span>
                                            {num(r.strata_count || 0)}
                                            {Number(r.strata_deferred) ? <Muted> +{num(r.strata_deferred)} deferred</Muted> : null}
                                        </span>
                                    </Table.Cell>
                                    <Table.Cell align="right">{num(r.field_count || 0)}</Table.Cell>
                                    <Table.Cell align="right">
                                        <span>
                                            {num(r.usage_count || 0)}
                                            {Number(r.usage_alert_count) ? <Muted> {num(r.usage_alert_count)} alerts</Muted> : null}
                                        </span>
                                    </Table.Cell>
                                    <Table.Cell>{r.state}</Table.Cell>
                                </Table.Row>
                            );
                        })}
                    </Table.Body>
                </Table>
            ) : null}
            <Muted>
                One row per <Mono>matalog_sources</Mono> row. Events and bytes are the trailing day (86,400 s) before the window end of the run that last wrote the row, {newestRun ? `run ${slot(newestRun)} for the newest rows: ${dayWindow}` : 'no run yet'}; a row written by an earlier run carries that run&apos;s day, in the cell tooltip. Strata counts active strata (deferred ones listed, never searched); fields counts present source-level rows, Splunk default fields included; used by counts knowledge objects whose scope resolves to the source. Days idle counts from the last human search; "never" means no search since the audit window start. Bytes come from the licence log; a status other than ok says why the figure is missing. {WINDOW_SOURCE}
            </Muted>
        </Wrap>
    );
}
