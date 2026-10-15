import React, { useEffect, useMemo, useState } from 'react';
import Link from '@splunk/react-ui/Link';
import NumberInput from '@splunk/react-ui/Number';
import Select from '@splunk/react-ui/Select';
import Table from '@splunk/react-ui/Table';
import { kvQuery } from '../../lib/kv';
import { age, bytes, daysSince, dateTime, num, plural } from '../../lib/format';
import { pageParams, replaceParams, sourceURL, sourcesURL } from '../../lib/links';
import { Mono, Muted, NoWrap, Row, Wrap } from '../../components/styles';
import { Failure, Loading } from '../../components/Page';
import Fragment from '../../components/Fragment';

const DEFAULT_DAYS = 30;

const COLUMNS = [
    'source_key', 'src_index', 'src_sourcetype', 'state', 'daily_events', 'daily_bytes', 'daily_bytes_status',
    'last_event_time', 'last_human_search_time', 'last_human_search_user', 'usage_count', 'usage_alert_count', 'field_count',
];

// The saved search "matalog job 5 find waste" with the threshold substituted; the page applies the same formula.
export function wasteSPL(days) {
    return (
        '| inputlookup matalog_sources' +
        ' | eval days_idle=round((now()-coalesce(last_human_search_time,0))/86400)' +
        ` | where days_idle >= ${num(days).replace(/,/g, '')}` +
        ' | sort 0 - daily_bytes' +
        ' | table src_index src_sourcetype daily_bytes daily_bytes_status daily_events last_human_search_time last_human_search_user days_idle usage_count usage_alert_count'
    );
}

// days_idle as the saved search computes it: a source never searched counts from the epoch.
function daysIdle(row) {
    return row.last_human_search_time ? daysSince(row.last_human_search_time) : daysSince(1);
}

export default function Waste() {
    const params = pageParams();
    const initial = parseInt(params.get('days') || '', 10);
    const [days, setDays] = useState(Number.isNaN(initial) ? DEFAULT_DAYS : initial);
    const [indexFilter, setIndexFilter] = useState(params.get('index') || '');
    const [state, setState] = useState({ loading: true, error: null, rows: [] });

    useEffect(() => {
        let live = true;
        kvQuery('matalog_sources', { fields: COLUMNS }).then(
            (rows) => live && setState({ loading: false, error: null, rows }),
            (error) => live && setState({ loading: false, error, rows: [] })
        );
        return () => {
            live = false;
        };
    }, []);

    useEffect(() => {
        replaceParams({ days: days === DEFAULT_DAYS ? '' : days, index: indexFilter });
    }, [days, indexFilter]);

    const indexes = useMemo(() => Array.from(new Set(state.rows.map((r) => r.src_index))).sort(), [state.rows]);
    const rows = useMemo(
        () =>
            state.rows
                .map((r) => ({ ...r, days_idle: daysIdle(r) }))
                .filter((r) => r.days_idle >= days)
                .filter((r) => !indexFilter || r.src_index === indexFilter)
                .sort((a, b) => (Number(b.daily_bytes) || 0) - (Number(a.daily_bytes) || 0) || (Number(b.daily_events) || 0) - (Number(a.daily_events) || 0) || a.src_sourcetype.localeCompare(b.src_sourcetype)),
        [state.rows, days, indexFilter]
    );
    const totals = useMemo(
        () => ({
            bytes: rows.reduce((n, r) => n + (r.daily_bytes_status === 'ok' ? Number(r.daily_bytes) || 0 : 0), 0),
            unreadable: rows.filter((r) => r.daily_bytes_status && r.daily_bytes_status !== 'ok').length,
            readable: rows.filter((r) => r.daily_bytes_status === 'ok').length,
            events: rows.reduce((n, r) => n + (Number(r.daily_events) || 0), 0),
            used: rows.reduce((n, r) => n + (Number(r.usage_count) || 0), 0),
            alerts: rows.reduce((n, r) => n + (Number(r.usage_alert_count) || 0), 0),
            never: rows.filter((r) => !r.last_human_search_time).length,
        }),
        [rows]
    );
    const all = useMemo(
        () => ({
            bytes: state.rows.reduce((n, r) => n + (r.daily_bytes_status === 'ok' ? Number(r.daily_bytes) || 0 : 0), 0),
            readable: state.rows.filter((r) => r.daily_bytes_status === 'ok').length,
            events: state.rows.reduce((n, r) => n + (Number(r.daily_events) || 0), 0),
        }),
        [state.rows]
    );

    return (
        <Wrap>
            <Row align="center">
                <Muted>waste: sources nobody has searched for</Muted>
                <div style={{ width: 110 }}>
                    <NumberInput value={days} onChange={(e, { value }) => setDays(value === undefined || value === null || Number.isNaN(value) ? 0 : Math.max(0, Math.round(value)))} min={0} step={1} aria-label="days idle threshold" />
                </div>
                <Muted>days or more, by licensed bytes per day</Muted>
                <Select value={indexFilter} onChange={(e, { value }) => setIndexFilter(value)} prefixLabel="index" appearance="subtle" inline filter>
                    <Select.Option label="all" value="" />
                    {indexes.map((i) => (
                        <Select.Option key={i} label={i} value={i} />
                    ))}
                </Select>
                {!state.loading ? (
                    <Muted>
                        {plural(rows.length, 'source')} of {num(state.rows.length)}, {totals.never ? `${num(totals.never)} never searched, ` : ''}
                        {all.readable ? `${bytes(totals.bytes)} of ${bytes(all.bytes)} licensed per day` : 'licensed bytes unavailable for every source'}, {num(totals.events)} of {num(all.events)} events per day. <Link to={sourcesURL()}>All sources</Link>
                    </Muted>
                ) : null}
            </Row>
            <Failure error={state.error} />
            {state.loading ? <Loading what="reading matalog_sources" /> : null}
            {!state.loading ? (
                <Table stripeRows>
                    <Table.Head>
                        <Table.HeadCell width={110}>index</Table.HeadCell>
                        <Table.HeadCell width={270}>sourcetype</Table.HeadCell>
                        <Table.HeadCell width={110} align="right">bytes per day</Table.HeadCell>
                        <Table.HeadCell width={110} align="right">events per day</Table.HeadCell>
                        <Table.HeadCell width={190}>last human search</Table.HeadCell>
                        <Table.HeadCell width={80} align="right">days idle</Table.HeadCell>
                        <Table.HeadCell width={90}>last event</Table.HeadCell>
                        <Table.HeadCell width={80} align="right">objects</Table.HeadCell>
                        <Table.HeadCell width={70} align="right">alerts</Table.HeadCell>
                        <Table.HeadCell>state</Table.HeadCell>
                    </Table.Head>
                    <Table.Body>
                        {rows.map((r) => (
                            <Table.Row key={r.source_key}>
                                <Table.Cell>{r.src_index}</Table.Cell>
                                <Table.Cell>
                                    <Link to={sourceURL(r.source_key)}>{r.src_sourcetype}</Link>
                                </Table.Cell>
                                <Table.Cell align="right">
                                    {r.daily_bytes_status === 'ok' ? bytes(r.daily_bytes || 0) : <Muted>{r.daily_bytes_status || 'unknown'}</Muted>}
                                </Table.Cell>
                                <Table.Cell align="right">{num(r.daily_events || 0)}</Table.Cell>
                                <Table.Cell>
                                    {r.last_human_search_time ? (
                                        <NoWrap title={dateTime(r.last_human_search_time)}>
                                            {dateTime(r.last_human_search_time)} <Muted>{r.last_human_search_user}</Muted>
                                        </NoWrap>
                                    ) : (
                                        <Muted>never</Muted>
                                    )}
                                </Table.Cell>
                                <Table.Cell align="right">{r.last_human_search_time ? num(r.days_idle) : <Muted>never</Muted>}</Table.Cell>
                                <Table.Cell>{r.last_event_time ? age(r.last_event_time) : 'none'}</Table.Cell>
                                <Table.Cell align="right">{num(r.usage_count || 0)}</Table.Cell>
                                <Table.Cell align="right">{num(r.usage_alert_count || 0)}</Table.Cell>
                                <Table.Cell>{r.state}</Table.Cell>
                            </Table.Row>
                        ))}
                        <Table.Row key="totals">
                            <Table.Cell><strong>total</strong></Table.Cell>
                            <Table.Cell>{plural(rows.length, 'source')}</Table.Cell>
                            <Table.Cell align="right">
                                <span>
                                    <strong>{totals.readable ? bytes(totals.bytes) : 'unavailable'}</strong>
                                    {totals.readable && totals.unreadable ? <Muted> +{num(totals.unreadable)} without a figure</Muted> : null}
                                </span>
                            </Table.Cell>
                            <Table.Cell align="right"><strong>{num(totals.events)}</strong></Table.Cell>
                            <Table.Cell>{totals.never ? `${num(totals.never)} never searched` : ''}</Table.Cell>
                            <Table.Cell align="right" />
                            <Table.Cell />
                            <Table.Cell align="right"><strong>{num(totals.used)}</strong></Table.Cell>
                            <Table.Cell align="right"><strong>{num(totals.alerts)}</strong></Table.Cell>
                            <Table.Cell />
                        </Table.Row>
                    </Table.Body>
                </Table>
            ) : null}
            <Fragment spl={wasteSPL(days)} />
            <Muted>
                The same rows as the saved search <Mono>matalog job 5 find waste</Mono> at this threshold. Human searches exclude the service account and the app's own searches (usage.exclude_users, usage.exclude_apps), and a search counts for a source only when it names the sourcetype or narrows to it through source, host, an eventtype, a tag, a macro or a data model: a search on the index alone counts for nothing. Objects and alerts are knowledge objects resolving to a field of the source. Bytes come from the licence log; a source without a licence row reads unavailable.
            </Muted>
        </Wrap>
    );
}
