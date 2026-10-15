import React, { useEffect, useMemo, useState } from 'react';
import styled from 'styled-components';
import { variables } from '@splunk/themes';
import Search from '@splunk/react-ui/Search';
import Select from '@splunk/react-ui/Select';
import Switch from '@splunk/react-ui/Switch';
import Table from '@splunk/react-ui/Table';
import Link from '@splunk/react-ui/Link';
import Chip from '@splunk/react-ui/Chip';
import Tooltip from '@splunk/react-ui/Tooltip';
import Card from '@splunk/react-ui/Card';
import { lookupByText, lookupByDataModelField, mostUsed } from './data';
import { snapshot, coverageOf } from '../../lib/snapshot';
import { age, bool, dateTime, list, num, pct, plural, slot, typeName } from '../../lib/format';
import { fieldURL, lookupURL, pageParams, replaceParams, searchFragment, sourceURL } from '../../lib/links';
import { WINDOW_SOURCE, countText, windowText } from '../../lib/window';
import { Bar, Mono, Muted, NoWrap, Row, Wrap } from '../../components/styles';
import { Failure, Loading } from '../../components/Page';
import Fragment from '../../components/Fragment';

const Grid = styled.div`
    display: flex;
    border-bottom: 1px solid ${variables.borderColorWeak};
    &.head {
        background: ${variables.backgroundColorPage};
    }
    &:last-child {
        border-bottom: 0;
    }
`;

const Cell = styled.div`
    padding: 7px 12px;
    border-right: 1px solid ${variables.borderColorWeak};
    display: flex;
    flex-direction: column;
    gap: 1px;
    min-width: 0;
    flex: ${(props) => props.flex || '0 0 auto'};
    &:last-child {
        border-right: 0;
    }
`;

const K = styled.span`
    font-size: 11px;
    color: ${variables.contentColorMuted};
    text-transform: uppercase;
    letter-spacing: 0.03em;
`;

const V = styled.span`
    font-size: 15px;
    font-weight: 600;
    white-space: nowrap;
`;

const S = styled.span`
    font-size: 12px;
    color: ${variables.contentColorMuted};
`;

const Vals = styled.span`
    font-family: ${variables.monoFontFamily};
    font-size: 12px;
    word-break: break-all;
`;

function declLabel(d) {
    if (!d) return '';
    return `${d.app}${d.app_version ? ` ${d.app_version}` : ''} ${d.conf_file} [${d.stanza}] ${d.attribute}`;
}

function CardView({ row, source, strata, losers, stored, runs }) {
    const snap = snapshot(row);
    const anchored = row.window_anchor === 'last_event' && !!snap && snap.mode === 'discovery';
    const sourcetype = (source && source.search_sourcetype) || row.src_sourcetype;
    const losing = list(row.origin_candidates)
        .filter((key) => key !== row.origin_decl_key)
        .map((key) => losers[key])
        .filter(Boolean);
    const topValues = list(row.top_values);
    const topCounts = list(row.top_counts);
    const samples = list(row.sample_values);
    const strataCount = source ? Number(source.strata_count) || 0 : 0;
    const rollup = bool(row.is_rollup);
    const shown = topValues.length;
    const more = snap ? Math.max(0, snap.distinct - shown) : 0;
    const cimFields = list(row.cim_fields);
    const cimVia = list(row.cim_via);
    const byStratum = strata
        .filter((s) => s.source_key === row.source_key && s.field_name === row.field_name)
        .sort((a, b) => coverageOf(b) - coverageOf(a));
    return (
        <Card style={{ width: '100%', maxWidth: 'none' }}>
            <Grid className="head">
                <Cell flex="1 1 240px">
                    <K>field</K>
                    <V>
                        <Link to={fieldURL(row.field_key)}>{row.field_name}</Link>
                    </V>
                    <S>
                        <Link to={sourceURL(row.source_key)}>
                            {row.src_index} / {row.src_sourcetype}
                        </Link>
                        {', '}
                        {rollup
                            ? `present in ${num(byStratum.length ? byStratum.filter((s) => coverageOf(s) > 0).length : Math.max(0, strataCount - (Number(row.absent_strata_count) || 0)))} of ${num(strataCount)} strata`
                            : `all events (${plural(strataCount || 1, 'stratum', 'strata')})`}
                        {row.presence !== 'present' ? ` ${row.presence}` : ''}
                    </S>
                </Cell>
                <Cell flex="0 1 330px">
                    <K>coverage{snap ? `, ${snap.mode} ${slot(snap.runId)}` : ''}</K>
                    <V>{snap ? pct(snap.coverage) : 'none'}</V>
                    <S style={{ whiteSpace: 'normal' }}>{countText(snap, runs, { anchored })}</S>
                </Cell>
                <Cell>
                    <K>distinct values</K>
                    <V>{snap ? num(snap.distinct) : ''}</V>
                    <S>{snap ? `same window, ${snap.exact === null ? 'discovery count' : snap.exact ? 'exact' : 'inexact'}` : ''}{bool(row.identifier) ? ', identifier' : ''}</S>
                </Cell>
                <Cell>
                    <K>type</K>
                    <V>{row.type_guess || ''}</V>
                    <S>{row.best_type_id ? `${typeName(row.best_type_id)} ${pct(row.best_type_rate)}` : 'no semantic type'}</S>
                </Cell>
                <Cell>
                    <K>last seen</K>
                    <V>{age(row.last_seen_time)}</V>
                    <S>first {slot(row.first_seen_run)}</S>
                </Cell>
                <Cell flex="0 1 260px">
                    <K>origin</K>
                    <V>{row.origin || 'unknown'}</V>
                    <S>
                        {row.origin_app ? `${row.origin_app}, ${row.origin_stanza}` : 'no declaration'}{' '}
                        {losing.length ? (
                            <Tooltip content={losing.map((d) => <div key={d.decl_key}>{declLabel(d)}</div>)}>
                                <Chip appearance="outline">conflict: {losing.map((d) => d.app).join(', ')}</Chip>
                            </Tooltip>
                        ) : null}
                    </S>
                </Cell>
                <Cell>
                    <K>used by</K>
                    <V>{num(row.usage_count || 0)}</V>
                    <S>
                        knowledge objects, {plural(row.usage_alert_count || 0, 'alert')}
                        {Number(row.usage_unscoped_count) ? `, ${num(row.usage_unscoped_count)} by name only (not counted)` : ''}
                    </S>
                </Cell>
            </Grid>
            <Grid>
                <Cell flex="1 1 400px">
                    <K>{bool(row.identifier) ? 'sample values' : 'top values'}{snap ? `, ${snap.mode} ${slot(snap.runId)}, counts over the same window as coverage` : ''}</K>
                    <Vals>
                        {!stored && !topValues.length && !samples.length ? 'values not stored' : null}
                        {stored || topValues.length || samples.length ? (
                            <>
                                {bool(row.identifier)
                                    ? samples.slice(0, 8).join('  ') + (samples.length > 8 ? `  +${num(samples.length - 8)} kept` : '')
                                    : topValues.map((v, i) => `${v} ${num(topCounts[i])}`).join('   ') + (more > 0 ? `   +${num(more)}` : '')}
                                {!bool(row.identifier) && !topValues.length ? 'none stored' : ''}
                            </>
                        ) : null}
                    </Vals>
                </Cell>
                <Cell flex="0 0 360px">
                    <K>meaning</K>
                    <S>
                        {row.meaning_human ? (
                            <>
                                {row.meaning_human} <Muted>{row.meaning_human_author || ''} {slotOrDate(row.meaning_human_time)} rev {num(row.meaning_human_revision)}</Muted>{' '}
                                <Link to={fieldURL(row.field_key, { edit: 1 })}>edit</Link>
                            </>
                        ) : (
                            <>
                                <Muted>none</Muted> <Link to={fieldURL(row.field_key, { edit: 1 })}>add</Link>
                            </>
                        )}
                        {cimFields.length ? <div><Muted>maps to {cimFields.map((f, i) => `${f} (${cimVia[i] || ''})`).join(', ')}</Muted></div> : null}
                    </S>
                </Cell>
            </Grid>
            <Grid>
                <Cell flex="1 1 400px">
                    <K>search</K>
                    <Fragment spl={searchFragment(row.src_index, sourcetype, row.field_name)} />
                </Cell>
                <Cell flex="0 0 360px">
                    <K>by stratum</K>
                    <S>
                        {byStratum.length
                            ? byStratum.map((s) => (
                                  <span key={s.field_key}>
                                      <Link to={fieldURL(s.field_key)}>{s.stratum_value}</Link> {pct(coverageOf(s))}{'   '}
                                  </span>
                              ))
                            : rollup
                            ? 'no stratum rows'
                            : '1 stratum, all events'}
                    </S>
                </Cell>
            </Grid>
        </Card>
    );
}

function slotOrDate(epoch) {
    if (!epoch) return '';
    return new Date(Number(epoch) * 1000).toISOString().slice(0, 10);
}

function groupCim(cim) {
    const groups = {};
    cim.forEach((r) => {
        const key = `${r.cim_dataset}.${r.cim_field}`;
        if (!groups[key]) groups[key] = { dataset: r.cim_dataset, field: r.cim_field, mapped: 0, unmapped: 0 };
        if (Number(r.mapped) === 1) groups[key].mapped += 1;
        else groups[key].unmapped += 1;
    });
    return Object.values(groups).sort((a, b) => b.mapped - a.mapped || a.dataset.localeCompare(b.dataset));
}

const KIND_ORDER = { 'name, other case': 0, prefix: 1, word: 2, 'word prefix': 3, substring: 4, sourcetype: 5 };
const IDLE_MS = 300;

function usedBy(row) {
    return Number(row.usage_count) || 0;
}

function distinctOf(row) {
    const snap = snapshot(row);
    return snap ? Number(snap.distinct) || 0 : 0;
}

function MostUsed() {
    const [state, setState] = useState({ rows: [], error: null });
    useEffect(() => {
        let live = true;
        mostUsed().then(
            (rows) => live && setState({ rows, error: null }),
            (error) => live && setState({ rows: [], error })
        );
        return () => {
            live = false;
        };
    }, []);
    return (
        <>
            <Muted>
                Type a field name, a sourcetype, a vendor or a word; the search runs on Enter or after a {IDLE_MS} ms pause. Sources whose sourcetype, source path or app contains it come first, an exact field name gives one card per source, and prefix and substring matches follow in the table.
            </Muted>
            <Failure error={state.error} />
            {state.rows.length ? (
                <Muted>
                    Most used fields (knowledge objects whose scope resolves to the field; Splunk default fields left out):{' '}
                    {state.rows.map((r, i) => (
                        <span key={r.field_key}>
                            {i ? ', ' : ''}
                            <Link to={lookupURL(r.field_name)}>{r.field_name}</Link> in {r.src_sourcetype} ({num(r.usage_count)}{Number(r.usage_alert_count) ? `, ${num(r.usage_alert_count)} alerts` : ''})
                        </span>
                    ))}
                </Muted>
            ) : null}
        </>
    );
}

export default function Lookup() {
    const params = pageParams();
    const [q, setQ] = useState(params.get('q') || '');
    const [dm, setDm] = useState(params.get('dm') || '');
    const [submitted, setSubmitted] = useState({ q: params.get('q') || '', dm: params.get('dm') || '' });
    const [indexFilter, setIndexFilter] = useState(params.get('index') || '');
    const [sourceFilter, setSourceFilter] = useState(params.get('source') || '');
    const [alertsOnly, setAlertsOnly] = useState(params.get('alerts') === '1');
    const [showDefaults, setShowDefaults] = useState(params.get('defaults') === '1');
    const [state, setState] = useState({ loading: false, error: null, data: null });

    useEffect(() => {
        replaceParams({ q: submitted.q, dm: submitted.dm, index: indexFilter, source: sourceFilter, alerts: alertsOnly ? 1 : '', defaults: showDefaults ? 1 : '' });
    }, [submitted, indexFilter, sourceFilter, alertsOnly, showDefaults]);

    // The search also runs after a pause in typing.
    useEffect(() => {
        const want = q.trim();
        if (want === submitted.q || (!want && submitted.dm)) return undefined;
        const timer = setTimeout(() => setSubmitted({ q: want, dm: '' }), IDLE_MS);
        return () => clearTimeout(timer);
    }, [q]);

    useEffect(() => {
        let live = true;
        if (!submitted.q && !submitted.dm) {
            setState({ loading: false, error: null, data: null });
            return undefined;
        }
        setState((s) => ({ ...s, loading: true, error: null }));
        const load = submitted.dm
            ? lookupByDataModelField(submitted.dm.slice(0, submitted.dm.lastIndexOf('.')), submitted.dm.slice(submitted.dm.lastIndexOf('.') + 1))
            : lookupByText(submitted.q);
        load.then(
            (data) => live && setState({ loading: false, error: null, data }),
            (error) => live && setState({ loading: false, error, data: null })
        );
        return () => {
            live = false;
        };
    }, [submitted]);

    const data = state.data;
    const cards = useMemo(() => {
        if (!data) return [];
        return data.cards
            .filter((r) => !indexFilter || r.src_index === indexFilter)
            .filter((r) => !sourceFilter || r.src_sourcetype === sourceFilter)
            .filter((r) => !alertsOnly || Number(r.usage_alert_count) > 0)
            .sort((a, b) => (Number(b.usage_alert_count) || 0) - (Number(a.usage_alert_count) || 0) || usedBy(b) - usedBy(a) || coverageOf(b) - coverageOf(a));
    }, [data, indexFilter, sourceFilter, alertsOnly]);
    const filteredOthers = useMemo(() => {
        if (!data) return [];
        return data.others
            .filter(({ row }) => !indexFilter || row.src_index === indexFilter)
            .filter(({ row }) => !sourceFilter || row.src_sourcetype === sourceFilter)
            .filter(({ row }) => !alertsOnly || Number(row.usage_alert_count) > 0);
    }, [data, indexFilter, sourceFilter, alertsOnly]);
    const matched = useMemo(() => {
        if (!data) return [];
        return data.matched
            .filter(({ row }) => !indexFilter || row.src_index === indexFilter)
            .filter(({ row }) => !sourceFilter || row.src_sourcetype === sourceFilter)
            .filter(({ row }) => !alertsOnly || Number(row.usage_alert_count) > 0);
    }, [data, indexFilter, sourceFilter, alertsOnly]);
    const hiddenDefaults = filteredOthers.filter(({ row }) => bool(row.is_default)).length;
    const others = useMemo(
        () =>
            filteredOthers
                .filter(({ row }) => showDefaults || !bool(row.is_default))
                .sort((a, b) => KIND_ORDER[a.kind] - KIND_ORDER[b.kind] || usedBy(b.row) - usedBy(a.row) || coverageOf(b.row) - coverageOf(a.row) || distinctOf(b.row) - distinctOf(a.row) || a.row.field_name.localeCompare(b.row.field_name)),
        [filteredOthers, showDefaults]
    );
    const rowsSeen = data ? data.cards.concat(data.others.map((o) => o.row), data.matched.map((m) => m.row)) : [];
    const indexes = Array.from(new Set(rowsSeen.map((r) => r.src_index))).sort();
    const sourcetypes = Array.from(new Set(rowsSeen.map((r) => r.src_sourcetype))).sort();
    const cimGroups = data ? groupCim(data.cim) : [];
    const cardNames = data ? Array.from(new Set(data.cards.map((r) => r.field_name))) : [];
    const named = cardNames.length ? cardNames.join(', ') : submitted.dm ? submitted.dm.slice(submitted.dm.lastIndexOf('.') + 1) : submitted.q;

    const submit = () => {
        setDm('');
        setSubmitted({ q: q.trim(), dm: '' });
    };

    return (
        <Wrap>
            <Row align="center">
                <Muted>lookup</Muted>
                <div style={{ width: 420 }}>
                    <Search
                        value={q}
                        onChange={(e, { value }) => setQ(value)}
                        onKeyDown={(e) => {
                            if (e.key === 'Enter') submit();
                        }}
                        placeholder="field name, sourcetype, vendor or word"
                        aria-label="lookup"
                    />
                </div>
                {dm ? (
                    <Muted>
                        data model field {dm}{' '}
                        <Link to={lookupURL(q)} onClick={(e) => { e.preventDefault(); submit(); }}>
                            clear
                        </Link>
                    </Muted>
                ) : null}
                {data ? (
                    <Muted>
                        {plural(matched.length, 'source')} matching {submitted.dm || submitted.q}, {plural(data.cards.length, 'field')} named {named} in {plural(new Set(data.cards.map((r) => r.source_key)).size, 'source')},{' '}
                        {plural(others.length, 'other match', 'other matches')}, {plural(cimGroups.length, 'data model field')}. Filter:
                    </Muted>
                ) : null}
                <Select value={indexFilter} onChange={(e, { value }) => setIndexFilter(value)} prefixLabel="index" appearance="subtle" inline>
                    <Select.Option label="all" value="" />
                    {indexes.map((i) => (
                        <Select.Option key={i} label={i} value={i} />
                    ))}
                </Select>
                <Select value={sourceFilter} onChange={(e, { value }) => setSourceFilter(value)} prefixLabel="source" appearance="subtle" inline filter>
                    <Select.Option label="all" value="" />
                    {sourcetypes.map((s) => (
                        <Select.Option key={s} label={s} value={s} />
                    ))}
                </Select>
                <Switch selected={alertsOnly} onClick={() => setAlertsOnly((v) => !v)} appearance="toggle" inline>
                    used by alerts
                </Switch>
                {data ? (
                    <Switch selected={showDefaults} onClick={() => setShowDefaults((v) => !v)} appearance="toggle" inline>
                        show default fields ({num(hiddenDefaults)})
                    </Switch>
                ) : null}
            </Row>
            <Failure error={state.error} />
            {state.loading ? <Loading what={`reading matalog_fields for ${submitted.dm || submitted.q}`} /> : null}
            {!data && !state.loading && !submitted.q && !submitted.dm ? <MostUsed /> : null}
            {matched.length ? (
                <Table stripeRows>
                    <Table.Head>
                        <Table.HeadCell width={320}>sources matching {submitted.q}</Table.HeadCell>
                        <Table.HeadCell width={140}>index</Table.HeadCell>
                        <Table.HeadCell width={180}>matched on</Table.HeadCell>
                        <Table.HeadCell width={140} align="right">events, day</Table.HeadCell>
                        <Table.HeadCell width={90} align="right">fields</Table.HeadCell>
                        <Table.HeadCell width={90} align="right">used by</Table.HeadCell>
                        <Table.HeadCell width={260}>last human search</Table.HeadCell>
                    </Table.Head>
                    <Table.Body>
                        {matched.map(({ row, via }) => (
                            <Table.Row key={row.source_key}>
                                <Table.Cell>
                                    <Link to={sourceURL(row.source_key)}>{row.src_sourcetype}</Link>
                                    {row.search_sourcetype && row.search_sourcetype !== row.src_sourcetype ? <Muted> searched as {row.search_sourcetype}</Muted> : null}
                                    {row.state !== 'active' ? <Chip appearance="outline">{row.state}</Chip> : null}
                                </Table.Cell>
                                <Table.Cell>{row.src_index}</Table.Cell>
                                <Table.Cell><Muted>{via.join(', ')}</Muted></Table.Cell>
                                <Table.Cell align="right">
                                    <NoWrap title={`events in ${windowText(row.updated_run_id, 'day', data.runs)}`}>{num(row.daily_events || 0)}</NoWrap>
                                </Table.Cell>
                                <Table.Cell align="right">{num(row.field_count || 0)}</Table.Cell>
                                <Table.Cell align="right">
                                    {num(row.usage_count || 0)}
                                    {Number(row.usage_alert_count) ? <Muted> ({num(row.usage_alert_count)} alerts)</Muted> : null}
                                </Table.Cell>
                                <Table.Cell>
                                    {row.last_human_search_time ? `${dateTime(row.last_human_search_time)} by ${row.last_human_search_user || ''}` : <Muted>none since the audit window start</Muted>}
                                </Table.Cell>
                            </Table.Row>
                        ))}
                    </Table.Body>
                </Table>
            ) : null}
            {cards.map((row) => (
                <CardView key={row.field_key} row={row} source={data.sources[row.source_key]} strata={data.strata} losers={data.losers} stored={data.stored !== false} runs={data.runs} />
            ))}
            {data && !cards.length && !state.loading ? <Muted>{submitted.dm ? `no source maps a field to ${submitted.dm}` : others.length || cimGroups.length || matched.length ? `no source carries a field named exactly ${submitted.q}` : `no source, source path, app, field name or data model field contains ${submitted.q}`}{indexFilter || sourceFilter || alertsOnly ? ' under the filters' : ''}</Muted> : null}
            {data && !cards.length && !others.length && !cimGroups.length && !matched.length && !data.unmapped.length && !state.loading ? <MostUsed /> : null}
            {data && (others.length || cimGroups.length || data.unmapped.length) ? (
                <Table stripeRows>
                    <Table.Head>
                        <Table.HeadCell width={280}>other matches</Table.HeadCell>
                        <Table.HeadCell width={320}>source</Table.HeadCell>
                        <Table.HeadCell width={120}>match</Table.HeadCell>
                        <Table.HeadCell width={220}>type</Table.HeadCell>
                        <Table.HeadCell width={150}>coverage, last window</Table.HeadCell>
                        <Table.HeadCell width={90} align="right">distinct values</Table.HeadCell>
                        <Table.HeadCell width={100}>last seen</Table.HeadCell>
                        <Table.HeadCell width={130}>origin</Table.HeadCell>
                        <Table.HeadCell width={90} align="right">used by</Table.HeadCell>
                    </Table.Head>
                    <Table.Body>
                        {others.map(({ row, kind }) => {
                            const snap = snapshot(row);
                            return (
                                <Table.Row key={row.field_key}>
                                    <Table.Cell>
                                        <Link to={fieldURL(row.field_key)}>{row.field_name}</Link>
                                    </Table.Cell>
                                    <Table.Cell>
                                        <Link to={sourceURL(row.source_key)}>
                                            {row.src_index} / {row.src_sourcetype}
                                        </Link>
                                    </Table.Cell>
                                    <Table.Cell>
                                        <Muted>{kind}</Muted>
                                    </Table.Cell>
                                    <Table.Cell>
                                        {row.type_guess || ''}{' '}
                                        <Muted>{row.best_type_id ? `${typeName(row.best_type_id)} ${pct(row.best_type_rate)}` : 'no semantic type'}</Muted>
                                    </Table.Cell>
                                    <Table.Cell>
                                        <NoWrap>
                                            <Bar ratio={snap ? snap.coverage : 0} />
                                            {snap ? pct(snap.coverage) : ''}
                                        </NoWrap>
                                        {row.presence !== 'present' ? <Chip appearance="outline">{row.presence}</Chip> : null}
                                    </Table.Cell>
                                    <Table.Cell align="right">{snap ? num(snap.distinct) : ''}</Table.Cell>
                                    <Table.Cell>{age(row.last_seen_time)}</Table.Cell>
                                    <Table.Cell>{row.origin}</Table.Cell>
                                    <Table.Cell align="right">{num(row.usage_count || 0)}</Table.Cell>
                                </Table.Row>
                            );
                        })}
                        {cimGroups.map((g) => (
                            <Table.Row key={`${g.dataset}.${g.field}`}>
                                <Table.Cell>
                                    <Link to={lookupURL(g.field, { dm: `${g.dataset}.${g.field}` })}>
                                        {g.dataset}.{g.field}
                                    </Link>
                                </Table.Cell>
                                <Table.Cell>
                                    <Muted>
                                        data model field: {plural(g.mapped, 'source')} mapped, {num(g.unmapped)} in class unmapped
                                    </Muted>
                                </Table.Cell>
                                <Table.Cell><Muted>data model</Muted></Table.Cell>
                                <Table.Cell />
                                <Table.Cell />
                                <Table.Cell />
                                <Table.Cell />
                                <Table.Cell />
                                <Table.Cell />
                            </Table.Row>
                        ))}
                        {data.unmapped.map((r) => (
                            <Table.Row key={`${r.source_key}:${r.cim_dataset}`}>
                                <Table.Cell>
                                    <Muted>{r.cim_dataset}.{r.cim_field} unmapped</Muted>
                                </Table.Cell>
                                <Table.Cell>
                                    <Link to={sourceURL(r.source_key)}>
                                        {r.src_index} / {r.src_sourcetype}
                                    </Link>
                                </Table.Cell>
                                <Table.Cell><Muted>in class, no field maps</Muted></Table.Cell>
                                <Table.Cell />
                                <Table.Cell />
                                <Table.Cell />
                                <Table.Cell />
                                <Table.Cell />
                                <Table.Cell />
                            </Table.Row>
                        ))}
                    </Table.Body>
                </Table>
            ) : null}
            {data ? (
                <Muted>
                    Sources: those whose sourcetype, search sourcetype, a source path seen in the trailing day or a config app name contains the text, exact sourcetype first, then prefix, substring, source path, app, each by usage then events; events are the trailing day before the window end of the run that last wrote the row (in the cell tooltip). Cards: sources with alerts first, then by usage, then coverage. Other matches: the exact name in another case first, then prefix, then a word of the name (ip in client.ipAddress), then a word prefix, then substring, then sourcetype matches, each by usage, coverage, then distinct values;
                    {hiddenDefaults ? ` ${num(hiddenDefaults)} Splunk default fields (host, source, date_* and the like) are ${showDefaults ? 'shown' : 'hidden'}.` : ' no Splunk default field matched.'}{' '}
                    In the table, coverage is the share of the source&apos;s events carrying the field in its newest window (profile when profiled, else discovery, named on the field page), distinct values are counted in that window, used by counts knowledge objects whose scope resolves to the field.
                    Everything on a card is one <Mono>matalog_fields</Mono> row; the search fragment is built from the row. {WINDOW_SOURCE}
                </Muted>
            ) : null}
        </Wrap>
    );
}
