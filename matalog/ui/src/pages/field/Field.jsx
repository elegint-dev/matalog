import React, { useEffect, useMemo, useState } from 'react';
import Heading from '@splunk/react-ui/Heading';
import Link from '@splunk/react-ui/Link';
import Chip from '@splunk/react-ui/Chip';
import Table from '@splunk/react-ui/Table';
import Button from '@splunk/react-ui/Button';
import TextArea from '@splunk/react-ui/TextArea';
import Text from '@splunk/react-ui/Text';
import Select from '@splunk/react-ui/Select';
import Tooltip from '@splunk/react-ui/Tooltip';
import { username } from '@splunk/splunk-utils/config';
import { historySPL, loadField, loadHistory } from './data';
import { removeMeaning, saveMeaning } from '../../lib/meanings';
import { snapshot, coverageOf } from '../../lib/snapshot';
import { age, bool, date, dateTime, list, num, pct, plural, slot, typeName } from '../../lib/format';
import { appURL, fieldURL, lookupURL, objectURL, pageParams, searchFragment, sourceURL } from '../../lib/links';
import { stratumFilter } from '../../lib/search';
import { WINDOW_SOURCE, countText, span, windowText } from '../../lib/window';
import { Bar, Box, Code, H, Kpi, Mono, Muted, NoWrap, Row, Tags, Wrap } from '../../components/styles';
import { Failure, Loading } from '../../components/Page';
import Fragment from '../../components/Fragment';
import HistoryChart from '../../components/HistoryChart';

function declLine(d) {
    return `${d.conf_file} [${d.stanza}] ${d.attribute} in ${d.app}${d.app_version ? ` ${d.app_version}` : ''}, sharing ${d.sharing || ''}`;
}

function Meaning({ data, onSaved }) {
    const params = pageParams();
    const newest = data.meanings.filter((m) => Number(m.is_current) === 1).sort((a, b) => Number(b.revision) - Number(a.revision))[0];
    const removed = newest && newest.status === 'removed' ? newest : null;
    const current = removed ? null : newest;
    const older = data.meanings.filter((m) => !newest || m._key !== newest._key).sort((a, b) => Number(b.revision) - Number(a.revision));
    const nextRevision = (newest ? Number(newest.revision) : 0) + 1;
    const [editing, setEditing] = useState(params.get('edit') === '1');
    const [removing, setRemoving] = useState(false);
    const [text, setText] = useState(current ? current.text : '');
    const [note, setNote] = useState('');
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState(null);
    const write = async (action) => {
        setBusy(true);
        setError(null);
        try {
            const result = await action();
            setEditing(false);
            setRemoving(false);
            setNote('');
            onSaved(result);
        } catch (err) {
            setError(err);
        } finally {
            setBusy(false);
        }
    };
    const save = () => {
        if (!text.trim()) return;
        write(() => saveMeaning(data.sourceRow, text.trim(), note.trim()));
    };
    const remove = () => write(() => removeMeaning(data.sourceRow, note.trim()));
    return (
        <Box flex="2 1 520px">
            <H>Meaning</H>
            <div>
                {current ? (
                    <>
                        {current.text} <Muted>{current.author}, {date(current.created_at)}, revision {num(current.revision)}{current.note ? `, ${current.note}` : ''}</Muted>{' '}
                    </>
                ) : removed ? (
                    <Muted>no meaning recorded; removed by {removed.author}, {date(removed.created_at)}, revision {num(removed.revision)}{removed.note ? `, ${removed.note}` : ''} </Muted>
                ) : (
                    <Muted>no meaning recorded </Muted>
                )}
                {!editing && !removing ? (
                    <Row align="center" style={{ display: 'inline-flex' }}>
                        <Button appearance="secondary" label={current ? 'edit' : 'add'} onClick={() => setEditing(true)} />
                        {current ? <Button appearance="secondary" label="remove" onClick={() => setRemoving(true)} /> : null}
                    </Row>
                ) : null}
            </div>
            {data.cim.map((c) => (
                <div key={c._key}>
                    Maps to {c.cim_dataset}.{c.cim_field} ({c.cim_via}
                    {c.coverage !== '' && c.coverage !== undefined ? `, coverage ${pct(c.coverage)}` : ''}).
                    {c.cim_description ? ` ${c.cim_description}` : ''}
                    {list(c.cim_expected_values).length ? <> Expected values: <Mono>{list(c.cim_expected_values).join(', ')}</Mono>.</> : null}
                </div>
            ))}
            {editing ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6, alignItems: 'flex-start' }}>
                    <div style={{ width: '100%' }}>
                        <TextArea value={text} onChange={(e, { value }) => setText(value)} rowsMin={3} placeholder="what this field means, as people use it" />
                    </div>
                    <div style={{ width: 360 }}>
                        <Text value={note} onChange={(e, { value }) => setNote(value)} placeholder="edit reason (optional)" />
                    </div>
                    <Row align="center">
                        <Button appearance="primary" label={busy ? 'saving' : `save as ${username || 'me'}, revision ${num(nextRevision)}`} disabled={busy || !text.trim()} onClick={save} />
                        <Button label="cancel" onClick={() => setEditing(false)} disabled={busy} />
                    </Row>
                    <Failure error={error} />
                </div>
            ) : null}
            {removing ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6, alignItems: 'flex-start' }}>
                    <Muted>Removing writes revision {num(nextRevision)} with no text and clears the meaning on every row of this field; the earlier revisions stay in the history.</Muted>
                    <div style={{ width: 360 }}>
                        <Text value={note} onChange={(e, { value }) => setNote(value)} placeholder="reason (optional)" />
                    </div>
                    <Row align="center">
                        <Button appearance="primary" label={busy ? 'removing' : `remove as ${username || 'me'}, revision ${num(nextRevision)}`} disabled={busy} onClick={remove} />
                        <Button label="cancel" onClick={() => setRemoving(false)} disabled={busy} />
                    </Row>
                    <Failure error={error} />
                </div>
            ) : null}
            {older.length ? (
                <Table>
                    <Table.Head>
                        <Table.HeadCell width={160}>earlier revisions</Table.HeadCell>
                        <Table.HeadCell width={120}>author</Table.HeadCell>
                        <Table.HeadCell width={110}>date</Table.HeadCell>
                        <Table.HeadCell>text</Table.HeadCell>
                    </Table.Head>
                    <Table.Body>
                        {older.map((m) => (
                            <Table.Row key={m._key}>
                                <Table.Cell>{num(m.revision)} {m.status}</Table.Cell>
                                <Table.Cell>{m.author}</Table.Cell>
                                <Table.Cell>{date(m.created_at)}</Table.Cell>
                                <Table.Cell>{m.text || <Muted>no text (a removal)</Muted>}</Table.Cell>
                            </Table.Row>
                        ))}
                    </Table.Body>
                </Table>
            ) : null}
        </Box>
    );
}

function History({ row }) {
    const [state, setState] = useState({ loading: true, error: null, points: [], spl: '', skipped: [] });
    const [mode, setMode] = useState('profile');
    useEffect(() => {
        let live = true;
        loadHistory(row).then(
            ({ points, spl, skipped }) => live && setState({ loading: false, error: null, points, spl, skipped }),
            (error) => live && setState({ loading: false, error, points: [], spl: '', skipped: [] })
        );
        return () => {
            live = false;
        };
    }, [row]);
    const modes = Array.from(new Set(state.points.map((p) => p.mode)));
    const effective = modes.includes(mode) ? mode : modes[0] || mode;
    // A run whose field count exceeds its stratum events comes from summary rows that could not be read as one row each.
    const unreadable = state.points.filter((p) => p.mode === effective && p.count > p.events);
    const points = state.points.filter((p) => p.mode === effective && p.count <= p.events);
    const newest = [...points].sort((a, b) => (b.runId > a.runId ? 1 : b.runId < a.runId ? -1 : 0)).slice(0, 24);
    return (
        <Box flex="1 1 100%">
            <Row align="center">
                <H>History, committed runs, 30 days</H>
                <Select value={effective} onChange={(e, { value }) => setMode(value)} prefixLabel="mode" appearance="subtle" inline>
                    <Select.Option label="profile" value="profile" />
                    <Select.Option label="discovery" value="discovery" />
                </Select>
                {state.loading ? null : <Muted>{plural(points.length, 'run')}</Muted>}
                {unreadable.length ? <Muted>{plural(unreadable.length, 'run')} left out ({unreadable.map((p) => slot(p.runId)).join(', ')}): the field count exceeds the stratum events, so the summary rows were not readable one per row</Muted> : null}
                {state.skipped.length ? <Muted>{plural(state.skipped.length, 'run')} left out ({state.skipped.map(slot).join(', ')}): not every active stratum had a profile yet, so the whole-source basis is unknown</Muted> : null}
            </Row>
            <Failure error={state.error} />
            {state.loading ? <Loading what="searching matalog_profiles" /> : <HistoryChart points={points} />}
            {points.length ? (
                <Table>
                    <Table.Head>
                        <Table.HeadCell width={200}>run</Table.HeadCell>
                        <Table.HeadCell width={200}>coverage</Table.HeadCell>
                        <Table.HeadCell align="right">distinct values</Table.HeadCell>
                        <Table.HeadCell align="right">events with a value</Table.HeadCell>
                        <Table.HeadCell align="right">events in the run&apos;s window</Table.HeadCell>
                    </Table.Head>
                    <Table.Body>
                        {newest.map((p) => (
                            <Table.Row key={p.runId + p.mode}>
                                <Table.Cell>{slot(p.runId)}</Table.Cell>
                                <Table.Cell>
                                    <NoWrap>
                                        <Bar ratio={p.coverage} />
                                        {pct(p.coverage)}
                                    </NoWrap>
                                </Table.Cell>
                                <Table.Cell align="right">{p.distinctExact === false ? `at least ${num(p.distinct)}` : num(p.distinct)}</Table.Cell>
                                <Table.Cell align="right">{num(p.count)}</Table.Cell>
                                <Table.Cell align="right">{num(p.events)}</Table.Cell>
                            </Table.Row>
                        ))}
                    </Table.Body>
                </Table>
            ) : null}
            {points.length > newest.length ? <Muted>{num(points.length - newest.length)} older runs in the chart only</Muted> : null}
            <Muted>Each row is one committed run: events carrying the field, the events of {bool(row.is_rollup) ? 'every active stratum from its latest profile as of that run' : 'the stratum'} and the distinct values, within the {effective} windows.</Muted>
            <Code>{state.spl || historySPL(row)}</Code>
        </Box>
    );
}

export default function Field() {
    const fieldKey = pageParams().get('field_key') || '';
    const [state, setState] = useState({ loading: true, error: null, data: null });
    const [reload, setReload] = useState(0);
    useEffect(() => {
        let live = true;
        if (!fieldKey) {
            setState({ loading: false, error: new Error('field_key is missing from the URL'), data: null });
            return undefined;
        }
        loadField(fieldKey).then(
            (data) => live && setState({ loading: false, error: data ? null : new Error(`no matalog_fields row has the key ${fieldKey}`), data }),
            (error) => live && setState({ loading: false, error, data: null })
        );
        return () => {
            live = false;
        };
    }, [fieldKey, reload]);

    const data = state.data;
    const typeLabels = useMemo(() => {
        const map = {};
        if (data) data.typeDefs.forEach((t) => { map[t.type_id] = t; });
        return map;
    }, [data]);

    if (state.loading) {
        return (
            <Wrap>
                <Loading what="reading matalog_fields" />
            </Wrap>
        );
    }
    if (!data) {
        return (
            <Wrap>
                <Failure error={state.error} />
                <Link to={lookupURL('')}>Lookup</Link>
            </Wrap>
        );
    }
    const { row, sourceRow, strata, source, declarations, scoped, unscoped, indexOnly, objects, types, strataRows, runs } = data;
    const snap = snapshot(row);
    const stratumRow = strataRows.find((s) => s.stratum_key === row.stratum_key);
    const anchored = row.window_anchor === 'last_event' && !!snap && snap.mode === 'discovery';
    const headCapped = !!snap && snap.mode === 'discovery' && !!stratumRow && bool(stratumRow.cur_truncated) && stratumRow.cur_run_id === snap.runId;
    // A stratum row carries its own discovery window; every other window comes from the run record.
    const windowOf = (s) => {
        if (!s) return '';
        if (s.mode === 'discovery' && stratumRow && stratumRow.cur_run_id === s.runId && stratumRow.cur_earliest && stratumRow.cur_latest) {
            return `the discovery window (${span({ earliest: stratumRow.cur_earliest, latest: stratumRow.cur_latest })}, from the stratum row)`;
        }
        return windowText(s.runId, s.mode, runs);
    };
    const coverageText = snap
        ? anchored
            ? countText(snap, runs, { anchored: true, truncated: headCapped })
            : `${num(snap.count)} of ${num(snap.events)} events in ${snap.ratio > 1 ? `a 1 in ${num(snap.ratio)} sample of ` : ''}${windowOf(snap)}${headCapped ? ' (the search stopped at its head cap before the window ended)' : ''}`
        : 'not measured';
    const absentValues = bool(row.is_rollup) ? list(row.absent_strata) : [];
    const strataByValue = {};
    strataRows.forEach((s) => { strataByValue[s.stratum_value] = s; });
    const winner = declarations.find((d) => d.decl_key === row.origin_decl_key);
    const losers = list(row.origin_candidates).filter((k) => k !== row.origin_decl_key).map((k) => declarations.find((d) => d.decl_key === k)).filter(Boolean);
    const objectsByKey = {};
    objects.forEach((o) => { objectsByKey[o.object_key] = o; });
    const dependents = Object.values(
        scoped.reduce((acc, e) => {
            if (!acc[e.object_key]) acc[e.object_key] = { edge: e, kinds: new Set(), inferred: false };
            acc[e.object_key].kinds.add(e.ref_kind);
            if (e.confidence === 'inferred') acc[e.object_key].inferred = true;
            return acc;
        }, {})
    )
        .map((d) => ({ ...d, object: objectsByKey[d.edge.object_key] || {} }))
        .sort((a, b) => (Number(b.edge.is_alert) || 0) - (Number(a.edge.is_alert) || 0) || (Number(b.object.last_run_time) || 0) - (Number(a.object.last_run_time) || 0));
    const topValues = list(row.top_values);
    const topCounts = list(row.top_counts).map(Number);
    const maxCount = Math.max(1, ...topCounts);
    const samples = list(row.sample_values);
    const sourcetype = (source && source.search_sourcetype) || row.src_sourcetype;
    const sortedTypes = [...types].sort((a, b) => (Number(b.is_best) || 0) - (Number(a.is_best) || 0) || (Number(b.is_match) || 0) - (Number(a.is_match) || 0) || (Number(b.cur_match_rate) || 0) - (Number(a.cur_match_rate) || 0));
    const strataSorted = [...strata].sort((a, b) => coverageOf(b) - coverageOf(a));

    return (
        <Wrap>
            <Muted>
                <Link to={lookupURL(row.field_name)}>Lookup</Link> / {row.field_name} / {row.src_index} / {row.src_sourcetype}
                {row.level === 'stratum' ? ` / ${row.stratum_label}` : ''}
            </Muted>
            <Row align="flex-start" style={{ justifyContent: 'space-between' }}>
                <div>
                    <Heading level={1} style={{ margin: 0 }}>
                        {row.field_name}
                    </Heading>
                    <Muted>
                        in{' '}
                        <Link to={sourceURL(row.source_key)}>
                            {row.src_index} / {row.src_sourcetype}
                        </Link>
                        , {row.stratum_label} ({row.level} level{bool(row.is_rollup) ? `, rollup of ${plural(row.rollup_strata, 'stratum', 'strata')}` : ''}).{' '}
                        {row.level === 'stratum' ? (
                            <>
                                Source-level row: <Link to={fieldURL(sourceRow.field_key)}>{sourceRow.stratum_label}</Link>.
                            </>
                        ) : (
                            `${plural(strata.length, 'stratum', 'strata')} below.`
                        )}{' '}
                        presence {row.presence}
                        {bool(row.identifier) ? ', identifier' : ''}
                    </Muted>
                </div>
                <Tags>
                    <Chip appearance="outline">origin: {row.origin || 'unknown'}</Chip>
                    {row.origin_app ? <Chip appearance="outline">{row.origin_app}</Chip> : null}
                    {row.origin_stanza ? <Chip appearance="outline">{row.origin_stanza}</Chip> : null}
                    {losers.length ? <Chip appearance="outline">conflict: {losers.map((d) => d.app).join(', ')}</Chip> : null}
                    {row.cur_prof_sample_ratio > 1 ? <Chip appearance="outline">sampled 1 in {num(row.cur_prof_sample_ratio)}</Chip> : null}
                </Tags>
            </Row>
            <Box flex="1 1 100%">
                <Row style={{ gap: 28 }}>
                    <Kpi>
                        <Muted>coverage, {snap ? `${snap.mode} ${slot(snap.runId)}` : 'no snapshot'}</Muted>
                        <b>{snap ? pct(snap.coverage) : 'none'}</b>
                        <Muted>{coverageText}</Muted>
                    </Kpi>
                    <Kpi>
                        <Muted>distinct values</Muted>
                        <b>{snap ? num(snap.distinct) : ''}</b>
                        <Muted>{snap ? `in the same ${snap.mode} window, ${snap.exact === null ? 'counted by the discovery search' : snap.exact ? 'exact' : 'inexact (the fieldsummary cap)'}` : 'not measured'}</Muted>
                    </Kpi>
                    <Kpi>
                        <Muted>type</Muted>
                        <b>{row.type_guess || ''}</b>
                        <Muted>{row.best_type_id ? `looks like ${typeName(row.best_type_id)} ${pct(row.best_type_rate)}` : 'no semantic type'}</Muted>
                    </Kpi>
                    <Kpi>
                        <Muted>last seen</Muted>
                        <b>{age(row.last_seen_time)}</b>
                        <Muted>{dateTime(row.last_seen_time)}, first seen {slot(row.first_seen_run)}</Muted>
                    </Kpi>
                    <Kpi>
                        <Muted>used by</Muted>
                        <b>{num(row.usage_count || 0)}</b>
                        <Muted>knowledge objects whose scope resolves here, {plural(row.usage_alert_count || 0, 'alert')} among them</Muted>
                    </Kpi>
                    {row.numeric_count ? (
                        <Kpi>
                            <Muted>numeric values</Muted>
                            <b>{num(row.numeric_count)}</b>
                            <Muted>values parsed as numbers in the same window: min {num(row.num_min)}, max {num(row.num_max)}, mean {num(row.num_mean)}</Muted>
                        </Kpi>
                    ) : null}
                </Row>
                <Muted>{WINDOW_SOURCE}</Muted>
                <Fragment spl={searchFragment(row.src_index, sourcetype, row.field_name, stratumFilter(row.stratum_field, row.stratum_value))} />
            </Box>
            <Row>
                <Meaning data={data} onSaved={() => setReload((n) => n + 1)} />
                <Box flex="1 1 300px">
                    <H>Where it comes from</H>
                    <div>
                        <Muted>winning declaration</Muted>{' '}
                        {winner ? (
                            <>
                                {declLine(winner)} <Mono>{winner.raw_value}</Mono>
                            </>
                        ) : row.origin_app ? (
                            `${row.origin_app} ${row.origin_stanza}`
                        ) : (
                            `none; ${row.origin || 'unknown'}`
                        )}
                    </div>
                    {losers.map((d) => (
                        <div key={d.decl_key}>
                            <Muted>also named by</Muted> {declLine(d)} (loses) <Mono>{d.raw_value}</Mono>
                        </div>
                    ))}
                    <div>
                        <Muted>search-time name</Muted> {sourcetype}
                        {sourcetype !== row.src_sourcetype ? ` (renamed from ${row.src_sourcetype})` : ' (no rename)'}
                    </div>
                    <div>
                        <Muted>declared</Muted> {bool(row.declared) ? 'yes' : 'no'}; <Muted>observed</Muted> {bool(row.observed) ? 'yes' : 'no'}
                        {row.origin_changed_run ? <>; <Muted>origin changed</Muted> {slot(row.origin_changed_run)}</> : null}
                    </div>
                </Box>
            </Row>
            <Box flex="1 1 100%">
                <H>Values{snap ? `, ${snap.mode} ${slot(snap.runId)}, counts over ${windowOf(snap)}` : ''}</H>
                {topValues.length ? (
                    <Table>
                        <Table.Head>
                            <Table.HeadCell>top values</Table.HeadCell>
                            <Table.HeadCell align="right">count</Table.HeadCell>
                            <Table.HeadCell>share of counted</Table.HeadCell>
                        </Table.Head>
                        <Table.Body>
                            {topValues.map((v, i) => (
                                <Table.Row key={`${i}:${v}`}>
                                    <Table.Cell><Mono>{v}</Mono></Table.Cell>
                                    <Table.Cell align="right">{num(topCounts[i])}</Table.Cell>
                                    <Table.Cell>
                                        <NoWrap>
                                            <Bar ratio={topCounts[i] / maxCount} width={160} />
                                            {snap && snap.count ? pct(topCounts[i] / snap.count) : ''}
                                        </NoWrap>
                                    </Table.Cell>
                                </Table.Row>
                            ))}
                        </Table.Body>
                    </Table>
                ) : (
                    <Muted>
                        {data.stored === false && !samples.length
                            ? 'values not stored (profile.store_sample_values is false)'
                            : bool(row.identifier) ? 'identifier: top values are not stored' : 'no top values stored'}
                    </Muted>
                )}
                {data.stored !== false || samples.length ? (
                    <Muted>
                        {snap ? `${num(Math.max(0, snap.distinct - topValues.length))} more distinct values in the same window, ` : ''}
                        {num(samples.length)} sample values kept{bool(row.samples_truncated) ? ' (truncated at the byte cap)' : ''}
                    </Muted>
                ) : null}
                {samples.length ? <Mono>{samples.slice(0, 40).join('  ')}{samples.length > 40 ? `  +${num(samples.length - 40)} more kept` : ''}</Mono> : null}
            </Box>
            <History row={row} />
            {strata.length || absentValues.length ? (
                <Box flex="1 1 100%">
                    <H>By stratum</H>
                    <Table stripeRows>
                        <Table.Head>
                            <Table.HeadCell width={360}>stratum</Table.HeadCell>
                            <Table.HeadCell width={180}>coverage in its last window</Table.HeadCell>
                            <Table.HeadCell align="right">distinct values</Table.HeadCell>
                            <Table.HeadCell>presence</Table.HeadCell>
                            <Table.HeadCell>last seen</Table.HeadCell>
                            <Table.HeadCell>profiled</Table.HeadCell>
                            <Table.HeadCell>discovered</Table.HeadCell>
                        </Table.Head>
                        <Table.Body>
                            {strataSorted.map((s) => {
                                const ss = snapshot(s);
                                const absent = absentValues.includes(s.stratum_value);
                                return (
                                    <Table.Row key={s.field_key}>
                                        <Table.Cell>
                                            <Link to={fieldURL(s.field_key)}>{s.stratum_label}</Link>
                                        </Table.Cell>
                                        <Table.Cell>
                                            <NoWrap>
                                                <Bar ratio={absent ? 0 : ss ? ss.coverage : 0} width={100} />
                                                {absent ? '0%' : ss ? pct(ss.coverage) : ''}
                                                {absent ? <Muted> absent in the last profile</Muted> : null}
                                            </NoWrap>
                                        </Table.Cell>
                                        <Table.Cell align="right">{ss ? num(ss.distinct) : ''}</Table.Cell>
                                        <Table.Cell>{s.presence}</Table.Cell>
                                        <Table.Cell>{age(s.last_seen_time)}</Table.Cell>
                                        <Table.Cell>{slot(s.cur_prof_run_id)}</Table.Cell>
                                        <Table.Cell>{slot(s.cur_disc_run_id)}</Table.Cell>
                                    </Table.Row>
                                );
                            })}
                            {absentValues.filter((v) => !strata.some((s) => s.stratum_value === v)).map((v) => {
                                const st = strataByValue[v] || {};
                                return (
                                    <Table.Row key={`absent:${v}`}>
                                        <Table.Cell>{st.stratum_label || `${row.stratum_field}=${v}`}</Table.Cell>
                                        <Table.Cell>
                                            <NoWrap>
                                                <Bar ratio={0} width={100} />
                                                0% <Muted>absent in the last profile</Muted>
                                            </NoWrap>
                                        </Table.Cell>
                                        <Table.Cell align="right">0</Table.Cell>
                                        <Table.Cell><Muted>no row</Muted></Table.Cell>
                                        <Table.Cell><Muted>never</Muted></Table.Cell>
                                        <Table.Cell>{slot(st.last_profiled_run)}</Table.Cell>
                                        <Table.Cell>{slot(st.cur_run_id)}</Table.Cell>
                                    </Table.Row>
                                );
                            })}
                        </Table.Body>
                    </Table>
                    {absentValues.length ? (
                        <Muted>
                            absent in {plural(absentValues.length, 'stratum', 'strata')} of {num(strataRows.filter((s) => s.level === 'stratum' && s.state === 'active').length)} active: {absentValues.join(', ')} (0 events carried the field in the stratum&apos;s last profile{row.cur_prof_run_id ? `, run ${slot(row.cur_prof_run_id)}` : ''})
                        </Muted>
                    ) : null}
                    <Muted>Coverage per stratum is that stratum row&apos;s share of its own events in its newest window (profile when profiled, else discovery); presence and last seen are the row&apos;s.</Muted>
                </Box>
            ) : null}
            <Row>
                <Box flex="1 1 100%">
                    <H>Who depends on it</H>
                    {dependents.length ? (
                        <Table stripeRows>
                            <Table.Head>
                                <Table.HeadCell width={360}>object</Table.HeadCell>
                                <Table.HeadCell width={180}>app</Table.HeadCell>
                                <Table.HeadCell width={110}>kind</Table.HeadCell>
                                <Table.HeadCell>reference</Table.HeadCell>
                                <Table.HeadCell width={100}>last run</Table.HeadCell>
                                <Table.HeadCell width={100} align="right">runs, 30 d</Table.HeadCell>
                            </Table.Head>
                            <Table.Body>
                                {dependents.map((d) => (
                                    <Table.Row key={d.edge.object_key}>
                                        <Table.Cell>
                                            {objectURL(d.edge, d.object) ? <Link to={objectURL(d.edge, d.object)}>{d.edge.name}</Link> : d.edge.name}
                                        </Table.Cell>
                                        <Table.Cell>
                                            <Link to={appURL(d.edge.app)}>{d.edge.app}</Link>
                                        </Table.Cell>
                                        <Table.Cell>{Number(d.edge.is_alert) ? <strong>alert</strong> : d.edge.ko_type}</Table.Cell>
                                        <Table.Cell>
                                            <Muted>
                                                {Array.from(d.kinds).join(', ')}
                                                {d.inferred ? ', inferred' : ''}; {d.edge.scope_text}
                                            </Muted>
                                        </Table.Cell>
                                        <Table.Cell>{d.object.last_run_time ? age(d.object.last_run_time) : 'none'}</Table.Cell>
                                        <Table.Cell align="right">{num(d.object.run_count_30d || 0)}</Table.Cell>
                                    </Table.Row>
                                ))}
                            </Table.Body>
                        </Table>
                    ) : (
                        <Muted>no knowledge object resolves to this field</Muted>
                    )}
                    {Number(row.usage_unscoped_count) || unscoped.length ? (
                        <Muted>
                            {plural(row.usage_unscoped_count || unscoped.length, 'reference')} by name only, without an index or sourcetype (name referenced without scope), not counted in used by
                            {unscoped.length ? `: ${Array.from(new Set(unscoped.map((e) => `${e.ko_type}:${e.app}:${e.name}`))).slice(0, 6).join(', ')}` : ''}
                        </Muted>
                    ) : null}
                    {indexOnly.length ? (
                        <Muted>
                            {plural(indexOnly.length, 'reference')} by index only ({Array.from(new Set(indexOnly.map((e) => e.scope_text))).join(', ')}), naming no sourcetype, not counted in used by: {Array.from(new Set(indexOnly.map((e) => `${e.ko_type}:${e.app}:${e.name}`))).slice(0, 6).join(', ')}
                        </Muted>
                    ) : null}
                </Box>
                <Box flex="1 1 100%">
                    <H>Semantic types</H>
                    {sortedTypes.length ? (
                        <Table>
                            <Table.Head>
                                <Table.HeadCell width={320}>type</Table.HeadCell>
                                <Table.HeadCell width={140}>rate</Table.HeadCell>
                                <Table.HeadCell width={200} align="right">matched / tested sample values</Table.HeadCell>
                                <Table.HeadCell width={90}>match</Table.HeadCell>
                                <Table.HeadCell>run</Table.HeadCell>
                            </Table.Head>
                            <Table.Body>
                                {sortedTypes.map((t) => {
                                    const def = typeLabels[t.type_id] || {};
                                    return (
                                        <Table.Row key={t._key}>
                                            <Table.Cell>
                                                <Tooltip content={def.description || typeName(t.type_id)}>
                                                    <span>{typeName(t.type_id)}{def.label ? <Muted> {def.label}</Muted> : null}</span>
                                                </Tooltip>
                                            </Table.Cell>
                                            <Table.Cell>
                                                <NoWrap>
                                                    <Bar ratio={t.cur_match_rate} width={60} />
                                                    {pct(t.cur_match_rate)}
                                                </NoWrap>
                                            </Table.Cell>
                                            <Table.Cell align="right">{num(t.cur_matched)} / {num(t.cur_tested)}</Table.Cell>
                                            <Table.Cell>
                                                {bool(t.is_best) ? <Chip appearance="fill">best</Chip> : bool(t.is_match) ? 'yes' : 'no'}
                                            </Table.Cell>
                                            <Table.Cell>{slot(t.cur_run_id)}{' '}<Muted>{t.source}</Muted></Table.Cell>
                                        </Table.Row>
                                    );
                                })}
                            </Table.Body>
                        </Table>
                    ) : (
                        <Muted>no type edge; {bool(row.identifier) ? 'identifier values were tested and matched nothing' : 'nothing matched'}</Muted>
                    )}
                </Box>
            </Row>
        </Wrap>
    );
}
