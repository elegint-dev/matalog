import React, { useEffect, useMemo, useState } from 'react';
import Heading from '@splunk/react-ui/Heading';
import Link from '@splunk/react-ui/Link';
import Chip from '@splunk/react-ui/Chip';
import Table from '@splunk/react-ui/Table';
import Text from '@splunk/react-ui/Text';
import RadioBar from '@splunk/react-ui/RadioBar';
import Switch from '@splunk/react-ui/Switch';
import { declarationSummary, loadSource } from './data';
import { snapshot, coverageOf } from '../../lib/snapshot';
import { age, bool, bytes, date, dateTime, list, num, pct, plural, slot, typeName } from '../../lib/format';
import { WINDOW_SOURCE, span, windowText } from '../../lib/window';
import { fieldURL, lookupURL, pageParams, replaceParams, sourcesURL } from '../../lib/links';
import { Bar, Box, H, Kpi, Mono, Muted, NoWrap, Row, Tags, Wrap } from '../../components/styles';
import { Failure, Loading } from '../../components/Page';
import Fragment from '../../components/Fragment';

const GROUP_ROWS = 15;

function stratumAnchor(stratumKey) {
    return `stratum-${stratumKey}`;
}

function versionText(values, counts) {
    const v = list(values);
    const c = list(counts);
    if (!v.length) return '';
    return v.map((value, i) => `${value}${c[i] !== undefined ? ` ${num(c[i])}` : ''}`).join(', ');
}

// One field row, returned as a Table.Row element so Table.Body can stripe it.
function fieldRow(row) {
    const snap = snapshot(row);
    const cim = list(row.cim_fields);
    return (
        <Table.Row key={row.field_key}>
            <Table.Cell>
                <Link to={fieldURL(row.field_key)}>{row.field_name}</Link>
                {bool(row.is_stratum_field) ? <Muted> stratum field</Muted> : null}
            </Table.Cell>
            <Table.Cell>
                {snap ? (
                    <NoWrap>
                        <Bar ratio={snap.coverage} />
                        {pct(snap.coverage)} <Muted>{snap.mode === 'profile' ? 'p' : 'd'}</Muted>
                    </NoWrap>
                ) : (
                    <Muted>{row.presence === 'declared_only' ? 'never seen' : row.presence}</Muted>
                )}
            </Table.Cell>
            <Table.Cell align="right">
                <NoWrap>
                    {snap ? num(snap.distinct) : ''}
                    {bool(row.identifier) ? <Muted> identifier</Muted> : null}
                </NoWrap>
            </Table.Cell>
            <Table.Cell>{row.type_guess || ''}</Table.Cell>
            <Table.Cell>{row.best_type_id ? <NoWrap>{typeName(row.best_type_id)} <Muted>{pct(row.best_type_rate)}</Muted></NoWrap> : ''}</Table.Cell>
            <Table.Cell>
                <span>
                    {row.origin || ''}
                    {row.origin_app ? <Muted> {row.origin_app}</Muted> : null}
                </span>
                {bool(row.origin_conflict) ? <Chip appearance="outline">conflict</Chip> : null}
            </Table.Cell>
            <Table.Cell>
                {cim.length ? cim.map((f) => (
                    <div key={f}>
                        <Link to={lookupURL(f.slice(f.lastIndexOf('.') + 1), { dm: f })}>{f}</Link>
                    </div>
                )) : <Muted>none</Muted>}
            </Table.Cell>
            <Table.Cell>
                {row.meaning_human ? (
                    <span title={row.meaning_human}>{row.meaning_human.length > 90 ? `${row.meaning_human.slice(0, 90)}...` : row.meaning_human}</span>
                ) : (
                    <Muted>none</Muted>
                )}
            </Table.Cell>
            <Table.Cell align="right">
                <span>
                    {num(row.usage_count || 0)}
                    {Number(row.usage_alert_count) ? <Muted> {num(row.usage_alert_count)} alerts</Muted> : null}
                </span>
            </Table.Cell>
        </Table.Row>
    );
}

// Rows of one group, flat so Table.Body sees Table.Row children only.
function groupRows(group, open, onOpen) {
    const rows = open ? group.rows : group.rows.slice(0, GROUP_ROWS);
    const hidden = group.rows.length - rows.length;
    const out = [
        <Table.Row key={`head:${group.id}`}>
            <Table.Cell colSpan={9}>
                <span id={group.anchor}>
                    <strong>{group.label}</strong>, {plural(group.rows.length, 'field')}
                    {group.note ? <Muted> {group.note}</Muted> : null}
                </span>
            </Table.Cell>
        </Table.Row>,
    ];
    rows.forEach((row) => out.push(fieldRow(row)));
    if (hidden > 0) {
        out.push(
            <Table.Row key={`more:${group.id}`}>
                <Table.Cell colSpan={9}>
                    <Link to="#" onClick={(e) => { e.preventDefault(); onOpen(group.id); }}>show {num(hidden)} more fields</Link>
                </Table.Cell>
            </Table.Row>
        );
    }
    return out;
}

function byName(a, b) {
    return a.field_name.localeCompare(b.field_name);
}

function byCoverageThenName(a, b) {
    return coverageOf(b) - coverageOf(a) || byName(a, b);
}

function buildGroups(fields, strata, view, filter, showDefaults) {
    const needle = filter.trim().toLowerCase();
    const match = (r) => (!needle || r.field_name.toLowerCase().includes(needle)) && (showDefaults || !bool(r.is_default));
    const sourceRows = fields.filter((r) => r.level === 'source' && match(r));
    const stratumRows = fields.filter((r) => r.level === 'stratum' && match(r));
    const groups = [];
    if (view === 'stratum' && stratumRows.length) {
        const order = [...strata].filter((s) => s.level === 'stratum').sort((a, b) => (Number(b.share_of_source) || 0) - (Number(a.share_of_source) || 0));
        const byKey = {};
        stratumRows.forEach((r) => {
            if (!byKey[r.stratum_key]) byKey[r.stratum_key] = [];
            byKey[r.stratum_key].push(r);
        });
        order.forEach((s) => {
            const rows = (byKey[s.stratum_key] || []).filter((r) => r.presence === 'present').sort(byCoverageThenName);
            if (rows.length) groups.push({ id: s.stratum_key, anchor: stratumAnchor(s.stratum_key), label: s.stratum_label, rows, note: `share ${pct(s.share_of_source)}` });
            delete byKey[s.stratum_key];
        });
        Object.keys(byKey).forEach((key) => {
            const rows = byKey[key].filter((r) => r.presence === 'present').sort(byCoverageThenName);
            if (rows.length) groups.push({ id: key, anchor: stratumAnchor(key), label: rows[0].stratum_label, rows, note: 'stratum row not listed' });
        });
        const unobserved = stratumRows.filter((r) => r.presence === 'unobserved').sort(byName);
        if (unobserved.length) groups.push({ id: 'unobserved', anchor: 'unobserved', label: 'Observed before, absent now', rows: unobserved, note: 'per stratum' });
        const retired = stratumRows.filter((r) => r.presence === 'retired').sort(byName);
        if (retired.length) groups.push({ id: 'retired', anchor: 'retired', label: 'Retired strata', rows: retired });
    } else {
        const present = sourceRows.filter((r) => r.presence === 'present').sort(byCoverageThenName);
        const sourceStratum = strata.find((s) => s.level === 'source');
        if (present.length) {
            groups.push({
                id: 'source',
                anchor: sourceStratum ? stratumAnchor(sourceStratum.stratum_key) : 'source',
                label: 'All events',
                rows: present,
                note: present.some((r) => bool(r.is_rollup)) ? 'rollup over active strata' : 'source level',
            });
        }
        const unobserved = sourceRows.filter((r) => r.presence === 'unobserved').sort(byName);
        if (unobserved.length) groups.push({ id: 'unobserved', anchor: 'unobserved', label: 'Observed before, absent now', rows: unobserved });
    }
    const declared = sourceRows.filter((r) => r.presence === 'declared_only').sort(byName);
    if (declared.length) groups.push({ id: 'declared', anchor: 'declared', label: 'Declared, never observed', rows: declared });
    return groups;
}

export default function Source() {
    const params = pageParams();
    const sourceKey = params.get('source_key') || '';
    const [state, setState] = useState({ loading: true, error: null, data: null });
    const [view, setView] = useState(params.get('view') === 'source' ? 'source' : 'stratum');
    const [filter, setFilter] = useState(params.get('f') || '');
    const [showDefaults, setShowDefaults] = useState(params.get('defaults') === '1');
    const [openGroups, setOpenGroups] = useState([]);
    const openGroup = (id) => setOpenGroups((ids) => ids.concat(id));

    useEffect(() => {
        let live = true;
        if (!sourceKey) {
            setState({ loading: false, error: new Error('source_key is missing from the URL'), data: null });
            return undefined;
        }
        loadSource(sourceKey).then(
            (data) => live && setState({ loading: false, error: data ? null : new Error(`no matalog_sources row has the key ${sourceKey}`), data }),
            (error) => live && setState({ loading: false, error, data: null })
        );
        return () => {
            live = false;
        };
    }, [sourceKey]);

    useEffect(() => {
        replaceParams({ source_key: sourceKey, view: view === 'source' ? 'source' : '', f: filter, defaults: showDefaults ? 1 : '' });
    }, [sourceKey, view, filter, showDefaults]);

    const data = state.data;
    const stratified = data ? data.source.stratum_field && data.source.stratum_field !== '__all__' : false;
    const effectiveView = stratified ? view : 'source';
    const groups = useMemo(() => (data ? buildGroups(data.fields, data.strata, effectiveView, filter, showDefaults) : []), [data, effectiveView, filter, showDefaults]);
    const defaultRows = useMemo(
        () => (data ? buildGroups(data.fields, data.strata, effectiveView, filter, true).reduce((n, g) => n + g.rows.filter((r) => bool(r.is_default)).length, 0) : 0),
        [data, effectiveView, filter]
    );
    const decl = useMemo(() => (data ? declarationSummary(data.declarations) : null), [data]);

    if (state.loading) {
        return (
            <Wrap>
                <Loading what="reading matalog_sources" />
            </Wrap>
        );
    }
    if (!data) {
        return (
            <Wrap>
                <Failure error={state.error} />
                <Link to={sourcesURL()}>Sources</Link>
            </Wrap>
        );
    }
    const { source, strata, fields, declarations, runs } = data;
    const sourcetype = source.search_sourcetype || source.src_sourcetype;
    const dayWindow = windowText(source.updated_run_id, 'day', runs);
    const cycleWindow = windowText(source.updated_run_id, 'cycle', runs);
    const listingRun = strata.filter((s) => s.level === 'stratum').map((s) => s.last_seen_run).sort().pop() || source.updated_run_id;
    const activeStrata = strata.filter((s) => s.level === 'stratum' && s.state === 'active').sort((a, b) => (Number(b.share_of_source) || 0) - (Number(a.share_of_source) || 0));
    const deferredStrata = strata.filter((s) => s.state === 'deferred').sort((a, b) => (Number(b.listed_events) || 0) - (Number(a.listed_events) || 0));
    const retiredStrata = strata.filter((s) => s.state === 'retired');
    const sourceStratum = strata.find((s) => s.level === 'source');
    const declaredNeverSeen = fields.filter((r) => r.level === 'source' && r.presence === 'declared_only').length;
    const presentSource = fields.filter((r) => r.level === 'source' && r.presence === 'present').length;
    const listedStrata = activeStrata.length ? activeStrata : sourceStratum ? [sourceStratum] : [];
    const fragment = `index=${source.src_index} sourcetype="${sourcetype}" | fieldsummary maxvals=5`;
    const bytesStatus = source.daily_bytes_status || '';
    const namedDeclarations = declarations
        .filter((d) => d.attribute !== 'INDEXED')
        .sort((a, b) => a.app.localeCompare(b.app) || a.conf_file.localeCompare(b.conf_file) || a.attribute.localeCompare(b.attribute));

    return (
        <Wrap>
            <Muted>
                <Link to={sourcesURL()}>Sources</Link> / {source.src_index} / {source.src_sourcetype}
            </Muted>
            <Row align="flex-start" style={{ justifyContent: 'space-between' }}>
                <div>
                    <Heading level={1} style={{ margin: 0 }}>
                        {source.src_sourcetype}
                    </Heading>
                    <Muted>
                        index {source.src_index}.{' '}
                        {stratified
                            ? `Stratified by ${source.stratum_field}${source.version_field ? `, version field ${source.version_field}` : ', no version field'}.`
                            : 'Not stratified: one stratum, all events.'}{' '}
                        {sourcetype !== source.src_sourcetype ? `Searches see it as ${sourcetype}. ` : ''}
                        Profiled as {source.profiled_as}; discovered {slot(source.last_discovered_run) || 'never'}, profiled {slot(source.last_profiled_run) || 'never'}
                        {source.next_profile_due ? `, next profile due ${dateTime(source.next_profile_due)}` : ''}.
                    </Muted>
                </div>
                <Tags>
                    <Chip appearance="outline">{source.state}</Chip>
                    <Chip appearance="outline">
                        {source.profile_mode === 'sampled' ? `profiled, sampled 1 in ${num(source.sample_ratio || 1)}` : 'profiled unsampled'}
                    </Chip>
                    {list(source.config_apps).map((app) => (
                        <Chip key={app} appearance="outline">{app}</Chip>
                    ))}
                </Tags>
            </Row>
            <Box flex="1 1 100%">
                <Row style={{ gap: 28 }}>
                    <Kpi>
                        <Muted>events in {dayWindow}</Muted>
                        <b>{num(source.daily_events || 0)}</b>
                        <Muted>
                            {bytesStatus === 'ok' ? `${bytes(source.daily_bytes || 0)} licensed in the same day` : `licensed bytes ${bytesStatus || 'unknown'}`}
                            {Number(source.events_last_cycle) ? `; ${num(source.events_last_cycle)} events in ${cycleWindow}` : ''}
                        </Muted>
                    </Kpi>
                    <Kpi>
                        <Muted>last event</Muted>
                        <b>{source.last_event_time ? age(source.last_event_time) : 'none'}</b>
                        <Muted>{source.last_event_time ? `${dateTime(source.last_event_time)}, ` : ''}first seen {source.first_event_time ? date(source.first_event_time) : slot(source.first_seen_run)}</Muted>
                    </Kpi>
                    <Kpi>
                        <Muted>last human search</Muted>
                        <b>{source.last_human_search_time ? age(source.last_human_search_time) : 'none'}</b>
                        <Muted>{source.last_human_search_time ? `by ${source.last_human_search_user}, ${dateTime(source.last_human_search_time)}` : 'none since the audit window start'}</Muted>
                    </Kpi>
                    <Kpi>
                        <Muted>strata</Muted>
                        <b>{num(source.strata_count || 0)}</b>
                        <Muted>{num(source.strata_deferred || 0)} deferred{retiredStrata.length ? `, ${num(retiredStrata.length)} retired` : ''}</Muted>
                    </Kpi>
                    <Kpi>
                        <Muted>fields</Muted>
                        <b>{num(source.field_count || presentSource)}</b>
                        <Muted>source-level rows present, Splunk default fields included; {num(declaredNeverSeen)} declared, never seen</Muted>
                    </Kpi>
                    <Kpi>
                        <Muted>used by</Muted>
                        <b>{num(source.usage_count || 0)}</b>
                        <Muted>knowledge objects whose scope resolves here, {plural(source.usage_alert_count || 0, 'alert')} among them</Muted>
                    </Kpi>
                </Row>
                <Fragment spl={fragment} />
                <Muted>{WINDOW_SOURCE}</Muted>
            </Box>
            <Box flex="1 1 100%">
                    <H>Strata</H>
                    <Table stripeRows>
                        <Table.Head>
                            <Table.HeadCell width={300}>{stratified ? source.stratum_field : 'stratum'}</Table.HeadCell>
                            <Table.HeadCell width={170}>share</Table.HeadCell>
                            <Table.HeadCell width={80} align="right">fields</Table.HeadCell>
                            <Table.HeadCell width={200}>discovered</Table.HeadCell>
                            <Table.HeadCell width={150} align="right">events seen in the last discovery</Table.HeadCell>
                            <Table.HeadCell>{source.version_field ? source.version_field : 'version values'}</Table.HeadCell>
                        </Table.Head>
                        <Table.Body>
                            {listedStrata.map((s) => (
                                <Table.Row key={s.stratum_key}>
                                    <Table.Cell>
                                        <Link to={`#${stratumAnchor(s.stratum_key)}`}>{s.level === 'source' ? s.stratum_label : s.stratum_value}</Link>
                                        {s.value_kind !== 'value' && s.value_kind !== 'all' ? <Muted> {s.value_kind}</Muted> : null}
                                    </Table.Cell>
                                    <Table.Cell>
                                        <NoWrap>
                                            <Bar ratio={s.level === 'source' ? 1 : s.share_of_source} />
                                            {s.level === 'source' ? '100%' : pct(s.share_of_source)}
                                        </NoWrap>
                                    </Table.Cell>
                                    <Table.Cell align="right">{num(s.field_count || 0)}</Table.Cell>
                                    <Table.Cell>
                                        <NoWrap>
                                            {s.cur_latest ? age(s.cur_latest) : 'never'}
                                            {s.last_discovered_run ? <Muted> {slot(s.last_discovered_run)}</Muted> : null}
                                        </NoWrap>
                                    </Table.Cell>
                                    <Table.Cell align="right">
                                        <NoWrap title={s.cur_earliest && s.cur_latest ? `discovery window ${span({ earliest: s.cur_earliest, latest: s.cur_latest })}` : ''}>
                                            {num(s.cur_events_seen || 0)}
                                            {bool(s.cur_truncated) ? <Muted> head cap</Muted> : null}
                                        </NoWrap>
                                        {bool(s.cur_fields_truncated) ? <Chip appearance="outline">fields truncated</Chip> : null}
                                    </Table.Cell>
                                    <Table.Cell>{versionText(s.version_top, s.version_top_counts) || <Muted>none</Muted>}</Table.Cell>
                                </Table.Row>
                            ))}
                            {deferredStrata.map((s) => (
                                <Table.Row key={s.stratum_key}>
                                    <Table.Cell>
                                        {s.stratum_value} <Muted>deferred</Muted>
                                    </Table.Cell>
                                    <Table.Cell>
                                        <NoWrap>
                                            <Bar ratio={s.share_of_source} />
                                            {pct(s.share_of_source)}
                                        </NoWrap>
                                    </Table.Cell>
                                    <Table.Cell align="right" />
                                    <Table.Cell><Muted>never</Muted></Table.Cell>
                                    <Table.Cell align="right"><span>{num(s.listed_events || 0)} <Muted>listed{Number(s.listed_sample_ratio) > 1 ? `, 1 in ${num(s.listed_sample_ratio)} sample` : ''}</Muted></span></Table.Cell>
                                    <Table.Cell />
                                </Table.Row>
                            ))}
                        </Table.Body>
                    </Table>
                    <Muted>
                        {stratified
                            ? `Listed daily at 1 in ${num(listedStrata[0] && listedStrata[0].listed_sample_ratio ? listedStrata[0].listed_sample_ratio : 100)}. Deferred strata are counted, never searched; ${num(deferredStrata.length)} here.`
                            : 'One stratum carries every event; the discovery and profile windows are its figures.'}
                        {list(source.stratum_candidates).length ? ` Stratum candidates: ${list(source.stratum_candidates).join(', ')}.` : ''}
                        {' '}Events seen are what the stratum&apos;s last discovery search returned in its window (cur_earliest to cur_latest on the stratum row, in the cell tooltip; head cap means the search stopped at discovery.discovery_head_events before the window ended). Listed events are the last listing&apos;s raw count over {windowText(listingRun, 'listing', runs)}.
                    </Muted>
            </Box>
            <Box flex="1 1 100%">
                    <H>Config</H>
                    <div>
                        <Muted>apps declaring fields</Muted>{' '}
                        {list(source.config_apps).length ? list(source.config_apps).join(', ') : 'none'}
                    </div>
                    <div>
                        <Muted>KV_MODE</Muted> {decl.kvMode || 'none'}; <Muted>aliases</Muted> {num(decl.aliases)}; <Muted>evals</Muted> {num(decl.evals)};{' '}
                        <Muted>extracts</Muted> {num(decl.extracts)}; <Muted>reports</Muted> {num(decl.reports)}; <Muted>lookups</Muted> {num(decl.lookups)};{' '}
                        <Muted>indexed field declarations</Muted> {num(decl.indexed)}
                    </div>
                    <div>
                        <Muted>declarations changed</Muted> {slot(source.config_apps_changed_run) || 'never'};{' '}
                        <Muted>version changed</Muted> {slot(source.version_changed_run) || 'never'}
                    </div>
                    <div>
                        <Muted>version values</Muted> {versionText(source.version_top, source.version_top_counts) || 'none'}
                    </div>
                    {namedDeclarations.length ? (
                        <Table>
                            <Table.Head>
                                <Table.HeadCell width={200}>app</Table.HeadCell>
                                <Table.HeadCell width={420}>declaration</Table.HeadCell>
                                <Table.HeadCell width={110}>origin</Table.HeadCell>
                                <Table.HeadCell width={70} align="right">fields</Table.HeadCell>
                                <Table.HeadCell>value</Table.HeadCell>
                            </Table.Head>
                            <Table.Body>
                                {namedDeclarations.map((d) => (
                                    <Table.Row key={d.decl_key}>
                                        <Table.Cell><span>{d.app}{d.app_version ? <Muted> {d.app_version}</Muted> : null}</span></Table.Cell>
                                        <Table.Cell>
                                            <Mono>{d.conf_file} [{d.stanza}] {d.attribute}</Mono>
                                        </Table.Cell>
                                        <Table.Cell>{d.origin_class || ''}</Table.Cell>
                                        <Table.Cell align="right">{num(list(d.fields_declared).length)}</Table.Cell>
                                        <Table.Cell><Mono>{(d.raw_value || '').slice(0, 160)}</Mono></Table.Cell>
                                    </Table.Row>
                                ))}
                            </Table.Body>
                        </Table>
                    ) : (
                        <Muted>{declarations.length ? 'only indexed field declarations apply to this source' : 'no declaration applies to this source'}</Muted>
                    )}
            </Box>
            <Box flex="1 1 100%">
                <Row align="center">
                    <H>Fields{effectiveView === 'stratum' ? ', grouped by stratum' : ', source level'}</H>
                    <div style={{ width: 240 }}>
                        <Text value={filter} onChange={(e, { value }) => setFilter(value)} placeholder="filter by name" aria-label="filter fields" />
                    </div>
                    {stratified ? (
                        <RadioBar value={effectiveView} onChange={(e, { value }) => setView(value)}>
                            <RadioBar.Option value="source" label="source level" />
                            <RadioBar.Option value="stratum" label="by stratum" />
                        </RadioBar>
                    ) : null}
                    <Switch selected={showDefaults} onClick={() => setShowDefaults((v) => !v)} appearance="toggle" inline>
                        show default fields ({num(defaultRows)})
                    </Switch>
                    <Muted>
                        {plural(groups.reduce((n, g) => n + g.rows.length, 0), 'row')} in {plural(groups.length, 'group')}
                        {filter ? ` matching ${filter}` : ''}
                    </Muted>
                </Row>
                <Table stripeRows>
                    <Table.Head>
                        <Table.HeadCell width={200}>field</Table.HeadCell>
                        <Table.HeadCell width={130}>coverage, last window</Table.HeadCell>
                        <Table.HeadCell width={110} align="right">distinct values</Table.HeadCell>
                        <Table.HeadCell width={75}>type</Table.HeadCell>
                        <Table.HeadCell width={135}>best type</Table.HeadCell>
                        <Table.HeadCell width={120}>origin</Table.HeadCell>
                        <Table.HeadCell width={190}>data model field</Table.HeadCell>
                        <Table.HeadCell>meaning</Table.HeadCell>
                        <Table.HeadCell width={75} align="right">used by</Table.HeadCell>
                    </Table.Head>
                    <Table.Body>
                        {groups.flatMap((group) => groupRows(group, openGroups.includes(group.id), openGroup))}
                    </Table.Body>
                </Table>
                {!groups.length ? <Muted>no field row matches</Muted> : null}
                <Muted>
                    Coverage is the share of the row&apos;s events (the source&apos;s for a source-level row, the stratum&apos;s for a stratum row) carrying the field in the row&apos;s newest window: p is the profile, last run {slot(source.last_profiled_run) || 'never'}, {source.last_profiled_run ? windowText(source.last_profiled_run, 'profile', runs) : 'no profile window'}; d is the discovery, last run {slot(source.last_discovered_run) || 'never'}, {source.last_discovered_run ? windowText(source.last_discovered_run, 'discovery', runs) : 'no discovery window'} (a stratum discovered in an earlier run carries that run&apos;s window, on its field page). Distinct values are counted in the same window; used by counts knowledge objects whose scope resolves to the field.
                    {defaultRows ? ` ${num(defaultRows)} Splunk default fields (host, source, date_* and the like) are ${showDefaults ? 'shown' : 'hidden'}.` : ''}{' '}
                    Every row is one <Mono>matalog_fields</Mono> row; the search fragment is built from the source row.
                </Muted>
            </Box>
        </Wrap>
    );
}
