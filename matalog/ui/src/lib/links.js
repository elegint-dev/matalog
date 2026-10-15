// Page links, relative to the app's view URLs (/<locale>/app/matalog/<page>), and links out to Splunk Web pages.
import { createURL } from '@splunk/splunk-utils/url';

function withParams(page, params) {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '') qs.set(key, String(value));
    });
    const text = qs.toString();
    return text ? `${page}?${text}` : page;
}

export function fieldURL(fieldKey, extra = {}) {
    return withParams('field', { field_key: fieldKey, ...extra });
}

export function sourceURL(sourceKey) {
    return withParams('source', { source_key: sourceKey });
}

export function lookupURL(q, extra = {}) {
    return withParams('lookup', { q, ...extra });
}

export function sourcesURL(extra = {}) {
    return withParams('sources', extra);
}

export function wasteURL(extra = {}) {
    return withParams('waste', extra);
}

export function statusURL() {
    return 'status';
}

export function pageParams() {
    return new URLSearchParams(window.location.search);
}

export function replaceParams(params) {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '' && value !== false) qs.set(key, String(value));
    });
    const text = qs.toString();
    const url = `${window.location.pathname}${text ? `?${text}` : ''}`;
    window.history.replaceState(null, '', url);
}

// The copyable fragment of a row: the source, the stratum filter when the row is a stratum, then the field.
export function searchFragment(index, sourcetype, fieldName, stratumFilter = '') {
    return `index=${index} sourcetype="${sourcetype}" ${stratumFilter ? `${stratumFilter} ` : ''}${fieldName}=* | stats count by ${fieldName}`;
}

function entity(owner, app, endpoint, name) {
    return `/servicesNS/${encodeURIComponent(owner || 'nobody')}/${encodeURIComponent(app)}/${endpoint}/${encodeURIComponent(name)}`;
}

// The Splunk Web home of an app.
export function appURL(app) {
    return createURL(`app/${encodeURIComponent(app)}`);
}

// The Splunk Web page of a knowledge object, from a usage edge (ko_type, app, name) and its matalog_objects row (owner).
export function objectURL(edge, object = {}) {
    const { ko_type: kind, app, name } = edge;
    const owner = object.owner || 'nobody';
    if (!app || !name) return '';
    switch (kind) {
        case 'alert':
            return createURL(`app/${app}/alert`, { s: entity(owner, app, 'saved/searches', name) });
        case 'report':
        case 'savedsearch':
            return createURL(`app/${app}/report`, { s: entity(owner, app, 'saved/searches', name) });
        case 'dashboard':
            return createURL(`app/${app}/${encodeURIComponent(name)}`);
        case 'datamodel':
            return createURL(`app/${app}/data_model_editor`, { model: entity(owner, app, 'datamodel/model', name) });
        case 'macro':
            return createURL(`manager/${app}/data/macros/${encodeURIComponent(name)}`, { action: 'edit', ns: app, uri: entity(owner, app, 'data/macros', name) });
        case 'eventtype':
            return createURL(`manager/${app}/saved/eventtypes/${encodeURIComponent(name)}`, { action: 'edit', ns: app, uri: entity(owner, app, 'saved/eventtypes', name) });
        case 'lookup':
            return createURL(`manager/${app}/data/transforms/lookups/${encodeURIComponent(name)}`, { action: 'edit', ns: app, uri: entity(owner, app, 'data/transforms/lookups', name) });
        default:
            return '';
    }
}
