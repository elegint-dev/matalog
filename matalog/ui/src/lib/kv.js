// Catalog reads and writes through the app's catalog endpoint, as the logged-in Splunk user. The handler reads the
// collections with the system session and returns the rows of the indexes the user's roles can search; writes
// are limited to the human layer and need the writer capability.
import { createRESTURL } from '@splunk/splunk-utils/url';
import { defaultFetchInit } from '@splunk/splunk-utils/fetch';

const NAMESPACE = { app: 'matalog', owner: 'nobody' };
const ENDPOINT = 'matalog/catalog';

function catalogURL(params) {
    return `${createRESTURL(ENDPOINT, NAMESPACE)}?${params.toString()}`;
}

async function failure(response, what) {
    let detail = '';
    try {
        const body = await response.json();
        detail = body.error || (body.messages || []).map((m) => m.text).join('; ');
    } catch (err) {
        detail = '';
    }
    if (response.status === 403 && !detail) detail = 'the matalog_reader role is required';
    return new Error(`${what}: HTTP ${response.status}${detail ? `, ${detail}` : ''}`);
}

export async function kvQuery(collection, { query, fields, limit, sort, skip } = {}) {
    const params = new URLSearchParams({ collection });
    if (query) params.set('query', JSON.stringify(query));
    if (fields && fields.length) params.set('fields', fields.join(','));
    if (limit) params.set('limit', String(limit));
    if (sort) params.set('sort', sort);
    if (skip) params.set('skip', String(skip));
    const response = await fetch(catalogURL(params), { ...defaultFetchInit, method: 'GET' });
    if (!response.ok) throw await failure(response, `read ${collection}`);
    return response.json();
}

export async function kvGet(collection, key) {
    const params = new URLSearchParams({ collection, key });
    const response = await fetch(catalogURL(params), { ...defaultFetchInit, method: 'GET' });
    if (response.status === 404) return null;
    if (!response.ok) throw await failure(response, `read ${collection}/${key}`);
    return response.json();
}

export async function kvBatchSave(collection, docs) {
    const clean = docs.map((doc) => {
        const copy = { ...doc };
        delete copy._user;
        return copy;
    });
    const response = await fetch(catalogURL(new URLSearchParams({ batch: '1' })), {
        ...defaultFetchInit,
        method: 'POST',
        headers: { ...defaultFetchInit.headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ collection, docs: clean }),
    });
    if (!response.ok) throw await failure(response, `write ${collection}`);
    return response.json();
}

// Whether the profiler stores values (profile.store_sample_values), from the newest committed run's budget.
export async function valuesStored() {
    const rows = await kvQuery('matalog_runs', { query: { committed: 1 }, fields: ['budget'], sort: 'started_at:-1', limit: 1 });
    const profile = rows.length && rows[0].budget && rows[0].budget.profile;
    if (!profile || profile.store_sample_values === undefined) return true;
    return !['0', 'false', 'False'].includes(String(profile.store_sample_values));
}

export function regexEscape(text) {
    return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
