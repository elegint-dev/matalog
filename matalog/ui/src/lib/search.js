// One-shot search jobs in the app context, as the logged-in Splunk user.
import { createRESTURL } from '@splunk/splunk-utils/url';
import { defaultFetchInit } from '@splunk/splunk-utils/fetch';
import { username } from '@splunk/splunk-utils/config';

export async function oneshot(spl, { earliest, latest } = {}) {
    const body = new URLSearchParams();
    body.set('search', spl);
    body.set('exec_mode', 'oneshot');
    body.set('output_mode', 'json');
    body.set('count', '0');
    if (earliest) body.set('earliest_time', earliest);
    if (latest) body.set('latest_time', latest);
    const url = createRESTURL('search/jobs', { app: 'matalog', owner: username || '-' });
    const response = await fetch(url, {
        ...defaultFetchInit,
        method: 'POST',
        headers: {
            ...defaultFetchInit.headers,
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        },
        body: body.toString(),
    });
    if (!response.ok) {
        let detail = '';
        try {
            const payload = await response.json();
            detail = (payload.messages || []).map((m) => m.text).join('; ');
        } catch (err) {
            detail = '';
        }
        throw new Error(`search: HTTP ${response.status}${detail ? `, ${detail}` : ''}`);
    }
    const payload = await response.json();
    return payload.results || [];
}

// A string literal inside double quotes in SPL.
export function splQuote(value) {
    return `"${String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

const PLAIN_NAME = /^[A-Za-z0-9_.:]+$/;

// A field name as the left side of a search term, quoted unless it is plain.
export function splName(name) {
    return PLAIN_NAME.test(String(name)) ? String(name) : `"${String(name).replace(/"/g, '\\"')}"`;
}

// The search term that selects one stratum, as the summary endpoint writes it; empty for the whole source
// and for a __multi__ set, which a search term cannot select.
export function stratumFilter(stratumField, stratumValue) {
    if (!stratumField || stratumField === '__all__' || !stratumValue || stratumValue === '__all__') return '';
    const name = splName(stratumField);
    if (stratumValue === '__missing__') return `NOT ${name}=*`;
    if (stratumValue === '__empty__') return `${name}=""`;
    if (stratumValue.startsWith('__multi__')) return '';
    return `${name}=${splQuote(stratumValue)}`;
}
