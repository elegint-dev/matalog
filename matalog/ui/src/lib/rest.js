// GET and POST of a splunkd endpoint in the app namespace, as the logged-in Splunk user, returning the JSON body.
import { createRESTURL } from '@splunk/splunk-utils/url';
import { defaultFetchInit } from '@splunk/splunk-utils/fetch';

const NAMESPACE = { app: 'matalog', owner: 'nobody' };

async function failure(response, what) {
    let detail = '';
    try {
        const body = await response.json();
        detail = body.error || (body.messages || []).map((m) => m.text).join('; ');
    } catch (err) {
        detail = '';
    }
    return new Error(`${what}: HTTP ${response.status}${detail ? `, ${detail}` : ''}`);
}

export async function restGet(path, params = {}) {
    const qs = new URLSearchParams({ output_mode: 'json', count: '0', ...params });
    const response = await fetch(`${createRESTURL(path, NAMESPACE)}?${qs.toString()}`, { ...defaultFetchInit, method: 'GET' });
    if (!response.ok) throw await failure(response, `read ${path}`);
    return response.json();
}

export async function restPost(path, body, contentType) {
    const response = await fetch(createRESTURL(path, NAMESPACE), {
        ...defaultFetchInit,
        method: 'POST',
        headers: { ...defaultFetchInit.headers, 'Content-Type': contentType },
        body,
    });
    if (!response.ok) throw await failure(response, `write ${path}`);
    return response.json();
}

// The browser-navigable URL of an app endpoint, for a download link.
export function restURL(path, params = {}) {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '') qs.set(key, String(value));
    });
    const text = qs.toString();
    return `${createRESTURL(path, NAMESPACE)}${text ? `?${text}` : ''}`;
}
