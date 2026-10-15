// Display helpers: numbers, percentages, times, run slots.

// Semantic type ids are namespaced (mt:, user:); pages show the bare name.
export function typeName(typeId) {
    if (!typeId) return '';
    const i = String(typeId).indexOf(':');
    return i < 0 ? String(typeId) : String(typeId).slice(i + 1);
}

export function num(value) {
    if (value === null || value === undefined || value === '') return '';
    const n = Number(value);
    if (Number.isNaN(n)) return String(value);
    return n.toLocaleString('en-US');
}

export function pct(ratio) {
    if (ratio === null || ratio === undefined || ratio === '') return '';
    const n = Number(ratio) * 100;
    if (Number.isNaN(n)) return '';
    if (n >= 99.95) return '100%';
    if (n > 0 && n < 0.05) return '<0.1%';
    return `${n.toFixed(n >= 10 ? 0 : 1)}%`;
}

export function nowSeconds() {
    return Date.now() / 1000;
}

// Age of an epoch as "2 min", "3 h", "7 d". Negative ages (a slot ahead of the clock) read as "0 min".
export function age(epoch) {
    if (!epoch) return '';
    const seconds = Math.max(0, nowSeconds() - Number(epoch));
    if (seconds < 90) return `${Math.round(seconds)} s`;
    if (seconds < 5400) return `${Math.round(seconds / 60)} min`;
    if (seconds < 172800) return `${Math.round(seconds / 3600)} h`;
    return `${Math.round(seconds / 86400)} d`;
}

export function dateTime(epoch) {
    if (!epoch) return '';
    const d = new Date(Number(epoch) * 1000);
    return d.toISOString().replace('T', ' ').slice(0, 16) + 'Z';
}

export function date(epoch) {
    if (!epoch) return '';
    return new Date(Number(epoch) * 1000).toISOString().slice(0, 10);
}

// 20261015T1700Z to 2026-10-15 17:00Z.
export function slot(runId) {
    if (!runId) return '';
    const m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})Z$/.exec(runId);
    if (!m) return runId;
    return `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}Z`;
}

export function slotEpoch(runId) {
    const m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})Z$/.exec(runId || '');
    if (!m) return null;
    return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]) / 1000;
}

export function bool(value) {
    return Number(value) === 1;
}

export function list(value) {
    return Array.isArray(value) ? value : [];
}

export function plural(count, singular, pluralForm) {
    const n = Number(count) || 0;
    return `${num(n)} ${n === 1 ? singular : pluralForm || `${singular}s`}`;
}

// Licensed bytes as "254 MB"; empty input stays empty so an unreadable figure is not shown as 0.
export function bytes(value) {
    if (value === null || value === undefined || value === '') return '';
    const n = Number(value);
    if (Number.isNaN(n)) return String(value);
    const units = ['B', 'kB', 'MB', 'GB', 'TB'];
    let v = n;
    let i = 0;
    while (v >= 1000 && i < units.length - 1) {
        v /= 1000;
        i += 1;
    }
    return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

export function seconds(value) {
    if (value === null || value === undefined || value === '') return '';
    const n = Number(value);
    if (Number.isNaN(n)) return String(value);
    if (n >= 100) return `${Math.round(n)} s`;
    return `${n.toFixed(1)} s`;
}

// Whole days since an epoch, the formula the waste saved search uses; null when the epoch is empty.
export function daysSince(epoch) {
    if (!epoch) return null;
    return Math.round((nowSeconds() - Number(epoch)) / 86400);
}
