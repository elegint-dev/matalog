// The human layer: a new matalog_meanings revision plus the meaning_human_* mirror on every
// matalog_fields row of the field, written in one action. A removal is a revision with empty text and
// status removed; the mirror is cleared so the field reads as having no meaning while the history stays.
import { username } from '@splunk/splunk-utils/config';
import { kvQuery, kvBatchSave } from './kv';
import { k } from './keys';

const CLEARED = { meaning_human: '', meaning_human_author: '', meaning_human_time: null, meaning_human_revision: 0 };

async function writeRevision(sourceRow, text, note, status) {
    const fieldKey = sourceRow.field_key;
    const existing = await kvQuery('matalog_meanings', { query: { field_key: fieldKey } });
    const revision = existing.reduce((max, row) => Math.max(max, Number(row.revision) || 0), 0) + 1;
    const createdAt = Math.floor(Date.now() / 1000);
    const author = username || 'unknown';
    const doc = {
        _key: k(fieldKey, revision),
        field_key: fieldKey,
        src_index: sourceRow.src_index,
        src_sourcetype: sourceRow.src_sourcetype,
        field_name: sourceRow.field_name,
        revision,
        is_current: 1,
        text,
        author,
        created_at: createdAt,
        note: note || '',
        status,
    };
    const superseded = existing
        .filter((row) => Number(row.is_current) === 1)
        .map((row) => ({ ...row, is_current: 0, status: 'superseded' }));
    await kvBatchSave('matalog_meanings', [...superseded, doc]);

    const mirror = status === 'removed'
        ? CLEARED
        : { meaning_human: text, meaning_human_author: author, meaning_human_time: createdAt, meaning_human_revision: revision };
    const rows = await kvQuery('matalog_fields', {
        query: { source_key: sourceRow.source_key, field_name: sourceRow.field_name },
    });
    if (rows.length) {
        await kvBatchSave('matalog_fields', rows.map((row) => ({ ...row, ...mirror })));
    }
    return { doc, mirrored: rows.length };
}

export function saveMeaning(sourceRow, text, note) {
    return writeRevision(sourceRow, text, note, 'current');
}

export function removeMeaning(sourceRow, note) {
    return writeRevision(sourceRow, '', note, 'removed');
}
