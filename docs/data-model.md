# matalog data model

Contract for the storage the profiler writes and for what the UI and the agent surface read: both go through the app's REST endpoints, which read the collections with the system session and return the rows of the indexes the caller's roles can search (see Agent surface, "Access"). The profiler's tests check the names, types, keys and rules in this file. Budget settings referenced as `stanza.setting` are defined in docs/budget-settings.md.

## Conventions

### Types

| type | meaning |
|---|---|
| string | UTF-8 text, stored verbatim |
| int | integer |
| float | number; ratios are 0 to 1 |
| bool | 0 or 1 |
| epoch | seconds since 1970 UTC, float |
| string[] | multivalue. In KV an array of strings; in the summary index repeated `name="value"` pairs that stash auto-kv reads back as one multivalue field, order preserved |
| json | KV only, an object or array |

Multivalue data that pairs values with numbers is stored as two parallel `string[]` columns (for example `top_values` and `top_counts`) and read back with `mvzip`. Arrays of objects are not stored anywhere SPL reads.

### Keys

`k(a, b, ...)` is the first 32 hex characters of SHA-256 over the parts joined with U+001F, UTF-8. A U+001F inside a part is replaced by U+FFFD before hashing. Every part is also stored as a plain field on the row, so SPL never decodes a key. Every KV `_key` and every summary row id is a `k(...)` of content, never a surrogate or a write time. Writing the same thing twice overwrites, and a field that vanishes and returns gets the same key. Everything in KV can be rebuilt from the summary index except human input: `matalog_meanings` and the `user` rows of `matalog_semantic_types` and `matalog_stratum_config`.

Identity fields and their normalization:

| field | rule |
|---|---|
| src_index | index name, lowercased |
| src_sourcetype | indexed sourcetype exactly as `metadata` and `tstats` report it |
| stratum_field | field name verbatim, or `__all__` |
| stratum_value | see sentinels below |
| field_name | field name verbatim, case kept, no trimming (`event.parameters{}.name` stays as is) |

The `src_` prefix is used in KV and in the summary index alike, because `index` and `sourcetype` on a summary row belong to the stash event.

Sentinels for `stratum_value`: `__all__` (the whole-source stratum, which exists for every source), `__empty__` (the stratum field is present with an empty value), `__missing__` (the event lacks the stratum field), and `__multi__` followed by U+001F and the sorted distinct values joined with U+001F (the field is multivalued in the event; the set is one stratum and is never split). No identity value is ever empty, null or `*`.

### Run identity

`run_id` is the UTC start of the cycle slot, `floor(now / budget.cycle_seconds) * budget.cycle_seconds`, formatted `YYYYMMDDTHHMMZ`. It sorts as text. `attempt` starts at 1 and goes up by 1 each time the same `run_id` is executed. Every search window is pinned to the slot, so a rerun searches the same window:

| window | latest | earliest |
|---|---|---|
| discovery (S3) | `slot_start - budget.window_lag_seconds` | `latest - discovery.discovery_window_seconds` |
| profile (S4) | `slot_start - budget.window_lag_seconds` | `latest - profile.profile_window_seconds` |
| stratum listing (S2) | `slot_start - budget.window_lag_seconds` | `latest - discovery.stratum_list_window_seconds` |
| source counts (S1) | `slot_start - budget.window_lag_seconds` | `latest - 86400` and `latest - budget.cycle_seconds` |

Anchored first discovery: a source with no events in the trailing day, a `last_event_time`, and no stratum with `last_discovered_run` (or one set by a rerun of this run) is due once with `window_anchor=last_event`: S2 lists it unsampled and S3 discovers it on a window `discovery.discovery_window_seconds` long ending at `last_event_time` (`latest` one second past its floor, since `latest` is exclusive) instead of the slot window, S4 leaves it alone that run, and the searched stratum rows and field rows record `window_anchor=last_event` (their `earliest` and `latest` are the anchored window). It is planned and budgeted like any discovery. Later runs treat the source as any other: its due rule stays slot-pinned, and a slot-pinned discovery clears `window_anchor`.

`run_mode` is `normal` or `rebuild`.

### Commit protocol

1. Steps S1 to S8 compute in memory. Summary rows (`kind` in `source`, `stratum`, `field`, `search_cost`) are appended to `matalog_profiles` as each step produces them, tagged `run_id`, `attempt`, `profiled_as`.
2. S10 writes one `kind=commit` row, then the KV batches, then sets `matalog_runs.committed=1` and `committed_attempt`.
3. The committed attempt of a `run_id` is the highest `attempt` that has a `kind=commit` row. Readers, rebuild and reclassify read only rows whose `(run_id, attempt)` is a committed attempt. Rows of other attempts stay in the index and are never read. A collect job that timed out can have indexed its batch before the retry, so a committed attempt can hold a row twice; every reader that counts or folds rows takes one row per `(run_id, attempt, row id)` (`profile_id` for `kind=field`, `row_id` otherwise).
4. KV holds committed state only; `matalog_write_buffer` is a staging area, not state. A crash before the commit row leaves every catalog collection untouched except `matalog_runs`. A crash after the commit row and before `committed=1` is detected by the next run at S1, which replays that run's KV writes from its committed rows (a bounded rebuild of one run) before its own work. The replay restores sources, strata and fields; the run's usage pass, type version check and CIM coverage are not replayed, so its record drops `objects_*`, `audit_watermark`, `type_versions`, `type_versions_hash`, `reclassified_types` and `cim_*` (with an error line saying so), and the next run redoes that work.
5. The commit row outlives the run record: `matalog_runs` is pruned at `retention.run_retention_count`, the index at `retention.profiles_frozen_days`, and commit rows age with the rows they commit.

### Baseline roll rule

Rows in `matalog_fields`, `matalog_strata` and `matalog_field_types` hold a `cur_*` snapshot and a `base_*` snapshot per mode.

- When a run writes a snapshot whose `run_id` is newer than the row's `cur_*_run_id`, it copies `cur_*` into `base_*` first, then overwrites `cur_*`.
- When `run_id` equals `cur_*_run_id` (a rerun), it overwrites `cur_*` only. A rerun never moves the baseline, so a run is never compared with itself.
- On `matalog_field_types`, a snapshot whose `source=reclassify` is written to `cur_*` and never rolled into `base_*`: when a later run rolls, it keeps the existing `base_*` if the outgoing `cur_*` has `source=reclassify`.
- `week_prof_*` on `matalog_fields` is not rolled; it is set by S4 from the committed profile row nearest `profile.week_baseline_days` before `run_id` (one search per run for the sources profiled that run).

### Write path to the summary index

Rows are built in Python and staged into the KV collection `matalog_write_buffer` (columns `run_id`, `attempt`, `seq`, `kind`, `r`, where `r` is the finished stash line: the slot timestamp followed by `name="value"` pairs, multivalues as repeated pairs). A batch is then copied with one job: `| inputlookup matalog_write_buffer where run_id=<run_id> attempt=<attempt> seq>=<first> seq<=<last> | eval _raw=r | fields - r | collect index=matalog_profiles sourcetype=stash`. A batch closes at `write.write_batch_rows` rows or `write.write_batch_bytes` bytes of payload, whichever comes first; a batch whose copied count differs from its distinct buffer keys is a failed batch. The buffer holds rows of the running attempt only and is cleared at the start of every run; it is not catalog state. `sourcetype=stash` keeps the rows off the ingest licence (verified). Every write search counts in the run's cost like any other search; the commit job's own cost is in the run record totals only.

Write reserve: before S3 is planned, the run sets `write_reserve = max(write.write_reserve_min, ceil(estimated_bytes / write.write_batch_bytes) + 2)`, capped at `budget.max_searches_per_cycle / 2`, where `estimated_bytes` is the previous committed run's `write_bytes` scaled by `strata_due / strata_discovered` of that run (or `write.write_reserve_min` when there is no previous run). S3 and S4 plan at most `budget.max_searches_per_cycle - searches_issued_so_far - write_reserve - config_reserve - 1` searches, where `config_reserve` is twice the indexes whose scan is due this run (S5's walklex and tstats probe per scanned index) and the 1 is S6's `_audit` read, 2 on a usage pass run (the run history read, see Usage).

Value encoding: every stored value is truncated to `profile.max_value_chars` characters. A row is at most `profile.max_row_bytes` bytes of JSON: `sample_values` is filled to `profile.sample_values` values or `profile.sample_values_max_bytes` bytes, whichever first, and `top_values`/`top_counts` entries are dropped from the tail until the row fits.

KV writes use `batch_save` in batches of `write.kv_batch_size` documents.

Read path: rebuild, crash replay and reclassify read summary rows as `_raw` (`| table _raw`) and parse each line with the exact inverse of the pair encoding above, never through auto-kv, which trims values ending in `=` or whitespace and values wrapped in double quotes. The SPL prunes on extracted or indexed terms only (`kind`, `run_id`, `attempt`, `shape`, the committed subsearch, the `dedup` subject).

### Rebuild and reclassify

`run_mode=rebuild` issues no search against data. It reads the latest committed row of every kind per subject from `matalog_profiles` (newest first, at most `rebuild.rebuild_max_rows` rows) and rewrites `matalog_sources`, `matalog_strata` (state, rate and share from the latest `mode=listing` rows), `matalog_fields` (snapshots, rollup rows recomputed from children, whose `cur_prof_distinct` is then the no-probe case of the rollup rule since the probed whole-source figure is not in the index, latest values, human mirror from `matalog_meanings`, usage summary from the stored `matalog_usage` and `matalog_objects`) and `matalog_field_types` (from the latest full `kind=field` rows). `matalog_cim_coverage` and the `cim_fields` and `cim_via` columns are not rebuilt: the next normal run's S8 recomputes them (see the CIM layer). It sets the run's `audit_watermark` `usage.audit_initial_lookback_days` before its audit window end, since no summary row carries `last_human_search_*`, so the next normal run rereads `_audit` over the whole lookback and rebuilds them (see Usage, "Last human search"). The declaration columns of `matalog_fields` (`declared`, `origin_decl_key`, `origin_candidates`, `origin_conflict`, `origin_stanza`), `search_sourcetype` and the `declared_only` rows are not in the index: rebuilt field rows get `declared=0` and `origin_conflict=0`, and the next normal run's S5, which resolves every enumerated source, restores the rest. `consecutive_unseen` is rebuilt from the stratum's two kept discoveries, so it is exact up to 2. `stratum_candidates` needs value counts the full rows do not keep and stays empty until the source's next profile. It then runs S10. It never writes `matalog_meanings`, `matalog_stratum_config` user rows or `matalog_semantic_types` user rows.

Reclassify is part of every normal run, not a mode. S7 compares `matalog_semantic_types.type_version` of every enabled type with `matalog_runs.type_versions` of the previous committed run. For each type whose version changed or that is new, S7 reads the latest committed full `kind=field` row per field (at most `rebuild.rebuild_max_rows`) and classifies that type against the stored `sample_values`, writing `matalog_field_types` with `source=reclassify`. Fields classified in the same run from a full row of that run are left to that classification, and a field whose `matalog_fields` row no longer exists is skipped. With no previous committed run, or one without `type_versions`, every enabled type is new.

### Profiler steps

Step names are used in every "written by" column. UI means the React app or REST as a Splunk user.

| step | name | does |
|---|---|---|
| S1 | enumerate_sources | `metadata type=sourcetypes` per index whose scan is due (`budget.index_scan_interval_seconds`), `tstats count max(_time)` by index and sourcetype for the trailing day and the trailing cycle, licence usage by index and sourcetype, app versions from `apps/local` |
| S2 | enumerate_strata | per stratified source due, one sampled `stats count by` the computed stratum value over the listing window |
| S3 | discover | per stratum due, unsampled: stratum filter, `head discovery.discovery_head_events`, `eval matalog_n=1`, `fieldsummary maxvals=profile.sample_values` on the discovery window |
| S4 | profile | per stratum due (its last profile empty or older than `profile.profile_interval_seconds`), in source order within the searches left, so a source's profile may span runs; `eval matalog_n=1`, `fieldsummary maxvals=profile.sample_values` on the profile window, sampled at `profile.sample_ratio` when the source is above `profile.sample_volume_threshold`, capped at `profile.profile_head_events`; one `stats dc()` probe per profiled unsampled source whose strata did not hit `head`, over the same window, by stratum value plus an `__all__` group for the whole source, for the fields whose `distinct_count` `fieldsummary` capped and then the fields present in more than one stratum, 1000 at most |
| S5 | read_config | props, transforms, fields, datamodels through the config endpoints as the service account; `walklex type=field` and one `tstats` probe per index whose scan is due, stored state for the other indexes; declarations and the winning declaration per field, for every enumerated source that is not `gone` |
| S6 | parse_usage | knowledge objects through REST, SPL parse to usage edges, `_audit` from a high watermark for last human search and last run |
| S7 | classify | semantic types over the `fieldsummary` values of S4 rows and of new-field S3 rows; reclassify for changed types |
| S8 | derive_meaning | data model class membership from the dataset constraints, eventtypes and tags; field mapping from the field rows, declarations and model calculations |
| S10 | commit | commit row, KV batches, run record |

There is no S9; S10 keeps its number.

Every search runs as `usage.service_account` in app context `matalog` and carries the SPL comment `` `comment("matalog run_id=<run_id> step=<step>")` ``.

Priority (orders S3 and S4 within a run) is computed at the end of S1 from this run's `daily_events` and the stored `usage_count` of the previous committed run:

`priority = log10(daily_events + 1) * (1 + budget.priority_usage_weight * usage_count) * (1 + cycles_since_discovered / budget.max_staleness_cycles)`

A stratum whose `cycles_since_discovered >= budget.max_staleness_cycles` is planned before any other work.

## Source

Storage: KV `matalog_sources`, accelerated on `src_sourcetype`, `state`, `daily_bytes`. Summary rows `kind=source`.
Key: `_key = k(src_index, src_sourcetype)`.

| field | type | definition | written by |
|---|---|---|---|
| source_key | string | Equals `_key`. | S1 |
| src_index | string | Index, lowercased. | S1 |
| src_sourcetype | string | Indexed sourcetype. | S1 |
| search_sourcetype | string | Name searches see after a props `rename`; equals `src_sourcetype` when there is none. | S5 |
| profiled_as | string | Account the data was seen as. | S1 |
| stratum_field | string | Stratum key in force from `matalog_stratum_config`; `__all__` when none. | S2 |
| version_field | string | Configured producer-version field, empty when none. | S2 |
| state | string | `active`, or `gone` (no events for `retention.gone_after_days`). A source with no events in the trailing cycle stays `active`; `events_last_cycle` and `last_event_time` show that it went quiet. | S1 |
| first_seen_run | string | First `run_id` that enumerated the source. | S1 |
| last_seen_run | string | Latest `run_id` in which `tstats` returned events. | S1 |
| first_event_time | epoch | Earliest event time from `metadata`, refreshed when the index scan is due. | S1 |
| last_event_time | epoch | Latest event time from `tstats max(_time)`. | S1 |
| events_last_cycle | int | Events in the trailing `budget.cycle_seconds`. | S1 |
| daily_events | int | Events in the trailing 86400 s. | S1 |
| daily_bytes | int | Licensed bytes in the trailing 86400 s; empty when `daily_bytes_status` is `unreadable` or `unavailable`. | S1 |
| daily_bytes_status | string | `ok` (the licence log has a row for the source; `daily_bytes` is its sum, 0 included); `unreadable` (the licence log could not be read, or its rows for the index carry no sourcetype); `stale` (events in the trailing cycle, newest licence entry older than the cycle); `unavailable` (the licence log was read and holds no row for this source, whatever its events: internal indexes `_*`, which Splunk does not license, and sources written with `sourcetype=stash` read `unavailable`). `0` with `ok` only when the log has a row with 0 bytes. | S1 |
| base_rate_per_hour | float | Median of `events_last_cycle * 3600 / cycle_seconds` over the last 7 committed `kind=source` rows. | S1 |
| profile_mode | string | `sampled` when `daily_events >= profile.sample_volume_threshold`, else `unsampled`. | S1 |
| sample_ratio | int | Ratio of the last S4 profile; 1 when unsampled. | S4 |
| priority | float | Priority for this run, formula above. | S1 |
| last_discovered_run | string | Latest `run_id` after which every active stratum had a committed discovery. | S3 |
| last_profiled_run | string | Run that profiled the last of the source's active strata still due, so every active stratum had a profile inside `profile.profile_interval_seconds` after it; empty until a profile first completes. | S4 |
| next_profile_due | epoch | `slot_start(last_profiled_run) + profile.profile_interval_seconds`. | S4 |
| strata_count | int | Strata with `state=active`. | S2 |
| strata_deferred | int | Strata with `state=deferred`. | S2 |
| strata_profile_due | int | Active strata still due for a profile after the last S4 pass; rebuild counts the active strata without one. | S4 |
| field_count | int | `matalog_fields` rows with `level=source` and `presence=present`. | S3, S4 |
| last_human_search_time | epoch | Latest `_audit` search whose scope resolves to this source (see Usage, "Last human search"), excluding `usage.exclude_users` and `usage.exclude_apps`; empty when none since the watermark start. | S6 |
| last_human_search_user | string | User of that search. | S6 |
| usage_count | int | Distinct knowledge objects with an edge whose `resolved_field_keys` lie in this source. | S6 |
| usage_alert_count | int | Of those, scheduled alerts. | S6 |
| config_apps | string[] | `app@version` of each app whose declarations apply to this sourcetype. | S5 |
| config_apps_changed_run | string | Latest `run_id` in which `config_apps` differed from the previous committed run. | S5 |
| version_top | string[] | Top `version_field` values across the latest discovery of each active stratum. | S3 |
| version_top_counts | string[] | Counts parallel to `version_top`. | S3 |
| version_changed_run | string | Latest `run_id` in which a value entered `version_top` that was not in it before. | S3 |
| stratum_candidates | string[] | Fields with `cur_prof_distinct <= 50` whose value predicts presence of other fields (suggestion only, see Stratum). | S4 |
| sources_top | string[] | Up to 20 `source` values the S5 probe saw for this source in the trailing day (the probe keeps up to 1000 per sourcetype; the first 20 are stored). Unchanged when the index was not probed this run; empty for a source never probed. `source=` terms in searches resolve against it. | S5 |
| hosts_top | string[] | Up to 20 `host` values, likewise; `host=` terms resolve against it. | S5 |
| index_scan_run | string | Latest run whose metadata read and index probe covered this source's index; empty until the first scan. | S5 |
| updated_run_id | string | Last run that wrote the row. | S10 |

Summary row `kind=source`, one per source per run, `_time` = slot start: `run_id`, `attempt`, `profiled_as`, `source_key`, `src_index`, `src_sourcetype`, `events_last_cycle`, `daily_events`, `daily_bytes`, `last_event_time`, `config_apps`, `version_top`, `version_top_counts`.

Invariants:
- A source row exists for every `(index, sourcetype)` that `tstats` or `metadata` reported in any committed run; `state=gone` rows are kept, never deleted.
- `daily_bytes` is never estimated from event counts; `unreadable` and `unavailable` are stated.

## Stratum

### Stratum configuration

Storage: KV `matalog_stratum_config`. Seed rows come from the `[stratum:<sourcetype>]` stanzas in matalog.conf (see docs/budget-settings.md).
Key: `_key = k(index_pattern, src_sourcetype)`.

| field | type | definition | written by |
|---|---|---|---|
| index_pattern | string | Index name or `*`. The most specific enabled row wins. | seed / UI |
| src_sourcetype | string | Sourcetype the row applies to. | seed / UI |
| stratum_field | string | Field whose value selects the schema. | seed / UI |
| version_field | string | Field whose value names the producer build, empty when none. | seed / UI |
| origin | string | `seed` or `user`. | seed / UI |
| enabled | bool | A disabled row is ignored. | UI |
| set_by | string | Splunk user for `user` rows; `matalog` for seed rows. | seed / UI |
| set_at | epoch | Last change. | seed / UI |

Invariants: reseeding upserts `origin=seed` rows only and never overwrites a `user` row with the same key.

### Stratum rows

Storage: KV `matalog_strata`, accelerated on `source_key`, `stratum_value`, `state`. Summary rows `kind=stratum`.
Key: `_key = k(src_index, src_sourcetype, stratum_field, stratum_value)`.

Every source has one `__all__` row (`stratum_field=__all__`, `stratum_value=__all__`, `level=source`). An unstratified source has only that row and it is the discovery and profile target. A stratified source has one `level=stratum` row per listed value; its `__all__` row is a rollup and is never searched.

S2 computes the stratum value per event as: `__missing__` when the field is absent, `__multi__` form when `mvcount > 1`, `__empty__` when the value is the empty string, otherwise the value. Values are ranked by `listed_events`, together with stored strata the listing missed on their stored counts; the first `discovery.max_strata_per_source` are `active`, the rest are `deferred`: listed, counted, never discovered, never profiled, never merged. A stratum key change to `__all__` writes one `mode=listing` row for the `__all__` stratum (`events_seen` 0, `sample_ratio` 1) so rebuild sees the change.

When the stratum field is extracted at search time and its extraction breaks, the listing returns `__missing__` for every event: the old strata are no longer listed and go silent (no events, then `retired` after `retention.stratum_retire_days`), and the `__missing__` stratum appears with the source's whole volume, which the source page shows. Nothing flags the break beyond that.

| field | type | definition | written by |
|---|---|---|---|
| stratum_key | string | Equals `_key`. | S2 |
| source_key | string | Parent source. | S2 |
| src_index, src_sourcetype | string | Parent identity. | S2 |
| stratum_field | string | Stratum key field, or `__all__`. | S2 |
| stratum_value | string | Value or sentinel. | S2 |
| stratum_label | string | Display form: `event_simpleName=ProcessRollup2`, `event_simpleName is missing`, `event_simpleName is empty`, `event_simpleName in {a, b}`, or `all events`. | S2 |
| value_kind | string | `all`, `value`, `empty`, `missing`, `multi`. | S2 |
| level | string | `source` for the `__all__` row, else `stratum`. | S2 |
| prunable | bool | 1 when `value_kind=value`: the discovery filter is `stratum_field="value"`, which the lexicon prunes. 0 otherwise: `NOT stratum_field=*`, `stratum_field=""`, or the conjunction of the set's values with an `mvcount` check. | S2 |
| state | string | `active`, `deferred`, `retired` (stratum key changed, or not listed for `retention.stratum_retire_days`). | S2 |
| listed_events | int | Count for this value in the last listing, raw, not scaled. | S2 |
| listed_sample_ratio | int | Sample ratio of that listing. | S2 |
| rate_per_hour | float | `listed_events * listed_sample_ratio * 3600 / discovery.stratum_list_window_seconds`. | S2 |
| share_of_source | float | `rate_per_hour` over the sum across the source's listed strata. | S2 |
| first_seen_run | string | Run that first listed the value. | S2 |
| last_seen_run | string | Latest run that listed it. | S2 |
| retired_run | string | Run that retired it; empty otherwise. | S2 |
| last_discovered_run | string | Latest run with a committed `kind=stratum mode=discovery` row. | S3 |
| discovery_due_run | string | Run by which this stratum must next be discovered: `last_discovered_run + budget.max_staleness_cycles` slots. | S3 |
| cur_run_id | string | Run of the current discovery snapshot. | S3 |
| cur_earliest, cur_latest | epoch | Window of that discovery. | S3 |
| cur_events_seen | int | Events the discovery returned (`count` of `matalog_n`). The absence denominator. | S3 |
| cur_events_scanned | int | Job `scanCount`. | S3 |
| cur_scan_ratio | float | `cur_events_scanned / max(cur_events_seen, 1)`. | S3 |
| cur_fields_found | int | Distinct fields in that discovery. | S3 |
| cur_truncated | bool | `head` was hit before the window ended. | S3 |
| cur_fields_truncated | bool | More than `discovery.max_fields_per_stratum` fields were returned; extras were counted, not stored. | S3 |
| window_anchor | string | `last_event` when the current listing or discovery used the anchored first-discovery window (Run identity); empty when slot-pinned. | S2, S3 |
| base_run_id, base_events_seen, base_events_scanned, base_scan_ratio, base_fields_found | as above | Previous committed discovery, moved under the roll rule. | S3 |
| last_profiled_run | string | Latest run with a committed `kind=stratum mode=profile` row. | S4 |
| profile_due_run | string | Slot of `last_profiled_run` plus `profile.profile_interval_seconds`; empty means due. | S4 |
| field_count | int | Fields with `presence=present` in this stratum. | S3, S4 |
| version_top | string[] | Top `version_field` values in the last discovery. | S3 |
| version_top_counts | string[] | Counts parallel to `version_top`. | S3 |
| version_changed_run | string | Latest run in which a value entered `version_top`. | S3 |
| updated_run_id | string | Last run that wrote the row. | S10 |

Summary row `kind=stratum`, one per searched stratum per mode per run, and one per listed stratum per S2 listing with `mode=listing` (carrying `earliest`, `latest`, `sample_ratio` = `listed_sample_ratio`, `events_seen` = `listed_events`, `fields_found` empty, so rebuild can derive `state`, `rate_per_hour` and `share_of_source`): `run_id`, `attempt`, `profiled_as`, `mode` (`discovery`, `profile` or `listing`), `source_key`, `stratum_key`, `src_index`, `src_sourcetype`, `stratum_field`, `stratum_value`, `earliest`, `latest`, `sample_ratio`, `events_seen`, `events_scanned`, `scan_ratio`, `fields_found`, `truncated`, `fields_truncated`, `prunable`, `version_top`, `version_top_counts`, `sid`, `search_seconds`, `window_anchor`.

Invariants:
- Absence rule: a field is absent in a run only when that run has a committed `kind=stratum mode=discovery` row for its stratum with `fields_truncated=0` and `events_seen >= discovery.min_events_for_absence`, and no `kind=field` row for it. An absent `present` row becomes `unobserved` and its `consecutive_unseen` goes up by 1.
- Deferred strata are never folded into another stratum.
- Stratum candidates (`matalog_sources.stratum_candidates`): on an unstratified source, S4 lists fields with `cur_prof_distinct` between 2 and 50 whose top value set partitions presence of at least 5 other fields (each present in events carrying one value and absent, at coverage below 0.05, in events carrying another). The computation uses the S4 `fieldsummary` rows only and never adds a search.

## Field

Storage: KV `matalog_fields`, accelerated on `field_name`, `source_key`, `stratum_key`, `level`, `presence`, `best_type_id`.
Key: `_key = k(src_index, src_sourcetype, stratum_field, stratum_value, field_name)`.

Rows:
- One `level=stratum` row per observed field per stratum.
- One `level=source` row per field name per source, keyed on the `__all__` stratum. For an unstratified source it is the measured row. For a stratified source it is a rollup (`is_rollup=1`) over the source's active strata, recomputed in any run that changed a child.
- A field that a declaration names and that no discovery has observed exists only as its `level=source` row with `observed=0`, `presence=declared_only`.

Rollup rule (`is_rollup=1`): `cur_prof_count` is the sum over the children's current profile snapshots; `cur_prof_events` is the sum of `events_seen` over every active stratum of the source with a profile, the strata profiled in `cur_prof_run_id` merged with the stored snapshots of the others (a stratum without the field contributes 0 to the count and its events to the denominator), so `cur_prof_coverage`, their ratio, is the field's share of the source's events. `cur_disc_count` and `cur_disc_events` follow the same rule over the strata's current discoveries (`cur_events_seen`, which can come from different runs; a stratum never discovered contributes nothing). `cur_prof_distinct` is the whole-source `dc()` of the field from the S4 distinct probe (the `__all__` group of the probe job, see kind=field below), with `cur_prof_distinct_exact=1`, when the probe carried the field. The union over strata is not known from per-stratum counts, so without a probe figure (sampled source, a stratum that hit `head`, no search left, field beyond the probe cap, probe failed, a rebuild) the rollup falls back: over exactly one child it keeps the child's distinct and exactness; for the source's stratum field, whose strata partition its values, it is the sum over children, exact when every child is and none is a `__multi__` set; for any other field it is the maximum over children with `cur_prof_distinct_exact=0`. `cur_disc_distinct` is the maximum over children (it carries no exactness). `week_prof_distinct` is the maximum over the children carrying the baseline, `week_prof_distinct_exact` 1 only over a single exact child. `top_values` merges children by summed counts, `sample_values` is the union capped at `profile.sample_values`, `identifier` is 1 when any child is 1 or when the probed figure passes the cardinality gate, `type_guess` is the children's majority or `mixed`, `cur_disc_run_id` and `cur_prof_run_id` are the newest child run. `week_prof_*` sums the children carrying it (the strata of that older run are not reread). `rollup_strata` counts the children included; `absent_strata` lists the active strata with a profile but without the field (while the rollup has no profile snapshot, the strata discovered without it), ordered as the strata table (`listed_events` descending, then value), and `absent_strata_count` is their number. Rebuild recomputes all of it from the children; the stratum events of the profile run are read off the children of that stratum and run.

| field | type | definition | written by |
|---|---|---|---|
| field_key | string | Equals `_key`. | S3 |
| source_key, stratum_key | string | Parents. | S3 |
| src_index, src_sourcetype, stratum_field, stratum_value, stratum_label | string | Identity, readable. | S3 |
| field_name | string | Name exactly as extracted. | S3 |
| level | string | `source` or `stratum`. | S3 |
| is_rollup | bool | `level=source` row of a stratified source. | S3 |
| rollup_strata | int | Children in the rollup; 0 when not a rollup. S4 sets it on a rollup only when S3 has not. | S3, S4 |
| absent_strata | string[] | On a rollup: `stratum_value` of each active stratum with 0 occurrences of the field in the last profile (rollup rule above), ordered as the strata table; empty otherwise. | S3, S4 |
| absent_strata_count | int | Length of `absent_strata`. | S3, S4 |
| is_stratum_field | bool | `field_name` equals the source's `stratum_field`. | S3 |
| is_default | bool | 1 for a Splunk default field (`host`, `source`, `sourcetype`, `index`, `linecount`, `punct`, `splunk_server`, `splunk_server_group`, `timestamp`, `timestartpos`, `timeendpos`, `eventtype`, `tag`, `tag::*`), an internal `_*` field or a `date_*` field. Set from the name on every row builder, rebuild included; readers hide these rows by default. | S3, S4, S5 |
| presence | string | `present`, `unobserved` (absent under the absence rule in Stratum rows), `declared_only`, `retired` (stratum retired). S4 sets `present` only on a row with no presence staged or stored. | S3, S4 |
| observed | bool | Seen in at least one committed discovery or profile. | S3, S4 |
| declared | bool | Named by at least one declaration applying to the source. | S5 |
| first_seen_run, last_seen_run | string | First and latest run that observed it in this stratum. | S3, S4 |
| last_seen_time | epoch | `latest` of the newest window in which it was observed. | S3, S4 |
| consecutive_unseen | int | Committed discoveries of the stratum in a row with `events_seen >= discovery.min_events_for_absence`, `fields_truncated=0` and no row for this field. Reset to 0 when observed. | S3 |
| retired_run | string | Run that retired the stratum; empty otherwise. | S2 |
| origin | string | `indexed`, `json_auto`, `kv_auto`, `regex_extract`, `regex_report`, `alias`, `eval`, `lookup`, `datamodel`, `unknown`. From the winning declaration; `json_auto` or `kv_auto` when no declaration names the field and the sourcetype has `KV_MODE=json` or `KV_MODE=auto`; `indexed` when `walklex type=field` lists it and a `tstats` probe confirms; else `unknown`. | S5 |
| origin_app | string | App of the winning declaration; empty when none. | S5 |
| origin_stanza | string | `props:<stanza>:<attribute>` form of the winning declaration. | S5 |
| origin_decl_key | string | `matalog_declarations._key` of the winner; empty when none. | S5 |
| origin_candidates | string[] | Declaration keys naming this field for the source, in precedence order as the service account sees it. | S5 |
| origin_conflict | bool | Declarations from more than one app name the field. | S5 |
| origin_changed_run | string | Latest run in which `origin` or `origin_decl_key` differed from the previous committed run. | S5 |
| cur_disc_run_id | string | Run of the current discovery snapshot. | S3 |
| cur_disc_count | int | Events in the discovery window carrying a non-null value. | S3 |
| cur_disc_events | int | `events_seen` of that discovery. | S3 |
| cur_disc_coverage | float | `cur_disc_count / cur_disc_events`. | S3 |
| cur_disc_distinct | int | `distinct_count` from that discovery. | S3 |
| window_anchor | string | `last_event` when the current discovery snapshot came from the anchored first-discovery window; empty when slot-pinned. | S3 |
| base_disc_run_id, base_disc_count, base_disc_events, base_disc_coverage, base_disc_distinct | as above | Previous committed discovery, moved under the roll rule. | S3 |
| cur_prof_run_id | string | Run of the current profile snapshot. | S4 |
| cur_prof_count, cur_prof_events, cur_prof_coverage, cur_prof_distinct | int, int, float, int | Profile figures, raw, not scaled by the sample ratio. | S4 |
| cur_prof_distinct_exact | bool | On a measured row `fieldsummary is_exact`, or 1 when the distinct probe replaced a capped `cur_prof_distinct` (kind=field below). On a rollup 1 only when `cur_prof_distinct` is the probe's whole-source `dc()`, the single child's exact figure, or the stratum field's partitioned sum (rollup rule above); 0 means the figure is a lower bound. | S4 |
| cur_prof_sample_ratio | int | 1 when unsampled. | S4 |
| base_prof_run_id, base_prof_count, base_prof_events, base_prof_coverage, base_prof_distinct, base_prof_distinct_exact, base_prof_sample_ratio | as above | Previous committed profile, moved under the roll rule. | S4 |
| week_prof_run_id, week_prof_count, week_prof_events, week_prof_coverage, week_prof_distinct, week_prof_distinct_exact, week_prof_sample_ratio | as above | Committed profile nearest `profile.week_baseline_days` before `cur_prof_run_id`; empty when none. | S4 |
| profile_id | string | Id of the newest full `kind=field` row for this field. | S3, S4 |
| type_guess | string | `string`, `integer`, `float`, `boolean`, `mixed`, `empty`. | S3, S4 |
| identifier | bool | Over the cardinality gate: `distinct >= profile.identifier_distinct`; or `distinct_exact=0` (a capped count) and `distinct >= profile.identifier_distinct_cap_min`; or `count >= profile.identifier_min_count` and `distinct / count >= profile.identifier_distinct_ratio`. | S3, S4 |
| numeric_count | int | Values that parse as numbers in the newest full row. | S3, S4 |
| num_min, num_max, num_mean | float | Numeric stats; empty when `numeric_count=0`. | S3, S4 |
| top_values | string[] | Up to `profile.top_values` values from the newest full row; empty when `identifier=1`. | S3, S4 |
| top_counts | string[] | Counts parallel to `top_values`. | S3, S4 |
| sample_values | string[] | The stored sample set of the newest full row, kept for identifiers too. | S3, S4 |
| samples_truncated | bool | The stored set hit `profile.sample_values_max_bytes` before `profile.sample_values`. | S3, S4 |
| values_hash | string | `values_hash` of the newest row. | S3, S4 |
| best_type_id | string | `type_id` of the edge with `is_best=1`; empty when none. | S7 |
| best_type_rate | float | Its `cur_match_rate`. | S7 |
| types | string[] | `type_id` of every edge with `is_match=1`, most specific first. | S7 |
| cim_fields | string[] | `Model.Dataset.field` entries this field maps to. | S8 |
| cim_via | string[] | Parallel to `cim_fields`: `same_name`, `alias`, `eval`, `lookup`, `datamodel_eval`. | S8 |
| meaning_human | string | `text` of the current `matalog_meanings` revision for the source-level `field_key`. | S10 / UI |
| meaning_human_author | string | Its `author`. | S10 / UI |
| meaning_human_time | epoch | Its `created_at`. | S10 / UI |
| meaning_human_revision | int | Its `revision`; 0 when none. | S10 / UI |
| usage_count | int | Distinct knowledge objects with an edge whose `resolved_field_keys` contains the source-level `field_key`. | S6 |
| usage_alert_count | int | Of those, scheduled alerts. | S6 |
| usage_objects | string[] | Up to `usage.usage_objects_shown` entries `ko_type:app:name`, alerts first, then by `last_run_time` descending. | S6 |
| usage_last_run_time | epoch | Latest `last_run_time` across those objects. | S6 |
| usage_unscoped_count | int | Edges with `resolution=unscoped` and this `field_name`; shown as "name referenced without scope", never added to `usage_count`. | S6 |
| updated_run_id | string | Last run that wrote the row. | S10 |

Invariants:
- Human meaning is attached to the source-level `field_key` only. Stratum rows carry the same `meaning_human_*` mirror for display. The mirror is copied from `matalog_meanings` immediately before each KV batch in S10; `matalog_meanings` stays authoritative and the UI writes both the revision row and the mirror columns of the affected rows in one action.
- No row has `presence=present` with `origin` empty; `unknown` is written explicitly.
- Rows with `presence` in `unobserved`, `declared_only`, no human meaning, no usage and `last_seen_run` older than `retention.unobserved_field_days` are deleted; the summary index keeps their history and the key returns unchanged if the field reappears.
- A field in a stratified source whose stratum is `deferred` has no row.

### Extraction declarations

Storage: KV `matalog_declarations`, accelerated on `src_sourcetype`, `app`.
Key: `_key = k(app, conf_file, stanza, attribute)`.

| field | type | definition | written by |
|---|---|---|---|
| decl_key | string | Equals `_key`. | S5 |
| app | string | Owning app. | S5 |
| app_version | string | Version of that app at read time. | S5 |
| owner, sharing | string | Config owner and sharing level. | S5 |
| conf_file | string | `props`, `transforms`, `fields`, `datamodels`. | S5 |
| stanza | string | Stanza name as written. | S5 |
| stanza_kind | string | `sourcetype`, `source`, `host`, `default`. | S5 |
| attribute | string | `EXTRACT-x`, `REPORT-x`, `FIELDALIAS-x`, `EVAL-x`, `LOOKUP-x`, `KV_MODE`, `INDEXED_EXTRACTIONS`, `rename`, `TRANSFORMS-x`. | S5 |
| origin_class | string | The `origin` value this declaration yields. | S5 |
| raw_value | string | Attribute value verbatim, truncated to 4096 characters. | S5 |
| fields_declared | string[] | Field names the declaration yields, where parseable. | S5 |
| parse_status | string | `parsed`, `partial`, `opaque`. | S5 |
| applies_to_source_keys | string[] | Sources whose sourcetype, source or host matches the stanza. | S5 |
| first_seen_run, last_seen_run | string | Config read bookkeeping. | S5 |

Invariants:
- Precedence between declarations for one field on one source follows Splunk's search-time operation sequence (index-time fields, then `EXTRACT`, `REPORT`, `KV_MODE`, `FIELDALIAS`, `EVAL`, `LOOKUP`): a later stage that writes the field is the winner, because its value is the one a search returns. `FIELDALIAS ... ASNEW` targets and every output of a `LOOKUP` with `OUTPUTNEW` never overwrite an existing field and rank below every writing stage; a data model calculation ranks just above them. Within one stage the order the config endpoints return for the service account (app precedence, then owner, then sharing) decides. `origin_candidates` holds this order, winner first.
- Rows not seen for `retention.object_stale_runs` S5 reads are deleted; an S5 read is a committed run that is not a rebuild, did not fail S5 and was not crash-replayed.

## Profile

Storage: summary index `matalog_profiles`, `sourcetype=stash`. Every row carries `kind`, `run_id`, `attempt`, `profiled_as`; `_time` is the slot start. Nothing here is edited; corrections are new rows under a new `attempt`.

### kind=field

Id: `profile_id = k(run_id, mode, field_key)`. One row per field per searched stratum per mode per run; no rows for rollups. Two shapes: `slim` for every discovery row, `full` for every profile row and for the discovery row of a field whose `first_seen_run` is this run.

| field | type | definition | shape |
|---|---|---|---|
| profile_id | string | Row id. | both |
| shape | string | `slim` or `full`. | both |
| mode | string | `discovery` or `profile`. | both |
| field_key, stratum_key, source_key | string | Parents. | both |
| src_index, src_sourcetype, stratum_field, stratum_value, field_name | string | Identity, readable. | both |
| earliest, latest | epoch | Search window. | both |
| sample_ratio | int | 1 when unsampled. | both |
| events_in_stratum | int | `count` of `matalog_n`: events the search returned for the stratum. | both |
| count | int | Events carrying a non-null value (`fieldsummary count`). | both |
| coverage | float | `count / events_in_stratum`. | both |
| distinct | int | `fieldsummary distinct_count`. | both |
| distinct_exact | bool | `fieldsummary is_exact`. `fieldsummary` stops counting at `max(maxvals, 500)` distinct values and then reports `is_exact=0` with `distinct_count` at that cap. On a profile row of an unsampled source whose stratum did not hit `head`, S4 replaces a capped `distinct` with the exact `dc()` of the field from one probe search per source over the same window and sets `distinct_exact=1`; a source the probe could not cover (sampled, `head` hit, no search left in the budget, probe failed) keeps the capped value with `distinct_exact=0`. The probe is `| <S2 stratum value eval> | eval matalog_sv=mvappend(matalog_sv, "__all__") | stats dc(f1) dc(f2) ... by matalog_sv` on a stratified source (`stats` counts an event in every group of a multivalue by-field, so the `__all__` row is the whole source's `dc()`, which the `level=source` rollup takes as its `cur_prof_distinct`; that row is ignored when any stratum of the source hit `head`) and `| stats dc(f1) ...` on an unstratified one. It carries, in this order and up to 1000 fields, the fields `fieldsummary` capped in a stratum that did not hit `head`, then, on a stratified source none of whose strata hit `head`, every field present in more than one profiled stratum, most strata first. The probe's figures are not stored as rows: a rebuild recomputes rollups without them (rollup rule). | both |
| numeric_count | int | Values that parse as numbers. | both |
| num_min, num_max, num_mean, num_stdev | float | Numeric stats; empty when `numeric_count=0`. | both |
| type_guess | string | As on the field row. | both |
| identifier | bool | As on the field row; the capped value counts through `profile.identifier_distinct_cap_min`. | both |
| values_hash | string | SHA-256 (32 hex) of the sorted top value set before any truncation. | both |
| sid | string | Search id that produced the row. | both |
| window_anchor | string | `last_event` for an anchored first discovery; empty otherwise. | both |
| top_values | string[] | Up to `profile.top_values` values, most frequent first; empty when `identifier=1`. | full |
| top_counts | string[] | Counts parallel to `top_values`. | full |
| sample_values | string[] | Distinct non-null, non-empty values from `fieldsummary values` (the empty string does not survive a stash line and is left out of `top_values`, `top_counts` and `sample_values` together; `values_hash` still covers it), most frequent first, filled to `profile.sample_values` values or `profile.sample_values_max_bytes` bytes. Kept for identifiers. The set S7 classifies. | full |
| samples_truncated | bool | The byte cap was hit first. | full |
| origin, origin_app | string | As S5 resolved them in this run: a normal run holds full rows unwritten until S5 has run. | full |

### kind=search_cost

Id: `k(run_id, sid)`. One row per search job, written by whichever step issued it: `step`, `subject_key` (source or stratum key, `write`, `week_baseline` for the S4 baseline read, or `replay:<run_id>`), `spl_hash` (first 32 hex of SHA-256 of the SPL), `earliest`, `latest`, `sample_ratio`, `scan_count`, `event_count`, `result_rows`, `run_duration`, `status` (`ok`, `failed`, `timeout`), `error` (the exception class when the job raised instead of returning a result, with `status=failed`; empty otherwise).

### kind=commit

Id: `k(run_id, attempt)`. Written last by S10: `run_mode`, `committed_at`, `type_versions_hash`, `config_hash`, `rows_written` as parallel `rows_kind`, `rows_count`, `write_bytes`, `searches_issued`, `events_scanned`, `search_seconds`, `wall_seconds`, `budget_exhausted`.

Invariants:
- A row is at most `profile.max_row_bytes` bytes; the trimming order is in Conventions.
- Only committed attempts are ever read.
- Slim rows exist only for strata the run discovered, so daily volume is bounded by `budget.max_searches_per_cycle` strata per cycle, not by the field count.

## Meaning

Two layers, shown in the order data model, human, never merged, each in its own store. No vendor field dictionaries ship; the stratum seeds in `matalog.conf` are configuration. The data model layer (S8, `matalog_cim_coverage`, `cim_fields`, `cim_via`) is tested against Splunk's internal data models only, not yet against CIM or vendor add-ons. The data model layer is read at run time from the datamodel REST endpoint (every installed model, CIM or custom) and from the installed add-ons' props, tags and eventtypes; a field's description and expected values are taken from the model definition's comment object when present and left empty otherwise. The `cim_` names below are kept for the common case; they hold whatever model is installed.

### CIM layer

Storage: KV `matalog_cim_coverage`, accelerated on `cim_dataset`, `cim_field`, `src_sourcetype`, `mapped`.
Key: `_key = k(cim_dataset, cim_field, src_index, src_sourcetype)`.

One row per dataset field per source in the dataset's class, for every dataset of every model the datamodel endpoint returns to the service account. `Dataset` is the object name; the dataset's fields are the model's field list for the object (inherited fields included, `objectCount` and `childCount` entries left out) plus the output fields of the calculations in its lineage.

Class membership. A dataset's constraint is the AND of its own constraint searches and its ancestors'. S8 parses the constraint into terms (parentheses, then `NOT`, then `OR`, then the implicit `AND`, as the search command does) and evaluates it per enumerated source that is not `gone` with three values:

- `index`, `sourcetype`, `source` and `host` terms (`=`, `::`, `!=`, wildcards, case-insensitive) resolve against the source's `src_index`, its `search_sourcetype`, and the source and host values the S5 probe saw for the sourcetype in the trailing day;
- `eventtype` terms resolve through the eventtypes the service account sees (the eventtype's search evaluated the same way, recursively); `tag` and `tag::<field>` terms through its tags config (every enabled `field=value` stanza of the tag, evaluated as a term);
- `earliest` and `latest` are time bounds and always hold;
- every other term is unresolved: a test on any other field, a bare keyword other than `*`, a comparison, a subsearch, a macro, a pipe, a base search or a transaction dataset. A `source` or `host` term is also unresolved for a source whose probe facts are missing (no events in the probe window, or the index was not probed this run) or capped at 1000 values without a match.

A source is in the class when the whole constraint is true. A dataset with a source left unresolved by a term is counted in `cim_datasets_unresolved` and named with its terms in one run record error per model; nothing is written for that source and dataset. The catalog never guesses membership from a field test.

Mapping. For a dataset field on a source in the class, the source-level `matalog_fields` row with that name decides, in this order: a row with `declared=1` and `origin` in `alias`, `eval`, `lookup` maps through its declaration (`cim_via` is the origin, `via_decl_key` its `origin_decl_key`, `coverage` empty unless the row is `present`); a `present` row of any other origin maps as `same_name`; a calculation in the dataset's lineage that outputs the name maps as `datamodel_eval` through the S5 `datamodels` declaration, with `field_name` the output name and `field_key` the row's key when a row exists, else empty; otherwise the row is `mapped=0`.

| field | type | definition | written by |
|---|---|---|---|
| cim_dataset | string | `Model.Dataset`, such as `Authentication.Authentication`. | S8 |
| cim_field | string | Dataset field name. | S8 |
| src_index, src_sourcetype | string | Source. | S8 |
| source_key | string | Its key. | S8 |
| mapped | bool | A source-level field maps to `cim_field`. | S8 |
| field_name | string | The mapping field; empty when unmapped. | S8 |
| field_key | string | Its source-level key; empty when unmapped or when a `datamodel_eval` output has no row. | S8 |
| cim_via | string | `same_name`, `alias`, `eval`, `lookup`, `datamodel_eval`; empty when unmapped. | S8 |
| via_decl_key | string | Declaration that supplies the mapping; empty for `same_name`. | S8 |
| coverage | float | `cur_prof_coverage` of that field, or `cur_disc_coverage` when no profile exists; empty when unmapped or not present. | S8 |
| cim_description | string | `description` of the field's comment object in the model definition, or the comment itself when it is a plain string; empty otherwise. | S8 |
| cim_expected_values | string[] | `expected_values` of that comment object; empty otherwise. | S8 |
| derived_run | string | Run that last confirmed the row. | S8 |

Invariants: rows not confirmed for `retention.cim_stale_runs` S8 runs are deleted (rebuild runs and runs where S8 failed do not count; rows of a model whose definition did not parse this run are kept). `cim_fields` and `cim_via` on the field row are the same facts seen from the field, in dataset order, and are cleared when the field no longer maps. S8 writes nothing, and deletes nothing, in a run where S5 could not read the datamodel endpoint. Rebuild does not derive coverage: the probe facts and declarations it needs are not in the summary index, so `matalog_cim_coverage` and the `cim_fields` and `cim_via` columns are left as stored and recomputed by the next normal run's S8.

### Human layer

Storage: KV `matalog_meanings`, accelerated on `field_key`, `is_current`.
Key: `_key = k(field_key, revision)`. One row per revision; rows are never edited in place.

`UI` below means the field page or the meanings import, both of which write through the app's REST handlers with the system session after the writer capability check (see Agent surface, "Access").

| field | type | definition | written by |
|---|---|---|---|
| field_key | string | Source-level `field_key` (the `__all__` row). | UI |
| src_index, src_sourcetype, field_name | string | Readable identity. | UI |
| revision | int | 1 for the first text, then +1 per edit. | UI |
| is_current | bool | 1 on the highest revision only. | UI |
| text | string | Definition as written. | UI |
| author | string | Splunk user. | UI |
| created_at | epoch | Write time. | UI |
| note | string | Optional edit reason. | UI |
| status | string | `current`, `superseded`, `orphaned` (the field has no `matalog_fields` row), `removed` (the field has no meaning again; see below). | UI, S10 |

Removing a meaning writes a new revision like an edit: `revision` one past the highest, `is_current=1`, `text` empty, `status=removed`, `author` the remover, `note` the reason; the earlier current revision becomes `superseded`. The history stays readable on the field page; the `meaning_human_*` mirror on every row of the field is cleared (`meaning_human` and `meaning_human_author` empty, `meaning_human_time` empty, `meaning_human_revision` 0), so the lookup card, the source page and the export show no meaning, and the next text written gets the next revision number. S10 copies the same cleared mirror for a `removed` current revision and leaves its status alone. The field page's "remove" control and a meanings import row whose `meaning` is `-` (one hyphen) both do this.

Invariants:
- The profiler never writes `text`, `author`, `created_at` or `revision`; S10 only flips `status` to `orphaned` or back to `current`, never on a `removed` revision.
- A meaning survives every run, every stratum key change and every vanish-and-return, because its key is the source-level content key.
- Only the newest `retention.meaning_revisions` revisions are kept.

## Usage

The knowledge object part of S6 is a usage pass. It runs when no committed normal run whose record carries `objects_total` has a slot within `usage.usage_interval_seconds` before this slot; every other run does the `_audit` read only and leaves the objects, edges and usage columns as stored. A pass lists, through REST as `usage.service_account` and across every app and owner the account can read, the saved searches (`saved/searches`), views (`data/ui/views`), macros (`data/macros`), lookup definitions (`data/transforms/lookups`), the eventtypes and the data models S5 read (`conf-eventtypes`, `datamodel/model`). A listing that fails is recorded in the run's `errors` and its type is left out of the pass; objects of a type that was not listed are neither counted nor deleted. Objects beyond `usage.max_objects`, in `ko_type`, `app`, `owner`, `name` order, are counted in `objects_total` and not written. One search per pass, over the 30 days before the run's `_audit` window end, reads `_internal sourcetype=scheduler status=success` and `_audit action=search info=completed` for `last_run_time` and `run_count_30d`: a saved search's count is the larger of the two sources, a dashboard's comes from `_audit` rows whose `provenance` is `UI:Dashboard:<name>`. The write reserve holds this search back from S3 and S4 planning on a pass run.

### Knowledge objects

Storage: KV `matalog_objects`, accelerated on `ko_type`, `parse_status`.
Key: `_key = k(ko_type, app, owner, name)`.

| field | type | definition | written by |
|---|---|---|---|
| object_key | string | Equals `_key`. | S6 |
| ko_type | string | `alert` (a saved search scheduled with an alert action or an alert condition), `report` (scheduled without), `savedsearch` (not scheduled), `dashboard`, `lookup`, `datamodel`, `macro`, `eventtype`. | S6 |
| app, owner, name, sharing | string | Identity and visibility; a macro's `name` is the endpoint name, `name(n)` with its argument count; a data model's is the model name. | S6 |
| is_scheduled | bool | Scheduled; for a data model, accelerated. | S6 |
| is_alert | bool | `ko_type=alert`. | S6 |
| disabled | bool | Disabled in config. | S6 |
| is_matalog_own | bool | Owned by `usage.service_account` or in `usage.exclude_apps`; parsed and listed, but no edge is written for it and it counts in no usage column. | S6 |
| spl_hash | string | First 32 hex of SHA-256 over the parser version, a newline and the SPL (a parser change reparses every object once): the search of a saved search or eventtype, the queries of a view joined with newlines, the definition of a macro, the model definition of a data model with its UUID calculation ids normalized, the definition columns of a lookup. An unchanged hash on a row whose `parse_status` is not `failed` skips the parse: the references of the stored edges are resolved again, `parse_status`, `parse_gaps` and `last_parsed_run` stay, and the object counts on the run record under its stored `parse_status`. | S6 |
| parse_status | string | `parsed` (no gap), `partial` (at least one gap), `failed` (the parser raised; the gap names the exception class). | S6 |
| parse_gaps | string[] | Constructs not resolved: `macro:<name>` (unknown, disabled, nested past 8 levels, or an eval macro whose definition is not one string literal), `eventtype:<pattern>` and `tag:<pattern>` (no enabled eventtype or tag assignment matches, the config could not be read, or nesting passed 8 levels), `subsearch` (a subsearch in a filtering position, whose returned terms are unknown), `map`, `foreach`, `pivot`, `command:<name>` (a command the parser does not know), `wildcard:<name>` (a field pattern), `token:<text>` (a dashboard token in a scope term or a command position), `iseval` (an eval macro object), `postprocess` and `chain` (a view search whose base could not be joined), `xml`, `json` and `definition` (a view or model definition that did not parse), `error:<class>`. | S6 |
| last_run_time | epoch | Latest completed run in the scheduler log or `_audit`; empty when none in the trailing 30 days and none stored. | S6 |
| run_count_30d | int | Completed runs in the trailing 30 days; 0 when none. | S6 |
| last_parsed_run | string | Run that parsed it. | S6 |
| last_seen_run | string | Latest pass that listed it. | S6 |

Invariants: objects of a listed type not seen for `retention.object_stale_runs` passes are deleted with their edges. `objects_total`, `objects_parsed`, `objects_partial` and `objects_failed` go to the run record of every pass run (`objects_total` less the other three is the number left unparsed by `usage.max_objects`); the catalog never claims completeness.

### Usage edges

Storage: KV `matalog_usage`, accelerated on `field_name`, `object_key`, `resolution`.
Key: `_key = k(object_key, scope, field_name, ref_kind)`.

The parser (`matalog.spl`) expands macros as the object's app sees them (its own app's definition first, then an exported one), to 8 levels, splits the text into subsearches and pipe segments, and reads each command. The scope of a pipeline comes from its generating command: the index, sourcetype, source and host terms of a search (each OR branch is one alternative; a later `search` command narrows every alternative), `from datamodel=`, `| datamodel` and `| from datamodel:` give a dataset, and a pipeline that starts from a command whose output is not event data (`rest`, `inputlookup`, `makeresults`, `metadata`, `dbinspect`, `eventcount`, `loadjob` and the like) references no catalog field. An `eventtype=<pattern>` term stands for the OR of the matching enabled eventtypes' own searches, read the same way; a `tag=<pattern>` or `tag::<field>=<pattern>` term stands for the OR of the enabled `tags.conf` assignments carrying the tag: an `eventtype=` assignment through that eventtype's search, an index, sourcetype, source or host assignment as that term, an assignment on any other field as no constraint. Eventtypes and tags come from the config S5 read this run (`conf-eventtypes`, `conf-tags`), else from REST; eight levels of nesting are followed. A term whose eventtype or tag is unknown, or whose config could not be read, constrains nothing and is a gap. A negated term (`NOT`, `!=`) constrains nothing. An alternative constrained on index alone (`index=x`, `index IN (...)`, an index wildcard, with no sourcetype, source or host term and no dataset) names no source: its references resolve as `index_only`, kept with the index pattern but counted nowhere, since reading an index is not using any one of its sourcetypes. A subsearch is parsed as its own pipeline with its own scope; one that filters its outer search is also a `subsearch` gap. The name an edge carries is the name as referenced, less a leading dataset or model prefix in a data model pipeline. A name produced earlier in the pipeline (`rename x AS y`, `... AS y` in a stats or eval, a `rex` group, a `spath` output, a lookup `OUTPUT`) is not a catalog field: a later reference to it becomes an `inferred` reference to each field it was computed from, and nothing when it was computed from no field. References to names starting with `_` and to names holding a dashboard token are dropped.

| field | type | definition | written by |
|---|---|---|---|
| object_key | string | Referencing object. | S6 |
| ko_type, app, name | string | Readable object identity. | S6 |
| is_alert | bool | Copied from the object. | S6 |
| field_name | string | Exact name referenced. | S6 |
| ref_kind | string | `filter` (a search, `where`-free term test, `regex`, or a `tstats` `where` term), `by` (`by` and `over` of a stats family command, `top`, `rare`, `dedup`, `sort`, `transaction`, `join`), `output` (`fields`, `table`, `fillnull`, `filldown`), `eval_input` (an eval or `where` expression, an aggregation argument, `rename` source, `rex` source, `spath` input, `bin`, `convert`, `mvexpand` and the like), `lookup_key` (the event-side field of a `lookup` command or a data model lookup calculation), `datamodel_field` (a field of a data model dataset, written for the `datamodel` object). | S6 |
| resolution | string | `exact_source` (literal index and sourcetype, an eventtype or tag whose search names both included), `sourcetype_pattern` (a wildcard in either, a missing index, or a missing sourcetype narrowed by a `source=` or `host=` term: `sourcetype=x` alone is `index=* sourcetype=x`, `source=x` alone is `index=* sourcetype=* source=x`), `index_only` (an index term and nothing else: `index=x`, `index IN (...)` or an index wildcard, with no sourcetype, source or host term; it resolves to no source), `partial` (an `exact_source` or `sourcetype_pattern` scope whose `source=` or `host=` pattern matches no known value of any matching source, so it resolves to nothing), `datamodel`, `unscoped` (no index, sourcetype, source or host term, a generating command the parser does not know, or `savedsearch`). | S6 |
| scope | string | `source_key` for `exact_source` (the typed identity's key when no enumerated source matches); `k("stpattern", index_pattern, sourcetype_pattern)` for `sourcetype_pattern`, with `source_pattern, host_pattern` appended when the scope carries either; `k("partial", index_pattern, sourcetype_pattern, source_pattern, host_pattern)` for `partial`; `k("index", index_pattern)` for `index_only`; `k("dm", Model.Dataset)` for `datamodel`; `*` for `unscoped`. | S6 |
| scope_text | string | `index=<pattern> sourcetype=<pattern>` with the patterns lowercased and `*` for a missing dimension, followed by ` source=<pattern>` and ` host=<pattern>` when the scope carries them; `Model.Dataset` for `datamodel`; `index=<pattern> sourcetype=*` for `index_only`; empty for `unscoped`. | S6 |
| resolved_field_keys | string[] | Source-level field keys the scope resolves to among the rows of `matalog_fields` after this run: the matching source's row for `exact_source` (the sourcetype matched case-insensitively against `src_sourcetype` and `search_sourcetype`), every matching source's row for `sourcetype_pattern`, every `mapped=1` row of the dataset and field in the stored `matalog_cim_coverage` for `datamodel`, empty for `partial`, `index_only` and `unscoped`. A `source=` or `host=` pattern keeps only the matching sources whose `sources_top` or `hosts_top` holds a matching value (case-insensitive, `*` a wildcard); a source with no stored values never matches such a pattern. | S6 |
| confidence | string | `exact`, or `inferred` when the reference sits inside a macro expansion or reaches the field through a derived name. | S6 |
| expanded | bool | The object's text expanded at least one macro before parsing. | S6 |
| macros | string[] | Names of the macros expanded in the object's text, nested ones included; empty when none. | S6 |
| scope_via | string[] | Knowledge objects the scope was reached through: `eventtype:<name>` and `tag:<name>`, in resolution order; empty when the scope comes from literal terms. | S6 |
| last_seen_run | string | Last parse that produced the edge; unchanged when the parse was skipped on an unchanged hash. | S6 |

Invariants:
- An `unscoped` edge is never fanned out to every field with that name and never counted in `usage_count`; it is shown separately through `usage_unscoped_count`. A `partial` edge counts in no usage column either; it stays on the object as the record of a scope the catalog could not place. An `index_only` edge counts in no usage column and is not in `usage_unscoped_count`; the field page lists it, by its index pattern, under the fields of the indexes the pattern matches.
- Edges of a parsed object that the parse did not produce again are deleted; edges of an object left unparsed by `usage.max_objects` stay and keep counting.
- The usage columns of the source-level field rows and of the sources are recomputed from every edge after the pass and staged where they differ from the stored values; a row that has never had usage keeps them empty, which reads as 0.
- `last_human_search_time` on sources comes from `_audit` searches whose scope resolves to the source, excluding `usage.exclude_users` and `usage.exclude_apps` (see "Last human search").

### Last human search

Every run reads `_audit` once, from the newest committed `audit_watermark` to the slot start less `budget.window_lag_seconds`: `action=search` events with `info` granted or completed, grouped by user, app and search text, keeping texts that carry an index, sourcetype, eventtype or tag term, a `datamodel` reference or a backtick. Each text is resolved like an object's SPL, with the app of the audit row deciding which macro definitions apply (to 4 levels), and its alternatives are matched against every known source: the stored and staged `matalog_sources` rows and this run's enumeration, with `src_sourcetype` and `search_sourcetype` as the names, and `sources_top` and `hosts_top` as the known source and host values. A source gets the newest matching search's time and user when newer than its stored value. A full read, whose window starts at the `usage.audit_initial_lookback_days` floor (the first run, or the run after a rebuild rewound the watermark), rebuilds the two columns instead: every known source takes the newest matching search of the window, and one whose stored stamp no search of the window reproduces is cleared; a full read that the row cap truncated only adds. Rules, per alternative:

- Index and sourcetype patterns must match. An alternative constrained on index alone (`index=x`, `index IN (...)`, an index wildcard) matches no source: a search counts for a source only when it names the sourcetype (`src_sourcetype` or `search_sourcetype`), narrows to it through `source=` or `host=` against `sources_top` or `hosts_top`, or reaches it through a resolved eventtype, tag, macro expansion or data model. A sourcetype pattern with no index term matches that sourcetype in every index.
- A `source=` or `host=` pattern keeps only the sources with a matching value in `sources_top` or `hosts_top`; a pattern that matches no known value stamps nothing, and a source never probed (no stored values) never matches such a pattern. `sources_top` holds at most 20 of up to 1000 probed values, so a search on a rare source file of a sourcetype with many files can miss; the stamp then stays absent rather than guessed.
- An `eventtype=` or `tag=` term resolves through the eventtype's search or the tag's assignments as above; `| datamodel`, `| from datamodel:` and `| tstats ... from datamodel=` resolve to the sources in the dataset's class in the stored `matalog_cim_coverage` (a model named without a dataset takes its root dataset), narrowed by any later `search` or `where` terms; a dataset with no coverage rows stamps nothing.
- A negated term constrains nothing; an alternative with no dimension at all stamps nothing.

## Semantic type

Storage: KV `matalog_semantic_types`, accelerated on `enabled`, `origin`. Shipped rows come from `lookups/matalog_semantic_types_shipped.csv` (registered as the file lookup `matalog_semantic_types_shipped`; its `enum_values` cell joins the values with `|`, and its `type_version` and `updated_at` cells are empty) and are upserted with `origin=shipped` by S7 on every normal run, in the S10 KV batch: `enabled` is kept from the stored row, `type_version` is recomputed, `updated_at` moves when the version does. A rebuild run does not reseed; it classifies against the stored rows.
Key: `_key = type_id`, where `type_id` is `mt:<name>` for shipped types and `user:<name>` for user types, `<name>` a lowercase slug.

Matching: a `regex` type is applied with `re.search` to the pattern as written, which is why patterns are anchored; `.` matches newlines; the match is case-insensitive unless `case_sensitive=1`. A type with `name_pattern` is tested only on fields whose `field_name` matches it (`re.search`, case-insensitive); elsewhere it counts as untested (0 tested, 0 matched), so shape-only integer types such as `port`, `pid` and `http_status` need a field name that says so. An `enum` type compares the value with `enum_values`, both lowercased unless `case_sensitive=1`. A `lookup` type reads the distinct values of `lookup_field` from `lookup_name` once per run, through one `inputlookup` job capped at `classify.max_lookup_values`, and then matches as an enum. Values are stripped of surrounding whitespace before testing. A row without `match_threshold` or `min_distinct` takes `classify.default_match_threshold` and `classify.default_min_distinct`; a row without `enabled` is enabled. A type whose matcher cannot be built (bad regex, unreadable lookup, unknown `matcher_kind`) is recorded in the run's `errors` and left out of that run: its edges and its entry in `type_versions` are untouched.

| field | type | definition | written by |
|---|---|---|---|
| type_id | string | Namespaced id, such as `mt:ipv4`. | shipped / UI |
| name | string | Slug without namespace. | shipped / UI |
| label | string | Display name. | shipped / UI |
| description | string | One-line meaning. | shipped / UI |
| origin | string | `shipped` or `user`. | shipped / UI |
| enabled | bool | Disabled types are not evaluated. | UI |
| matcher_kind | string | `regex`, `enum`, `lookup`. | shipped / UI |
| pattern | string | Anchored regex, for `regex`. | shipped / UI |
| name_pattern | string | Optional regex over the field name; the type is tested only where it matches. Empty means every field. | shipped / UI |
| enum_values | string[] | Allowed values, for `enum`. | shipped / UI |
| enum_source | string | CIM field whose value set the enum mirrors; empty otherwise. | shipped / UI |
| lookup_name, lookup_field | string | Lookup definition and column, for `lookup`. | shipped / UI |
| case_sensitive | bool | Matching is case sensitive. | shipped / UI |
| match_threshold | float | Share of tested values that must match. | shipped / UI |
| min_distinct | int | Minimum distinct tested values before the type can match. | shipped / UI |
| specificity | int | Higher wins among matching types; ties break by `type_id`. | shipped / UI |
| parent_type_id | string | Broader type, such as `mt:ipv4` for `mt:ipv4_private`; empty when none. | shipped / UI |
| type_version | string | `k(matcher_kind, pattern, enum_values, lookup_name, lookup_field, case_sensitive, match_threshold, min_distinct)` with `enum_values` as a compact JSON array, `case_sensitive` as `0` or `1`, the numbers in `num_text` form and the defaults above filled in; `name_pattern` is appended as a ninth part only when set, so a type without one keeps its version. Recomputed on every write; S7 writes it back on a `user` row whose stored value differs. | shipped / UI / S7 |
| author, updated_at | string, epoch | Last editor and time. | shipped / UI |

Invariants: reseeding touches `origin=shipped` rows only. A `user:` row never shadows an `mt:` row; both can match a field and specificity decides.

## Field-to-type edge

Storage: KV `matalog_field_types`, accelerated on `type_id`, `field_key`, `is_match`.
Key: `_key = k(field_key, type_id)`.

S7 classifies every field with a full row this run, identifiers included (the cardinality gate limits stored values, not classification); when a field has a discovery and a profile row in one run, the profile row is tested. Rollup rows (`is_rollup=1`) have no full row; they are classified from the `sample_values` of the rollup doc staged this run (the union over the children), with `cur_profile_id` empty and `source` after the rollup's newest snapshot; reclassify and rebuild read the stored present rollup docs. The tested set is exactly the row's `sample_values`. Rows are written for: types with `cur_match_rate >= classify.edge_store_floor`, the best type, and any type whose stored edge has `is_match=1` or a `cur_match_rate` or `base_match_rate` at or above the floor (rewritten with `is_match=0` when it no longer matches, so no stored match outlives the values it was tested on). `classify.max_types_per_field` caps the rows written for types without a stored edge, the best type first, then highest rate first; stored edges selected by the rules above are always rewritten. A stored edge of a type not written this run has its `is_best` flipped when the best type moved. The field row's `types` lists the written edges with `is_match=1` and, on a reclassify, the stored edges of unchanged types that still match.

| field | type | definition | written by |
|---|---|---|---|
| field_key, type_id | string | Edge ends. | S7 |
| src_index, src_sourcetype, stratum_value, field_name, level | string | Readable identity. | S7 |
| cur_run_id | string | Run of the current rate. | S7 |
| cur_type_version | string | Version that produced it. | S7 |
| cur_profile_id | string | Row whose `sample_values` were tested. | S7 |
| cur_tested | int | Values tested (`length(sample_values)`). | S7 |
| cur_matched | int | Tested values that matched. | S7 |
| cur_match_rate | float | `cur_matched / cur_tested`. | S7 |
| base_run_id, base_type_version, base_profile_id, base_tested, base_matched, base_match_rate | as above | Previous committed values, moved under the roll rule. | S7 |
| is_match | bool | `cur_match_rate >= match_threshold` and `cur_tested >= min_distinct`. | S7 |
| is_best | bool | The matching type with the highest specificity for this field; ties go to the lower `type_id`, so `mt:` before `user:`. | S7 |
| source | string | `profile`, `discovery` (new-field row), `reclassify`. | S7 |
| first_match_run | string | First run with `is_match=1`. | S7 |

Invariants:
- "Which fields are of type X" is `| inputlookup matalog_field_types where type_id="X" is_match=1`.
- Rates are compared only within one `type_version` and never between `source=reclassify` and another source.

## Run

Storage: KV `matalog_runs`, accelerated on `started_at`, `status`.
Key: `_key = run_id`. Rows beyond `retention.run_retention_count` are deleted, oldest first.

| field | type | definition | written by |
|---|---|---|---|
| run_id | string | Slot id. | S1 |
| attempt | int | Current attempt. | S1 |
| committed | bool | Commit flag. | S10 |
| committed_attempt | int | Attempt whose rows are authoritative. | S10 |
| run_mode | string | `normal` or `rebuild`. | S1 |
| status | string | `running`, `ok`, `partial` (a budget ceiling was hit or a step failed), `failed`, `skipped_locked` (another attempt held the run lock; nothing ran). | S1, S10 |
| profiled_as | string | Service account. | S1 |
| app_context | string | App the searches ran under. | S1 |
| started_at, finished_at | epoch | Wall clock. | S1, S10 |
| budget | json | Every setting in docs/budget-settings.md as used by this run. | S1 |
| config_hash | string | First 32 hex of SHA-256 over `budget`, the stratum config rows and the declaration keys in force. | S1 |
| type_versions | json | `{type_id: type_version}` for every enabled type at S7. | S7 |
| type_versions_hash | string | Hash of `type_versions`. | S7 |
| reclassified_types | string[] | Types S7 reclassified this run. | S7 |
| searches_issued | int | All jobs, writes included. | S10 |
| searches_failed | int | Jobs that errored or timed out. | S10 |
| write_searches | int | `collect` jobs. | S10 |
| write_reserve | int | Reserve computed for this run. | S1 |
| write_bytes | int | JSON bytes sent to the index. | S10 |
| events_scanned | int | Sum of `scanCount` over the searches that read events (not `tstats`, `metadata`, `eventcount`, `walklex` or `inputlookup` jobs). | S10 |
| events_matched | int | Sum of `eventCount`. | S10 |
| search_seconds | float | Sum of `runDuration`. | S10 |
| wall_seconds | float | `finished_at - started_at`. | S10 |
| peak_concurrency | int | Highest number of concurrent jobs. | S10 |
| per_step | json | `{step: {searches, scanned, seconds, rows_written, wall_seconds}}` for S1 to S8 and S10. | S10 |
| sources_total, sources_due, sources_profiled, sources_deferred | int | Work planned against work done; `sources_deferred` are the sources with strata still due after this run. | S10 |
| strata_profile_due, strata_profiled | int | Strata due for a profile this run; strata whose profile job returned. | S10 |
| indexes_total, indexes_scanned | int | Indexes listed with events; indexes whose metadata read, `walklex` and probe ran this run (`budget.index_scan_interval_seconds`). | S10 |
| indexes_sourceless | string[] | Indexes scanned this run whose metadata read and `tstats` reported no sourcetype (a metrics index); such an index is scanned again only once per `budget.index_scan_interval_seconds`. | S1 |
| strata_total, strata_due, strata_discovered, strata_deferred, strata_over_cap | int | Same per stratum; `strata_over_cap` are `state=deferred`. | S10 |
| fields_present, fields_new | int | Field rows of either level with `presence=present` after S3, over the sources S3 discovered this run; fields first seen this run. | S3 |
| budget_exhausted | string | First ceiling hit: `searches`, `scanned`, `search_seconds`, `wall_seconds`, or empty. | S10 |
| rows_written | json | `{kind: count}` for the index and `{collection: count}` for KV. | S10 |
| objects_total, objects_parsed, objects_partial, objects_failed | int | Parse outcomes, set on usage pass runs only: objects listed, and per parse outcome; an object skipped on an unchanged hash counts under its stored `parse_status`. | S6 |
| cim_datasets, cim_datasets_unresolved, cim_mapped | int | Datasets read from the installed models, those with a source left unresolved by a constraint term, and `mapped=1` coverage rows written. | S8 |
| scan_ratio_max | float | Worst `scan_ratio` among this run's discoveries. | S10 |
| audit_watermark | epoch | End of the `_audit` window S6 read in this run; the window start again when the read failed; on a rebuild run, `usage.audit_initial_lookback_days` before the window end. The next run reads `_audit` from the newest committed value of a run that did not finalize as failed. | S6, rebuild |
| errors | json | Up to 50 `{step, subject, message}`. | any |

Invariants: a run record exists for every attempt that reached S1; `committed=1` is set only after the commit row and every KV batch succeeded.

Run lock: KV `matalog_run_lock` holds one document, `_key=lock`, with `run_id`, `attempt`, `pid`, `host` and `started_at` of the attempt in progress. An attempt takes it before its run record opens and deletes it after the record is finalized (commit or failure), only while the document still carries its own `run_id`, `attempt` and `pid`. An attempt that finds a lock younger than `budget.max_wall_seconds_per_cycle` held by another process exits with `status=skipped_locked`, `errors` naming the holder, and writes that record unless the holder has the same `run_id` (the holder owns that record; the skip is then logged only). A lock at least `budget.max_wall_seconds_per_cycle` old is stale and taken over. The lock is not catalog state: it is never rebuilt and rebuild runs take it like any other attempt.

## Identity rules

**Sourcetype rename.** An index-time rename (a new sourcetype name on new events) is a new source with a new key. The old source stops receiving events and goes `gone` after `retention.gone_after_days`. Nothing is merged, moved or inferred; meanings on the old key stay readable on its `gone` row. A search-time `rename` in props changes `search_sourcetype` only; the key, every stratum, field, meaning and edge are unchanged.

**Sourcetype split.** One old source, several new ones: the rename rule applied once per new source. Each new source starts its own strata and fields; the old source's meanings stay on the old key.

**Stratum key change.** A change to `stratum_field` in `matalog_stratum_config` gives the source new stratum keys. In the first run under the new key: old `level=stratum` strata and their field rows get `state=retired` / `presence=retired` with `retired_run`; new strata and field rows are created. The source-level `__all__` rows are keyed without the stratum field, so human meanings, usage edges, type edges and CIM rows attached to them are untouched. Reverting to the earlier key reactivates the retired rows under their old keys; nothing is created twice. Retired stratum rows and their fields are deleted after `retention.stratum_retire_days`; their history stays in the index.

**Conflicting extractions across apps.** One name in one stratum is one field, however many apps declare it, because each event yields one value as the service account sees it. Each declaring stanza is a `matalog_declarations` row; the field's `origin_candidates` lists them in precedence order (the search-time operation sequence, then endpoint order; Extraction declarations), `origin_decl_key` points at the winner, and `origin_conflict=1` says more than one app claims it. A different winner in a later run sets `origin_changed_run`. The catalog applies Splunk's sequence and never shows the losing definition as the field's origin.

**Same name, different sourcetypes.** Two fields. They are linked by `field_name` queries and by `cim_fields`, never by identity.

## Jobs as queries

One query per job, against the collections or the summary index.

| job | query | collections read |
|---|---|---|
| 1 look up a field | `\| inputlookup matalog_fields where field_name="user" level="source"` | 1 |
| 1 drill to strata | `\| inputlookup matalog_fields where field_name="user" level="stratum"` | 1 |
| 1 full usage list | `\| inputlookup matalog_usage where field_name="user"` | 1 |
| 2 browse a source | `\| inputlookup matalog_fields where source_key="<k>" \| sort stratum_value, field_name`, header from `\| inputlookup matalog_sources where source_key="<k>"` | 2 |
| 4 data for an intent | `\| inputlookup matalog_cim_coverage where cim_dataset="Authentication.Authentication" cim_field="user"` (rows with `mapped=0` are the unmapped class members) | 1 |
| 5 find waste | `\| inputlookup matalog_sources \| eval days_idle=round((now()-coalesce(last_human_search_time,0))/86400) \| sort - daily_bytes` | 1 |
| 6 record meaning | write a `matalog_meanings` revision, then the `meaning_human_*` columns of the field rows with that source-level key | 2 writes |
| drift chart | `index=matalog_profiles kind=field mode=profile field_key="<k>" \| timechart max(coverage) max(distinct)` (filter to committed attempts by `kind=commit`) | index |
| which fields are type X | `\| inputlookup matalog_field_types where type_id="mt:aws_arn" is_match=1` | 1 |
| cost per run | `\| inputlookup matalog_runs \| table run_id searches_issued events_scanned search_seconds wall_seconds budget_exhausted` | 1 |

## Agent surface

The same graph for a model, through two routes that both exist on Splunk Cloud: a custom REST endpoint in the app, and four saved searches for a caller that only has a run-search tool. Both return the information of the lookup card per field, with the same compact names; the endpoint nests, the saved searches flatten to one row per field or source. Every count states the window it was measured in, so an absent or zero answer reads as "not seen in this window", never as "not in the data".

### Endpoint

`GET /services/matalog/summary` (also `/servicesNS/<user>/matalog/matalog/summary`), JSON, one of:

| parameter | returns |
|---|---|
| `source=<index>:<sourcetype>` | `source` (the source essentials), `fields` (every source-level `presence=present` field, by name), `n` (the source's `field_count`, less the default fields hidden), `limit`, `truncated` |
| `field=<name>` | `field`, `cards` (one per source carrying that exact name, alerts first, then usage, coverage, daily events; listed whatever `dflt` is), `n`, `truncated`, `other` (source-level fields whose name contains the word, the exact name left out), `other_truncated`, `dm` (data model fields of that name: `ds`, `mapped`, `unmapped`, `sources`), `limit` |
| `type=<name>` | `type`, `ids` (the `best_type_id` values matched, `mt:<name>` or `user:<name>`), `threshold` (`{type_id: match_threshold}` of the matching `matalog_semantic_types` rows), `cards` (one per source-level field whose best type has that bare name, case-insensitive, and whose `tr` reaches that type's `match_threshold`; the same shape as `field=` cards, best `tr` first, then the `field=` order; default fields left out unless `defaults=1`), `n`, `below_threshold` (rows of that type left out for a rate under the threshold), `truncated`, `limit` |
| `q=<word>` | `q`, `srcs` (sources whose sourcetype, search sourcetype, a `sources_top` path or a `config_apps` app name contains the word, case-insensitive; the source match object below), `srcs_n`, `srcs_truncated`, `matches` (source-level fields whose name contains the word, case-insensitive), `n`, `truncated`, `limit` |

`limit=<n>` caps `fields`, `cards`, `srcs`, `other` and `matches` (default 200, at most 2000); top values are capped at 10, samples and usage objects at 5. `other` and `matches` rank the exact name (case-insensitive) first, then names starting with the word, then names containing it, and within each by `used` then `cov` descending. `srcs` rank the exact sourcetype (or search sourcetype) first, then a prefix, a substring, a source path match, an app name match, and within each by `used` then `events_day` descending; a vendor word matches only what the data and the config carry (`okta` finds `OktaIM2:log` by sourcetype, `cloudtrail` finds `aws:cloudtrail`; `google` finds nothing when no sourcetype, path or app name carries it), there is no alias list. Every response carries `window` (below), the windows of the newest committed run, so an empty `cards`, `srcs` or `matches` still states what was looked at. `defaults=1` lists Splunk default fields (`dflt=1`) in `fields`, `other` and `matches`; without it they are left out, and every response carries `defaults` (the parameter as read) and `defaults_hidden` (how many rows it left out). Every response carries `values_stored` (0 when the newest committed run had `profile.store_sample_values` off: `top` and `samples` are then empty everywhere and a reader should say "values not stored") and `note`, a list of short strings naming what the request said that was ignored or not found, empty when nothing was: `unknown parameter foo ignored` (a parameter the endpoint does not take), `field ignored, source given` (two routes in one request: the first of `source`, `field`, `type`, `q` answers, the others are named), `type nosuchtype is not a known semantic type` (no `matalog_semantic_types` row has that bare name), `field nosuchfield is not in the readable catalog` (no card for the exact name). A malformed request (a `source` without the colon) is still a 400; a `limit` that is not a number is taken as the default. The handler (`bin/matalog_summary.py`, `restmap.conf`) requires the capability `matalog_summary_read`, reads the collections with the system session and applies the index filter of "Access" below: a `source=` whose index the caller cannot search is a 404 like an unknown source, and cards, `srcs`, matches, `dm` sources and the `window` totals of other indexes are left out. Errors come back as `{"error": ...}` with 400 (bad parameters), 403 (capability), 404 (unknown source) or 405.

### Access

Roles and capabilities, in `default/authorize.conf`:

| role | capabilities | can |
|---|---|---|
| `matalog_reader` | `matalog_summary_read`, `matalog_catalog_read` | read the catalog through the endpoints, narrowed to its indexes |
| `matalog_writer` | imports `matalog_reader`; `matalog_meanings_write`, `matalog_types_write` | also write meanings and user semantic types and stratum configuration through the endpoints |
| `admin`, `sc_admin`, `matalog_profiler` | all four, enabled on the role directly | everything above, plus the collections and lookups directly |

The built-in roles and the profiler's role get the capabilities directly rather than through `importRoles`: an `importRoles` line in the app's `authorize.conf` would replace the import list those roles already carry. `metadata/default.meta` gives read and write on `[collections]` and `[transforms]` to `admin`, `sc_admin` and `matalog_profiler` only, and read on `[savedsearches]` to `admin`, `sc_admin` and `matalog_profiler` (the saved searches read the collections through `inputlookup`, so only a role with lookup access can run them); a reader or writer who addresses `storage/collections/data` or `| inputlookup` directly is refused, and the writers never hold direct KV write. Every handler stanza in `restmap.conf` runs with `passSystemAuth`: the handler checks the caller's capability (the restmap `capability.get` and `capability.post` lines, or the handler itself where the capability depends on the collection), reads and writes with the system session, and filters by the caller's index access.

The filter: the caller's roles are read from `authentication/current-context` and each role's `srchIndexesAllowed` plus `imported_srchIndexesAllowed` from `authorization/roles` (so inheritance counts; `srchIndexesDefault` does not). A pattern matches as Splunk matches it: `*` is the wildcard and a pattern that does not start with `_` never matches an internal index. The index-scoped collections are the ones with a `src_index` column: `matalog_sources`, `matalog_strata`, `matalog_fields`, `matalog_cim_coverage`, `matalog_meanings`, `matalog_field_types`; their reads carry `src_index $in <the catalog's readable indexes>` inside the KV query, so `limit` and `skip` count readable rows only, and a row of an unreadable index is never returned. The usage graph and the run records have no `src_index` column and are scoped through the rows they point at; a caller whose roles can search every index of the catalog (the distinct `src_index` values of `matalog_sources`) reads them whole, every other caller gets:

| collection | rule for a caller who cannot search every catalog index |
|---|---|
| `matalog_usage` | an edge is readable when at least one of its `resolved_field_keys` is a `matalog_fields` row of a readable index; an edge with no resolved key (`unscoped`, `index_only`, `partial`, an unmatched `exact_source` or `datamodel`) is not |
| `matalog_declarations` | a declaration is readable when at least one of its `applies_to_source_keys` is a `matalog_sources` row of a readable index; one that applies to no source is not |
| `matalog_objects` | read by key only: `key=<object_key>` or a `query` whose top level (or a top-level `$and` term) carries `object_key` as a string or `{"$in": [...]}`; any other query is a 403. A key is served when a readable `matalog_usage` edge names it, so the objects a caller sees are the ones that reference fields it can read |
| `matalog_runs` | every row, cut to `_key`, `run_id`, `attempt`, `committed`, `committed_attempt`, `run_mode`, `status`, `started_at`, `finished_at`, `budget`, `searches_issued`, `searches_failed`, `write_searches`, `write_reserve`, `write_bytes`, `events_scanned`, `events_matched`, `search_seconds`, `wall_seconds`, `peak_concurrency`, `budget_exhausted`, `rows_written`, `sources_*`, `strata_*`, `fields_present`, `fields_new`, `objects_*`, `cim_*`, `scan_ratio_max`, `audit_watermark`; `errors`, `per_step`, `type_versions`, `type_versions_hash`, `reclassified_types`, `profiled_as`, `app_context` and `config_hash` are not served |

The edge rules are applied after the KV query, so for these collections `limit` and `skip` count readable rows after the rule (the whole query result is read first). `matalog_semantic_types` and `matalog_stratum_config` pass through for any reader. The summary endpoint's `used`, `alerts`, `unscoped` and `objects` come from the `matalog_fields` row they are on, so they follow the field's index. `matalog_write_buffer` and `matalog_run_lock` are not served. Writes are checked the same way: a meaning or a mirror row of an unreadable index is refused (403 on the catalog endpoint, `index not readable` on the meanings import).

### Catalog endpoint

`GET /services/matalog/catalog?collection=<name>` is what the pages read (`ui/src/lib/kv.js`); it requires `matalog_catalog_read` and takes `query=<json>`, `fields=<csv>`, `sort=<column[:dir]>`, `limit=<n>` and `skip=<n>` as the KV data endpoint takes them, returning the filtered rows as a JSON array; `key=<_key>` returns one row (404 when missing or unreadable). `POST /services/matalog/catalog?batch=1` with `{"collection": <name>, "docs": [...]}` (every doc with a `_key`, at most 5000 docs and 8 MB) writes the human layer and returns the keys written:

| collection | capability | rule |
|---|---|---|
| `matalog_meanings` | `matalog_meanings_write` | contract columns only; `src_index` must be readable; `author` is set to the caller |
| `matalog_fields` | `matalog_meanings_write` | only `meaning_human`, `meaning_human_author`, `meaning_human_time`, `meaning_human_revision` are taken from the doc and applied to the stored row, which must exist and be readable; `meaning_human_author` is set to the caller |
| `matalog_semantic_types` | `matalog_types_write` | `origin=user` rows only; a stored row of another origin under that key is refused; `author` is set to the caller |
| `matalog_stratum_config` | `matalog_types_write` | `origin=user` rows only; a stored row of another origin is refused; `set_by` is set to the caller |

Any other collection is refused with 403. The one-shot searches the pages run (field history, the source page's event counts) still run as the caller through `search/jobs`, so they see what the caller's roles can search.

Field object, the lookup card as data (every key is always present; `null` means not measured):

| key | from | meaning |
|---|---|---|
| n, idx, st, key | field_name, src_index, src_sourcetype, field_key | identity |
| cov, cnt, ev, dist | cur_prof_* or cur_disc_* | coverage 0 to 1, events carrying the field, events in the window, distinct values |
| exact | cur_prof_distinct_exact | 1 when dist is exact; null on a discovery snapshot |
| win, ratio, run | snapshot | `profile` when a profile snapshot exists, else `discovery`; its sample ratio and run id |
| ws, we | run record of `run`, or the stratum row | start and end epoch of the window `cov`, `cnt`, `ev`, `dist`, `top`, `samples` and `num` were measured in: the profile window of `run` when `win` is `profile`; on a discovery snapshot the window the stratum row records for that run (`cur_earliest`, `cur_latest` of the row's `stratum_key` when its `cur_run_id` is `run`, else the span of the source's stratum-level rows discovered in `run`), falling back to the run's discovery window (Windows below); `null` when neither is there |
| no_events | ev | 1 when `ev` is 0: nothing was seen in `ws` to `we`, so the counts say nothing about the field |
| anchor | window_anchor of the row, else of the stratum row | `last_event` when the discovery snapshot came from the anchored first discovery (its window ends at the source's `last_event_time`, which is why `ws` and `we` can sit long before `window`); empty on a slot-pinned discovery and on a profile snapshot |
| tg, id | type_guess, identifier | type guess; 1 when over the cardinality gate (then `top` is empty and `samples` carries values) |
| ty, tr | best_type_id, best_type_rate | best semantic type (bare name without the mt: or user: namespace) and its match rate |
| seen, first_run | last_seen_time, first_seen_run | epoch last observed; first run that observed it |
| org, app, stanza, conflict | origin, origin_app, origin_stanza, origin_conflict | extraction origin and the winning declaration |
| dm | cim_fields | `Model.Dataset.field` entries |
| mean, mean_by, mean_at | meaning_human_* | people's meaning, author, epoch |
| used, alerts, unscoped, objects | usage_* | knowledge objects, alerts among them, name-only references, up to 5 `ko_type:app:name` |
| top | top_values, top_counts | up to 10 `[value, count]` pairs |
| samples | sample_values | up to 5 values, only when `top` is empty |
| num | num_min, num_max, num_mean | `[min, max, mean]`, empty when not numeric |
| strata_n | rollup_strata | strata the source-level row rolls up; 0 when the source is unstratified |
| abs, absn | absent_strata, absent_strata_count | strata of the source without the field in its last profile (rollup rule), ordered as `src.strata`; `[]` and 0 on an unstratified source. The profile that found them absent is `run` when `win` is `profile`, so `ws` and `we` are its window; while the row has no profile snapshot the list comes from the strata's discoveries |
| dflt | is_default | 1 on a Splunk default, internal or `date_*` field; left out of `fields`, `other` and `matches` unless `defaults=1`, always listed in `cards` |
| spl | built from the row | `index=<idx> sourcetype="<st>" <n>=* \| stats count by <n>`; names outside `[A-Za-z0-9_.:]` are double-quoted |

A card adds `presence`, `src` (the source essentials below, less `strata`, plus `strata_n`), `strata` (`[stratum_value, coverage, ev, ws, we]` per stratum carrying the field, best coverage first: the stratum row's own newest snapshot, its events and its window, which can be a different run from the card's) and `absent` (active strata of the source without the field). A match (`other`, `matches`) carries `n, idx, st, key, ty, cov, dist, ev, win, run, ws, we, no_events, anchor, seen, org, used, alerts`: `cov` and `dist` are measured in the window `ws` to `we` of `run`, over `ev` events.

Source match object (`srcs`), one per `matalog_sources` row:

| key | from |
|---|---|
| idx, st, sst, key, state | src_index, src_sourcetype, search_sourcetype (`st` when there is no rename), source_key, state |
| events_day, ws, we, updated | daily_events and the trailing day it counts: the day window of `updated_run_id`, the run that last wrote the row |
| fields, used, alerts | field_count, usage_count, usage_alert_count |
| last_search, last_search_user, apps | last_human_search_time, last_human_search_user, config_apps |
| via | which columns matched, in order: `sourcetype`, `search_sourcetype`, `source` (a `sources_top` path), `app` (a `config_apps` name, the `@version` left out) |
| spl, page | `index=<idx> sourcetype="<st>"`; the source page, `/app/matalog/source?source_key=<key>` under Splunk Web's locale root (for example `http://<host>:8000/en-US`) |

Windows. Rows carry run ids, not bounds; the handler computes every window from the run record's `budget` exactly as the pages do (`ui/src/lib/window.js`): the window ends `budget.window_lag_seconds` before the run's slot start and reaches back `profile.profile_window_seconds` (profile), `discovery.discovery_window_seconds` (discovery), `budget.cycle_seconds` (cycle) or 86,400 s (day). A discovery window is the one the stratum row records (`cur_earliest`, `cur_latest`) when that row's current discovery is the entry's `run`: an anchored first discovery (Run identity, `window_anchor=last_event`) searched a window ending at the source's `last_event_time`, not the slot window, and the entry says so in `anchor`. The run records and the stratum rows a response needs are read once each, in one query. `window`, on every response:

| key | meaning |
|---|---|
| run | the newest committed run |
| ws, we, ev, srcs | its day window, the events the readable active sources saw in it (sum of `daily_events`) and how many sources those are |
| pws, pwe | its profile window: what a profile of that run searched, so a field with no card was not seen in a profile covering this span |
| dws, dwe | its discovery window |
| cws, cwe | its cycle window (`events_cycle` of a source) |

An absent answer is read against these: `cards: []` for `field=` or `type=` means no source-level row carries the name or type after the profiles and discoveries up to `run`; `srcs: []` means no readable source row matched; `abs` on a card names strata the profile `run` (window `ws` to `we`) searched without finding the field.

Source essentials (`source`):

| key | from |
|---|---|
| idx, st, key, state | src_index, src_sourcetype, source_key, state |
| events_day, events_cycle, bytes_day, bytes_status | daily_events, events_last_cycle, daily_bytes, daily_bytes_status |
| ws, we, updated | the trailing day `events_day` and `bytes_day` count (the day window of `updated_run_id`, the run that last wrote the row, `updated`); `events_cycle` is the trailing `budget.cycle_seconds` ending at `we` |
| first_event, last_event | first_event_time, last_event_time (the data span a search over the source needs) |
| last_search, last_search_user | last_human_search_time, last_human_search_user |
| stratum_field, strata, strata_deferred | the stratum key; `[value, share, field_count, filter]` per active stratum, largest share first, `filter` the SPL term that selects it; deferred count |
| fields, used, alerts, apps | field_count, usage_count, usage_alert_count, config_apps |
| mode, ratio, profiled, discovered | profile_mode, sample_ratio, last_profiled_run, last_discovered_run |
| spl | `index=<idx> sourcetype="<st>"` |

### Meanings export and import

`GET /services/matalog/meanings` returns every catalogued field with its human meaning, one row per field, for a person to fill in a spreadsheet or for a model to read the whole catalog in one call; `POST` to the same path takes the filled file back. `GET` requires `matalog_summary_read`, `POST` requires `matalog_meanings_write` (the `matalog_writer` and admin roles; the profiler never posts). Both read and write with the system session after the capability check and apply the index filter of "Access": the export holds the rows of the caller's readable indexes only, and an import row of another index is rejected with `index not readable`. Its own stanza, `[script:matalog_meanings]` in `restmap.conf`, and its own script, `bin/matalog_meanings.py`, which shares the value helpers and the collection reader of `bin/matalog_summary.py` (a persistent handler script holds exactly one handler class).

`GET` parameters: `format=csv` (default) or `json`; `level=source` (default, the `__all__` rows) or `all` (stratum rows too); `index=<name>` and `sourcetype=<name>` as optional filters; `defaults=1` to include Splunk default fields (`is_default=1`), left out otherwise. Rows are the `matalog_fields` rows at that level with `presence` in `present`, `declared_only`, sorted by `src_index`, `src_sourcetype`, `field_name` (source row before its strata). CSV is RFC 4180 (comma, double quote, CRLF), UTF-8, served as an attachment named `matalog-meanings.csv`; JSON is `{"columns": [...], "rows": [{...}], "n": <count>}` with the same keys per row.

| column | from |
|---|---|
| field_key | field_key, the key to post back |
| src_index, src_sourcetype, level, stratum_field, stratum_value, field_name | identity |
| type_guess | type_guess |
| semantic_type | best_type_id without the `mt:` or `user:` namespace |
| coverage, distinct | cur_prof_coverage, cur_prof_distinct (empty when not profiled) |
| top_values, cim_fields | the lists joined with ` \| ` |
| meaning, meaning_author, meaning_revision | meaning_human, meaning_human_author, meaning_human_revision (0 when none) |
| meaning_note | always empty on export; the note of the next revision on import |

`POST` body: the CSV (`Content-Type: text/csv`, any columns, `field_key` and `meaning` required, `meaning_note` optional) or JSON `{"rows": [{"field_key": ..., "meaning": ..., "meaning_note": ...}]}` (the export's JSON posts back as is). Bodies over 8 MB get 413. Per row, in this order: an empty `meaning` is skipped (the export leaves the column empty, so an untouched row changes nothing); a `field_key` already seen in the file is rejected (`duplicate field_key`); a key with no `matalog_fields` row is rejected (`unknown field_key`); a key whose index the caller cannot search is rejected (`index not readable`); a stratum row's key is rejected (`stratum row, use the source-level key`); a `meaning` equal to the row's `meaning_human` is unchanged, as is a `-` on a row with no meaning; anything else is written exactly as the field page writes it: a new `matalog_meanings` revision (`_key = k(field_key, revision)`, `revision` one past the highest existing, `is_current=1`, `status=current`, `text`, `note`, `author` the calling user, `created_at` now), the earlier current revision flipped to `is_current=0`, `status=superseded`, and the `meaning_human`, `meaning_human_author`, `meaning_human_time`, `meaning_human_revision` mirror on every `matalog_fields` row of that `source_key` and `field_name`, source level and strata. A `meaning` of `-` (one hyphen) removes the current meaning instead: the revision carries empty `text` and `status=removed` and the mirror is cleared (Meaning, "Human layer"). Writes go through `batch_save` in chunks of 500. Response: `{"written": n, "unchanged": n, "skipped": n, "rejected": [{"field_key": ..., "reason": ...}], "rows": <rows in the file>}`.

### Saved searches

The same columns, one row per field or source, for `| savedsearch`. The four searches live in the app namespace (`default/savedsearches.conf`, shared at app level, readable by `admin`, `sc_admin` and `matalog_profiler`), so a caller addresses them through the app: either a search job in the app namespace, or the saved search's own dispatch endpoint. Both work as `svc_matalog`:

    curl -sk -u svc_matalog:$SVC_PW "https://<search-head>:8089/servicesNS/svc_matalog/matalog/search/jobs/export" \
      --data-urlencode 'search=| savedsearch "matalog agent name matches" q="user"' -d output_mode=json
    curl -sk -u svc_matalog:$SVC_PW -X POST "https://<search-head>:8089/servicesNS/svc_matalog/matalog/saved/searches/matalog%20agent%20source%20summary/dispatch" \
      -d 'args.source=matalog_json:crowdstrike:events:sensor' -d output_mode=json

The export returns one JSON line per row; the dispatch call returns a `sid` whose results are read from `search/jobs/<sid>/results`. A call outside the app namespace (`/services/search/jobs`, or `/servicesNS/<user>/search/...`) does not find the saved search, because the app does not export it.

| saved search | token | rows |
|---|---|---|
| `matalog agent source summary` | `source`, a source_key or `<index>:<sourcetype>` | the field objects of the source, with the source essentials as `src_*` columns (`src_events_day`, `src_last_event`, `src_strata` as a `value=share` multivalue split on `;`, and so on) |
| `matalog agent field summary` | `field_name`, matched case-insensitively (a full read of `matalog_fields`) | the cards: field object columns, `presence`, `strata` as a `value=coverage@ev@ws-we` multivalue, `absent`, and the `src_*` columns |
| `matalog agent type summary` | `type`, the bare type name, matched case-insensitively (a full read of `matalog_fields`) | the same rows as the field summary for every source-level field whose best type has that name; `ty` carries the name, `dflt=1` rows included |
| `matalog agent name matches` | `q` | `kind=source` rows first (the source match columns, ranked as the endpoint ranks `srcs`), then `kind=field` rows (the match columns for source-level fields whose name contains the word, ranked as the endpoint ranks `matches`); both case-insensitive |

A token that is not passed makes `savedsearch` fail, so each search takes exactly one (`type=` is therefore its own search rather than a second token of the field summary); a token cannot be optional, so the searches list Splunk default fields with `dflt=1` where the endpoint hides them unless `defaults=1`. Every row carries `kind` (`field`, `source`) and its windows (`ws`, `we`; `src_ws`, `src_we`, `src_updated` for the source's day), computed by the macros in `default/macros.conf` (`matalog_row_window`, `matalog_source_window`) with a `join` on `matalog_runs` (`inputlookup` flattens the `budget` json to `budget.budget.window_lag_seconds` and the like; `lookup` cannot output those columns). An empty answer is one `kind=window` row (`matalog_window_row`) with the endpoint's `window` keys: `run`, `ws`, `we`, `ev`, `srcs`, `pws`, `pwe`, `dws`, `dwe`, `cws`, `cwe`; a non-empty answer carries no window row, its rows carry their own windows. The columns are the endpoint's keys with these shape differences:

| endpoint key | saved search column | shape |
|---|---|---|
| `top` (`[value, count]` pairs) | `top` | one multivalue of `count value` strings, the count before the first space |
| `dm`, `objects`, `samples`, `abs` | same names | plain multivalues |
| `num` (`[min, max, mean]`) | `num` | one string `min,max,mean` |
| `exact`, `ratio`, `win`, `run` | same names | from the same snapshot rule (profile when `cur_prof_run_id` is set) |
| `strata_n`, `absn`, `dflt`, `used`, `alerts`, `unscoped`, `conflict`, `id` | same names | `fillnull` 0 |
| card `strata` (`[value, coverage, ev, ws, we]`) | `strata` | multivalue of `value=coverage@ev@ws-we`: coverage to three decimals, then the stratum's events and window after `@`; `ws` and `we` empty when the run record is gone |
| `ws`, `we` | same names | from the row's `run` and `win` through `matalog_row_window`, which joins the stratum row (by `stratum_key`, else the span of the source's stratum rows of that run) for a discovery row as the endpoint does |
| `no_events`, `anchor` | same names | from `matalog_row_window`; `no_events` is empty on a `kind=source` row, `anchor` is not on the name matches |
| `src.ws`, `src.we`, `src.updated` | `src_ws`, `src_we`, `src_updated` | the source's day window through `matalog_source_window` |
| `srcs` entries (`q=`) | `kind=source` rows of the name matches | `idx`, `st`, `sst`, `key`, `state`, `events_day`, `ws`, `we` (the day, `win=day`, `run` the updated run), `fields`, `used`, `alerts`, `last_search`, `last_search_user`, `apps`, `via` (multivalue), `spl`, `page` |
| `window` object | one `kind=window` row, only when the answer is empty | same keys |
| card `absent` (count) | `absent` | `src_strata_n` less the strata carrying the field; `abs` and `absn` carry the profiled list |
| card `src` object | `src_*` columns | `src_state`, `src_events_day`, `src_bytes_day`, `src_first_event`, `src_last_event`, `src_last_search`, `src_last_search_user`, `src_stratum_field`, `src_strata_n`, `src_fields`, `src_used`, `src_alerts`, `src_apps`, `src_mode`, `src_ratio`; `src_strata` (`value=share`) on the source summary only |
| `src.strata` entries (`[value, share, field_count, filter]`) | `src_strata` | `value=share` only; `field_count` and the filter term are on the source summary rows' `src_*` columns and the field page |
| `spl` | `spl` | same string |
| `presence`, `n`, `idx`, `st`, `key`, `cov`, `cnt`, `ev`, `dist`, `tg`, `ty`, `tr`, `seen`, `first_run`, `org`, `app`, `stanza`, `mean`, `mean_by`, `mean_at` | same names | same values; `ty` is the bare type name, as the endpoint gives it, on the name matches too |

## Storage bound

At the defaults, per day, pre-compression, 50,000 fields:

| rows | count | size each | per day |
|---|---|---|---|
| `kind=field` slim | at most 50,000 fields x 24 discoveries, bounded by `max_searches_per_cycle` strata per cycle | about 300 B | up to 360 MB |
| `kind=field` full | 50,000 (one profile per field per day) plus new-field rows | 3 KB typical, 8 KB cap | 150 to 400 MB |
| `kind=stratum`, `kind=source`, `kind=search_cost`, `kind=commit` | about 10,000 x 24 | about 300 B | about 70 MB |
| total | | | about 0.5 to 0.8 GB |

That is about 92 to 150 GB at the 180-day default and 186 to 300 GB over a year, linear in field count and in strata actually discovered. KV grows with field rows (one per field per stratum plus one per field name per source), declarations, objects and edges; run records are capped by `retention.run_retention_count`.

## Platform behaviour relied on

Observed on Splunk 10.4.3:

- `fieldsummary` returns exactly `field`, `count`, `distinct_count`, `is_exact`, `numeric_count`, `values`.
- `scanCount` on a job with `sample_ratio` counts sampled events (14,156 scanned of 141,435 at 1 in 10), so `profile.profile_head_events` is compared against sampled counts.

- `makeresults format=json data=` refuses inline data over 30,000 characters and limits.conf has no knob; the write path uses the KV buffer and `inputlookup ... | collect` instead, verified with a 2 MB batch.
- `collect sourcetype=stash` and the REST receiver with `sourcetype=stash` do not add to licence usage.
- KV bool columns read back as true/false, so `collections.conf` declares them as number and the profiler writes 0/1. `string[]` and json columns carry no `field.<name>` type in `collections.conf` (the only accepted types are number, bool, string and time); the store accepts arrays and objects as written.
- A modular input is launched with the system session key: searches run as `splunk-system-user`, which `usage.exclude_users` lists by default; `profiled_as` records the actual account.

Not yet confirmed on Splunk Cloud: that `collect sourcetype=stash` stays licence-free on Victoria; whether licence usage by sourcetype is readable from the search head there.
