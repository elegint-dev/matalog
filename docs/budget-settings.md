# matalog budget settings

Settings live in `matalog.conf` in the app, readable at `/servicesNS/nobody/matalog/configs/conf-matalog`. Every value in force is copied into `matalog_runs.budget` at the start of each run and hashed into `config_hash`. "Shown where" names the UI page that displays the value; every setting is also on the status page under its stanza. Setting names below are written `stanza.setting` as docs/data-model.md references them.

## Settings

| setting | type | default | bounds what | shown where |
|---|---|---|---|---|
| budget.cycle_seconds | int | 3600 | Run slot width and modular input interval. `run_id` is the slot start; a launch whose slot already has a committed run exits without work. | status |
| budget.max_searches_per_cycle | int | 400 | Search jobs per run, write searches included. S3 and S4 plan against this minus the write reserve. | status, run record |
| budget.max_concurrent_searches | int | 3 | Size of the job pool; must stay under the service account's search quota. | status |
| budget.max_events_scanned_per_cycle | int | 20000000 | Sum of `scanCount` across the run; no further S3 or S4 job is dispatched once reached, remaining work is deferred. | status, run record |
| budget.max_search_seconds_per_cycle | int | 1800 | Sum of `runDuration`; same deferral. | status, run record |
| budget.max_wall_seconds_per_cycle | int | 2700 | Wall time of one run; must be below `cycle_seconds`. Work not started by then is deferred. | status, run record |
| budget.search_timeout_seconds | int | 120 | One job; past it the job is finalized, recorded as `timeout`, and its subject is deferred. | status |
| budget.max_staleness_cycles | int | 24 | Every active stratum is discovered at least once per this many cycles, whatever its priority. | status, source page |
| budget.priority_usage_weight | float | 1.0 | Weight of `usage_count` in the priority formula (data model, Conventions). | status |
| budget.window_lag_seconds | int | 300 | Every search window ends this far before the slot start, so late-indexed events are counted and a rerun sees the same window. | status |
| budget.index_scan_interval_seconds | int | 86400 | Every index is scanned (S1 `metadata type=sourcetypes`, S5 `walklex` and the indexed-field probe) once per this many seconds; each run scans `ceil(indexes * cycle_seconds / this)` indexes, never-scanned ones first, then the stalest by source priority; an index whose scan finds no sourcetype is rechecked once per interval. | status, run record |
| discovery.discovery_window_seconds | int | 900 | Length of the S3 window per stratum. | status |
| discovery.discovery_head_events | int | 2000 | `head` per S3 search; the search ends at the window or this count, whichever comes first. | status |
| discovery.max_strata_per_source | int | 300 | Strata per source with `state=active`; the rest are `deferred`, listed but never searched or merged. | status, source page |
| discovery.stratum_list_window_seconds | int | 86400 | Window of the S2 listing. | status |
| discovery.stratum_list_sample_ratio | int | 100 | Sample ratio of the S2 listing. | status |
| discovery.stratum_list_interval_seconds | int | 86400 | Time between S2 listings of one source. | status |
| discovery.max_fields_per_stratum | int | 500 | Fields stored per stratum per discovery; extras set `fields_truncated=1` and are counted in the run record. | status |
| discovery.min_events_for_absence | int | 200 | Minimum `events_seen` of a discovery before a field it did not return is absent (the absence rule in docs/data-model.md). | status, field page |
| profile.profile_interval_seconds | int | 86400 | Minimum time between S4 profiles of one source. | status, source page |
| profile.profile_window_seconds | int | 86400 | Length of the S4 window. | status |
| profile.sample_volume_threshold | int | 1000000 | `daily_events` at or above which S4 samples; below it S4 is unsampled. | status, source page |
| profile.sample_ratio | int | 100 | 1 in N for sampled profiles. | status, source page |
| profile.profile_head_events | int | 100000 | `head` per S4 search after sampling; the row records the window actually covered. | status |
| profile.top_values | int | 10 | Values in `top_values` per full row and field row. | status |
| profile.sample_values | int | 100 | Values in `sample_values` per full row; also `fieldsummary maxvals` for S3 and S4 and the set S7 tests. | status |
| profile.sample_values_max_bytes | int | 6144 | Byte cap on `sample_values`; the set stops at this or `sample_values`, whichever first. | status |
| profile.max_value_chars | int | 128 | Truncation of every stored value. | status |
| profile.max_row_bytes | int | 8192 | Cap on one summary row; `top_values` entries are dropped from the tail until the row fits. | status |
| profile.identifier_distinct | int | 1000 | `distinct` at or above which a field is an identifier and stores no top values. | status |
| profile.identifier_distinct_ratio | float | 0.9 | `distinct / count` at or above which a field is an identifier, when `count >= identifier_min_count`. | status |
| profile.identifier_min_count | int | 50 | Minimum `count` before the ratio gate applies. | status |
| profile.identifier_distinct_cap_min | int | 500 | `fieldsummary` stops counting distinct values at `max(maxvals, 500)` and reports `is_exact=0`; a field whose distinct count is inexact and at or above this value is an identifier when the dc() probe could not replace the count (sampled or head-truncated strata, no search left, probe failed). The probe is one search per profiled unsampled source whose strata did not hit head, over the profile window, carrying up to 1000 fields: the capped ones, then the fields present in more than one stratum, whose whole-source dc() becomes the rollup row's distinct. | status |
| profile.week_baseline_days | int | 7 | Age of the profile copied into `week_prof_*` on field rows. | status, field page |
| profile.store_sample_values | bool | true | When false, no `top_values`, `top_counts` or `sample_values` are stored on any field row or summary row, identifier or not; counts, distinct, numeric stats and `type_guess` are kept. S7 then has no values to classify. The pages and the summary endpoint say "values not stored" where they would show values. | status, field page |
| classify.edge_store_floor | float | 0.5 | Lowest `cur_match_rate` stored as a non-best edge. | status |
| classify.max_types_per_field | int | 3 | Edge rows written per field for types without a stored edge; stored edges that still qualify are rewritten beyond it. | status |
| classify.default_match_threshold | float | 0.9 | `match_threshold` of a semantic type row that carries none. | status |
| classify.default_min_distinct | int | 2 | `min_distinct` of a semantic type row that carries none. | status |
| classify.max_lookup_values | int | 10000 | Distinct values read from the lookup of a `matcher_kind=lookup` type; one `inputlookup` job per such type per run. | status |
| usage.usage_interval_seconds | int | 86400 | Time between usage passes (knowledge object listing, parse and run history read); a pass runs when no committed normal run carrying `objects_total` has a slot within this many seconds before the run's slot. `_audit` is read every cycle from the high watermark. | status |
| usage.audit_initial_lookback_days | int | 30 | `_audit` window read on the first run, before a watermark exists. | status |
| usage.max_objects | int | 20000 | Knowledge objects parsed per usage pass, in `ko_type`, `app`, `owner`, `name` order; the rest are counted in `objects_total` and not written. | status, run record |
| usage.usage_objects_shown | int | 10 | Entries in `usage_objects` on a field row. | status |
| usage.service_account | string | svc_matalog | Account the profiler runs as. | status |
| usage.exclude_users | string | svc_matalog,splunk-system-user | Comma list of users whose searches are not human use. | status, waste page |
| usage.exclude_apps | string | matalog | Comma list of apps whose searches are not human use. | status, waste page |
| write.write_batch_rows | int | 4000 | Rows per `collect` job. | status |
| write.write_batch_bytes | int | 1048576 | JSON bytes per `collect` job; a batch closes at this or `write_batch_rows`, whichever first. | status |
| write.write_reserve_min | int | 10 | Floor of the write reserve held back from `max_searches_per_cycle`. | status, run record |
| write.kv_batch_size | int | 500 | Documents per KV `batch_save`; must stay under the server's 1000 limit. | status |
| rebuild.rebuild_max_rows | int | 5000000 | Summary rows a rebuild or a reclassify reads in one run. | status |
| retention.profiles_frozen_days | int | 180 | `frozenTimePeriodInSecs` of `matalog_profiles`, in days. | status |
| retention.run_retention_count | int | 2000 | Run records kept (about 83 days at an hourly cycle). | status |
| retention.unobserved_field_days | int | 30 | Field rows not present, with no meaning and no usage, are deleted after this. | status |
| retention.stratum_retire_days | int | 30 | Strata not listed for this long, and retired strata, are deleted with their field rows. | status |
| retention.meaning_revisions | int | 20 | Revisions kept per field in `matalog_meanings`. | status |
| retention.object_stale_runs | int | 3 | S6 passes before an unseen object and its edges are deleted; also S5 reads before an unseen declaration is deleted. | status |
| retention.cim_stale_runs | int | 3 | S8 runs before an unconfirmed `matalog_cim_coverage` row is deleted. | status |
| retention.gone_after_days | int | 30 | Days without events before a source is `gone`. | status, waste page |

## Stratum seed stanzas

One stanza per sourcetype, `[stratum:<sourcetype>]`, with keys `stratum_field` (string), `version_field` (string, may be empty), `index_pattern` (string, default `*`). Install upserts them into `matalog_stratum_config` with `origin=seed`; a `user` row with the same key wins. Shown on the source page.

| sourcetype | stratum_field | version_field |
|---|---|---|
| crowdstrike:events:sensor | event_simpleName | ConfigBuild |
| aws:cloudtrail | eventName | eventVersion |
| OktaIM2:log | eventType | (empty) |
| gws:reports:drive | type | (empty) |
| gws:reports:login | event.name | (empty) |
| gws:reports:admin | event.name | (empty) |
| XmlWinEventLog | EventCode | (empty) |
| WinEventLog | EventCode | (empty) |
| XmlWinEventLog:Security | EventCode | (empty) |
| WinEventLog:Security | EventCode | (empty) |

## Discovery schedule

The modular input runs once per `budget.cycle_seconds`, at the slot start. Each run:

1. S1 enumerates every source and computes priority. `first_event_time` and the indexed-field origins are refreshed on the index scan, once per `budget.index_scan_interval_seconds`; enumeration itself comes from `tstats` every run. Sources with no events in the trailing cycle and no open work are skipped for the rest of the run, with one exception: a source that has never been discovered and has a `last_event_time` is listed (unsampled) and discovered once on the window `discovery.discovery_window_seconds` long ending at `last_event_time`, its stratum and field rows marked `window_anchor=last_event`; it is budgeted like any discovery and follows the schedule below from then on.
2. S2 relists strata for each stratified source whose last listing is older than `discovery.stratum_list_interval_seconds`. The top `discovery.max_strata_per_source` values by count are active; the rest are deferred.
3. S3 plans discovery for strata in this order: every active stratum whose `discovery_due_run` is this run or earlier (the staleness guarantee), then every other active stratum by source priority descending and `rate_per_hour` descending. Strata that are not due are planned only in what remains after the S4 jobs of the strata whose profile is due this run (one per due stratum, capped at what is left after the due discoveries, plus the week baseline read). It stops planning when the next job would exceed `budget.max_searches_per_cycle` less the write reserve, or when any other ceiling is hit; unplanned strata keep their `discovery_due_run`, so at most `budget.max_staleness_cycles` cycles pass between discoveries of any active stratum. Each job searches the stratum filter on the window ending `budget.window_lag_seconds` before the slot start and `discovery.discovery_window_seconds` long, stops at `discovery.discovery_head_events` events, and runs `fieldsummary` with `maxvals=profile.sample_values`, unsampled. For an unstratified source the whole source is the one stratum.
4. Every discovery writes one `kind=stratum` row and one `kind=field` row per field (slim, or full for a field new this run). Fields absent from a discovery are judged by the absence rule in the data model.

With the defaults a run can discover about 350 strata, so up to 8,400 active strata are each discovered at least daily, and a stratum of a high-priority source is discovered every cycle.

## Profile schedule

S4 runs inside the same cycle after S3 and profiles the strata due, in source order (overdue sources first, then priority; within a source by `rate_per_hour`), within what is left of the search budget. A stratum is due when its `last_profiled_run` is empty or its slot plus `profile.profile_interval_seconds` is at or before the slot start. Each due stratum is one `fieldsummary` job over the window ending `budget.window_lag_seconds` before the slot start and `profile.profile_window_seconds` long, unsampled when the source's `daily_events` is below `profile.sample_volume_threshold` and sampled at `profile.sample_ratio` otherwise, with `head` at `profile.profile_head_events` after sampling. Each job writes one `kind=stratum mode=profile` row and one full `kind=field` row per field with top values, samples and numeric stats. A source's profile may span runs: the strata that did not fit stay due and are first in line next cycle, the source's rollup covers every active stratum from its latest profile, and `last_profiled_run` and `next_profile_due` are set when no stratum is left due; `sources_deferred` on the run record counts the sources with strata still due, `strata_profile_due` and `strata_profiled` the strata. With `profile.profile_interval_seconds` at 86400, each stratum is profiled once a day, and the work spreads across the 24 cycles because due times inherit the slot of the last profile.

S7 classifies the fields profiled this cycle from their stored `sample_values`. Each field row keeps its new profile snapshot beside the previous and the week-old one, and the summary index keeps the full history. Discovery, not the profile, is what sees a field appear or go missing within one cycle; the daily profile is what measures coverage, cardinality and values on the whole window.
