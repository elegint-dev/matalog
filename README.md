# matalog

A Splunk app that catalogs every field Splunk can see: what it means, where it lives, how fresh it is, how often it is populated, what values it takes, and who depends on it.

## The problem

Splunk holds the data, the extraction config and the record of every search anyone has run, so it can answer those questions for any field. Without a catalog, the answers take ad hoc searches, reading props.conf and asking a colleague. The usual results:

- A detection engineer picks the wrong field, or the right field from a sourcetype where it is null 40% of the time.
- An extraction breaks after an add-on upgrade or a sensor rollout, and nobody notices until an alert goes quiet.
- A sourcetype costs real ingest and has not been searched in months.

Splunk's schema is emergent: it exists at search time and is contested between apps. matalog reads it from inside Splunk.

## How it works

- **Profiler.** A scheduled Python modular input on the search head. Each run enumerates sources (index and sourcetype) from metadata, lists the strata of sources whose schema depends on one field (CrowdStrike by `event_simpleName`, CloudTrail by `eventName`), discovers fields on a bounded window per stratum, profiles coverage, cardinality, values and type on a sampled window, reads the config endpoints to name each field's extraction origin, and parses knowledge objects and `_audit` for usage. It runs as a dedicated service account, inside a configurable budget of searches, events scanned and concurrency, and records its own cost per run.
- **Storage.** KV store collections hold the current state and what people write (meanings, user semantic types); the `matalog_profiles` summary index holds the profile history, so a field's history is an ordinary search.
- **Pages and agent surface.** React pages and a compact JSON endpoint read the catalog through the app's REST endpoints, narrowed to the indexes the caller's roles can search. The profiler writes storage only; neither side calls the other.

## What it shows

- **Lookup:** type a field name, a sourcetype or a word; get every source carrying it with coverage, distinct count, last seen, sample values, origin, absent strata and usage, plus a copyable search fragment.
- **Field, source and sources:** one page per entity, every reference a link to the next.
- **Waste:** sources nobody has searched for 30 days or more, by licensed bytes per day.
- **Status:** the profiler's runs, cost against budget, errors and the settings in force.
- **Meanings:** written on the field page, or exported as CSV and imported back.
- **Agent surface:** `GET /services/matalog/summary` and four saved searches give a model the same information as the lookup card, machine-readable.

## What it is not

No lineage through Edge Processor or Ingest Processor, no writes to props.conf, transforms.conf or data models, no meanings inferred by a language model, no bundled vendor field dictionaries, no federation across stacks, no metrics indexes. The profiler sees the data as one service account sees it.

## Requirements

Splunk 10.4 or later, Splunk Enterprise or Splunk Cloud (Victoria experience). The pages use the `splunk_ui_app` template that 10.4 ships.

## Install and use

[matalog/README.md](matalog/README.md) covers packaging, AppInspect, installation through ACS, the service account, roles, the agent surface, meanings export and import, and running the tests. The reference documentation is in [docs/](docs): [data-model.md](docs/data-model.md) for collections, rows and endpoints, [budget-settings.md](docs/budget-settings.md) for every setting and its default.

To rebuild the pages: `npm ci && npm run build` in `matalog/ui`, which writes `matalog/appserver/static/pages`.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
