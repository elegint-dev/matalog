[matalog_profiler://<name>]
run_mode = <value>
* normal, rebuild or mirror. Default: normal.
* normal profiles the data and writes the catalog; enable it on one search head only.
* rebuild rewrites the collections from the matalog_profiles index without searching data.
* mirror does the same and writes nothing to the index: the mode for every other search head of the stack,
  whose KV store is its own.
