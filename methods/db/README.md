# Method databases

One file per method, owned by that method. There is deliberately no shared
schema: p0f signatures, ja4 hash lists and banner rules have nothing useful in
common, and forcing a common format would couple every method to every other.

Each method's manifest points here via `database.path` (relative to the manifest
directory) and `database.format`, and its adapter implements
`pf_methods::db::Database` for that format.

| File               | Format       | Method    | Source |
| ------------------ | ------------ | --------- | ------ |
| `p0f.fp`           | `p0f`        | `tcp-syn` | TODO: vendor from p0f, note the licence |
| `ja4-known.jsonl`  | `json-lines` | `ja4`     | TODO |
| `banners.yaml`     | `rules`      | `banner`  | TODO: hand-written |

`fusion` has no file here on purpose — its combination logic lives in its
manifest's `params`.
