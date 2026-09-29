# Method databases

One file per method, owned by that method. There is deliberately no shared
schema: p0f signatures, ja4 hash lists and User-Agent rules have nothing useful in
common, and forcing a common format would couple every method to every other.

Each method's manifest points here via `database.path` (relative to the manifest
directory) and `database.format`, and its adapter implements
`pf_methods::db::Database` for that format.

| File                   | Format      | Method    | Source |
| ---------------------- | ----------- | --------- | ------ |
| `p0f.fp`               | `p0f`       | `f0p`     | Vendored unmodified from the p0f project (LGPL-2.1) — see `p0f.fp.LICENSE` |
| `ja4_fingerprint.csv`  | `ja4db-csv` | `ja4`     | ja4db export |
| `ja4h_fingerprint.csv` | `ja4db-csv` | `ja4h`    | ja4db export |
| `ja4t_fingerprint.csv` | `ja4db-csv` | `ja4t`    | ja4db export |
| `user-agents.yaml`     | `rules`     | `claimed` | Hand-written: HTTP libraries, named scanners, research crawlers |

The ja4db exports are loaded as-is. Only rows naming an application, library,
device or OS are kept (most rows are unlabelled sightings), and fingerprints
that are not `[A-Za-z0-9_-]` are dropped (the exports have a few corrupted ones).
Each method's `match-sections` param sets how many leading sections take part
in a lookup — see its manifest. The JA4+ methods are under the FoxIO License
1.1 (`ja4.LICENSE`).

`fusion` has no file here on purpose — its combination logic lives in its
manifest's `params`.
