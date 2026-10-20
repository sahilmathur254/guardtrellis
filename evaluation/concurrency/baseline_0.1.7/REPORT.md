# Bounded async checked-delivery baseline, v1

Authored synthetic development fixtures; no accuracy, capacity, tail-latency or SLO claim.
Timings include Guard async scheduling and an in-memory callback. Admission wait is separate.
Repeated requests are timing observations, not independent detector cases.

Mode: `full`. Measurement checks passed: `True`.

| Family | Characters | Active limit | Observed / expected | Exact matches | Incomplete runs | arun median ms (range) |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| allow | 10000 | 1 | 60 / 60 | 60 | 0 | 0.559 (0.523–0.723) |
| allow | 10000 | 4 | 60 / 60 | 60 | 0 | 1.664 (1.140–2.056) |
| allow | 100000 | 1 | 60 / 60 | 60 | 0 | 3.101 (2.995–3.578) |
| allow | 100000 | 4 | 60 / 60 | 60 | 0 | 11.778 (7.467–16.584) |
| redact | 10000 | 1 | 60 / 60 | 60 | 0 | 0.563 (0.538–0.715) |
| redact | 10000 | 4 | 60 / 60 | 60 | 0 | 1.663 (1.222–1.979) |
| redact | 100000 | 1 | 60 / 60 | 60 | 0 | 3.117 (3.014–3.759) |
| redact | 100000 | 4 | 60 / 60 | 60 | 0 | 11.788 (7.520–13.999) |
| block | 10000 | 1 | 60 / 60 | 60 | 0 | 0.308 (0.292–0.392) |
| block | 10000 | 4 | 60 / 60 | 60 | 0 | 1.041 (0.564–1.146) |
| block | 100000 | 1 | 60 / 60 | 60 | 0 | 2.138 (2.092–2.508) |
| block | 100000 | 4 | 60 / 60 | 60 | 0 | 8.456 (4.213–12.275) |

Stopped, failed and missing samples remain in results.json and are not zero-duration successes.
CPU/RSS are whole-process observations; unavailable measurements are null.
Raw metadata, startup/setup/warmup boundaries, outcomes and hashes are in results.json.
