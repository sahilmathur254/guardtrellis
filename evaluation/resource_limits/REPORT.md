# Bounded resource measurements

Fixed synthetic scenarios; no provider calls, private inputs, or general capacity claims.
CPU/wall stops are retained measurements, not completed Guard checks. Missing values are unknown.

Generated: 2026-09-26T13:24:33.608836+00:00
Runtime: 3.12.0, Darwin 25.6.0, arm64.
Dependencies: `{"attrs": "26.1.0", "guardtrellis": "0.1.0a2", "jsonschema": "4.26.0", "jsonschema-specifications": "2025.9.1", "referencing": "0.37.0", "rpds-py": "2026.6.3"}`.
Package source SHA-256: `ebeae1335f6f465bcda8e9bb4e569a4e0cfd39872680fd5718f4f2d5ba08880a`.
Harness SHA-256: `50a689dc52935d3e94ebda49b8232765d685baaa6c5a1371807f70f99c3d29b4`.
Lock SHA-256: `452c414fe73c5554ffbd8368de0ce1e34fb653897ab42d6c9fe429a3fb120d89`.
Configuration: `{"cpu_seconds": 2, "memory_mib": 512, "repetitions": 3, "scenario_names": ["text_at_limit", "text_over_limit", "pii_at_finding_limit", "pii_over_finding_limit", "literal_max_configuration", "json_at_default_depth", "json_over_default_depth", "json_at_maximum_depth", "json_over_maximum_depth", "schema_at_size_limit", "nested_schema", "reference_fanout_small", "reference_fanout_large", "wide_anyof_mismatch", "unique_object_array", "sync_callback_timeout", "sync_scanner_timeout", "caller_cancels_sync_callback", "callback_suppresses_cancellation", "callback_blocks_event_loop", "supervisor_wall_timeout"], "wall_seconds": 5.0}`.

Each repetition uses a fresh child. Operation times exclude imports and setup; process wall
times include startup and cleanup. RSS is whole-child peak memory, not incremental allocations.
Only completed operation samples contribute to the median; interrupted work is never a zero.

| Scenario | Completed / runs | Stops or errors | Operation median ms | Max process wall ms | Max RSS MiB |
| --- | --- | --- | --- | --- | --- |
| text_at_limit | 3/3 | none | 6.758 | 124.6 | 36.89 |
| text_over_limit | 3/3 | none | 0.005 | 77.3 | 36.86 |
| pii_at_finding_limit | 3/3 | none | 4.648 | 76.9 | 37.27 |
| pii_over_finding_limit | 3/3 | none | 0.205 | 76.7 | 36.98 |
| literal_max_configuration | 3/3 | none | 4.790 | 77.0 | 37.00 |
| json_at_default_depth | 3/3 | none | 0.025 | 77.2 | 36.92 |
| json_over_default_depth | 3/3 | none | 0.027 | 77.1 | 36.84 |
| json_at_maximum_depth | 3/3 | none | 0.031 | 76.6 | 36.97 |
| json_over_maximum_depth | 3/3 | none | 0.027 | 77.0 | 36.91 |
| schema_at_size_limit | 3/3 | none | 0.025 | 76.9 | 37.20 |
| nested_schema | 3/3 | none | 0.088 | 132.1 | 37.02 |
| reference_fanout_small | 3/3 | none | 2.241 | 77.3 | 37.02 |
| reference_fanout_large | 0/3 | cpu_limit | unknown | 2038.1 | unknown |
| wide_anyof_mismatch | 3/3 | none | 0.752 | 129.6 | 37.38 |
| unique_object_array | 3/3 | none | 91.670 | 187.1 | 37.03 |
| sync_callback_timeout | 3/3 | none | 101.244 | 187.3 | 37.08 |
| sync_scanner_timeout | 3/3 | none | 101.234 | 239.8 | 37.16 |
| caller_cancels_sync_callback | 3/3 | none | 0.048 | 128.4 | 37.16 |
| callback_suppresses_cancellation | 3/3 | none | 101.277 | 187.4 | 37.12 |
| callback_blocks_event_loop | 3/3 | none | 306.124 | 459.7 | 37.09 |
| supervisor_wall_timeout | 0/3 | wall_timeout | unknown | 1011.4 | unknown |

## Retained observations

- `sync_callback_timeout` repetition 1: `{"accepted": false, "action": "error", "cleanup_ms": 0.21558301523327827, "dimensions": {"guard_timeout_seconds": 0.1, "input_chars": 1}, "finding_codes": ["callback_timeout"], "finding_count": 1, "has_deliverable_text": false, "operation_ms": 101.18470783345401, "worker_finished_after_release": true, "worker_running_after_await": true, "worker_started": true}`.
- `sync_callback_timeout` repetition 2: `{"accepted": false, "action": "error", "cleanup_ms": 0.27916720137000084, "dimensions": {"guard_timeout_seconds": 0.1, "input_chars": 1}, "finding_codes": ["callback_timeout"], "finding_count": 1, "has_deliverable_text": false, "operation_ms": 101.26270912587643, "worker_finished_after_release": true, "worker_running_after_await": true, "worker_started": true}`.
- `sync_callback_timeout` repetition 3: `{"accepted": false, "action": "error", "cleanup_ms": 0.27658301405608654, "dimensions": {"guard_timeout_seconds": 0.1, "input_chars": 1}, "finding_codes": ["callback_timeout"], "finding_count": 1, "has_deliverable_text": false, "operation_ms": 101.24433389864862, "worker_finished_after_release": true, "worker_running_after_await": true, "worker_started": true}`.
- `sync_scanner_timeout` repetition 1: `{"accepted": false, "action": "error", "cleanup_ms": 0.263832975178957, "dimensions": {"guard_timeout_seconds": 0.1, "input_chars": 1}, "finding_codes": ["scanner_timeout"], "finding_count": 1, "has_deliverable_text": false, "operation_ms": 101.23425000347197, "worker_finished_after_release": true, "worker_running_after_await": true, "worker_started": true}`.
- `sync_scanner_timeout` repetition 2: `{"accepted": false, "action": "error", "cleanup_ms": 0.27012499049305916, "dimensions": {"guard_timeout_seconds": 0.1, "input_chars": 1}, "finding_codes": ["scanner_timeout"], "finding_count": 1, "has_deliverable_text": false, "operation_ms": 100.37550004199147, "worker_finished_after_release": true, "worker_running_after_await": true, "worker_started": true}`.
- `sync_scanner_timeout` repetition 3: `{"accepted": false, "action": "error", "cleanup_ms": 0.381499994546175, "dimensions": {"guard_timeout_seconds": 0.1, "input_chars": 1}, "finding_codes": ["scanner_timeout"], "finding_count": 1, "has_deliverable_text": false, "operation_ms": 101.24625009484589, "worker_finished_after_release": true, "worker_running_after_await": true, "worker_started": true}`.
- `caller_cancels_sync_callback` repetition 1: `{"caller_cancellation_propagated": true, "cleanup_ms": 0.14270818792283535, "dimensions": {"guard_timeout_seconds": 3.0, "input_chars": 1}, "operation_ms": 0.04845811054110527, "worker_finished_after_release": true, "worker_running_after_await": true, "worker_started": true}`.
- `caller_cancels_sync_callback` repetition 2: `{"caller_cancellation_propagated": true, "cleanup_ms": 0.14204205945134163, "dimensions": {"guard_timeout_seconds": 3.0, "input_chars": 1}, "operation_ms": 0.048582907766103745, "worker_finished_after_release": true, "worker_running_after_await": true, "worker_started": true}`.
- `caller_cancels_sync_callback` repetition 3: `{"caller_cancellation_propagated": true, "cleanup_ms": 0.13833306729793549, "dimensions": {"guard_timeout_seconds": 3.0, "input_chars": 1}, "operation_ms": 0.047833193093538284, "worker_finished_after_release": true, "worker_running_after_await": true, "worker_started": true}`.
- `callback_suppresses_cancellation` repetition 1: `{"accepted": false, "action": "error", "callback_finished_after_release": true, "callback_running_after_await": true, "dimensions": {"guard_timeout_seconds": 0.1, "input_chars": 1}, "finding_codes": ["callback_timeout"], "finding_count": 1, "has_deliverable_text": false, "operation_ms": 101.38258407823741}`.
- `callback_suppresses_cancellation` repetition 2: `{"accepted": false, "action": "error", "callback_finished_after_release": true, "callback_running_after_await": true, "dimensions": {"guard_timeout_seconds": 0.1, "input_chars": 1}, "finding_codes": ["callback_timeout"], "finding_count": 1, "has_deliverable_text": false, "operation_ms": 101.19183291681111}`.
- `callback_suppresses_cancellation` repetition 3: `{"accepted": false, "action": "error", "callback_finished_after_release": true, "callback_running_after_await": true, "dimensions": {"guard_timeout_seconds": 0.1, "input_chars": 1}, "finding_codes": ["callback_timeout"], "finding_count": 1, "has_deliverable_text": false, "operation_ms": 101.27729107625782}`.
- `callback_blocks_event_loop` repetition 1: `{"accepted": true, "action": "allow", "dimensions": {"event_loop_block_seconds": 0.3, "guard_timeout_seconds": 0.1, "input_chars": 1}, "finding_codes": [], "finding_count": 0, "has_deliverable_text": true, "operation_ms": 306.1939578037709}`.
- `callback_blocks_event_loop` repetition 2: `{"accepted": true, "action": "allow", "dimensions": {"event_loop_block_seconds": 0.3, "guard_timeout_seconds": 0.1, "input_chars": 1}, "finding_codes": [], "finding_count": 0, "has_deliverable_text": true, "operation_ms": 302.7857500128448}`.
- `callback_blocks_event_loop` repetition 3: `{"accepted": true, "action": "allow", "dimensions": {"event_loop_block_seconds": 0.3, "guard_timeout_seconds": 0.1, "input_chars": 1}, "finding_codes": [], "finding_count": 0, "has_deliverable_text": true, "operation_ms": 306.12404202111065}`.

All raw samples, setup/cleanup times, resource caps, process exit codes, and errors
are in `results.json`. See the resource-limits guide in `docs/` for methodology and host controls.
