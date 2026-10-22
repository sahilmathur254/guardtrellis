# Connection-string contract supplement: current SDK observations

SDK 0.1.7; 600 observations; opt-in not implemented.

Authored synthetic development cases, with desired decisions fixed before outcomes. This run exercises the frozen v1 harness's unchanged secret-only and tool-return policies. It does not execute the proposed connection-string detector. Excluded/resource-pending cases have null comparisons; absence of a finding is not a safety or driver-validity claim. No resource-limit experiment is performed here.

| Contract status | Observations | Scored | Exact matches | ALLOW | REDACT | BLOCK | ERROR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| excluded | 60 | 0 | 0 | 60 | 0 | 0 | 0 |
| resource_pending | 20 | 0 | 0 | 3 | 3 | 0 | 14 |
| selected | 520 | 520 | 102 | 416 | 96 | 8 | 0 |

Whole-URI spans are proposed targets, including when an existing token signature already blocks a smaller span. Incidental PII redaction and input-limit ERROR remain distinct from URI detection. Raw JSON is scanned as wire text; explicit decoded equivalents use decoded-string offsets. No raw input/output, credentials or exception text are included in the report.

## Retained mismatches

| Case | Policy / representation | Mismatched comparisons |
| --- | --- | --- |
| contract-origin-mask | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-origin-mask | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-mask | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-mask | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-mask | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-mask | tool_return/plain | action, delivery, target_spans |
| contract-origin-mask | tool_return/json_plain | action, delivery, target_spans |
| contract-origin-mask | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-mask | tool_return/decoded_plain | action, delivery, target_spans |
| contract-origin-mask | tool_return/decoded_escaped | action, delivery, target_spans |
| contract-origin-env | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-origin-env | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-env | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-env | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-env | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-env | tool_return/plain | action, delivery, target_spans |
| contract-origin-env | tool_return/json_plain | action, delivery, target_spans |
| contract-origin-env | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-env | tool_return/decoded_plain | action, delivery, target_spans |
| contract-origin-env | tool_return/decoded_escaped | action, delivery, target_spans |
| contract-origin-doc-word | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-origin-doc-word | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-doc-word | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-doc-word | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-doc-word | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-doc-word | tool_return/plain | action, delivery, target_spans |
| contract-origin-doc-word | tool_return/json_plain | action, delivery, target_spans |
| contract-origin-doc-word | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-doc-word | tool_return/decoded_plain | action, delivery, target_spans |
| contract-origin-doc-word | tool_return/decoded_escaped | action, delivery, target_spans |
| contract-origin-angle | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-origin-angle | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-angle | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-angle | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-angle | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-angle | tool_return/plain | action, delivery, target_spans, credential_coverage |
| contract-origin-angle | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-angle | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-angle | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-angle | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-bad-percent | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-origin-bad-percent | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-bad-percent | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-bad-percent | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-bad-percent | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-bad-percent | tool_return/plain | action, delivery, target_spans |
| contract-origin-bad-percent | tool_return/json_plain | action, delivery, target_spans |
| contract-origin-bad-percent | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-bad-percent | tool_return/decoded_plain | action, delivery, target_spans |
| contract-origin-bad-percent | tool_return/decoded_escaped | action, delivery, target_spans |
| contract-origin-no-host | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-origin-no-host | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-no-host | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-no-host | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-no-host | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-no-host | tool_return/plain | action, delivery, target_spans, credential_coverage |
| contract-origin-no-host | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-no-host | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-no-host | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-no-host | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-bad-bracket | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-origin-bad-bracket | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-bad-bracket | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-bad-bracket | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-bad-bracket | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-bad-bracket | tool_return/plain | action, delivery, target_spans, credential_coverage |
| contract-origin-bad-bracket | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-bad-bracket | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-bad-bracket | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-bad-bracket | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-hard-newline | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-origin-hard-newline | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-hard-newline | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-hard-newline | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-hard-newline | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-hard-newline | tool_return/plain | action, delivery, target_spans, credential_coverage |
| contract-origin-hard-newline | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-hard-newline | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-hard-newline | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-hard-newline | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-srv-port | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-origin-srv-port | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-srv-port | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-srv-port | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-origin-srv-port | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-srv-port | tool_return/plain | action, delivery, target_spans |
| contract-origin-srv-port | tool_return/json_plain | action, delivery, target_spans |
| contract-origin-srv-port | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-origin-srv-port | tool_return/decoded_plain | action, delivery, target_spans |
| contract-origin-srv-port | tool_return/decoded_escaped | action, delivery, target_spans |
| contract-upper-pg | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-upper-pg | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-upper-pg | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-upper-pg | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-upper-pg | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-upper-pg | tool_return/plain | action, delivery, target_spans |
| contract-upper-pg | tool_return/json_plain | action, delivery, target_spans |
| contract-upper-pg | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-upper-pg | tool_return/decoded_plain | action, delivery, target_spans |
| contract-upper-pg | tool_return/decoded_escaped | action, delivery, target_spans |
| contract-mixed-pg-alias | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-mixed-pg-alias | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-mixed-pg-alias | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-mixed-pg-alias | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-mixed-pg-alias | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-mixed-pg-alias | tool_return/plain | action, delivery, target_spans |
| contract-mixed-pg-alias | tool_return/json_plain | action, delivery, target_spans |
| contract-mixed-pg-alias | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-mixed-pg-alias | tool_return/decoded_plain | action, delivery, target_spans |
| contract-mixed-pg-alias | tool_return/decoded_escaped | action, delivery, target_spans |
| contract-upper-mongo | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-upper-mongo | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-upper-mongo | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-upper-mongo | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-upper-mongo | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-upper-mongo | tool_return/plain | action, delivery, target_spans |
| contract-upper-mongo | tool_return/json_plain | action, delivery, target_spans |
| contract-upper-mongo | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-upper-mongo | tool_return/decoded_plain | action, delivery, target_spans |
| contract-upper-mongo | tool_return/decoded_escaped | action, delivery, target_spans |
| contract-mixed-srv | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-mixed-srv | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-mixed-srv | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-mixed-srv | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-mixed-srv | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-mixed-srv | tool_return/plain | action, delivery, target_spans |
| contract-mixed-srv | tool_return/json_plain | action, delivery, target_spans |
| contract-mixed-srv | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-mixed-srv | tool_return/decoded_plain | action, delivery, target_spans |
| contract-mixed-srv | tool_return/decoded_escaped | action, delivery, target_spans |
| contract-upper-query-key | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-upper-query-key | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-upper-query-key | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-upper-query-key | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-upper-query-key | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-upper-query-key | tool_return/plain | action, delivery, target_spans, credential_coverage |
| contract-upper-query-key | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| contract-upper-query-key | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-upper-query-key | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-upper-query-key | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-encoded-query-key | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-encoded-query-key | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-encoded-query-key | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-encoded-query-key | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-encoded-query-key | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-encoded-query-key | tool_return/plain | action, delivery, target_spans, credential_coverage |
| contract-encoded-query-key | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| contract-encoded-query-key | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-encoded-query-key | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-encoded-query-key | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-mixed-encoded-query-key | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-mixed-encoded-query-key | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-mixed-encoded-query-key | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-mixed-encoded-query-key | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-mixed-encoded-query-key | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-mixed-encoded-query-key | tool_return/plain | action, delivery, target_spans, credential_coverage |
| contract-mixed-encoded-query-key | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| contract-mixed-encoded-query-key | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-mixed-encoded-query-key | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-mixed-encoded-query-key | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-hash-in-userinfo | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-hash-in-userinfo | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-hash-in-userinfo | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-hash-in-userinfo | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-hash-in-userinfo | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-hash-in-userinfo | tool_return/plain | action, delivery, target_spans |
| contract-hash-in-userinfo | tool_return/json_plain | action, delivery, target_spans |
| contract-hash-in-userinfo | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-hash-in-userinfo | tool_return/decoded_plain | action, delivery, target_spans |
| contract-hash-in-userinfo | tool_return/decoded_escaped | action, delivery, target_spans |
| contract-hash-starts-query-value | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-hash-starts-query-value | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-hash-starts-query-value | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-hash-starts-query-value | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-hash-starts-query-value | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-hash-starts-query-value | tool_return/plain | action, delivery, target_spans, credential_coverage |
| contract-hash-starts-query-value | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| contract-hash-starts-query-value | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-hash-starts-query-value | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-hash-starts-query-value | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-encoded-hash | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-encoded-hash | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-encoded-hash | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-encoded-hash | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-encoded-hash | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-encoded-hash | tool_return/plain | action, delivery, target_spans |
| contract-encoded-hash | tool_return/json_plain | action, delivery, target_spans |
| contract-encoded-hash | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-encoded-hash | tool_return/decoded_plain | action, delivery, target_spans |
| contract-encoded-hash | tool_return/decoded_escaped | action, delivery, target_spans |
| contract-inner-apostrophe | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-inner-apostrophe | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-inner-apostrophe | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-inner-apostrophe | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-inner-apostrophe | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-inner-apostrophe | tool_return/plain | action, delivery, target_spans |
| contract-inner-apostrophe | tool_return/json_plain | action, delivery, target_spans |
| contract-inner-apostrophe | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-inner-apostrophe | tool_return/decoded_plain | action, delivery, target_spans |
| contract-inner-apostrophe | tool_return/decoded_escaped | action, delivery, target_spans |
| contract-double-quote-wrapper | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-double-quote-wrapper | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-double-quote-wrapper | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-double-quote-wrapper | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-double-quote-wrapper | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-double-quote-wrapper | tool_return/plain | action, delivery, target_spans |
| contract-double-quote-wrapper | tool_return/json_plain | action, delivery, target_spans |
| contract-double-quote-wrapper | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-double-quote-wrapper | tool_return/decoded_plain | action, delivery, target_spans |
| contract-double-quote-wrapper | tool_return/decoded_escaped | action, delivery, target_spans |
| contract-backtick-wrapper | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-backtick-wrapper | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-backtick-wrapper | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-backtick-wrapper | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-backtick-wrapper | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-backtick-wrapper | tool_return/plain | action, delivery, target_spans |
| contract-backtick-wrapper | tool_return/json_plain | action, delivery, target_spans |
| contract-backtick-wrapper | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-backtick-wrapper | tool_return/decoded_plain | action, delivery, target_spans |
| contract-backtick-wrapper | tool_return/decoded_escaped | action, delivery, target_spans |
| contract-outer-angle-wrapper | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-outer-angle-wrapper | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-outer-angle-wrapper | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-outer-angle-wrapper | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-outer-angle-wrapper | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-outer-angle-wrapper | tool_return/plain | action, delivery, target_spans |
| contract-outer-angle-wrapper | tool_return/json_plain | action, delivery, target_spans |
| contract-outer-angle-wrapper | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-outer-angle-wrapper | tool_return/decoded_plain | action, delivery, target_spans |
| contract-outer-angle-wrapper | tool_return/decoded_escaped | action, delivery, target_spans |
| contract-pg-empty-user | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-pg-empty-user | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-pg-empty-user | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-pg-empty-user | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-pg-empty-user | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-pg-empty-user | tool_return/plain | action, delivery, target_spans |
| contract-pg-empty-user | tool_return/json_plain | action, delivery, target_spans |
| contract-pg-empty-user | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-pg-empty-user | tool_return/decoded_plain | action, delivery, target_spans |
| contract-pg-empty-user | tool_return/decoded_escaped | action, delivery, target_spans |
| contract-mongo-empty-user | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-mongo-empty-user | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-mongo-empty-user | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-mongo-empty-user | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-mongo-empty-user | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-mongo-empty-user | tool_return/plain | action, delivery, target_spans |
| contract-mongo-empty-user | tool_return/json_plain | action, delivery, target_spans |
| contract-mongo-empty-user | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-mongo-empty-user | tool_return/decoded_plain | action, delivery, target_spans |
| contract-mongo-empty-user | tool_return/decoded_escaped | action, delivery, target_spans |
| contract-invalid-host-label | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-invalid-host-label | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-invalid-host-label | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-invalid-host-label | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-invalid-host-label | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-invalid-host-label | tool_return/plain | action, delivery, target_spans, credential_coverage |
| contract-invalid-host-label | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| contract-invalid-host-label | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-invalid-host-label | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-invalid-host-label | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-nonnumeric-port | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-nonnumeric-port | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-nonnumeric-port | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-nonnumeric-port | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-nonnumeric-port | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-nonnumeric-port | tool_return/plain | action, delivery, target_spans |
| contract-nonnumeric-port | tool_return/json_plain | action, delivery, target_spans |
| contract-nonnumeric-port | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-nonnumeric-port | tool_return/decoded_plain | action, delivery, target_spans |
| contract-nonnumeric-port | tool_return/decoded_escaped | action, delivery, target_spans |
| contract-invalid-query-value-escape | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-invalid-query-value-escape | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-invalid-query-value-escape | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-invalid-query-value-escape | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-invalid-query-value-escape | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-invalid-query-value-escape | tool_return/plain | action, delivery, target_spans, credential_coverage |
| contract-invalid-query-value-escape | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| contract-invalid-query-value-escape | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-invalid-query-value-escape | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-invalid-query-value-escape | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-duplicate-empty-last | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-duplicate-empty-last | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-duplicate-empty-last | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-duplicate-empty-last | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-duplicate-empty-last | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-duplicate-empty-last | tool_return/plain | action, delivery, target_spans, credential_coverage |
| contract-duplicate-empty-last | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| contract-duplicate-empty-last | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-duplicate-empty-last | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-duplicate-empty-last | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-duplicate-empty-first | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-duplicate-empty-first | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-duplicate-empty-first | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-duplicate-empty-first | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-duplicate-empty-first | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-duplicate-empty-first | tool_return/plain | action, delivery, target_spans, credential_coverage |
| contract-duplicate-empty-first | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| contract-duplicate-empty-first | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-duplicate-empty-first | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-duplicate-empty-first | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-mixed-user-and-query | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-mixed-user-and-query | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-mixed-user-and-query | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-mixed-user-and-query | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-mixed-user-and-query | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-mixed-user-and-query | tool_return/plain | action, delivery, target_spans, credential_coverage |
| contract-mixed-user-and-query | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| contract-mixed-user-and-query | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-mixed-user-and-query | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-mixed-user-and-query | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-encoded-userinfo-delimiters | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-encoded-userinfo-delimiters | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-encoded-userinfo-delimiters | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-encoded-userinfo-delimiters | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-encoded-userinfo-delimiters | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-encoded-userinfo-delimiters | tool_return/plain | action, delivery, target_spans |
| contract-encoded-userinfo-delimiters | tool_return/json_plain | action, delivery, target_spans |
| contract-encoded-userinfo-delimiters | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-encoded-userinfo-delimiters | tool_return/decoded_plain | action, delivery, target_spans |
| contract-encoded-userinfo-delimiters | tool_return/decoded_escaped | action, delivery, target_spans |
| contract-literal-plus-query | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-literal-plus-query | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-literal-plus-query | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-literal-plus-query | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-literal-plus-query | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-literal-plus-query | tool_return/plain | action, delivery, target_spans, credential_coverage |
| contract-literal-plus-query | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| contract-literal-plus-query | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-literal-plus-query | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-literal-plus-query | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-encoded-query-delimiters | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-encoded-query-delimiters | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-encoded-query-delimiters | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-encoded-query-delimiters | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-encoded-query-delimiters | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-encoded-query-delimiters | tool_return/plain | action, delivery, target_spans, credential_coverage |
| contract-encoded-query-delimiters | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| contract-encoded-query-delimiters | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-encoded-query-delimiters | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-encoded-query-delimiters | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-unicode-original-offsets | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-unicode-original-offsets | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-unicode-original-offsets | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-unicode-original-offsets | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-unicode-original-offsets | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-unicode-original-offsets | tool_return/plain | action, delivery, target_spans |
| contract-unicode-original-offsets | tool_return/json_plain | action, delivery, target_spans |
| contract-unicode-original-offsets | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-unicode-original-offsets | tool_return/decoded_plain | action, delivery, target_spans |
| contract-unicode-original-offsets | tool_return/decoded_escaped | action, delivery, target_spans |
| contract-two-uri-candidates | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-two-uri-candidates | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-two-uri-candidates | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-two-uri-candidates | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-two-uri-candidates | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-two-uri-candidates | tool_return/plain | action, delivery, target_spans |
| contract-two-uri-candidates | tool_return/json_plain | action, delivery, target_spans |
| contract-two-uri-candidates | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-two-uri-candidates | tool_return/decoded_plain | action, delivery, target_spans |
| contract-two-uri-candidates | tool_return/decoded_escaped | action, delivery, target_spans |
| contract-existing-token-overlap | secret_only/plain | target_spans |
| contract-existing-token-overlap | secret_only/json_plain | target_spans |
| contract-existing-token-overlap | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-existing-token-overlap | secret_only/decoded_plain | target_spans |
| contract-existing-token-overlap | secret_only/decoded_escaped | target_spans |
| contract-existing-token-overlap | tool_return/plain | target_spans |
| contract-existing-token-overlap | tool_return/json_plain | target_spans |
| contract-existing-token-overlap | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-existing-token-overlap | tool_return/decoded_plain | target_spans |
| contract-existing-token-overlap | tool_return/decoded_escaped | target_spans |
| contract-benign-user-only | tool_return/plain | action, delivery, target_spans, credential_coverage |
| contract-benign-user-only | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| contract-benign-user-only | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-benign-user-only | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-query-mask | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-query-mask | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-query-mask | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-query-mask | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-query-mask | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-query-mask | tool_return/plain | action, delivery, target_spans, credential_coverage |
| contract-query-mask | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| contract-query-mask | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-query-mask | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-query-mask | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-query-env | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-query-env | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-query-env | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-query-env | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-query-env | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-query-env | tool_return/plain | action, delivery, target_spans, credential_coverage |
| contract-query-env | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| contract-query-env | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-query-env | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-query-env | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-query-angle | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-query-angle | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-query-angle | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-query-angle | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-query-angle | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-query-angle | tool_return/plain | action, delivery, target_spans, credential_coverage |
| contract-query-angle | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| contract-query-angle | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-query-angle | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-query-angle | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-empty-userinfo-nonempty-query | secret_only/plain | action, delivery, target_spans, credential_coverage |
| contract-empty-userinfo-nonempty-query | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| contract-empty-userinfo-nonempty-query | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-empty-userinfo-nonempty-query | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-empty-userinfo-nonempty-query | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-empty-userinfo-nonempty-query | tool_return/plain | action, delivery, target_spans, credential_coverage |
| contract-empty-userinfo-nonempty-query | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| contract-empty-userinfo-nonempty-query | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| contract-empty-userinfo-nonempty-query | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-empty-userinfo-nonempty-query | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| contract-benign-mongo-user-only | tool_return/plain | action, delivery, target_spans, credential_coverage |
| contract-benign-mongo-user-only | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| contract-benign-mongo-user-only | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| contract-benign-mongo-user-only | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
