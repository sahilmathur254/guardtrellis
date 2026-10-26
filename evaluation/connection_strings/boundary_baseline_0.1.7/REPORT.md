# Connection-string structural boundaries: current SDK observations

Dataset `connection-strings-boundaries-v1`; SDK 0.1.7; 160 observations; opt-in not implemented.

Authored synthetic development cases, with desired decisions fixed before outcomes. This run exercises the frozen v1 harness's unchanged secret-only and tool-return policies. It does not execute the proposed connection-string detector. Excluded/resource-pending cases have null comparisons; absence of a finding is not a safety or driver-validity claim. No resource-limit experiment is performed here.

| Contract status | Observations | Scored | Exact matches | ALLOW | REDACT | BLOCK | ERROR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| selected | 160 | 160 | 40 | 116 | 44 | 0 | 0 |

Whole-URI spans are proposed targets, including when an existing token signature already blocks a smaller span. Incidental PII redaction and input-limit ERROR remain distinct from URI detection. Raw JSON is scanned as wire text; explicit decoded equivalents use decoded-string offsets. No raw input/output, credentials or exception text are included in the report.

## Retained mismatches

| Case | Policy / representation | Mismatched comparisons |
| --- | --- | --- |
| boundary-pg-extra-colon | secret_only/plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-extra-colon | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-extra-colon | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-extra-colon | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-extra-colon | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-extra-colon | tool_return/plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-extra-colon | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-extra-colon | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-extra-colon | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-extra-colon | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-mongo-extra-colon | secret_only/plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-extra-colon | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-extra-colon | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| boundary-mongo-extra-colon | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-extra-colon | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-mongo-extra-colon | tool_return/plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-extra-colon | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-extra-colon | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| boundary-mongo-extra-colon | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-extra-colon | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-multiple-at | secret_only/plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-multiple-at | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-multiple-at | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-multiple-at | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-multiple-at | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-multiple-at | tool_return/plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-multiple-at | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-multiple-at | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-multiple-at | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-multiple-at | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-mongo-multiple-at | secret_only/plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-multiple-at | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-multiple-at | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| boundary-mongo-multiple-at | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-multiple-at | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-mongo-multiple-at | tool_return/plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-multiple-at | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-multiple-at | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| boundary-mongo-multiple-at | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-multiple-at | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-first-gap-empty | secret_only/plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-first-gap-empty | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-first-gap-empty | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-first-gap-empty | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-first-gap-empty | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-first-gap-empty | tool_return/plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-first-gap-empty | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-first-gap-empty | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-first-gap-empty | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-first-gap-empty | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-mongo-first-gap-empty | secret_only/plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-first-gap-empty | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-first-gap-empty | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| boundary-mongo-first-gap-empty | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-first-gap-empty | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-mongo-first-gap-empty | tool_return/plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-first-gap-empty | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-first-gap-empty | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| boundary-mongo-first-gap-empty | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-first-gap-empty | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-empty-and-user-only | tool_return/plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-empty-and-user-only | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-empty-and-user-only | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-empty-and-user-only | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-mongo-empty-and-user-only | tool_return/plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-empty-and-user-only | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-empty-and-user-only | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-empty-and-user-only | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-path-and-query-lookalikes | tool_return/plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-path-and-query-lookalikes | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-path-and-query-lookalikes | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-path-and-query-lookalikes | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-mongo-path-and-query-lookalikes | tool_return/plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-path-and-query-lookalikes | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-path-and-query-lookalikes | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-path-and-query-lookalikes | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-encoded-password-separators | secret_only/plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-encoded-password-separators | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-encoded-password-separators | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-encoded-password-separators | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-encoded-password-separators | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-encoded-password-separators | tool_return/plain | action, delivery, target_spans |
| boundary-pg-encoded-password-separators | tool_return/json_plain | action, delivery, target_spans |
| boundary-pg-encoded-password-separators | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-encoded-password-separators | tool_return/decoded_plain | action, delivery, target_spans |
| boundary-pg-encoded-password-separators | tool_return/decoded_escaped | action, delivery, target_spans |
| boundary-mongo-encoded-password-separators | secret_only/plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-encoded-password-separators | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-encoded-password-separators | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| boundary-mongo-encoded-password-separators | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-mongo-encoded-password-separators | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-mongo-encoded-password-separators | tool_return/plain | action, delivery, target_spans |
| boundary-mongo-encoded-password-separators | tool_return/json_plain | action, delivery, target_spans |
| boundary-mongo-encoded-password-separators | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| boundary-mongo-encoded-password-separators | tool_return/decoded_plain | action, delivery, target_spans |
| boundary-mongo-encoded-password-separators | tool_return/decoded_escaped | action, delivery, target_spans |
| boundary-pg-encoded-colon-not-delimiter | tool_return/plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-encoded-colon-not-delimiter | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-encoded-colon-not-delimiter | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-encoded-colon-not-delimiter | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-malformed-query-before | secret_only/plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-malformed-query-before | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-malformed-query-before | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-malformed-query-before | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-malformed-query-before | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-malformed-query-before | tool_return/plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-malformed-query-before | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-malformed-query-before | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-malformed-query-before | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-malformed-query-before | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-malformed-query-after | secret_only/plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-malformed-query-after | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-malformed-query-after | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-malformed-query-after | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-malformed-query-after | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-malformed-query-after | tool_return/plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-malformed-query-after | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-malformed-query-after | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| boundary-pg-malformed-query-after | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| boundary-pg-malformed-query-after | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
