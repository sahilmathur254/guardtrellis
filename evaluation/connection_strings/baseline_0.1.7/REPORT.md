# Connection-string development baseline

SDK 0.1.7; 520 observations.

Authored synthetic development data; no accuracy, credential-validity or driver compatibility claim. Desired BLOCK/ALLOW labels precede detector changes. Policy-dependent rows are unscored. Historical gaps and incidental PII redactions remain visible.

| Policy / representation | Scored | Action matches | Delivery matches | Incidental PII | Unexpected errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| secret_only/plain | 40 | 12 | 13 | 0 | 0 |
| secret_only/json_plain | 40 | 12 | 14 | 0 | 0 |
| secret_only/json_escaped | 40 | 10 | 12 | 0 | 0 |
| secret_only/decoded_plain | 40 | 12 | 13 | 0 | 0 |
| secret_only/decoded_escaped | 40 | 12 | 13 | 0 | 0 |
| tool_return/plain | 40 | 11 | 12 | 23 | 0 |
| tool_return/json_plain | 40 | 11 | 13 | 22 | 0 |
| tool_return/json_escaped | 40 | 10 | 12 | 0 | 0 |
| tool_return/decoded_plain | 40 | 11 | 12 | 23 | 0 |
| tool_return/decoded_escaped | 40 | 11 | 12 | 23 | 0 |

## Observed actions by authored label

| Label | Observations | ALLOW | REDACT | BLOCK | ERROR |
| --- | ---: | ---: | ---: | ---: | ---: |
| ambiguous | 120 | 100 | 20 | 0 | 0 |
| benign | 100 | 96 | 4 | 0 | 0 |
| control | 20 | 4 | 0 | 16 | 0 |
| deferred | 40 | 40 | 0 | 0 | 0 |
| sensitive | 240 | 159 | 67 | 0 | 14 |

## Interpretation

A secret-signature finding is distinct from incidental PII and from dedicated connection-string detection (which is not implemented in this baseline). Whole-URI target-span comparisons are aspirational coverage checks; existing secret controls target their supported token spans. Credential coverage checks authored credential intervals and spellings against actual consumer data; accepted text is also compared with the fixed policy's independently reconstructed transformation. This is not a general sanitization guarantee. An input-limit ERROR withholds delivery but is not a credential detection.

Plain/decoded offsets refer to that string; serialized offsets refer to JSON wire. All finding offsets retain their scanner revision. No input/output text or credential values are copied into this report.

## Retained mismatches

| Case | Policy / representation | Mismatched comparisons |
| --- | --- | --- |
| pg-userinfo | secret_only/plain | action, delivery, target_spans, credential_coverage |
| pg-userinfo | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| pg-userinfo | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-userinfo | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| pg-userinfo | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| pg-userinfo | tool_return/plain | action, delivery, target_spans |
| pg-userinfo | tool_return/json_plain | action, delivery, target_spans |
| pg-userinfo | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-userinfo | tool_return/decoded_plain | action, delivery, target_spans |
| pg-userinfo | tool_return/decoded_escaped | action, delivery, target_spans |
| pg-short-scheme | secret_only/plain | action, delivery, target_spans, credential_coverage |
| pg-short-scheme | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| pg-short-scheme | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-short-scheme | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| pg-short-scheme | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| pg-short-scheme | tool_return/plain | action, delivery, target_spans |
| pg-short-scheme | tool_return/json_plain | action, delivery, target_spans |
| pg-short-scheme | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-short-scheme | tool_return/decoded_plain | action, delivery, target_spans |
| pg-short-scheme | tool_return/decoded_escaped | action, delivery, target_spans |
| pg-query-password | secret_only/plain | action, delivery, target_spans, credential_coverage |
| pg-query-password | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| pg-query-password | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-query-password | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| pg-query-password | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| pg-query-password | tool_return/plain | action, delivery, target_spans, credential_coverage |
| pg-query-password | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| pg-query-password | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-query-password | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| pg-query-password | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| pg-query-encoded-password | secret_only/plain | action, delivery, target_spans, credential_coverage |
| pg-query-encoded-password | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| pg-query-encoded-password | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-query-encoded-password | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| pg-query-encoded-password | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| pg-query-encoded-password | tool_return/plain | action, delivery, target_spans, credential_coverage |
| pg-query-encoded-password | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| pg-query-encoded-password | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-query-encoded-password | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| pg-query-encoded-password | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| pg-userinfo-encoded-password | secret_only/plain | action, delivery, target_spans, credential_coverage |
| pg-userinfo-encoded-password | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| pg-userinfo-encoded-password | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-userinfo-encoded-password | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| pg-userinfo-encoded-password | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| pg-userinfo-encoded-password | tool_return/plain | action, delivery, target_spans |
| pg-userinfo-encoded-password | tool_return/json_plain | action, delivery, target_spans |
| pg-userinfo-encoded-password | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-userinfo-encoded-password | tool_return/decoded_plain | action, delivery, target_spans |
| pg-userinfo-encoded-password | tool_return/decoded_escaped | action, delivery, target_spans |
| pg-encoded-username | secret_only/plain | action, delivery, target_spans, credential_coverage |
| pg-encoded-username | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| pg-encoded-username | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-encoded-username | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| pg-encoded-username | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| pg-encoded-username | tool_return/plain | action, delivery, target_spans |
| pg-encoded-username | tool_return/json_plain | action, delivery, target_spans |
| pg-encoded-username | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-encoded-username | tool_return/decoded_plain | action, delivery, target_spans |
| pg-encoded-username | tool_return/decoded_escaped | action, delivery, target_spans |
| pg-ipv6-host | secret_only/plain | action, delivery, target_spans, credential_coverage |
| pg-ipv6-host | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| pg-ipv6-host | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-ipv6-host | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| pg-ipv6-host | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| pg-ipv6-host | tool_return/plain | action, delivery, target_spans, credential_coverage |
| pg-ipv6-host | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| pg-ipv6-host | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-ipv6-host | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| pg-ipv6-host | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| pg-multiple-hosts | secret_only/plain | action, delivery, target_spans, credential_coverage |
| pg-multiple-hosts | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| pg-multiple-hosts | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-multiple-hosts | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| pg-multiple-hosts | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| pg-multiple-hosts | tool_return/plain | action, delivery, target_spans |
| pg-multiple-hosts | tool_return/json_plain | action, delivery, target_spans |
| pg-multiple-hosts | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-multiple-hosts | tool_return/decoded_plain | action, delivery, target_spans |
| pg-multiple-hosts | tool_return/decoded_escaped | action, delivery, target_spans |
| pg-omitted-host-query | secret_only/plain | action, delivery, target_spans, credential_coverage |
| pg-omitted-host-query | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| pg-omitted-host-query | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-omitted-host-query | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| pg-omitted-host-query | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| pg-omitted-host-query | tool_return/plain | action, delivery, target_spans, credential_coverage |
| pg-omitted-host-query | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| pg-omitted-host-query | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-omitted-host-query | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| pg-omitted-host-query | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| pg-repeated-query-password | secret_only/plain | action, delivery, target_spans, credential_coverage |
| pg-repeated-query-password | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| pg-repeated-query-password | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-repeated-query-password | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| pg-repeated-query-password | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| pg-repeated-query-password | tool_return/plain | action, delivery, target_spans, credential_coverage |
| pg-repeated-query-password | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| pg-repeated-query-password | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-repeated-query-password | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| pg-repeated-query-password | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| mongo-userinfo | secret_only/plain | action, delivery, target_spans, credential_coverage |
| mongo-userinfo | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| mongo-userinfo | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| mongo-userinfo | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| mongo-userinfo | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| mongo-userinfo | tool_return/plain | action, delivery, target_spans |
| mongo-userinfo | tool_return/json_plain | action, delivery, target_spans |
| mongo-userinfo | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| mongo-userinfo | tool_return/decoded_plain | action, delivery, target_spans |
| mongo-userinfo | tool_return/decoded_escaped | action, delivery, target_spans |
| mongo-srv-userinfo | secret_only/plain | action, delivery, target_spans, credential_coverage |
| mongo-srv-userinfo | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| mongo-srv-userinfo | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| mongo-srv-userinfo | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| mongo-srv-userinfo | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| mongo-srv-userinfo | tool_return/plain | action, delivery, target_spans |
| mongo-srv-userinfo | tool_return/json_plain | action, delivery, target_spans |
| mongo-srv-userinfo | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| mongo-srv-userinfo | tool_return/decoded_plain | action, delivery, target_spans |
| mongo-srv-userinfo | tool_return/decoded_escaped | action, delivery, target_spans |
| mongo-encoded-password | secret_only/plain | action, delivery, target_spans, credential_coverage |
| mongo-encoded-password | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| mongo-encoded-password | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| mongo-encoded-password | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| mongo-encoded-password | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| mongo-encoded-password | tool_return/plain | action, delivery, target_spans |
| mongo-encoded-password | tool_return/json_plain | action, delivery, target_spans |
| mongo-encoded-password | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| mongo-encoded-password | tool_return/decoded_plain | action, delivery, target_spans |
| mongo-encoded-password | tool_return/decoded_escaped | action, delivery, target_spans |
| mongo-multiple-hosts | secret_only/plain | action, delivery, target_spans, credential_coverage |
| mongo-multiple-hosts | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| mongo-multiple-hosts | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| mongo-multiple-hosts | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| mongo-multiple-hosts | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| mongo-multiple-hosts | tool_return/plain | action, delivery, target_spans |
| mongo-multiple-hosts | tool_return/json_plain | action, delivery, target_spans |
| mongo-multiple-hosts | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| mongo-multiple-hosts | tool_return/decoded_plain | action, delivery, target_spans |
| mongo-multiple-hosts | tool_return/decoded_escaped | action, delivery, target_spans |
| mongo-ipv6-host | secret_only/plain | action, delivery, target_spans, credential_coverage |
| mongo-ipv6-host | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| mongo-ipv6-host | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| mongo-ipv6-host | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| mongo-ipv6-host | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| mongo-ipv6-host | tool_return/plain | action, delivery, target_spans, credential_coverage |
| mongo-ipv6-host | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| mongo-ipv6-host | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| mongo-ipv6-host | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| mongo-ipv6-host | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| pg-quoted-metadata | secret_only/plain | action, delivery, target_spans, credential_coverage |
| pg-quoted-metadata | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| pg-quoted-metadata | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-quoted-metadata | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| pg-quoted-metadata | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| pg-quoted-metadata | tool_return/plain | action, delivery, target_spans |
| pg-quoted-metadata | tool_return/json_plain | action, delivery, target_spans |
| pg-quoted-metadata | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-quoted-metadata | tool_return/decoded_plain | action, delivery, target_spans |
| pg-quoted-metadata | tool_return/decoded_escaped | action, delivery, target_spans |
| pg-emoji-offset | secret_only/plain | action, delivery, target_spans, credential_coverage |
| pg-emoji-offset | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| pg-emoji-offset | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-emoji-offset | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| pg-emoji-offset | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| pg-emoji-offset | tool_return/plain | action, delivery, target_spans |
| pg-emoji-offset | tool_return/json_plain | action, delivery, target_spans |
| pg-emoji-offset | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-emoji-offset | tool_return/decoded_plain | action, delivery, target_spans |
| pg-emoji-offset | tool_return/decoded_escaped | action, delivery, target_spans |
| two-credential-uris | secret_only/plain | action, delivery, target_spans, credential_coverage |
| two-credential-uris | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| two-credential-uris | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| two-credential-uris | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| two-credential-uris | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| two-credential-uris | tool_return/plain | action, delivery, target_spans |
| two-credential-uris | tool_return/json_plain | action, delivery, target_spans |
| two-credential-uris | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| two-credential-uris | tool_return/decoded_plain | action, delivery, target_spans |
| two-credential-uris | tool_return/decoded_escaped | action, delivery, target_spans |
| benign-then-credential | secret_only/plain | action, delivery, target_spans, credential_coverage |
| benign-then-credential | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| benign-then-credential | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| benign-then-credential | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| benign-then-credential | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| benign-then-credential | tool_return/plain | action, delivery, target_spans |
| benign-then-credential | tool_return/json_plain | action, delivery, target_spans |
| benign-then-credential | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| benign-then-credential | tool_return/decoded_plain | action, delivery, target_spans |
| benign-then-credential | tool_return/decoded_escaped | action, delivery, target_spans |
| four-credential-candidates | secret_only/plain | action, delivery, target_spans, credential_coverage |
| four-credential-candidates | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| four-credential-candidates | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| four-credential-candidates | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| four-credential-candidates | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| four-credential-candidates | tool_return/plain | action, delivery, target_spans |
| four-credential-candidates | tool_return/json_plain | action, delivery, target_spans |
| four-credential-candidates | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| four-credential-candidates | tool_return/decoded_plain | action, delivery, target_spans |
| four-credential-candidates | tool_return/decoded_escaped | action, delivery, target_spans |
| pg-userinfo-and-query-password | secret_only/plain | action, delivery, target_spans, credential_coverage |
| pg-userinfo-and-query-password | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| pg-userinfo-and-query-password | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-userinfo-and-query-password | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| pg-userinfo-and-query-password | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| pg-userinfo-and-query-password | tool_return/plain | action, delivery, target_spans, credential_coverage |
| pg-userinfo-and-query-password | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| pg-userinfo-and-query-password | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-userinfo-and-query-password | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| pg-userinfo-and-query-password | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| pg-encoded-backslash-password | secret_only/plain | action, delivery, target_spans, credential_coverage |
| pg-encoded-backslash-password | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| pg-encoded-backslash-password | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-encoded-backslash-password | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| pg-encoded-backslash-password | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| pg-encoded-backslash-password | tool_return/plain | action, delivery, target_spans |
| pg-encoded-backslash-password | tool_return/json_plain | action, delivery, target_spans |
| pg-encoded-backslash-password | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| pg-encoded-backslash-password | tool_return/decoded_plain | action, delivery, target_spans |
| pg-encoded-backslash-password | tool_return/decoded_escaped | action, delivery, target_spans |
| pg-candidate-2000-characters | secret_only/plain | action, delivery, target_spans, credential_coverage |
| pg-candidate-2000-characters | secret_only/json_plain | action, target_spans |
| pg-candidate-2000-characters | secret_only/json_escaped | action, target_spans |
| pg-candidate-2000-characters | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| pg-candidate-2000-characters | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| pg-candidate-2000-characters | tool_return/plain | action, delivery, target_spans |
| pg-candidate-2000-characters | tool_return/json_plain | action, target_spans |
| pg-candidate-2000-characters | tool_return/json_escaped | action, target_spans |
| pg-candidate-2000-characters | tool_return/decoded_plain | action, delivery, target_spans |
| pg-candidate-2000-characters | tool_return/decoded_escaped | action, delivery, target_spans |
| pg-candidate-2001-characters | secret_only/plain | action, target_spans |
| pg-candidate-2001-characters | secret_only/json_plain | action, target_spans |
| pg-candidate-2001-characters | secret_only/json_escaped | action, target_spans |
| pg-candidate-2001-characters | secret_only/decoded_plain | action, target_spans |
| pg-candidate-2001-characters | secret_only/decoded_escaped | action, target_spans |
| pg-candidate-2001-characters | tool_return/plain | action, target_spans |
| pg-candidate-2001-characters | tool_return/json_plain | action, target_spans |
| pg-candidate-2001-characters | tool_return/json_escaped | action, target_spans |
| pg-candidate-2001-characters | tool_return/decoded_plain | action, target_spans |
| pg-candidate-2001-characters | tool_return/decoded_escaped | action, target_spans |
| benign-pg-username-only | tool_return/plain | action, delivery, target_spans, credential_coverage |
| benign-pg-username-only | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| benign-pg-username-only | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| benign-pg-username-only | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| control-github-classic | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| control-github-classic | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| control-aws-access-key-id | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| control-aws-access-key-id | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| deferred-libpq-keywords | secret_only/plain | action, delivery, target_spans, credential_coverage |
| deferred-libpq-keywords | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| deferred-libpq-keywords | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| deferred-libpq-keywords | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| deferred-libpq-keywords | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| deferred-libpq-keywords | tool_return/plain | action, delivery, target_spans, credential_coverage |
| deferred-libpq-keywords | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| deferred-libpq-keywords | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| deferred-libpq-keywords | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| deferred-libpq-keywords | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| deferred-libpq-quoted-password | secret_only/plain | action, delivery, target_spans, credential_coverage |
| deferred-libpq-quoted-password | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| deferred-libpq-quoted-password | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| deferred-libpq-quoted-password | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| deferred-libpq-quoted-password | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| deferred-libpq-quoted-password | tool_return/plain | action, delivery, target_spans, credential_coverage |
| deferred-libpq-quoted-password | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| deferred-libpq-quoted-password | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| deferred-libpq-quoted-password | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| deferred-libpq-quoted-password | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| deferred-sqlserver-keywords | secret_only/plain | action, delivery, target_spans, credential_coverage |
| deferred-sqlserver-keywords | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| deferred-sqlserver-keywords | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| deferred-sqlserver-keywords | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| deferred-sqlserver-keywords | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| deferred-sqlserver-keywords | tool_return/plain | action, delivery, target_spans, credential_coverage |
| deferred-sqlserver-keywords | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| deferred-sqlserver-keywords | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| deferred-sqlserver-keywords | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| deferred-sqlserver-keywords | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
| deferred-odbc-keywords | secret_only/plain | action, delivery, target_spans, credential_coverage |
| deferred-odbc-keywords | secret_only/json_plain | action, delivery, target_spans, credential_coverage |
| deferred-odbc-keywords | secret_only/json_escaped | action, delivery, target_spans, credential_coverage |
| deferred-odbc-keywords | secret_only/decoded_plain | action, delivery, target_spans, credential_coverage |
| deferred-odbc-keywords | secret_only/decoded_escaped | action, delivery, target_spans, credential_coverage |
| deferred-odbc-keywords | tool_return/plain | action, delivery, target_spans, credential_coverage |
| deferred-odbc-keywords | tool_return/json_plain | action, delivery, target_spans, credential_coverage |
| deferred-odbc-keywords | tool_return/json_escaped | action, delivery, target_spans, credential_coverage |
| deferred-odbc-keywords | tool_return/decoded_plain | action, delivery, target_spans, credential_coverage |
| deferred-odbc-keywords | tool_return/decoded_escaped | action, delivery, target_spans, credential_coverage |
