# Changelog

## 0.1.0a1 — 2026-09-25

The first alpha is available on [PyPI](https://pypi.org/project/guardtrellis/0.1.0a1/).
The [GitHub prerelease](https://github.com/sahilmathur254/guardtrellis/releases/tag/v0.1.0a1)
records the exact source commit, unchanged rehearsed artifacts, and verification evidence.
Publication is tracked in [#4](https://github.com/sahilmathur254/guardtrellis/issues/4).

### Included

- Typed `Guard` and scanner contracts with synchronous/asynchronous entry points,
  explicit input/output/retrieval/tool stages, and ordered redaction provenance.
- Explicit allow, warn, redact, block, and error outcomes. Rejected inputs do not reach
  callbacks; blocked/error results do not expose ordinary deliverable text or arguments.
- Local checks for documented PII shapes, selected secret signatures, Unicode control/format
  characters, literal policies, strict JSON/constrained Draft 2020-12 schemas, and tool-call
  name/object-argument validation.
- Bounded text, findings, and JSON depth; per-operation async waits with documented
  cancellation limitations; metadata-only diagnostics and payload-free rejection errors.
- Optional, credential-free callable, FastAPI, and LangGraph examples. The core requires
  only jsonschema and referencing plus their dependencies, with no provider SDK or model download.
- Python 3.11–3.14 support, typed package metadata, Apache-2.0 licensing, wheel/sdist
  installation checks, and a reproducible synthetic smoke evaluation with retained failures.

### Compatibility and known limitations

This is an experimental API. Names, contracts, and dependencies can change before a stable
version; such changes will be documented with migration guidance. Pin an exact alpha version
or source commit when evaluating it. No new runtime API changes are included in release preparation.

Checks inspect only explicitly supplied text and configured formats. Coverage excludes many
PII/secret formats and semantic safety judgments. WARN permits delivery, unconfigured stages
permit bounded text, and tool validation supplies neither authorization nor sandboxing.
Outputs are checked only after the complete callback response; there is no streaming API.
Async timeout does not terminate arbitrary Python code or undo callback side effects.

The 72-case authored smoke corpus includes four known misses and two false positives. Its
aggregate results are not a general accuracy estimate or an independent security benchmark.
See [limitations](docs/limitations.md), [API contracts](docs/api.md), and the
[evaluation report](evaluation/REPORT.md) before integrating.
