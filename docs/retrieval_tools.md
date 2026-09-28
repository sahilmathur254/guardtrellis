# Retrieval and tool-call recipe

Run the credential-free [example](../examples/retrieval_tools.py) with core dependencies:

```sh
uv sync --frozen --group dev
uv run --frozen python examples/retrieval_tools.py
```

The example uses fabricated data, a deterministic model callback, and a fixed in-memory
reference. It makes no network requests and needs no provider or framework extras.

`run_workflow` makes the data boundaries explicit:

1. Scan the retrieved text at `Stage.RETRIEVAL` before composing the prompt. Only
   `retrieval.require_text()` reaches the model callback, so its email has been redacted.
   Rejected retrieval raises before either callback runs.
2. The model adapter returns a proposed tool name and its original JSON argument string.
   Keeping the string allows `ToolGuard` to reject duplicate keys before parsing.
3. Validate the exact tool name, argument text policies, and object schema. The schema is
   checked after redaction. Only the pair returned by `require_call()` reaches execution;
   rejected arguments never reach that callback. Do not reuse the original proposal or
   mutate the checked arguments before consuming them.
4. The host callback separately authorizes access to the fixed public reference. A valid
   schema can still request an unauthorized document. GuardTrellis does not dispatch tools,
   grant permissions, or enforce execution limits.

The runnable demo shows an accepted path, rejected retrieval that skips both callbacks,
and a rejected tool name that skips execution. Tests also cover transformed tool arguments,
invalid JSON, duplicate keys, schema failures, bounded-input errors, and host permission denial.
Distribution smoke checks run this script against both freshly installed package formats
before installing optional integrations.

This recipe checks retrieval and proposed tool calls. The host owns model/tool callback
exceptions, identity, permissions, deadlines, execution budgets, and any checks on tool output
before delivery. Callback exceptions propagate to the host; avoid logging their raw contents.
Synchronous scanning does not provide a hard execution deadline.

Argument text scanners inspect serialized JSON characters. They do not recursively check
decoded values, and escaped or encoded values can evade signatures. This example does not
establish comprehensive PII redaction or safe tool execution. See the
[API contracts](api.md#json-and-tool-calls), [limitations](limitations.md), and
[host resource controls](resource_limits.md).
