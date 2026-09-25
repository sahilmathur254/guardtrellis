"""Run: python examples/langgraph_app.py after installing the langgraph extra.

No checkpointer, real provider, or hosted service is used. The demo disables
LangSmith tracing for invocation, regardless of the surrounding environment.
"""

from typing import TypedDict

from langgraph.graph import END, START, StateGraph
from langsmith import tracing_context

from guardtrellis import Guard, PIIScanner, SecretScanner


class State(TypedDict):
    prompt: str
    answer: str


input_guard = Guard(input_scanners=[SecretScanner(), PIIScanner()])
output_guard = Guard(output_scanners=[SecretScanner(), PIIScanner()])


def respond(state: State) -> dict[str, str]:
    # Validate inside the node before any generated text becomes graph state.
    result = output_guard.run(state["prompt"], lambda text: f"Local demo received: {text}")
    return {"answer": result.require_text()}


def guarded_invoke(text: str) -> State:
    # This check is outside the graph: sensitive input never enters initial graph state.
    checked = input_guard.scan(text)
    sanitized = checked.require_text()
    with tracing_context(enabled=False):
        builder = StateGraph(State)
        builder.add_node("respond", respond)
        builder.add_edge(START, "respond")
        builder.add_edge("respond", END)
        return builder.compile().invoke({"prompt": sanitized, "answer": ""})


def main() -> None:
    state = guarded_invoke("Contact demo@example.org")
    print(state["answer"])


if __name__ == "__main__":
    main()
