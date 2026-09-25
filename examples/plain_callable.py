"""Run: python examples/plain_callable.py. No credentials or network calls."""

import asyncio

from guardtrellis import Action, Guard, PIIScanner, SecretScanner


def demo_model(text: str) -> str:
    """Deterministic demo, not a real LLM."""
    return f"Local demo received: {text}"


def main() -> None:
    guard = Guard(
        input_scanners=[SecretScanner(), PIIScanner()],
        output_scanners=[SecretScanner(), PIIScanner()],
    )
    result = guard.run("Please contact demo@example.org", demo_model)
    print(result.require_text())
    print(result.diagnostics())

    # Artificial signature only: this is not a credential.
    blocked = guard.run("ghp_" + "A" * 36, demo_model)
    assert blocked.action == Action.BLOCK and blocked.text is None
    print("Synthetic token:", blocked.action.value)

    async def async_demo(text: str) -> str:
        return demo_model(text)

    print(asyncio.run(guard.arun("No sensitive data", async_demo)).require_text())


if __name__ == "__main__":
    main()
