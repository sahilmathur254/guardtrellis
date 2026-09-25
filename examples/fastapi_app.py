"""Run locally: python examples/fastapi_app.py (in-process TestClient).

Optional server: uvicorn examples.fastapi_app:app --host 127.0.0.1
Install the fastapi extra first. No real LLM or provider credentials are used.
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from guardtrellis import Action, Guard, PIIScanner, SecretScanner

app = FastAPI(title="GuardTrellis local demo")
guard = Guard(
    input_scanners=[SecretScanner(), PIIScanner()],
    output_scanners=[SecretScanner(), PIIScanner()],
)


class Prompt(BaseModel):
    text: str = Field(max_length=100_000, repr=False)


@app.exception_handler(RequestValidationError)
async def invalid_request(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Framework validation details may include user input. Keep this response metadata-only.
    return JSONResponse(status_code=422, content={"detail": "Invalid request"})


def demo_model(text: str) -> str:
    return f"Local demo received: {text}"


@app.post("/chat")
async def chat(prompt: Prompt) -> dict[str, str]:
    result = await guard.arun(prompt.text, demo_model)
    if not result.accepted:
        raise HTTPException(
            status_code=503 if result.action == Action.ERROR else 422,
            detail=result.diagnostics(),
        )
    return {"action": result.action.value, "text": result.require_text()}


def main() -> None:
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        response = client.post("/chat", json={"text": "Contact demo@example.org"})
        response.raise_for_status()
        print(response.json())


if __name__ == "__main__":
    main()
