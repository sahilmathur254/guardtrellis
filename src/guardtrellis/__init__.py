"""GuardTrellis: explicit, local boundaries around model and tool calls."""

from .guard import Guard, Scanner
from .json_check import JSONScanner
from .models import Action, Check, Edit, Finding, Rejected, Result, RunResult, Stage, Trace
from .scanners import InvisibleScanner, LiteralScanner, PIIScanner, SecretScanner
from .tools import ToolGuard, ToolResult

__version__ = "0.1.0a1"

__all__ = [
    "Action",
    "Check",
    "Edit",
    "Finding",
    "Guard",
    "InvisibleScanner",
    "JSONScanner",
    "LiteralScanner",
    "PIIScanner",
    "Rejected",
    "Result",
    "RunResult",
    "Scanner",
    "SecretScanner",
    "Stage",
    "ToolGuard",
    "ToolResult",
    "Trace",
    "__version__",
]
