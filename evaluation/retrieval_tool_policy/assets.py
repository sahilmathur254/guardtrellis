"""Verify immutable study inputs before SDK observation; standard library only."""

import hashlib
import re
from pathlib import Path

if __package__:
    from . import contract
else:
    import contract

HERE = Path(__file__).resolve().parent
FREEZE_SHA256 = "d08e3c0fa5909e087364e98f71390ce4e85d81d51e4c5b7f49bf13c9b69d771d"
RECEIPT = "https://github.com/sahilmathur254/guardtrellis/issues/35#issuecomment-6634543759"
FROZEN_FILES = (
    "PROTOCOL_v1.md",
    "contract.py",
    "corpus_v1.jsonl",
    "expectations_v1.json",
    "harness_controls_v1.jsonl",
    "sources_v1.json",
)
MAX_ASSET_BYTES = 1024 * 1024


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_bounded(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_ASSET_BYTES + 1)
    if len(raw) > MAX_ASSET_BYTES:
        raise ValueError("Frozen asset exceeds size limit")
    return raw


def load_frozen():
    """Reject missing receipt, byte changes and altered pure expectations before scanning."""
    try:
        if not re.fullmatch(r"[0-9a-f]{64}", FREEZE_SHA256) or not re.fullmatch(
            r"https://github\.com/sahilmathur254/guardtrellis/issues/35#issuecomment-[0-9]+",
            RECEIPT,
        ):
            raise ValueError
        raw = read_bounded(HERE / "freeze_v1.json")
        if digest(raw) != FREEZE_SHA256:
            raise ValueError
        manifest = contract.strict_json(raw.decode("utf-8"))
        if (
            type(manifest) is not dict
            or manifest.get("schema_version") != 1
            or manifest.get("dataset_version") != contract.VERSION
            or manifest.get("phase") != "before_first_new_scenario_observation"
            or manifest.get("independent_case_review") is not False
            or manifest.get("maintainer_approval") != "scope only"
            or type(manifest.get("files")) is not dict
            or set(manifest["files"]) != set(FROZEN_FILES)
        ):
            raise ValueError
        raw_assets = {}
        for name in FROZEN_FILES:
            expected_hash = manifest["files"][name]
            if type(expected_hash) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
                raise ValueError
            raw_assets[name] = read_bounded(HERE / name)
            if digest(raw_assets[name]) != expected_hash:
                raise ValueError
        research, controls = [], []
        for name, target in (
            ("corpus_v1.jsonl", research),
            ("harness_controls_v1.jsonl", controls),
        ):
            for line in raw_assets[name].decode("utf-8").splitlines():
                target.append(contract.validate_case(contract.strict_json(line)))
        if [case["id"] for case in research] != [f"R{i:02}" for i in range(1, 13)]:
            raise ValueError
        if [case["id"] for case in controls] != [f"H{i:02}" for i in range(1, 12)]:
            raise ValueError
        if any(
            sum(case["pair_id"] == f"P{i}" for case in research) != 2 for i in range(1, 7)
        ) or any(case["pair_id"] is not None for case in controls):
            raise ValueError
        expected = contract.strict_json(raw_assets["expectations_v1.json"].decode("utf-8"))
        if (
            type(expected) is not dict
            or set(expected) != {"schema_version", "dataset_version", "cases"}
            or type(expected["schema_version"]) is not int
            or expected["schema_version"] != 1
            or expected["dataset_version"] != contract.VERSION
            or type(expected["cases"]) is not dict
            or set(expected["cases"]) != {case["id"] for case in research + controls}
        ):
            raise ValueError
        for case in research + controls:
            if expected["cases"][case["id"]] != contract.expected(case):
                raise ValueError
        return research, controls, expected["cases"], manifest
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        raise ValueError("Frozen study inputs or receipt are invalid") from None
