"""Validate the pre-observation freeze without importing or observing the SDK."""

import hashlib
import re
from collections import Counter
from pathlib import Path

if __package__:
    from . import contract
else:
    import contract

HERE = Path(__file__).resolve().parent
FREEZE_SHA256 = "261e01a4482dcdde5bd87880c8c80e7238b99321cc0fe7a1a121fd2f7c667e19"
RECEIPT = "https://github.com/sahilmathur254/guardtrellis/issues/45#issuecomment-6444217374"
CASE_FIELDS = {
    "id",
    "pair_id",
    "dataset_version",
    "family",
    "language",
    "label",
    "source",
    "usage",
    "license",
    "review",
    "label_basis",
    "text",
    "targets",
    "privacy_markers",
    "contracts",
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_bounded(path):
    with path.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("Asset limit exceeded")
    return raw


def spans_valid(spans, text):
    return (
        type(spans) is list
        and len(spans) <= 2
        and all(
            type(span) is list
            and len(span) == 2
            and all(type(index) is int for index in span)
            and 0 <= span[0] < span[1] <= len(text)
            for span in spans
        )
        and all(a[1] <= b[0] for a, b in zip(spans, spans[1:], strict=False))
    )


def validate_cases(raw):
    try:
        cases = [contract.strict_json(line) for line in raw.decode("utf-8").splitlines()]
        ids = set()
        for case in cases:
            if type(case) is not dict or case.keys() != CASE_FIELDS:
                raise ValueError
            if (
                case["id"] in ids
                or not re.fullmatch(r"[a-z0-9-]{1,80}", case["id"])
                or not re.fullmatch(r"[a-z0-9-]{1,80}", case["pair_id"])
                or case["dataset_version"] != contract.VERSION
                or case["family"] not in contract.FAMILIES
                or case["language"] != "en"
                or case["label"] not in ("sensitive", "benign")
                or case["usage"] != "development"
                or case["license"] != "Apache-2.0"
                or case["review"] != "author_self_review_only"
                or not contract.valid_text(case["text"])
                or not all(
                    type(case[field]) is str and 1 <= len(case[field]) <= 400
                    for field in ("source", "label_basis")
                )
                or not spans_valid(case["targets"], case["text"])
                or bool(case["targets"]) != (case["label"] == "sensitive")
                or type(case["privacy_markers"]) is not list
                or not 1 <= len(case["privacy_markers"]) <= 3
                or not all(
                    contract.valid_text(marker) and len(marker) >= 8
                    for marker in case["privacy_markers"]
                )
                or type(case["contracts"]) is not dict
                or case["contracts"].keys() != set(contract.PROFILES)
            ):
                raise ValueError
            ids.add(case["id"])
            for config in case["contracts"].values():
                if (
                    type(config) is not dict
                    or config.keys() != {"scope", "spans", "action", "codes"}
                    or config["scope"]
                    not in ("supported", "unsupported", "contextual_shape", "disabled_control")
                    or config["action"] not in (None, "allow", "redact", "block")
                ):
                    raise ValueError
                if config["scope"] == "unsupported":
                    if any(config[key] is not None for key in ("spans", "action", "codes")):
                        raise ValueError
                elif (
                    not spans_valid(config["spans"], case["text"])
                    or type(config["codes"]) is not list
                    or len(config["codes"]) != len(config["spans"])
                    or not set(config["codes"]) <= contract.PRIMARY_CODES[case["family"]]
                ):
                    raise ValueError
            for representation in contract.REPRESENTATIONS:
                if not contract.valid_text(contract.represented(case, representation, [])[0]):
                    raise ValueError
        if len(cases) != 48 or Counter((c["family"], c["label"]) for c in cases) != {
            (family, label): 8 for family in contract.FAMILIES for label in ("sensitive", "benign")
        }:
            raise ValueError
        pairs = Counter(c["pair_id"] for c in cases)
        if len(pairs) != 24 or any(count != 2 for count in pairs.values()):
            raise ValueError
        if any(
            {c["label"] for c in cases if c["pair_id"] == pair} != {"sensitive", "benign"}
            for pair in pairs
        ):
            raise ValueError
        return cases
    except (ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        raise ValueError("Invalid frozen scenarios") from None


def load_frozen(directory=HERE):
    raw = read_bounded(directory / "freeze_v1.json")
    if digest(raw) != FREEZE_SHA256:
        raise ValueError("Freeze receipt mismatch")
    freeze = contract.strict_json(raw)
    blobs = {}
    for name, expected in freeze["files"].items():
        raw = read_bounded(directory / name)
        if digest(raw) != expected:
            raise ValueError("Frozen asset changed")
        blobs[name] = raw
    cases = validate_cases(blobs["corpus_v1.jsonl"])
    expected = [
        contract.expectation(case, profile, representation)
        for case in cases
        for profile in contract.PROFILES
        for representation in contract.REPRESENTATIONS
    ]
    data = contract.strict_json(blobs["expectations_v1.json"])
    if data != {"version": contract.VERSION, "rows": expected}:
        raise ValueError("Expectation projection mismatch")
    return (
        cases,
        {(row["id"], row["profile"], row["representation"]): row for row in expected},
        freeze,
    )
