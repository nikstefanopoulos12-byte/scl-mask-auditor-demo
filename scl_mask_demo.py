"""Audit safety masks in a simplified SCL example."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


CALL_PATTERN = re.compile(r'"ProtectionDemo"\s*\(', re.IGNORECASE)
MASK_PATTERN = re.compile(
    r"(?im)^[ \t]*(?P<lhs>[^;\r\n]+?)[ \t]*:=[ \t]*"
    r"16#(?P<value>[0-9A-Fa-f]{4})[ \t]*;"
)
CONDITION_NAMES = tuple(f"SafetyCondition{number:02d}" for number in range(1, 5))
PARAMETER_NAMES = ("Target", *CONDITION_NAMES)
MASK_SUFFIX = ".protection.safetymask"


class DemoError(ValueError):
    """Input does not follow the supported example structure."""


@dataclass(frozen=True, slots=True)
class AuditResult:
    device_name: str
    active_conditions: tuple[bool, bool, bool, bool]
    current_mask: int
    expected_mask: int
    mask_start: int
    mask_end: int

    @property
    def matches(self) -> bool:
        return self.current_mask == self.expected_mask


def _without_comments(text: str) -> str:
    """Blank comments without moving any remaining character offsets."""

    output = list(text)
    index = 0
    state = "code"
    while index < len(output):
        char = output[index]
        following = output[index + 1] if index + 1 < len(output) else ""

        if state == "code":
            if char == '"':
                state = "quote"
            elif char == "'":
                state = "string"
            elif char == "/" and following == "/":
                output[index] = output[index + 1] = " "
                state = "line"
                index += 1
            elif char == "(" and following == "*":
                output[index] = output[index + 1] = " "
                state = "block"
                index += 1
        elif state == "quote":
            if char == '"' and following == '"':
                index += 1
            elif char == '"':
                state = "code"
        elif state == "string":
            if char == "'" and following == "'":
                index += 1
            elif char == "'":
                state = "code"
        elif state == "line":
            if char in "\r\n":
                state = "code"
            else:
                output[index] = " "
        elif char == "*" and following == ")":
            output[index] = output[index + 1] = " "
            state = "code"
            index += 1
        elif char not in "\r\n":
            output[index] = " "
        index += 1

    if state == "block":
        raise DemoError("Unterminated block comment")
    if state == "quote":
        raise DemoError("Unterminated quoted identifier")
    if state == "string":
        raise DemoError("Unterminated string literal")
    return "".join(output)


def _closing_parenthesis(text: str, opening: int) -> int | None:
    depth = 1
    quote = ""
    index = opening + 1
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if quote:
            if char == quote and following == quote:
                index += 1
            elif char == quote:
                quote = ""
        elif char in {'"', "'"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _normalize(value: str) -> str:
    return re.sub(r"\s+", "", value).casefold()


def _parse_call(body: str, line_number: int) -> tuple[str, str, tuple[bool, bool, bool, bool]]:
    allowed_names = {name.casefold(): name for name in PARAMETER_NAMES}
    values: dict[str, str] = {}

    # This example accepts only simple comma-separated values.
    for segment in _without_comments(body).split(","):
        segment = segment.strip()
        if not segment:
            continue
        if ":=" not in segment:
            raise DemoError(f"Malformed argument at line {line_number}")
        raw_name, expression = segment.split(":=", 1)
        name = allowed_names.get(re.sub(r"\s+", "", raw_name).casefold())
        if name is None:
            raise DemoError(f"Unsupported parameter {raw_name.strip()!r} at line {line_number}")
        if name in values:
            raise DemoError(f"Duplicate parameter {name} at line {line_number}")
        if not expression.strip():
            raise DemoError(f"Empty expression for {name} at line {line_number}")
        values[name] = expression.strip()

    missing = [name for name in PARAMETER_NAMES if name not in values]
    if missing:
        raise DemoError(f"Missing parameter(s) at line {line_number}: {', '.join(missing)}")

    target = values["Target"]
    target_key = _normalize(target)
    if not target_key.endswith(".protection"):
        raise DemoError(f"Target must end with .protection at line {line_number}")
    parts = re.sub(r"\s+", "", target).split(".")
    device_name = parts[-2].strip('"') if len(parts) >= 2 else ""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", device_name):
        raise DemoError(f"Target device name is malformed at line {line_number}")

    flags = [_normalize(values[name]) != "false" for name in CONDITION_NAMES]
    active = (flags[0], flags[1], flags[2], flags[3])
    return target_key, device_name, active


def calculate_mask(active_conditions: tuple[bool, bool, bool, bool]) -> int:
    """Clear bit N-1 when condition N is active."""

    mask = 0xFFFF
    for position, active in enumerate(active_conditions, start=1):
        if active:
            mask &= ~(1 << (position - 1))
    return mask


def analyze_text(text: str) -> list[AuditResult]:
    uncommented = _without_comments(text)
    assignments: dict[str, list[tuple[int, int, int]]] = {}
    for match in MASK_PATTERN.finditer(uncommented):
        lhs = _normalize(uncommented[match.start("lhs") : match.end("lhs")])
        if lhs.endswith(MASK_SUFFIX):
            assignments.setdefault(lhs, []).append(
                (int(match.group("value"), 16), match.start("value"), match.end("value"))
            )

    results: list[AuditResult] = []
    seen_targets: set[str] = set()
    for call in CALL_PATTERN.finditer(uncommented):
        line = text.count("\n", 0, call.start()) + 1
        opening = call.end() - 1
        closing = _closing_parenthesis(uncommented, opening)
        if closing is None:
            raise DemoError(f"Unclosed ProtectionDemo call at line {line}")
        if re.match(r"[ \t\r\n]*;", uncommented[closing + 1 :]) is None:
            raise DemoError(f"ProtectionDemo call at line {line} must end with a semicolon")
        target, device, active = _parse_call(text[opening + 1 : closing], line)
        if target in seen_targets:
            raise DemoError(f"Duplicate Target at line {line}")
        seen_targets.add(target)

        masks = assignments.get(target + ".safetymask", [])
        if not masks:
            raise DemoError(f"Safety mask not found for {device}")
        if len(masks) > 1:
            raise DemoError(f"Multiple safety masks found for {device}")
        current, start, end = masks[0]
        results.append(
            AuditResult(device, active, current, calculate_mask(active), start, end)
        )

    if not results:
        raise DemoError("No ProtectionDemo call was found")
    return results


def analyze_file(path: Path) -> tuple[bytes, str, list[AuditResult]]:
    path = path.resolve()
    if not path.is_file():
        raise DemoError(f"Input file does not exist: {path}")
    if path.suffix.casefold() != ".scl":
        raise DemoError("The public demo accepts one .scl file only")
    source = path.read_bytes()
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as error:
        raise DemoError("The public demo accepts UTF-8 SCL text only") from error
    return source, text, analyze_text(text)


def verify_byte_changes(
    original: bytes,
    corrected: bytes,
    approved_ranges: list[tuple[int, int]],
) -> bool:
    if len(original) != len(corrected):
        return False
    if any(start < 0 or end - start != 4 or end > len(original) for start, end in approved_ranges):
        return False
    return all(
        before == after
        or any(start <= index < end for start, end in approved_ranges)
        for index, (before, after) in enumerate(zip(original, corrected))
    )


def build_corrected_bytes(
    source: bytes,
    text: str,
    results: list[AuditResult],
) -> tuple[bytes, list[tuple[int, int]]]:
    corrected = bytearray(source)
    ranges: list[tuple[int, int]] = []
    for result in results:
        if result.matches:
            continue
        start = len(text[: result.mask_start].encode("utf-8"))
        end = len(text[: result.mask_end].encode("utf-8"))
        if end - start != 4:
            raise DemoError("Mask correction range is not exactly four bytes")
        corrected[start:end] = f"{result.expected_mask:04X}".encode("ascii")
        ranges.append((start, end))

    output = bytes(corrected)
    if not verify_byte_changes(source, output, ranges):
        raise DemoError("Correction verification failed")
    return output, ranges


def write_corrected_copy(input_path: Path, output_path: Path) -> tuple[list[AuditResult], int]:
    input_path = input_path.resolve()
    output_path = output_path.resolve()
    if input_path == output_path:
        raise DemoError("Input and output paths must be different")
    if output_path.suffix.casefold() != ".scl":
        raise DemoError("Output must use the .scl extension")
    if output_path.exists():
        raise DemoError(f"Output already exists: {output_path}")
    if not output_path.parent.is_dir():
        raise DemoError(f"Output folder does not exist: {output_path.parent}")

    source, text, results = analyze_file(input_path)
    corrected, ranges = build_corrected_bytes(source, text, results)
    try:
        with output_path.open("xb") as output_file:
            output_file.write(corrected)
        written = output_path.read_bytes()
        if written != corrected or not verify_byte_changes(source, written, ranges):
            output_path.unlink(missing_ok=True)
            raise DemoError("Written output failed byte-level verification")
    except FileExistsError as error:
        raise DemoError(f"Output already exists: {output_path}") from error
    return results, len(ranges)


def format_result(result: AuditResult) -> str:
    conditions = [
        f"{number:02d} {'ACTIVE' if active else 'UNUSED'}"
        for number, active in enumerate(result.active_conditions, start=1)
    ]
    return "\n".join(
        [
            result.device_name,
            "",
            "Safety conditions:",
            *conditions,
            "",
            f"Current mask : {result.current_mask:04X}",
            f"Expected mask: {result.expected_mask:04X}",
            "",
            f"Result: {'MATCH' if result.matches else 'MISMATCH'}",
        ]
    )


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scl-mask-demo",
        description="Audit one UTF-8 SCL file using the ProtectionDemo example.",
    )
    parser.add_argument("input", type=Path, help="one .scl source file")
    parser.add_argument("--fix", action="store_true", help="create a corrected copy")
    parser.add_argument("--output", type=Path, help="new .scl output path")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser()
    arguments = parser.parse_args(argv)
    if arguments.fix != (arguments.output is not None):
        parser.error("--fix and --output must be used together")

    try:
        if arguments.fix:
            results, changed = write_corrected_copy(arguments.input, arguments.output)
        else:
            _, _, results = analyze_file(arguments.input)
            changed = 0
    except (DemoError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    print("\n\n".join(format_result(result) for result in results))
    if arguments.fix:
        print(f"\n\nCorrected copy: {arguments.output}")
        print(f"Masks corrected: {changed}")
        return 0
    return 0 if all(result.matches for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
