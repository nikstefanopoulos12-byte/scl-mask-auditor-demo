from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from scl_mask_demo import (
    DemoError,
    analyze_file,
    analyze_text,
    build_corrected_bytes,
    calculate_mask,
    main,
    verify_byte_changes,
    write_corrected_copy,
)


def make_source(
    active: tuple[bool, bool, bool, bool] = (True, False, True, False),
    current_mask: str = "FFFF",
    device: str = "MACHINE_101",
) -> str:
    expressions = [
        f"DemoSignals.Condition{position:02d}" if enabled else "FALSE"
        for position, enabled in enumerate(active, start=1)
    ]
    return (
        '"ProtectionDemo"(\n'
        f'    Target := "{device}_DB".{device}.protection,\n'
        f"    SafetyCondition01 := {expressions[0]},\n"
        f"    SafetyCondition02 := {expressions[1]},\n"
        f"    SafetyCondition03 := {expressions[2]},\n"
        f"    SafetyCondition04 := {expressions[3]}\n"
        ");\n\n"
        f'"{device}_DB".{device}.protection.safetyMask := 16#{current_mask};\n'
    )


class MaskRuleTests(unittest.TestCase):
    def test_all_conditions_unused_produce_ffff(self) -> None:
        self.assertEqual(calculate_mask((False, False, False, False)), 0xFFFF)

    def test_condition_one_clears_bit_zero(self) -> None:
        self.assertEqual(calculate_mask((True, False, False, False)), 0xFFFE)

    def test_condition_two_clears_bit_one(self) -> None:
        self.assertEqual(calculate_mask((False, True, False, False)), 0xFFFD)

    def test_condition_three_clears_bit_two(self) -> None:
        self.assertEqual(calculate_mask((False, False, True, False)), 0xFFFB)

    def test_condition_four_clears_bit_three(self) -> None:
        self.assertEqual(calculate_mask((False, False, False, True)), 0xFFF7)

    def test_conditions_one_and_three_produce_fffa(self) -> None:
        self.assertEqual(calculate_mask((True, False, True, False)), 0xFFFA)

    def test_all_conditions_active_produce_fff0(self) -> None:
        self.assertEqual(calculate_mask((True, True, True, True)), 0xFFF0)


class AnalysisTests(unittest.TestCase):
    def test_correct_existing_mask_matches(self) -> None:
        result = analyze_text(make_source(current_mask="FFFA"))[0]
        self.assertTrue(result.matches)

    def test_wrong_existing_mask_is_reported(self) -> None:
        result = analyze_text(make_source(current_mask="FFFF"))[0]
        self.assertFalse(result.matches)
        self.assertEqual(result.expected_mask, 0xFFFA)

    def test_multiple_example_calls_are_analyzed(self) -> None:
        text = make_source(device="MACHINE_101") + make_source(
            active=(False, True, False, False),
            current_mask="FFFD",
            device="CONVEYOR_201",
        )
        results = analyze_text(text)
        self.assertEqual([result.device_name for result in results], ["MACHINE_101", "CONVEYOR_201"])

    def test_unclosed_call_is_rejected(self) -> None:
        text = make_source().replace(");\n\n", "\n\n")
        with self.assertRaisesRegex(DemoError, "Unclosed"):
            analyze_text(text)

    def test_missing_condition_is_rejected(self) -> None:
        text = make_source().replace("    SafetyCondition04 := FALSE\n", "")
        with self.assertRaisesRegex(DemoError, "SafetyCondition04"):
            analyze_text(text)

    def test_missing_mask_is_rejected(self) -> None:
        text = "\n".join(make_source().splitlines()[:-1])
        with self.assertRaisesRegex(DemoError, "mask not found"):
            analyze_text(text)

    def test_simple_comments_are_supported(self) -> None:
        text = make_source(active=(False, False, True, False)).replace(
            "SafetyCondition01 := FALSE,",
            "SafetyCondition01 := FALSE (* intentionally unused *),",
        )
        result = analyze_text("// synthetic test\n" + text)[0]
        self.assertEqual(result.active_conditions, (False, False, True, False))

    def test_commented_call_is_ignored(self) -> None:
        with self.assertRaisesRegex(DemoError, "No ProtectionDemo"):
            analyze_text("(*\n" + make_source() + "\n*)")

    def test_duplicate_mask_is_rejected(self) -> None:
        text = make_source() + '"MACHINE_101_DB".MACHINE_101.protection.safetyMask := 16#FFFA;\n'
        with self.assertRaisesRegex(DemoError, "Multiple safety masks"):
            analyze_text(text)

    def test_call_requires_trailing_semicolon(self) -> None:
        text = make_source().replace(");\n\n", ")\n\n")
        with self.assertRaisesRegex(DemoError, "must end with a semicolon"):
            analyze_text(text)


class CorrectionTests(unittest.TestCase):
    def test_correction_is_limited_to_the_four_digit_field(self) -> None:
        text = make_source()
        original = text.encode("utf-8")
        results = analyze_text(text)
        corrected, ranges = build_corrected_bytes(original, text, results)
        self.assertEqual(len(ranges), 1)
        self.assertEqual(ranges[0][1] - ranges[0][0], 4)
        self.assertTrue(verify_byte_changes(original, corrected, ranges))
        self.assertEqual(corrected.decode("utf-8"), make_source(current_mask="FFFA"))

    def test_output_overwrite_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "demo.scl"
            output = root / "corrected.scl"
            source.write_text(make_source(), encoding="utf-8")
            output.write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(DemoError, "already exists"):
                write_corrected_copy(source, output)
            self.assertEqual(output.read_text(encoding="utf-8"), "keep")

    def test_in_place_correction_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "demo.scl"
            source.write_text(make_source(), encoding="utf-8")
            with self.assertRaisesRegex(DemoError, "must be different"):
                write_corrected_copy(source, source)

    def test_checked_in_example_matches_expected_copy(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = root / "examples" / "demo.scl"
        expected = (root / "examples" / "demo_corrected.scl").read_bytes()
        source_bytes, text, results = analyze_file(source)
        corrected, _ = build_corrected_bytes(source_bytes, text, results)
        self.assertEqual(corrected, expected)

    def test_single_quoted_text_does_not_end_the_call(self) -> None:
        text = make_source().replace(
            "DemoSignals.Condition01",
            "'sample ) (* text *)'",
        )
        result = analyze_text(text)[0]
        self.assertTrue(result.active_conditions[0])

    def test_non_scl_input_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "demo.txt"
            source.write_text(make_source(), encoding="utf-8")
            with self.assertRaisesRegex(DemoError, "one .scl file only"):
                analyze_file(source)


class CliTests(unittest.TestCase):
    def test_cli_prints_mismatch_and_returns_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "demo.scl"
            source.write_text(make_source(), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = main([str(source)])
            self.assertEqual(exit_code, 1)
            self.assertIn("Result: MISMATCH", output.getvalue())


if __name__ == "__main__":
    unittest.main()
