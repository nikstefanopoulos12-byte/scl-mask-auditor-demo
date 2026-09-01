# SCL Mask Auditor — Public Demo

A small Python static-analysis tool for Siemens SCL source files. It detects active
safety conditions in a simplified example structure, calculates the expected 16-bit
mask, and reports mismatches.

It can also create a corrected copy while verifying that no bytes outside the
four-character hexadecimal mask were modified.

The SCL block and parameter names used in this repository are demonstration
conventions and are not Siemens-defined constructs.

## Why

Maintaining a bit mask beside condition logic is repetitive and easy to get wrong.
This tool shows how a focused parser can calculate the expected value and make the
result easy to review.

## Example

~~~scl
"ProtectionDemo"(
    Target := "MACHINE_101_DB".MACHINE_101.protection,
    SafetyCondition01 := DemoSignals.GuardClosed,
    SafetyCondition02 := FALSE,
    SafetyCondition03 := DemoSignals.EStopHealthy,
    SafetyCondition04 := FALSE
);

"MACHINE_101_DB".MACHINE_101.protection.safetyMask := 16#FFFF;
~~~

Only literal FALSE is unused. Every other simple expression is active. Conditions
01–04 control bits 0–3:

~~~text
FFFF
condition 01 active -> clear bit 0 -> FFFE
condition 03 active -> clear bit 2 -> FFFA
~~~

The current mask is FFFF, so the result is MISMATCH and the expected mask is FFFA.

## Features

- Audit one .scl file.
- Detect four example safety conditions.
- Calculate and compare a 16-bit mask.
- Print MATCH or MISMATCH results.
- Optionally create a corrected copy.
- Refuse in-place edits and output overwrites.
- Verify that correction changes only the four hexadecimal mask characters.
- Use only the Python standard library at runtime.

## Run

Python 3.11 or newer is required.

~~~powershell
python -m pip install -e .
scl-mask-demo examples\demo.scl
~~~

The module command works without the installed console-script name:

~~~powershell
python -m scl_mask_demo examples\demo.scl
~~~

Create a corrected copy at a new path:

~~~powershell
scl-mask-demo examples\demo.scl --fix --output demo_output.scl
~~~

Scan mode returns 0 for a match, 1 for a mismatch, and 2 for invalid input. A
successful corrected-copy operation returns 0.

## Windows quick start

On Windows, double-click `run_demo.bat` to run the complete example.
The launcher audits the original file, creates a corrected copy, and verifies the corrected result.

## Tests

~~~powershell
python -m unittest discover -s tests -p "test_demo.py" -v
~~~

The test file covers each bit position, combined masks, invalid input, comments,
multiple example calls, safe correction, overwrite protection, CLI output, and the
checked-in example.

## Demo vs. Extended Version

This repository contains the public demonstration edition. An extended version with
additional analysis and batch-processing capabilities is maintained separately.

| Capability | Demo | Extended |
| --- | --- | --- |
| Single SCL file | Yes | Yes |
| Basic safety-mask audit | Yes | Yes |
| Safe corrected copy | Yes | Yes |
| Batch processing | No | Yes |
| Safety + Process rules | No | Yes |
| Multiple rule profiles | No | Yes |
| Reporting | No | Yes |

## Scope

This demo focuses on one small SCL pattern:

- one UTF-8 .scl file;
- four safety conditions;
- one matching 16#XXXX mask;
- simple comma-separated condition expressions;
- no TIA Portal project parsing or compilation.

More complex parsing, additional rules, batch processing, and reporting are outside
this demo.

## Safety and license

This is an engineering example, not a certified verification or functional-safety
product. Results must be reviewed by a qualified controls engineer before use in a
real control system.

Siemens, SIMATIC, and TIA Portal are trademarks of their respective owners. This
independent project is not affiliated with or endorsed by Siemens.

## License

This project is licensed under the [MIT License](LICENSE).
