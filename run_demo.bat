@echo off
cd /d "%~dp0"

python --version >nul 2>&1
if errorlevel 1 (
    echo Python was not found.
    echo Install Python 3.11 or newer and try again.
    pause
    exit /b 1
)

if exist "demo_output.scl" (
    echo demo_output.scl already exists.
    echo Delete or rename it before running the demo again.
    pause
    exit /b 1
)

echo ========================================
echo STEP 1 - AUDIT ORIGINAL FILE
echo ========================================
python -m scl_mask_demo examples\demo.scl

echo.
echo ========================================
echo STEP 2 - CREATE CORRECTED COPY
echo ========================================
python -m scl_mask_demo examples\demo.scl --fix --output demo_output.scl
if errorlevel 1 (
    echo.
    echo The corrected copy could not be created.
    pause
    exit /b 1
)

echo.
echo ========================================
echo STEP 3 - VERIFY CORRECTED FILE
echo ========================================
python -m scl_mask_demo demo_output.scl

echo.
pause
