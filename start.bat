@echo off
echo PivotMap - Attack Path Intelligence Engine
echo ==========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.12+ from https://python.org
    pause
    exit /b 1
)

REM Check if virtual environment exists, create if not
if not exist ".venv" (
    echo Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo Error: Failed to create virtual environment
        pause
        exit /b 1
    )
)

REM Activate virtual environment
echo Activating virtual environment...
call .venv\Scripts\activate.bat

REM Install dependencies if requirements.txt exists
if exist "requirements.txt" (
    echo Installing dependencies...
    pip install -q -r requirements.txt
    if errorlevel 1 (
        echo Error: Failed to install dependencies
        pause
        exit /b 1
    )
)

REM Install pivotmap package in development mode
echo Installing PivotMap...
pip install -q -e .

echo.
echo PivotMap is ready to use.
echo.
echo Available commands:
echo   pivotmap --help          Show CLI help
echo   pivotmap import --help    Show import command help
echo   python -m pivotmap.api   Start API server
echo.
echo Example usage:
echo   pivotmap import nmap_scan.xml
echo   pivotmap analyze --nmap nmap_scan.xml --nuclei nuclei_output.json
echo   pivotmap paths --top 5
echo   pivotmap report --format html
echo.

REM Keep window open
cmd /k
