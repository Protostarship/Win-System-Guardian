@echo off
setlocal enabledelayedexpansion

echo Starting SystemGuardian Installation...

REM Check for administrative privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Administrative privileges required
    echo Please run this script as Administrator
    pause
    exit /b 1
)

REM Create directory structure
echo Creating directory structure...
set "BASE_DIR=C:\ProgramData\SystemGuardian"
set "DIRS=logs backups recovery_points quarantine"

mkdir "%BASE_DIR%" 2>nul
for %%d in (%DIRS%) do (
    mkdir "%BASE_DIR%\%%d" 2>nul
    if !errorlevel! neq 0 (
        echo Error creating directory: %BASE_DIR%\%%d
        exit /b 1
    )
)

REM Set directory permissions
echo Setting directory permissions...
icacls "%BASE_DIR%" /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" /T

REM Install Python dependencies
echo Installing Python dependencies...
python -m pip install --upgrade pip
pip install pywin32 wmi psutil win10toast

REM Verify Python installation
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher
    pause
    exit /b 1
)

REM Copy service files
echo Copying service files...
copy /Y "SystemGuardian.py" "%BASE_DIR%\" >nul
if %errorlevel% neq 0 (
    echo Error copying SystemGuardian.py
    exit /b 1
)

REM Create service
echo Installing Windows Service...
sc stop SystemGuardian >nul 2>&1
sc delete SystemGuardian >nul 2>&1
timeout /t 2 /nobreak >nul

python "%BASE_DIR%\SystemGuardian.py" install
if %errorlevel% neq 0 (
    echo Error installing service
    exit /b 1
)

REM Configure service
echo Configuring service...
sc config SystemGuardian start= auto
sc description SystemGuardian "Advanced system stability guardian with automated recovery capabilities"
sc failure SystemGuardian reset= 86400 actions= restart/60000/restart/60000/restart/60000

REM Initialize database
echo Initializing database...
python -c "from SystemGuardian import DatabaseManager; DatabaseManager('%BASE_DIR%/guardian.db').init_database()"

REM Set up logging
echo Configuring logging...
type nul > "%BASE_DIR%\logs\guardian.log"
icacls "%BASE_DIR%\logs\guardian.log" /grant "SYSTEM:F" /grant "Administrators:F"

REM Verify installation
echo Verifying installation...
sc query SystemGuardian >nul
if %errorlevel% neq 0 (
    echo Error: Service verification failed
    exit /b 1
)

echo.
echo Installation completed successfully!
echo.
echo Directory: %BASE_DIR%
echo Service Name: SystemGuardian
echo Status: Installed
echo.
echo To start the service:
echo sc start SystemGuardian
echo.
echo To check service status:
echo sc query SystemGuardian
echo.
echo To view logs:
echo type "%BASE_DIR%\logs\guardian.log"
echo.

choice /C YN /M "Do you want to start the service now?"
if %errorlevel% equ 1 (
    echo Starting service...
    sc start SystemGuardian
    if !errorlevel! equ 0 (
        echo Service started successfully
    ) else (
        echo Error starting service
    )
)

endlocal