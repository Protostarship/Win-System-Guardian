@echo off
mkdir C:\ProgramData\ComponentMonitor
mkdir C:\ProgramData\ComponentMonitor\config
mkdir C:\ProgramData\ComponentMonitor\logs
mkdir C:\ProgramData\ComponentMonitor\quarantine

copy event_patterns.json C:\ProgramData\ComponentMonitor\config\
copy dependencies.json C:\ProgramData\ComponentMonitor\config\
copy driver_map.json C:\ProgramData\ComponentMonitor\config\

powershell -Command "Set-ExecutionPolicy RemoteSigned -Force"
pip install pywin32 psutil win10toast

sc create SystemGuardian binPath= "%CD%\SystemGuardian.py" start= auto
sc description SystemGuardian "Advanced system component monitoring and protection service"

echo Installation complete. Start service with: sc start SystemGuardian