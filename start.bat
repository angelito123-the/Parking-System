@echo off
rem Start MariaDB server
start "" "d:\parking-system\mariadb\mariadb-10.11.8-winx64\bin\mysqld.exe" --datadir="d:\parking-system\mariadb-data" --port=3307 --console
rem Pause briefly to allow DB to initialize
timeout /t 5 /nobreak >nul

rem Start the Node.js development server
cd /d "d:\parking-system\Parking-management-main"
call npm run dev
