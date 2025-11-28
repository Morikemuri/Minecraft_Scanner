@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo Minecraft Scanner Compiler [with Security]
echo ============================================================
echo.

cd /d "C:\Users\dontl\Desktop\Example"

echo [*] Checking Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found!
    pause
    exit /b 1
)

echo [OK] Python found
echo.

if not exist "minecraft_scanner.py" (
    echo [ERROR] minecraft_scanner.py not found!
    pause
    exit /b 1
)

echo [OK] Source file found
echo.

REM ===== SECURITY INJECTION =====
echo [*] Injecting security protection...
python generate_security.py 730
if %errorlevel% neq 0 (
    echo [ERROR] Security injection failed!
    pause
    exit /b 1
)

echo [OK] Security protection injected
echo.

REM ===== COMPILATION =====
echo [*] Installing PyInstaller...
pip install --upgrade pyinstaller -q

echo.
echo [*] Compiling to EXE with Minecraft icon...
echo.

if exist "minecraft.ico" (
    echo Using custom minecraft.ico
    pyinstaller --onefile --console --icon=minecraft.ico --name "Minecraft_Scanner" minecraft_scanner.py
) else (
    echo Using default icon
    pyinstaller --onefile --console --name "Minecraft_Scanner" minecraft_scanner.py
)

if %errorlevel% equ 0 (
    echo.
    echo ============================================================
    echo [SUCCESS] Compilation completed!
    echo ============================================================
    echo.
    
    if exist "dist\Minecraft_Scanner.exe" (
        copy "dist\Minecraft_Scanner.exe" "C:\Users\dontl\Desktop\Example\Minecraft_Scanner.exe"
        echo.
        echo [OK] File created: Minecraft_Scanner.exe
        echo.
        
        echo [*] Cleaning up...
        rmdir /s /q build 2>nul
        del *.spec 2>nul
        echo [OK] Cleanup done
        echo.
    )
) else (
    echo.
    echo [ERROR] Compilation failed!
    echo.
)

pause

