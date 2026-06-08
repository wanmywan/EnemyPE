@echo off
echo [*] Building EnemyPE (Release) ...
echo.

echo [1/2] Building x64 (MSVC) ...
cargo build --release --target x86_64-pc-windows-msvc

echo.
echo [2/2] Building x86 (MSVC) ...
cargo build --release --target i686-pc-windows-msvc

echo.
echo [+] Done! Output:
echo     x64: target\x86_64-pc-windows-msvc\release\EnemyPE.exe
echo     x86: target\i686-pc-windows-msvc\release\EnemyPE.exe
echo.
echo Note: Use GNU targets for cross-compilation from macOS/Linux:
echo     cargo build --release --target x86_64-pc-windows-gnu
echo     cargo build --release --target i686-pc-windows-gnu
pause
