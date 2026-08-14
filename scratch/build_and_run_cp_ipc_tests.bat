@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

cl.exe /std:c++20 /EHsc /W4 /I. /Id:\projects\fingerprintapp ^
  windows\common\NamedPipeIpc.cpp ^
  windows\agent\DpapiStorage.cpp ^
  tests\test_cp_ipc_main.cpp ^
  /Fe:test_cp_ipc_suite.exe ^
  crypt32.lib

if %ERRORLEVEL% EQU 0 (
    echo Compilation successful! Running PhoneKey Milestone 6 CP IPC Test Suite...
    test_cp_ipc_suite.exe
) else (
    echo Compilation failed!
    exit /b 1
)
