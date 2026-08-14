@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

cl.exe /std:c++20 /EHsc /W4 /I. /Id:\projects\fingerprintapp ^
  windows\common\FrameProtocol.cpp ^
  windows\common\TcpTransport.cpp ^
  windows\common\BluetoothTransport.cpp ^
  tests\test_transport_main.cpp ^
  /Fe:test_transport_suite.exe ^
  ws2_32.lib

if %ERRORLEVEL% EQU 0 (
    echo Compilation successful! Running PhoneKey Milestone 4 Transport Test Suite...
    test_transport_suite.exe
) else (
    echo Compilation failed!
    exit /b 1
)
