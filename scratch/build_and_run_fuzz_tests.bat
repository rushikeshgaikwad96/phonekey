@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

cl.exe /std:c++20 /EHsc /O2 /I. /Id:\projects\fingerprintapp ^
  windows\common\FrameProtocol.cpp ^
  tests\test_fuzz_frame_parser.cpp ^
  /Fe:test_fuzz_frame_parser.exe

if %ERRORLEVEL% NEQ 0 (
    echo Build failed: test_fuzz_frame_parser.exe
    exit /b 1
)

test_fuzz_frame_parser.exe
