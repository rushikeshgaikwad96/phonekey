@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

cl.exe /std:c++20 /EHsc /W4 /I. /Id:\projects\fingerprintapp ^
  windows\common\EcdhKeyExchange.cpp ^
  windows\common\HkdfEngine.cpp ^
  windows\common\SasEngine.cpp ^
  windows\agent\DpapiStorage.cpp ^
  tests\test_pairing_main.cpp ^
  /Fe:test_pairing_suite.exe ^
  bcrypt.lib crypt32.lib

if %ERRORLEVEL% EQU 0 (
    echo Compilation successful! Running PhoneKey Milestone 3 Pairing Test Suite...
    test_pairing_suite.exe
) else (
    echo Compilation failed!
    exit /b 1
)
