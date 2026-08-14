@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

cl.exe /std:c++20 /EHsc /W4 /I. /Id:\projects\fingerprintapp ^
  windows\common\Protocol.cpp ^
  windows\common\PublicKeyImporter.cpp ^
  windows\common\CryptoEngine.cpp ^
  windows\common\Ctap2Bridge.cpp ^
  windows\agent\DpapiStorage.cpp ^
  windows\agent\MultiDeviceManager.cpp ^
  tests\test_phase2_main.cpp ^
  /Fe:test_phase2_suite.exe ^
  bcrypt.lib crypt32.lib

if %ERRORLEVEL% EQU 0 (
    echo Compilation successful! Running PhoneKey Phase 2 Enhancement Test Suite...
    test_phase2_suite.exe
) else (
    echo Compilation failed!
    exit /b 1
)
