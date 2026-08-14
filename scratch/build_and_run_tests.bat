@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

cl.exe /std:c++20 /EHsc /W4 /I. /Id:\projects\fingerprintapp ^
  windows\common\Protocol.cpp ^
  windows\common\PublicKeyImporter.cpp ^
  windows\common\CryptoEngine.cpp ^
  windows\agent\ChallengeGenerator.cpp ^
  windows\agent\ChallengeStore.cpp ^
  windows\agent\DeviceRegistry.cpp ^
  tests\test_main.cpp ^
  /Fe:test_suite.exe ^
  bcrypt.lib

if %ERRORLEVEL% EQU 0 (
    echo Compilation successful! Running PhoneKey Milestone 2 Test Suite...
    test_suite.exe
) else (
    echo Compilation failed!
    exit /b 1
)
