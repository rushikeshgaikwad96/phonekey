@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

cl.exe /std:c++20 /EHsc /W4 /I. /Id:\projects\fingerprintapp ^
  windows\common\Protocol.cpp ^
  windows\common\PublicKeyImporter.cpp ^
  windows\common\CryptoEngine.cpp ^
  windows\common\FrameProtocol.cpp ^
  windows\common\TcpTransport.cpp ^
  windows\agent\ChallengeGenerator.cpp ^
  windows\agent\ChallengeStore.cpp ^
  windows\agent\DeviceRegistry.cpp ^
  windows\agent\AgentService.cpp ^
  tests\test_e2e_main.cpp ^
  /Fe:test_e2e_suite.exe ^
  bcrypt.lib ws2_32.lib

if %ERRORLEVEL% EQU 0 (
    echo Compilation successful! Running PhoneKey Milestone 5 E2E Integration Test Suite...
    test_e2e_suite.exe
) else (
    echo Compilation failed!
    exit /b 1
)
