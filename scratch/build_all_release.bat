@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

echo ====================================================
echo      BUILDING PHONEKEY RELEASE BINARIES (x64)     
echo ====================================================

rem 1. Build Desktop Agent Host Executable
cl.exe /std:c++20 /EHsc /O2 /I. /Id:\projects\fingerprintapp ^
  windows\common\Protocol.cpp ^
  windows\common\PublicKeyImporter.cpp ^
  windows\common\CryptoEngine.cpp ^
  windows\common\EcdhKeyExchange.cpp ^
  windows\common\HkdfEngine.cpp ^
  windows\common\SasEngine.cpp ^
  windows\common\FrameProtocol.cpp ^
  windows\common\TcpTransport.cpp ^
  windows\common\BluetoothTransport.cpp ^
  windows\common\NamedPipeIpc.cpp ^
  windows\agent\ChallengeGenerator.cpp ^
  windows\agent\ChallengeStore.cpp ^
  windows\agent\DeviceRegistry.cpp ^
  windows\agent\DpapiStorage.cpp ^
  windows\agent\AgentService.cpp ^
  windows\agent\PhoneKeyAgent.cpp ^
  /Fe:PhoneKeyAgent.exe ^
  bcrypt.lib ws2_32.lib crypt32.lib

if %ERRORLEVEL% NEQ 0 (
    echo Build failed: PhoneKeyAgent.exe
    exit /b 1
)

rem 2. Build Credential Provider COM DLL
cl.exe /std:c++20 /EHsc /O2 /LD /I. /Id:\projects\fingerprintapp ^
  windows\common\NamedPipeIpc.cpp ^
  windows\agent\DpapiStorage.cpp ^
  windows\credential-provider\PhoneKeyCredentialProvider.cpp ^
  windows\credential-provider\PhoneKeyCredential.cpp ^
  windows\credential-provider\dllmain.cpp ^
  /Fe:PhoneKeyCredentialProvider.dll ^
  crypt32.lib shlwapi.lib ole32.lib advapi32.lib

if %ERRORLEVEL% NEQ 0 (
    echo Build failed: PhoneKeyCredentialProvider.dll
    exit /b 1
)

rem 3. Build Unified Master Test Runner
cl.exe /std:c++20 /EHsc /O2 /I. /Id:\projects\fingerprintapp ^
  windows\common\Protocol.cpp ^
  windows\common\PublicKeyImporter.cpp ^
  windows\common\CryptoEngine.cpp ^
  windows\common\EcdhKeyExchange.cpp ^
  windows\common\HkdfEngine.cpp ^
  windows\common\SasEngine.cpp ^
  windows\common\FrameProtocol.cpp ^
  windows\common\TcpTransport.cpp ^
  windows\common\BluetoothTransport.cpp ^
  windows\common\NamedPipeIpc.cpp ^
  windows\agent\ChallengeGenerator.cpp ^
  windows\agent\ChallengeStore.cpp ^
  windows\agent\DeviceRegistry.cpp ^
  windows\agent\DpapiStorage.cpp ^
  windows\agent\AgentService.cpp ^
  tests\test_master_runner.cpp ^
  /Fe:test_master_runner.exe ^
  bcrypt.lib ws2_32.lib crypt32.lib

if %ERRORLEVEL% NEQ 0 (
    echo Build failed: test_master_runner.exe
    exit /b 1
)

echo ====================================================
echo   BUILD COMPLETED SUCCESSFULLY! RUNNING TEST RUNNER  
echo ====================================================

test_master_runner.exe
