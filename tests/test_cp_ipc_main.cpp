#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <cassert>
#include "../windows/common/NamedPipeIpc.h"
#include "../windows/agent/DpapiStorage.h"

using namespace PhoneKey;

#define TEST_ASSERT(cond, msg) \
    if (!(cond)) { \
        std::cerr << " [FAIL] " << msg << " (Line " << __LINE__ << ")" << std::endl; \
        return false; \
    } else { \
        std::cout << " [PASS] " << msg << std::endl; \
    }

bool TestNamedPipeIpcAndDpapiCredentials() {
    std::cout << "--- Running Local Named Pipe IPC & DPAPI Credential Handoff Test ---" << std::endl;

    NamedPipeServer server;
    bool serverStart = server.Start([](const IpcPacket& req) -> IpcPacket {
        IpcPacket resp;
        resp.type = IpcMessageType::RESP_UNLOCK;

        if (req.type == IpcMessageType::REQ_UNLOCK) {
            // Simulate DPAPI encrypted KERB_INTERACTIVE_LOGON payload
            std::vector<uint8_t> plainCreds = {'L', 'O', 'G', 'O', 'N', '_', 'S', 'E', 'C', 'R', 'E', 'T'};
            std::vector<uint8_t> encrypted;
            if (DpapiStorage::EncryptData(plainCreds, encrypted)) {
                resp.statusCode = 0x0000; // SUCCESS
                resp.payload = encrypted;
            } else {
                resp.statusCode = 0xFFFF; // CRYPTO_ERROR
            }
        } else {
            resp.statusCode = 0x0001; // INVALID_REQUEST
        }

        return resp;
    });

    TEST_ASSERT(serverStart, "NamedPipeServer started listening on \\\\.\\pipe\\PhoneKeyIPC");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Simulated Credential Provider COM DLL sending request over IPC
    IpcPacket req;
    req.type = IpcMessageType::REQ_UNLOCK;
    req.statusCode = 0;

    IpcPacket resp;
    bool clientOk = NamedPipeClient::SendIpcRequest(req, resp, 3000);

    TEST_ASSERT(clientOk, "Credential Provider client sent IPC request over Named Pipe");
    TEST_ASSERT(resp.type == IpcMessageType::RESP_UNLOCK, "Received RESP_UNLOCK IPC type");
    TEST_ASSERT(resp.statusCode == 0x0000, "Received SUCCESS status code (0x0000)");
    TEST_ASSERT(!resp.payload.empty(), "Received non-empty DPAPI encrypted payload");

    // Decrypt DPAPI payload
    std::vector<uint8_t> decrypted;
    bool decOk = DpapiStorage::DecryptData(resp.payload, decrypted);
    TEST_ASSERT(decOk, "Successfully decrypted DPAPI credential payload");
    std::string secretStr(decrypted.begin(), decrypted.end());
    TEST_ASSERT(secretStr == "LOGON_SECRET", "Decrypted logon credential matches expected secret!");

    server.Stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Fail-Closed Test when Server Pipe is Stopped
    IpcPacket offlineResp;
    bool offlineOk = NamedPipeClient::SendIpcRequest(req, offlineResp, 500);
    TEST_ASSERT(!offlineOk, "Client safely fails closed when Agent service is offline!");

    return true;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "  PHONEKEY MILESTONE 6 CREDENTIAL PROVIDER IPC TEST " << std::endl;
    std::cout << "====================================================" << std::endl;

    bool allPassed = true;
    allPassed &= TestNamedPipeIpcAndDpapiCredentials();

    std::cout << "====================================================" << std::endl;
    if (allPassed) {
        std::cout << "    ALL MILESTONE 6 CP IPC TESTS PASSED!          " << std::endl;
        std::cout << "====================================================" << std::endl;
        return 0;
    } else {
        std::cerr << "    SOME CP IPC TESTS FAILED!                     " << std::endl;
        std::cout << "====================================================" << std::endl;
        return 1;
    }
}
