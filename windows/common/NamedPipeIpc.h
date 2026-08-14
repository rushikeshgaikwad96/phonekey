#ifndef PHONEKEY_NAMED_PIPE_IPC_H
#define PHONEKEY_NAMED_PIPE_IPC_H

#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>
#include <functional>
#include <thread>
#include <atomic>

namespace PhoneKey {

constexpr const wchar_t* PHONEKEY_IPC_PIPE_NAME = L"\\\\.\\pipe\\PhoneKeyIPC";
constexpr DWORD IPC_MAX_BUFFER_SIZE = 4096;

enum class IpcMessageType : uint16_t {
    REQ_STATUS  = 0x0001,
    RESP_STATUS = 0x0002,
    REQ_UNLOCK  = 0x0003,
    RESP_UNLOCK = 0x0004
};

struct IpcPacket {
    IpcMessageType type;
    uint16_t statusCode;
    std::vector<uint8_t> payload;
};

class NamedPipeServer {
public:
    using RequestHandler = std::function<IpcPacket(const IpcPacket&)>;

    NamedPipeServer();
    ~NamedPipeServer();

    bool Start(RequestHandler handler);
    void Stop();

private:
    HANDLE m_hPipe;
    RequestHandler m_handler;
    std::atomic<bool> m_isRunning;
    std::thread m_workerThread;

    void ServerWorker();
};

class NamedPipeClient {
public:
    // Sends IPC request packet to PhoneKey Desktop Agent Named Pipe and returns response
    static bool SendIpcRequest(const IpcPacket& request, IpcPacket& outResponse, DWORD timeoutMs = 5000);
};

} // namespace PhoneKey

#endif // PHONEKEY_NAMED_PIPE_IPC_H
