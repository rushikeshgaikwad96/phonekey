#include "NamedPipeIpc.h"
#include <iostream>
#include <cstring>

namespace PhoneKey {

NamedPipeServer::NamedPipeServer()
    : m_hPipe(INVALID_HANDLE_VALUE), m_isRunning(false) {}

NamedPipeServer::~NamedPipeServer() {
    Stop();
}

bool NamedPipeServer::Start(RequestHandler handler) {
    Stop();
    m_handler = handler;
    m_isRunning = true;
    m_workerThread = std::thread(&NamedPipeServer::ServerWorker, this);
    return true;
}

void NamedPipeServer::Stop() {
    m_isRunning = false;
    if (m_hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
    }
    if (m_workerThread.joinable()) {
        m_workerThread.join();
    }
}

void NamedPipeServer::ServerWorker() {
    while (m_isRunning) {
        m_hPipe = CreateNamedPipeW(
            PHONEKEY_IPC_PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            IPC_MAX_BUFFER_SIZE,
            IPC_MAX_BUFFER_SIZE,
            0,
            NULL
        );

        if (m_hPipe == INVALID_HANDLE_VALUE) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        BOOL connected = ConnectNamedPipe(m_hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (connected && m_isRunning) {
            std::vector<uint8_t> rxBuf(IPC_MAX_BUFFER_SIZE);
            DWORD bytesRead = 0;

            if (ReadFile(m_hPipe, rxBuf.data(), static_cast<DWORD>(rxBuf.size()), &bytesRead, NULL) && bytesRead >= 4) {
                IpcPacket req;
                req.type = static_cast<IpcMessageType>((static_cast<uint16_t>(rxBuf[0]) << 8) | rxBuf[1]);
                req.statusCode = (static_cast<uint16_t>(rxBuf[2]) << 8) | rxBuf[3];
                if (bytesRead > 4) {
                    req.payload.assign(rxBuf.begin() + 4, rxBuf.begin() + bytesRead);
                }

                IpcPacket resp;
                if (m_handler) {
                    resp = m_handler(req);
                } else {
                    resp.type = req.type;
                    resp.statusCode = 0xFFFF;
                }

                std::vector<uint8_t> txBuf;
                txBuf.push_back(static_cast<uint8_t>((static_cast<uint16_t>(resp.type) >> 8) & 0xFF));
                txBuf.push_back(static_cast<uint8_t>(static_cast<uint16_t>(resp.type) & 0xFF));
                txBuf.push_back(static_cast<uint8_t>((resp.statusCode >> 8) & 0xFF));
                txBuf.push_back(static_cast<uint8_t>(resp.statusCode & 0xFF));
                txBuf.insert(txBuf.end(), resp.payload.begin(), resp.payload.end());

                DWORD bytesWritten = 0;
                WriteFile(m_hPipe, txBuf.data(), static_cast<DWORD>(txBuf.size()), &bytesWritten, NULL);
                FlushFileBuffers(m_hPipe);
            }
        }

        DisconnectNamedPipe(m_hPipe);
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
    }
}

bool NamedPipeClient::SendIpcRequest(const IpcPacket& request, IpcPacket& outResponse, DWORD timeoutMs) {
    if (!WaitNamedPipeW(PHONEKEY_IPC_PIPE_NAME, timeoutMs)) {
        return false;
    }

    HANDLE hPipe = CreateFileW(
        PHONEKEY_IPC_PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD dwMode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL);

    std::vector<uint8_t> txBuf;
    txBuf.push_back(static_cast<uint8_t>((static_cast<uint16_t>(request.type) >> 8) & 0xFF));
    txBuf.push_back(static_cast<uint8_t>(static_cast<uint16_t>(request.type) & 0xFF));
    txBuf.push_back(static_cast<uint8_t>((request.statusCode >> 8) & 0xFF));
    txBuf.push_back(static_cast<uint8_t>(request.statusCode & 0xFF));
    txBuf.insert(txBuf.end(), request.payload.begin(), request.payload.end());

    DWORD bytesWritten = 0;
    if (!WriteFile(hPipe, txBuf.data(), static_cast<DWORD>(txBuf.size()), &bytesWritten, NULL)) {
        CloseHandle(hPipe);
        return false;
    }

    std::vector<uint8_t> rxBuf(IPC_MAX_BUFFER_SIZE);
    DWORD bytesRead = 0;
    if (!ReadFile(hPipe, rxBuf.data(), static_cast<DWORD>(rxBuf.size()), &bytesRead, NULL) || bytesRead < 4) {
        CloseHandle(hPipe);
        return false;
    }

    outResponse.type = static_cast<IpcMessageType>((static_cast<uint16_t>(rxBuf[0]) << 8) | rxBuf[1]);
    outResponse.statusCode = (static_cast<uint16_t>(rxBuf[2]) << 8) | rxBuf[3];
    if (bytesRead > 4) {
        outResponse.payload.assign(rxBuf.begin() + 4, rxBuf.begin() + bytesRead);
    }

    CloseHandle(hPipe);
    return true;
}

} // namespace PhoneKey
