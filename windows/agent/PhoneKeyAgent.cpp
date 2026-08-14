#include "AgentService.h"
#include <iostream>
#include <array>
#include <thread>
#include <chrono>

using namespace PhoneKey;

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "     PHONEKEY WINDOWS DESKTOP AGENT HOST SERVICE    " << std::endl;
    std::cout << "====================================================" << std::endl;

    std::array<uint8_t, UUID_SIZE> pcId; pcId.fill(0x99);
    uint16_t listenPort = 8443;

    AgentService agent(listenPort, pcId);

    if (!agent.Start()) {
        std::cerr << "[PhoneKeyAgent] Failed to start Agent Service on port " << listenPort << std::endl;
        return 1;
    }

    std::cout << "[PhoneKeyAgent] Agent Service listening on TCP port " << listenPort << "..." << std::endl;
    std::cout << "[PhoneKeyAgent] Press ENTER to stop service." << std::endl;

    std::cin.get();

    agent.Stop();
    std::cout << "[PhoneKeyAgent] Service stopped gracefully." << std::endl;
    return 0;
}
