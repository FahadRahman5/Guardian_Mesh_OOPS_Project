#ifndef STATICRELAY_H
#define STATICRELAY_H
#include "Node.h"

class StaticRelay : public Node { // The Automated Echo Box
    public:
        StaticRelay(std::string deviceID, float posX, float posY);
        void receiveMessage(Packet msg, std::ofstream& log) override; // The boomerang/duplicate check logic
        void sendToNeighbors(Packet& msg, std::ofstream& log) override; // Blind auto-forwarding logic
        bool isWorking() const override;
        std::string getDeviceType() const override;
};
#endif