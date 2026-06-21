#ifndef EMERGENCYBASE_H
#define EMERGENCYBASE_H

#include "Node.h"
#include <vector>

class EmergencyBase : public Node { // The Rescue Tent inherits the basic rules of being a Node
private:
    // Permanent archive of every message received
    std::vector<Packet> receivedMessages; // The Big Binder sitting on the operator's desk

public:
    EmergencyBase(std::string deviceID, float posX, float posY);

    // Fulfilling the abstract rules set by the parent class
    void receiveMessage(Packet msg, std::ofstream& log) override; 
    void sendToNeighbors(Packet& msg, std::ofstream& log) override; // Sinks don't broadcast, but we still have to define the rule!
    bool isWorking() const override;
    std::string getDeviceType() const override;

    // Write every received message to a file
    // (the final record of what the base station collected)
    void saveAllReceivedMessages(const std::string& filePath) const; // Hitting "Print" on the master binder
};

#endif