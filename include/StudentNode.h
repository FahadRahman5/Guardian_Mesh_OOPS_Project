#ifndef STUDENTNODE_H
#define STUDENTNODE_H

#include "Node.h"

class StudentNode : public Node { // The Helpful Student in the Crowd
public:
    StudentNode(std::string deviceID, float posX, float posY);

    void receiveMessage(Packet msg, std::ofstream& log) override; // The "Is this for me?" mesh routing logic
    void sendToNeighbors(Packet& msg, std::ofstream& log) override; // The Good Samaritan broadcasting logic
    bool isWorking() const override;
    std::string getDeviceType() const override;

    // Update this device's position on the map
    // (neighbor list is cleared since range may have changed)
    void moveTo(float newX, float newY, std::ofstream& log); // Note: A specialized helper function for dynamic simulation events!
};

#endif