#include "../include/StudentNode.h"

using namespace std;

StudentNode::StudentNode(string deviceID, float posX, float posY)
    : Node(deviceID, posX, posY, 200.0f, 100.0f) {} // The student joins: 100% full battery, but weak 50 range antenna

string StudentNode::getDeviceType() const { return "StudentNode"; }
bool StudentNode::isWorking() const { return isOn && !power.isFinished(); }

void StudentNode::receiveMessage(Packet msg, ofstream& log) {
    if (!isWorking()) return; // Am I awake?
    
    if (msg.getSenderID() == deviceID) return; // Boomerang fix: Don't process my own message

    // Prevent duplicate processing
    for (int i = 0; i < (int)inbox.size(); i++) {
        if (inbox[i].getSenderID() == msg.getSenderID() && inbox[i].getContent() == msg.getContent()) return; // Did I read this exact envelope already?
    }

    dropLowestUrgencyMessage(log); 
    inbox.push_back(msg); // Safe to put in pocket          
    
    log << "[Student " << deviceID << "] received " << msg.getTypeAsText() 
        << " from " << msg.getSenderID() << " (Hops: " << msg.getHopCount() << ")\n";

    // If the student receives a message, but they are NOT the final destination, 
    // they must act as a mesh router and pass it along!
    if (msg.getReceiverID() != deviceID) { // The "Is this for me?" check
        log << "[Student " << deviceID << "] Not the final destination. Forwarding...\n";
        sendToNeighbors(msg, log); // Good Samaritan routing: Pass the envelope to the next person
    }
}

void StudentNode::sendToNeighbors(Packet& msg, ofstream& log) {
    if (!isWorking()) return;
    if (!msg.forwardOnce()) {
        log << "[EXPIRED] Message dropped at " << deviceID << " (Max hops reached).\n";
        return;  // The 10-stamp TTL rule enforcement
    }

    power.useBattery(); // Sacrifice 5% of my own battery to help pass the note
    if (power.isFinished()) {
        isOn = false;
        log << "[WARNING] " << deviceID << " battery died!\n"; // Fatal event: If I run out of juice, my node drops off the network
    }

    log << "[Student " << deviceID << "] broadcasting message to neighbors...\n";

    for (int i = 0; i < (int)nearbyDevices.size(); i++) {
        if (nearbyDevices[i]->isWorking())
            nearbyDevices[i]->receiveMessage(msg, log); // Polymorphic magic: Yell to the neighbor, regardless of what device they are
    }
}