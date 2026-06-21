#include "../include/EmergencyBase.h"
#include <fstream>

using namespace std;

EmergencyBase::EmergencyBase(string deviceID, float posX, float posY)
    : Node(deviceID, posX, posY, 500.0f, 999.0f) {} // Build the Rescue Tent: massive 200 range megaphone, 999 generator power

string EmergencyBase::getDeviceType() const { return "EmergencyBase"; } // ID badge: "I am the Base"
bool EmergencyBase::isWorking() const { return true; } // The tent runs on a generator; it is ALWAYS awake

void EmergencyBase::receiveMessage(Packet msg, ofstream& log) {
    for (int i = 0; i < (int)receivedMessages.size(); i++) {
        if (receivedMessages[i].getSenderID() == msg.getSenderID() &&
            receivedMessages[i].getContent() == msg.getContent()) return; // Duplicate check: if note is already in the binder, throw it away
    }
    receivedMessages.push_back(msg); // New note! Lock it in the binder
    log << ">>> [BASE COMMAND " << deviceID << "] SECURED MESSAGE: '" 
        << msg.getContent() << "' from " << msg.getSenderID() << " <<<\n"; // Shout for the record
}

void EmergencyBase::sendToNeighbors(Packet& msg, ofstream& log) {
    // Sinks do not broadcast. // The tent is a vault, not a mailman. It stops infinite routing loops by never forwarding.
}

void EmergencyBase::saveAllReceivedMessages(const string& filePath) const {
    ofstream file(filePath);
    file << "=== EMERGENCY BASE FINAL ARCHIVE ===\n\n";
    for (int i = 0; i < (int)receivedMessages.size(); i++)
        receivedMessages[i].writeToLog(file); // Print the master binder to a hard drive for post-disaster analysis
}