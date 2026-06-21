#include "../include/StaticRelay.h"

using namespace std;

StaticRelay::StaticRelay(string deviceID, float posX, float posY)
    : Node(deviceID, posX, posY, 380.0f, 80.0f) {} // Mount the rooftop box: 150 range, but starts at 80% battery

string StaticRelay::getDeviceType() const { return "StaticRelay"; } // ID badge
bool StaticRelay::isWorking() const { return isOn && !power.isFinished(); } // Physics check: Switch on AND battery has juice?

void StaticRelay::receiveMessage(Packet msg, ofstream& log) {
    if (!isWorking()) return;

    if (msg.getSenderID() == deviceID) return; // Boomerang fix: Don't echo my own shouts

    for (int i = 0; i < (int)inbox.size(); i++) {
        if (inbox[i].getSenderID() == msg.getSenderID() && inbox[i].getContent() == msg.getContent()) return; // Duplicate check: already heard this?
    }

    dropLowestUrgencyMessage(log); // Make room on the clipboard if it's full
    inbox.push_back(msg); // Write it down
    
    log << "[Relay " << deviceID << "] caught message. Auto-forwarding...\n";
    sendToNeighbors(msg, log); // Pure middleman action: immediately shout it back out to everyone
}

void StaticRelay::sendToNeighbors(Packet& msg, ofstream& log) {
    if (!isWorking()) return;
    if (!msg.forwardOnce()) return; // TTL Check: If 10 stamps reached, throw the envelope away

    power.useBattery(); // Take a 5% sip of juice to pay for the radio blast

    for (int i = 0; i < (int)nearbyDevices.size(); i++) {
        if (nearbyDevices[i]->isWorking() && nearbyDevices[i]->getDeviceID() != msg.getSenderID()) // Loop prevention: don't shout it back to the guy who just handed it to me
            nearbyDevices[i]->receiveMessage(msg, log); // Pass it to everyone else in the address book
    }
}