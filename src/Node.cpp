#include "../include/Node.h"
#include <cmath>

using namespace std;

Node::Node(string deviceID, float posX, float posY, float signalRange, float startingBattery)
    : deviceID(deviceID), posX(posX), posY(posY), signalRange(signalRange),
      isOn(true), power(startingBattery), inboxLimit(10) {} // The operator's profile card, complete with a 10-note pocket limit

Node::~Node() {}

int Node::getInboxSize() const  { return (int)inbox.size(); }
int Node::getInboxLimit() const { return inboxLimit; }

float Node::distanceTo(const Node* other) const {
    float dx = other->posX - posX;
    float dy = other->posY - posY;
    return sqrt(dx * dx + dy * dy); // Pure physics: calculates straight-line distance between two grid coordinates
}

bool Node::canReach(const Node* other) const {
    return distanceTo(other) <= signalRange; // Can the other guy see my flashlight? Validates connection based on hardware limits
}

void Node::addNeighbor(Node* device) { nearbyDevices.push_back(device); } // Write the guy's name in my address book
void Node::clearNeighbors() { nearbyDevices.clear(); } // Erase the whole book when I move

// Congestion Control: Drops the least important message if full
void Node::dropLowestUrgencyMessage(ofstream& log) {
    if ((int)inbox.size() >= inboxLimit) { // Pocket is full!
        int lowestUrgency = inbox[0].getUrgency();
        int lowestIndex = 0;

        for (int i = 1; i < (int)inbox.size(); i++) {
            if (inbox[i].getUrgency() < lowestUrgency) {
                lowestUrgency = inbox[i].getUrgency();
                lowestIndex = i; // Search through to find the least important note (QoS sorting)
            }
        }
        inbox.erase(inbox.begin() + lowestIndex); // Throw away the low priority note to make room for SOS
    }
}

string Node::getDeviceID() const { return deviceID; } // Show ID badge
float Node::getPosX() const { return posX; }
float Node::getPosY() const { return posY; }
float Node::getSignalRange() const { return signalRange; }
float Node::getBatteryLevel() const { return power.getCharge(); }
bool Node::isActive() const { return isOn; }
const vector<Node*>& Node::getNeighbors() const { return nearbyDevices; }

void Node::setPosX(float x) { posX = x; } // Move to a new X spot
void Node::setPosY(float y) { posY = y; } // Move to a new Y spot
void Node::setBatteryLevel(float b) { power.setCharge(b); } // Swap the battery

void Node::writeStateToLog(ofstream& log) const {
    log << "[DEVICE] ID: " << deviceID << " | Type: " << getDeviceType()
        << " | Pos: (" << posX << "," << posY << ") | Batt: " << power.getCharge() << "%\n"; // Write current status in the diary
}