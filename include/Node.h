#ifndef NODE_H
#define NODE_H // These Header Guards prevent the infinite looping compiler crash!

#include <string>
#include <vector>
#include <fstream>
#include "Packet.h"
#include "Battery.h"

using namespace std;

class Node { // The Radio Operator's abstract rulebook
protected: 
    string deviceID;
    float posX, posY;
    float signalRange;
    bool isOn;
    Battery power; // Composition: Node has-a Battery (Every operator is handed a juice box)
    vector<Packet> inbox; // The operator's pocket for holding notes
    vector<Node*> nearbyDevices; // The address book of who is in shouting distance
    int inboxLimit;

public:
    int getInboxSize() const;
    int getInboxLimit() const;
    Node(string deviceID, float posX, float posY, float signalRange, float startingBattery);
    virtual ~Node(); // Virtual destructor ensures the Game Master cleans up the specific child pieces properly

    // This makes Node abstract—you cannot write `new Node()`, only `new StudentNode()`.
    virtual string getDeviceType() const = 0;
    virtual void receiveMessage(Packet msg, ofstream& log) = 0;
    virtual void sendToNeighbors(Packet& msg, ofstream& log) = 0;
    virtual bool isWorking() const = 0;

    float distanceTo(const Node* other) const; // The Pythagoras calculation
    bool canReach(const Node* other) const;    // Flashlight beam check
    
    void addNeighbor(Node* device);
    void clearNeighbors();
    void dropLowestUrgencyMessage(ofstream& log); // Quality of Service sorting to prevent a full pocket from dropping an SOS

    string getDeviceID() const;
    float getPosX() const;
    float getPosY() const;
    float getSignalRange() const;
    float getBatteryLevel() const;
    bool isActive() const;
    const vector<Node*>& getNeighbors() const;

    void setPosX(float x);
    void setPosY(float y);
    void setBatteryLevel(float b);

    void writeStateToLog(ofstream& log) const;
};

#endif