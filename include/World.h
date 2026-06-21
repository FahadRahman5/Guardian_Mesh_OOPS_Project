#ifndef WORLD_H
#define WORLD_H

#include <vector>
#include <string>
#include <fstream>
#include "Node.h"
#include "EmergencyBase.h"

using namespace std;

class World { // The Game Master
private:
    vector<Node*> allDevices; // The board itself: a dynamic array of pointers holding polymorphic objects
    EmergencyBase* baseStation; // Tracking the Rescue Tent for easy access
    ofstream networkLog;
    ofstream messageLog; // The Game Master's blank diary books

public:
    const std::vector<Node*>& getDevices() const { return allDevices; }

    World();
    ~World(); // Crucial memory cleanup step

    // The God Hand: CRUD Operations
    void loadDevicesFromFile(const string& filePath);
    void addDevice(Node* device);
    bool removeDevice(const string& deviceID);
    bool updateDevice(const string& deviceID, float newX, float newY, float newBattery);
    void showNetworkStatus() const;

    void connectNeighbors(); // Drawing the red strings across the board
    Node* findDevice(const string& deviceID); 
    void sendMessage(const string& fromID, const string& toID, const string& text, MessageType msgType, int urgency); // Poking a toy
    void runSimulation(int numberOfRounds); // Rolling the dice
    
    void saveNetworkConfig(const string& filePath) const;
    void saveAllLogs() const;
};

#endif