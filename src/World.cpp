#include "../include/World.h"
#include "../include/StudentNode.h"
#include "../include/StaticRelay.h"
#include "../include/EmergencyBase.h"
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <ctime>

using namespace std;

World::World() : baseStation(nullptr) {
    networkLog.open("logs/network_log.txt");
    messageLog.open("logs/message_log.txt");
    networkLog << "=== MESH NETWORK LOG ===\n";
    messageLog << "=== MESSAGE ROUTING LOG ===\n"; // The Game Master opens the blank diary books
}

World::~World() {
    for (int i = 0; i < (int)allDevices.size(); i++) {
        delete allDevices[i]; // Meticulous cleanup: free the heap RAM for every toy on the board to prevent memory leaks
    }
    allDevices.clear();
    if (networkLog.is_open()) networkLog.close();
    if (messageLog.is_open()) messageLog.close(); // Close the books
}

void World::loadDevicesFromFile(const string& filePath) {
    ifstream file(filePath);
    if (!file.is_open()) return;

    for (int i = 0; i < (int)allDevices.size(); i++) delete allDevices[i]; // Clean board first
    allDevices.clear();
    baseStation = nullptr;

    string type, id;
    float x, y;
    while (file >> type >> id >> x >> y) { // Read the guest list format: TYPE ID X Y
        if (type == "STUDENT") allDevices.push_back(new StudentNode(id, x, y));
        else if (type == "RELAY") allDevices.push_back(new StaticRelay(id, x, y));
        else if (type == "BASE") {
            EmergencyBase* base = new EmergencyBase(id, x, y);
            baseStation = base;
            allDevices.push_back(base); // Dynamically place new action figures on the heap
        }
    }
}

void World::addDevice(Node* device) {
    allDevices.push_back(device);
    if (device->getDeviceType() == "EmergencyBase") baseStation = (EmergencyBase*)device; // Track the command tent
    connectNeighbors(); // Re-measure all strings when a new toy is added
}

void World::showNetworkStatus() const {
    cout << "\n=== CURRENT NETWORK STATUS ===\n";
    for (int i = 0; i < (int)allDevices.size(); i++) { // READ operation: iterates through vector polymorphically
        cout << "[" << allDevices[i]->getDeviceType() << "] "
             << allDevices[i]->getDeviceID()
             << " | Battery: " << allDevices[i]->getBatteryLevel() << "%"
             << " | Neighbors: " << allDevices[i]->getNeighbors().size() << "\n";
    }
}

bool World::updateDevice(const string& deviceID, float newX, float newY, float newBattery) {
    Node* device = findDevice(deviceID);
    if (device != nullptr) {
        device->setPosX(newX);
        device->setPosY(newY);
        device->setBatteryLevel(newBattery); // UPDATE operation: move piece or swap battery
        connectNeighbors(); // Rebuild graph topology since the piece moved
        return true;
    }
    return false; 
}

bool World::removeDevice(const string& deviceID) {
    bool deletedSomething = false;
    for (int i = (int)allDevices.size() - 1; i >= 0; i--) { // Reverse loop for safe vector erasure
        if (allDevices[i]->getDeviceID() == deviceID) {
            if (allDevices[i] == baseStation) baseStation = nullptr; 
            delete allDevices[i]; // DELETE operation: Vaporize the toy and free the heap
            allDevices.erase(allDevices.begin() + i); // Remove dangling pointer from list
            deletedSomething = true;
        }
    }
    if (deletedSomething) {
        connectNeighbors(); // Network fractured, redraw the strings
        return true;
    }
    return false; 
}

void World::connectNeighbors() {
    for (int i = 0; i < (int)allDevices.size(); i++) allDevices[i]->clearNeighbors(); 
    
    networkLog << "\n[NETWORK REFRESH] Recalculating strict TWO-WAY connections...\n";

    for (int i = 0; i < (int)allDevices.size(); i++) {
        for (int j = 0; j < (int)allDevices.size(); j++) {
            if (i != j) { 
                // THE FIX: Strict Two-Way Handshake Protocol
                // Both devices MUST be able to reach each other's antennas to form a link.
                if (allDevices[i]->canReach(allDevices[j]) && allDevices[j]->canReach(allDevices[i])) { 
                    allDevices[i]->addNeighbor(allDevices[j]); 
                    networkLog << " -> Bidirectional link secured: " 
                               << allDevices[i]->getDeviceID() << " <-> " 
                               << allDevices[j]->getDeviceID() << "\n";
                }
            }
        }
    }
}

Node* World::findDevice(const string& deviceID) {
    for (int i = 0; i < (int)allDevices.size(); i++) {
        if (allDevices[i]->getDeviceID() == deviceID) return allDevices[i]; // Helper function to grab a specific toy
    }
    return nullptr;
}

void World::sendMessage(const string& fromID, const string& toID, const string& text, MessageType msgType, int urgency) {
    Node* sender = findDevice(fromID);
    if (sender == nullptr || !sender->isActive()) {
        cout << "\n[ERROR] Device is offline or doesn't exist.\n";
        return;
    }

    messageLog << "\n============================================\n";
    messageLog << "[INITIATING SEND] " << fromID << " attempting to reach " << toID << "\n";

    if (sender->getNeighbors().empty()) {
        cout << "\n[WARNING] Message vanished in the air, no one in range to receive.\n";
        messageLog << "[FAILED] " << fromID << " is in a dead zone. Message vanished.\n"; // Dead zone failure check
    }

    Packet msg(fromID, toID, text, msgType, urgency, 10); // Pack the magic envelope with 10 TTL
    sender->sendToNeighbors(msg, messageLog); // Hand it to the puppet and start the chain reaction
}

void World::runSimulation(int numberOfRounds) {
    if (allDevices.empty()) return;
    srand((unsigned)time(nullptr)); 
    
    for (int round = 0; round < numberOfRounds; round++) {
        connectNeighbors(); 
        int randomIndex = rand() % allDevices.size(); 
        Node* randomSender = allDevices[randomIndex]; // Roll dice to pick a random toy

        if (randomSender->isActive()) {
            string uniqueContent = "Automated SOS round " + to_string(round + 1);
            Packet emergencyMsg(randomSender->getDeviceID(), "B1", uniqueContent, MessageType::SOS, 5, 10); // Highest urgency SOS
            randomSender->sendToNeighbors(emergencyMsg, messageLog); // Force it to yell
        }
    }
}

void World::saveNetworkConfig(const string& filePath) const {
    ofstream file(filePath);
    for (int i = 0; i < (int)allDevices.size(); i++) {
        string rawType = allDevices[i]->getDeviceType();
        string saveType = (rawType == "EmergencyBase") ? "BASE" : (rawType == "StaticRelay") ? "RELAY" : "STUDENT";

        file << saveType << " " << allDevices[i]->getDeviceID() << " "
             << allDevices[i]->getPosX() << " " << allDevices[i]->getPosY() << "\n"; // Save the exact board state back to disk
    }
}

void World::saveAllLogs() const {
    if (baseStation != nullptr) baseStation->saveAllReceivedMessages("logs/final_received_messages.txt"); // Print the final binder
}