#ifndef PACKET_H
#define PACKET_H

#include <string>
#include <fstream>

using namespace std;

enum class MessageType { SOS, SupplyRequest, StatusUpdate }; // Color-coded labels so routers know what to prioritize

class Packet { // The Magic Envelope
private: // Pure encapsulation. Metadata cannot be tampered with while in transit.
    string senderID;
    string receiverID;
    string content;
    MessageType msgType;
    int hopCount; // Tracks how many times it was forwarded (The stamp box)
    int maxHops;  // Prevents infinite network loops (The self-destruct threshold)
    int urgency;

public:
    Packet(string senderID, string receiverID, string content, 
           MessageType msgType, int urgency, int maxHops = 10);

    // Transparent windows: you can read the envelope, but you can't erase and rewrite the addresses
    string getSenderID() const;
    string getReceiverID() const;
    string getContent() const;
    MessageType getMsgType() const;
    int getHopCount() const;
    int getUrgency() const;
    string getTypeAsText() const;

    bool forwardOnce(); // Adding a stamp
    bool isExpired() const; // Checking if we hit 10 stamps
    void writeToLog(ofstream& logFile) const;
};

#endif