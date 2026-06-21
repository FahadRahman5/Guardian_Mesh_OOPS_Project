#include "../include/Packet.h"

using namespace std;

Packet::Packet(string senderID, string receiverID, string content,
               MessageType msgType, int urgency, int maxHops)
    : senderID(senderID), receiverID(receiverID), content(content),
      msgType(msgType), hopCount(0), maxHops(maxHops), urgency(urgency) {} // Write the address label and put a '0' in the stamp box

string Packet::getSenderID() const { return senderID; } // Read the "From:" transparent window
string Packet::getReceiverID() const { return receiverID; } // Read the "To:" transparent window
string Packet::getContent() const { return content; }
MessageType Packet::getMsgType() const { return msgType; }
int Packet::getHopCount() const { return hopCount; }
int Packet::getUrgency() const { return urgency; }

string Packet::getTypeAsText() const {
    if (msgType == MessageType::SOS) return "SOS";
    if (msgType == MessageType::SupplyRequest) return "SupplyRequest";
    return "StatusUpdate"; // Translate the color-coded priority into human text
}

bool Packet::forwardOnce() {
    hopCount++; // Add a stamp to the envelope
    return (hopCount <= maxHops); // The self-destruct check: Returns false if we hit 10 stamps (Time-To-Live protocol)
}

bool Packet::isExpired() const { return hopCount >= maxHops; } // Is the envelope trashed yet?

void Packet::writeToLog(ofstream& logFile) const {
    logFile << "[PACKET] Type: " << getTypeAsText()
            << " | From: " << senderID << " -> To: " << receiverID
            << " | Hops: " << hopCount << " | Urgency: " << urgency
            << " | Msg: " << content << "\n"; // Post office record: write the envelope details to the persistent text log
}