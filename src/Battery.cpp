#include "../include/Battery.h"
#include <iomanip>

using namespace std;

Battery::Battery(float startCharge, float costPerSend)
    : currentCharge(startCharge), costPerSend(costPerSend) {} // Setup the juice box: how full it is, and how big of a sip to take

void Battery::useBattery() {
    if (currentCharge > 0) currentCharge -= costPerSend; // Take a sip (simulates radio transmission power cost)
    if (currentCharge < 0) currentCharge = 0; // Safety rule: No negative juice allowed
}

bool Battery::isFinished() const { return currentCharge <= 0.0f; } // Shake the box: is it completely empty?
float Battery::getCharge() const { return currentCharge; } // Look inside to get the exact percentage

void Battery::setCharge(float newCharge) {
    currentCharge = newCharge; // Magic spell to refill the juice box
    if (currentCharge < 0) currentCharge = 0; // Another safety check to prevent negative battery states
}

void Battery::writeToLog(ofstream& logFile, const string& deviceID) const {
    logFile << "[BATTERY] Device " << deviceID
            << " | Remaining: " << fixed << setprecision(1)
            << currentCharge << "%\n"; // Write the exact remaining power to the permanent audit trail
}