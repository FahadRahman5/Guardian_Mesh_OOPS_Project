#ifndef BATTERY_H
#define BATTERY_H

#include <fstream>
#include <string>

using namespace std;

class Battery {
private:
    float currentCharge; // Encapsulation: The juice is locked inside so a math error can't set it to -50%
    float costPerSend;   // The size of the sip taken during each transmission

public:
    Battery(float startCharge, float costPerSend = 5.0f); // The Juice Box setup
    
    void useBattery();
    bool isFinished() const;
    float getCharge() const;
    void setCharge(float newCharge); // The refill spell (Needed for CRUD 'Update' operation)
    
    void writeToLog(ofstream& logFile, const string& deviceID) const; // Writing the exact percentage to the master diary
};

#endif