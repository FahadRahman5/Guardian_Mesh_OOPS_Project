#include <SFML/Graphics.hpp>
#include <SFML/Window.hpp>
#include <SFML/Audio.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <optional>
#include <cmath>
#include <cctype>
#include <cstdlib>
#include <cstdint>
#include <ctime>
#include <queue>
#include <map>
#include <functional>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include "include/World.h"
#include "include/StudentNode.h"
#include "include/StaticRelay.h"
#include "include/EmergencyBase.h"

// Set to 0 if GLSL shaders cause a compile/runtime issue on your machine -
// everything still runs with the (already lush) procedural fallbacks.
#ifndef ENABLE_SHADERS
#define ENABLE_SHADERS 1
#endif

// EXPERIMENTAL real bloom (scene -> render-texture -> bright-pass -> blur ->
// additive composite). This is the one piece that can't be compile-tested in
// the dev sandbox. If the build fails, set this to 0 and EVERYTHING ELSE
// (gravity grid, popups, pills, glows) still works untouched. You can also
// toggle it live at runtime with the B key.
#ifndef ENABLE_BLOOM
#define ENABLE_BLOOM 1
#endif

using namespace std;

// Fixed window size - also doubles as the "neutral" 1:1 coordinate
// space that every screen-space UI element (HUD/log/popups) is laid
// out in, independent of however far the world camera is zoomed.
constexpr unsigned WINDOW_W = 1000;
constexpr unsigned WINDOW_H = 800;

//
// Where we are in the "compose a message" flow.
//
enum class FlowState { None, AwaitingTarget, ChoosingType, TypingMessage };

// Message clearance for the security layer (defined fully further down).
enum class Clearance { Civilian, Government, Sos };

struct VisualPacket {
    std::vector<Node*>        routeNodes;
    std::vector<sf::Vector2f> waypoints;
    std::vector<int>          waypointLogicalIndex;
    int   currentTargetIndex = 1;
    sf::Vector2f currentPos;
    bool  active     = true;
    bool  willExpire = false;
    bool  isAck      = false;   // a response retracing the path back to the sender
    int   attempts   = 0;       // retransmission attempts so far
    Clearance clearance = Clearance::Civilian;   // who may decrypt on arrival
    sf::Color color  = sf::Color(255, 200, 50);
    MessageType msgType = MessageType::StatusUpdate;
    std::string content;
    std::vector<sf::Vector2f> trail;
};

struct ShatterShard {
    sf::Vector2f pos;
    sf::Vector2f vel;
    float life = 1.0f;
};

struct DroppedEvent {
    sf::Vector2f origin;
    sf::Vector2f baseTarget;
    std::vector<ShatterShard> shards;
    float age      = 0.0f;
    float lifespan = 0.9f;
    bool  active   = true;
};

struct DisasterEvent {
    sf::Vector2f center;
    float age      = 0.0f;
    float lifespan = 0.6f;
    int   hitCount = 0;
    bool  active   = true;
};

struct LogEntry {
    std::string text;
    sf::Color   color;
    float       spawnTime = 0.0f;
    float       currentY  = 0.0f;
    bool        yInit     = false;
};

//
// Slowly-drifting background specks - inspired by the
// Breakbot / Because Recollection particle atmosphere.
//
struct AmbientParticle {
    sf::Vector2f pos;
    sf::Vector2f vel;
    float        baseAlpha; // base opacity (12-34)
    float        radius;    // 0.7 - 2.2
    float        phase;     // individual twinkle phase offset
};

// Short-lived additive spark used for delivery / spawn / strike bursts.
struct Spark {
    sf::Vector2f pos;
    sf::Vector2f vel;
    float        life;     // 1 -> 0
    float        maxLife;
    float        radius;
    sf::Color    color;
};

// Screen-space twinkling star (sky layer behind everything, no parallax).
struct Star {
    sf::Vector2f pos;
    float        baseB;   // base brightness
    float        size;
    float        phase;
    float        speed;
    bool         bright;  // gets a soft cross-flare
};

//
sf::ConvexShape createStar(float radius) {
    sf::ConvexShape star(10);
    for (int i = 0; i < 10; ++i) {
        float angle = i * (3.14159f / 5.0f) - (3.14159f / 2.0f);
        float r = (i % 2 == 0) ? radius : radius / 2.0f;
        star.setPoint(i, sf::Vector2f(std::cos(angle) * r, std::sin(angle) * r));
    }
    return star;
}

sf::Color colorForType(MessageType t) {
    switch (t) {
        case MessageType::SOS:           return sf::Color(235, 80,  70);
        case MessageType::SupplyRequest: return sf::Color(90,  200, 210);
        case MessageType::StatusUpdate:  return sf::Color(130, 210, 130);
    }
    return sf::Color::White;
}

std::string msgTypeName(MessageType t) {
    switch (t) {
        case MessageType::SOS:           return "SOS";
        case MessageType::SupplyRequest: return "SupplyRequest";
        case MessageType::StatusUpdate:  return "StatusUpdate";
    }
    return "Unknown";
}

//
// SECURITY LAYER  (illustrative - demonstrates the architecture, NOT a
// production cipher). Models the two threats a real emergency mesh faces:
// • Confidentiality: every payload is encrypted end-to-end with a key
// derived from BOTH endpoints' master keys. Relays carry the ciphertext
// but never hold that pairwise key, so they cannot read it. Clearance
// (Civilian / Government / public-SOS) gates who may decrypt on arrival.
// • Availability: a per-node token bucket rate-limits forwarding, low
// battery refuses non-SOS traffic, and SOS pre-empts both - so a flood
// degrades gracefully instead of crippling the mesh.
// The Emergency Base is the certificate authority: every node shares a
// master key with it, and pairwise keys are derived from those.
//
std::string clearanceName(Clearance c) {
    return c == Clearance::Government ? "GOV" : c == Clearance::Sos ? "SOS" : "CIV";
}
// Mapping the existing three message types onto clearances for the demo:
// SOS           -> public cry, anyone may read
// StatusUpdate  -> sensitive government directive (civilians can't read)
// SupplyRequest -> ordinary civilian traffic
Clearance clearanceForType(MessageType t) {
    if (t == MessageType::SOS)          return Clearance::Sos;
    if (t == MessageType::StatusUpdate) return Clearance::Government;
    return Clearance::Civilian;
}

struct SecurityManager {
    std::map<std::string, std::uint32_t> master;     // node -> master key shared w/ base (CA)
    std::map<std::string, Clearance>     clr;        // node -> clearance
    std::map<std::string, float>         tok;        // node -> flood tokens
    static constexpr float TOK_MAX = 8.0f, TOK_REFILL = 3.5f;

    // Idempotent registration. Base = Government (the CA); everyone else Civilian.
    void enroll(const std::string& id, Clearance c) {
        if (master.count(id)) return;
        std::uint32_t h = 2166136261u;               // FNV-ish hash of the ID = its master key
        for (char ch : id) { h ^= (std::uint8_t)ch; h *= 16777619u; }
        master[id] = h ? h : 1u;
        clr[id]    = c;
        tok[id]    = TOK_MAX;
    }
    Clearance clearanceOf(const std::string& id) const {
        auto it = clr.find(id); return it == clr.end() ? Clearance::Civilian : it->second;
    }
    // Pairwise key derived from both master keys - a relay holding neither
    // endpoint's master key cannot reconstruct it.
    std::uint32_t pairKey(const std::string& a, const std::string& b) const {
        std::uint32_t ka = master.count(a) ? master.at(a) : 1u;
        std::uint32_t kb = master.count(b) ? master.at(b) : 1u;
        std::uint32_t k = (ka * 2654435761u) ^ (kb + 0x9e3779b9u + (ka << 6) + (ka >> 2));
        return k ? k : 1u;
    }
    // Keystream XOR (LCG-seeded). Same call encrypts and decrypts.
    std::string cipher(const std::string& in, std::uint32_t key) const {
        std::string out = in; std::uint32_t s = key;
        for (size_t i = 0; i < out.size(); ++i) {
            s = s * 1103515245u + 12345u;
            out[i] = (char)((std::uint8_t)out[i] ^ (std::uint8_t)((s >> 16) & 0xFFu));
        }
        return out;
    }
    // Authorization: who may decrypt a payload of a given clearance.
    bool canRead(Clearance node, Clearance msg) const {
        if (msg == Clearance::Civilian || msg == Clearance::Sos) return true;
        return node == Clearance::Government;             // Government traffic: gov only
    }
    void refill(float dt) { for (auto& kv : tok) kv.second = std::min(TOK_MAX, kv.second + TOK_REFILL * dt); }
    bool consume(const std::string& id) {                 // returns false if rate-limited
        float& t = tok[id];
        if (t >= 1.0f) { t -= 1.0f; return true; }
        return false;
    }
};
SecurityManager sec;   // file-scope so spawnPacket and the loop share it

// First 4 bytes of a ciphertext as hex - used to show "unreadable" intercepts.
std::string cipherSnippet(const std::string& c) {
    static const char* H = "0123456789abcdef";
    std::string s; size_t n = std::min<size_t>(4, c.size());
    for (size_t i = 0; i < n; ++i) { std::uint8_t b = (std::uint8_t)c[i]; s += H[b >> 4]; s += H[b & 0xF]; s += ' '; }
    return s.empty() ? "--" : s;
}

//
// BFS pathfinding. Base is a black hole. Dead nodes skipped.
//
std::vector<Node*> calculateRoute(Node* start, Node* end) {
    std::queue<Node*> frontier;
    std::map<Node*, Node*> came_from;

    frontier.push(start);
    came_from[start] = nullptr;

    while (!frontier.empty()) {
        Node* current = frontier.front();
        frontier.pop();

        if (current == end) break;
        if (current->getDeviceType() == "EmergencyBase") continue;

        for (Node* next : current->getNeighbors()) {
            if (!next->isWorking()) continue;
            if (came_from.find(next) == came_from.end()) {
                frontier.push(next);
                came_from[next] = current;
            }
        }
    }

    std::vector<Node*> path;
    if (came_from.find(end) == came_from.end()) return path;

    Node* current = end;
    while (current != nullptr) {
        path.push_back(current);
        current = came_from[current];
    }
    std::reverse(path.begin(), path.end());
    return path;
}

std::pair<Node*, Node*> findDirectStudentPair(const std::vector<Node*>& students) {
    for (size_t i = 0; i < students.size(); i++)
        for (size_t j = 0; j < students.size(); j++) {
            if (i == j) continue;
            auto route = calculateRoute(students[i], students[j]);
            if (route.size() == 2) return { students[i], students[j] };
        }
    return { nullptr, nullptr };
}

std::pair<Node*, Node*> findMultiHopStudentPair(const std::vector<Node*>& students) {
    for (size_t i = 0; i < students.size(); i++)
        for (size_t j = 0; j < students.size(); j++) {
            if (i == j) continue;
            auto route = calculateRoute(students[i], students[j]);
            if (route.size() > 2) return { students[i], students[j] };
        }
    return { nullptr, nullptr };
}

void drainNodeBattery(Node* node) {
    if (!node) return;
    if (node->getDeviceType() == "EmergencyBase") return;
    float newLevel = node->getBatteryLevel() - 5.0f;
    if (newLevel < 0.0f) newLevel = 0.0f;
    node->setBatteryLevel(newLevel);
}

void spawnDroppedEvent(sf::Vector2f origin, std::vector<DroppedEvent>& events,
                        Node* base, int& dropCounter) {
    dropCounter++;

    DroppedEvent ev;
    ev.origin     = origin;
    ev.baseTarget = base ? sf::Vector2f(base->getPosX(), base->getPosY()) : origin;
    ev.lifespan   = 0.9f;

    int shardCount = 7;
    for (int i = 0; i < shardCount; i++) {
        float angle = (float)i / shardCount * 6.2831853f + (float)(rand() % 100) / 100.0f;
        float speed = 60.0f + (float)(rand() % 60);
        ShatterShard s;
        s.pos  = origin;
        s.vel  = sf::Vector2f(std::cos(angle) * speed, std::sin(angle) * speed);
        s.life = 1.0f;
        ev.shards.push_back(s);
    }
    events.push_back(ev);
}

struct VisualPath {
    std::vector<sf::Vector2f> points;
    std::vector<int>          logicalIndex;
};

VisualPath buildVisualPath(const std::vector<Node*>& route, Node* base) {
    VisualPath vp;
    if (route.empty()) return vp;

    sf::Vector2f basePos = base ? sf::Vector2f(base->getPosX(), base->getPosY()) : sf::Vector2f(0, 0);
    const float avoidRadius = 35.0f;

    vp.points.push_back(sf::Vector2f(route[0]->getPosX(), route[0]->getPosY()));
    vp.logicalIndex.push_back(0);

    for (size_t i = 0; i + 1 < route.size(); i++) {
        sf::Vector2f A(route[i]->getPosX(), route[i]->getPosY());
        sf::Vector2f B(route[i + 1]->getPosX(), route[i + 1]->getPosY());

        if (base) {
            sf::Vector2f AB = B - A;
            float lenSq = AB.x * AB.x + AB.y * AB.y;

            if (lenSq > 1.0f) {
                float t = ((basePos.x - A.x) * AB.x + (basePos.y - A.y) * AB.y) / lenSq;
                t = std::max(0.05f, std::min(0.95f, t));
                sf::Vector2f closest = A + AB * t;

                sf::Vector2f toBase = basePos - closest;
                float dist = std::sqrt(toBase.x * toBase.x + toBase.y * toBase.y);

                if (dist < avoidRadius) {
                    sf::Vector2f pushDir;
                    if (dist > 0.5f) {
                        pushDir = toBase / dist;
                    } else {
                        float segLen = std::sqrt(lenSq);
                        sf::Vector2f perp(-AB.y / segLen, AB.x / segLen);
                        pushDir = perp;
                    }
                    sf::Vector2f away = closest - pushDir * (avoidRadius - dist + 22.0f);
                    vp.points.push_back(away);
                    vp.logicalIndex.push_back(-1);
                }
            }
        }

        vp.points.push_back(B);
        vp.logicalIndex.push_back((int)(i + 1));
    }
    return vp;
}

// Hit radius matched to each shape's actual rendered size (+ a few px
// of forgiving touch padding) instead of one oversized blanket value -
// that's what let an adjacent relay "steal" clicks meant for a student.
float nodeHitRadius(const Node* d) {
    std::string t = d->getDeviceType();
    if (t == "EmergencyBase") return 25.0f;  // star, visual radius 21
    if (t == "StaticRelay")   return 15.0f;  // square, visual half-extent 11
    return 16.0f;                             // StudentNode circle, visual radius 12
}

Node* findNodeAt(World& world, sf::Vector2f pos, bool requireWorking) {
    Node* best = nullptr;
    float bestDist = 0.0f;
    for (Node* d : world.getDevices()) {
        if (requireWorking && !d->isWorking()) continue;
        float dx = d->getPosX() - pos.x, dy = d->getPosY() - pos.y;
        float dist = std::sqrt(dx * dx + dy * dy);
        if (dist < nodeHitRadius(d) && (!best || dist < bestDist)) {
            best = d;
            bestDist = dist;
        }
    }
    return best;
}

std::string joinNeighborIDs(Node* n) {
    const auto& neighbors = n->getNeighbors();
    if (neighbors.empty()) return "(none)";
    std::ostringstream oss;
    int shown = 0;
    for (Node* nb : neighbors) {
        if (shown > 0) oss << ", ";
        oss << nb->getDeviceID();
        shown++;
        if (shown >= 6 && (int)neighbors.size() > 6) {
            oss << ", +" << (neighbors.size() - 6) << " more";
            break;
        }
    }
    return oss.str();
}

struct TypeButtonInfo {
    sf::FloatRect bounds;
    MessageType   type;
    std::string   label;
    std::string   description;
    sf::Color     color;
};

std::string msgTypeDescription(MessageType t) {
    switch (t) {
        case MessageType::SOS:           return "Highest priority - routes immediately";
        case MessageType::SupplyRequest: return "Logistics & resource request";
        case MessageType::StatusUpdate:  return "Routine network status";
    }
    return "";
}

// Single source of truth for the message-type panel's geometry, shared
// by both the click hit-test and the renderer, so they can never drift
// out of sync (which previously let the last button overflow the panel).
namespace TypePanel {
    constexpr float X = 320.0f, Y = 280.0f, W = 360.0f;
    constexpr float HeaderH   = 72.0f;   // room for title + subtitle
    constexpr float BtnW      = W - 40.0f;
    constexpr float BtnH      = 56.0f;
    constexpr float Gap       = 14.0f;
    constexpr float BottomPad = 22.0f;
    constexpr int   BtnCount  = 3;
    constexpr float H = HeaderH + BtnCount * BtnH + (BtnCount - 1) * Gap + BottomPad;
}

std::vector<TypeButtonInfo> getTypeButtons() {
    using namespace TypePanel;
    float startY = Y + HeaderH;

    return {
        { sf::FloatRect({X + 20, startY},                 {BtnW, BtnH}),
          MessageType::SOS, "[1]  SOS - Emergency",
          msgTypeDescription(MessageType::SOS), colorForType(MessageType::SOS) },
        { sf::FloatRect({X + 20, startY + (BtnH + Gap)},   {BtnW, BtnH}),
          MessageType::SupplyRequest, "[2]  Supply Request",
          msgTypeDescription(MessageType::SupplyRequest), colorForType(MessageType::SupplyRequest) },
        { sf::FloatRect({X + 20, startY + 2*(BtnH + Gap)}, {BtnW, BtnH}),
          MessageType::StatusUpdate, "[3]  Status Update",
          msgTypeDescription(MessageType::StatusUpdate), colorForType(MessageType::StatusUpdate) },
    };
}

bool spawnPacket(Node* sender, Node* receiver, MessageType msgType, const std::string& content,
                  std::vector<VisualPacket>& packets,
                  std::vector<DroppedEvent>& droppedEvents,
                  Node* baseStationPtr,
                  int& dropCounter,
                  const std::string& label,
                  const std::function<void(const std::string&, sf::Color)>& log)
{
    sf::Color logInfo(190, 195, 205), logError(235, 90, 80);

    if (!sender || !receiver || !sender->isWorking()) {
        log("[" + label + " FAILED] Sender unavailable.", logError);
        return false;
    }

    std::vector<Node*> route = calculateRoute(sender, receiver);

    if (route.size() < 2) {
        log("[" + label + " FAILED] \"" + content + "\" - DEAD ZONE, no path to target!", logError);
        spawnDroppedEvent(sf::Vector2f(sender->getPosX(), sender->getPosY()),
                          droppedEvents, baseStationPtr, dropCounter);
        return false;
    }

    const int MAX_HOPS = 10;
    bool willExpire = false;
    if ((int)route.size() - 1 > MAX_HOPS) {
        route.resize(MAX_HOPS + 1);
        willExpire = true;
    }

    VisualPath vp = buildVisualPath(route, baseStationPtr);

    VisualPacket pkt;
    pkt.routeNodes           = route;
    pkt.waypoints            = vp.points;
    pkt.waypointLogicalIndex = vp.logicalIndex;
    pkt.currentPos           = pkt.waypoints[0];
    pkt.currentTargetIndex   = 1;
    pkt.msgType              = msgType;
    // Encrypt end-to-end: relays carry only this ciphertext
    pkt.clearance            = clearanceForType(msgType);
    pkt.content              = sec.cipher(content, sec.pairKey(sender->getDeviceID(), receiver->getDeviceID()));
    pkt.color                = colorForType(msgType);
    pkt.willExpire           = willExpire;
    pkt.trail.push_back(pkt.currentPos);

    drainNodeBattery(sender);
    packets.push_back(pkt);

    std::ostringstream route_oss;
    for (size_t k = 0; k < route.size(); k++) {
        route_oss << route[k]->getDeviceID();
        if (k + 1 < route.size()) route_oss << " -> ";
    }
    // The operator sees their own plaintext; on the wire it is sealed.
    log("[" + label + " SENT - sealed " + clearanceName(pkt.clearance) + "] (" + msgTypeName(msgType) +
        ") \"" + content + "\"  " + route_oss.str() + "  (" + std::to_string(route.size() - 1) + " hops)" +
        (willExpire ? "  [will expire - TTL]" : ""), logInfo);
    return true;
}

//
// Soft multi-layer glow halo around a world-space point.
// ADDITIVE blending makes overlapping layers accumulate into a
// hot, blooming core - the key to the neon / dopamine look.
//
void drawGlow(sf::RenderTarget& target, sf::Vector2f pos, float baseR, sf::Color c, float intensity = 1.0f) {
    sf::RenderStates add; add.blendMode = sf::BlendAdd;
    const float   offsets[] = { 34.0f, 24.0f, 16.0f, 9.0f, 4.0f };
    const float   alphas[]  = {  10.f,  20.f,  34.f, 52.f, 78.f };
    for (int i = 0; i < 5; ++i) {
        float gr = baseR + offsets[i];
        sf::CircleShape g(gr);
        g.setOrigin(sf::Vector2f(gr, gr));
        g.setPosition(pos);
        auto a = (std::uint8_t)std::min(255.0f, alphas[i] * intensity);
        g.setFillColor(sf::Color(c.r, c.g, c.b, a));
        target.draw(g, add);
    }
}

//
// Same idea, scaled for flying packets.
//
void drawPacketGlow(sf::RenderTarget& target, const VisualPacket& pkt, float pulse = 1.0f) {
    sf::RenderStates add; add.blendMode = sf::BlendAdd;
    sf::Color c = pkt.color;
    const float   offsets[] = { 30.0f, 20.0f, 12.0f, 6.0f, 2.0f };
    const float   alphas[]  = {   9.f,  20.f,  36.f, 60.f, 95.f };
    for (int i = 0; i < 5; ++i) {
        float gr = 8.0f + offsets[i];
        sf::CircleShape g(gr);
        g.setOrigin(sf::Vector2f(gr, gr));
        g.setPosition(pkt.currentPos);
        auto a = (std::uint8_t)std::min(255.0f, alphas[i] * pulse);
        g.setFillColor(sf::Color(c.r, c.g, c.b, a));
        target.draw(g, add);
    }
}

//
// Trail - additive comet tail with a bright leading edge.
//
void drawTrail(sf::RenderTarget& target, const VisualPacket& pkt) {
    sf::RenderStates add; add.blendMode = sf::BlendAdd;
    int n = (int)pkt.trail.size();
    for (int i = 0; i < n; i++) {
        float ageRatio = (float)(i + 1) / (float)n;
        float radius   = 1.5f + 7.0f * ageRatio;
        auto  alpha    = (std::uint8_t)(150.f * ageRatio * ageRatio);

        sf::CircleShape dot(radius);
        dot.setOrigin(sf::Vector2f(radius, radius));
        dot.setPosition(pkt.trail[i]);
        sf::Color c = pkt.color;
        dot.setFillColor(sf::Color(c.r, c.g, c.b, alpha));
        target.draw(dot, add);
    }
}

//
// Packet shapes - all bumped ~30-40 % larger.
//
void drawPacketShape(sf::RenderTarget& target, const VisualPacket& pkt, float globalTime) {
    sf::Color c = pkt.color;

    if (pkt.msgType == MessageType::SOS) {
        float pulse = 1.0f + 0.28f * std::sin(globalTime * 9.0f);
        float r = 8.5f * pulse;                             // was 6.5
        sf::ConvexShape diamond(4);
        diamond.setPoint(0, sf::Vector2f(0, -r));
        diamond.setPoint(1, sf::Vector2f(r,  0));
        diamond.setPoint(2, sf::Vector2f(0,  r));
        diamond.setPoint(3, sf::Vector2f(-r, 0));
        diamond.setPosition(pkt.currentPos);
        diamond.setFillColor(c);
        target.draw(diamond);
    }
    else if (pkt.msgType == MessageType::SupplyRequest) {
        sf::RectangleShape sq(sf::Vector2f(13.0f, 13.0f));  // was 10
        sq.setOrigin(sf::Vector2f(6.5f, 6.5f));
        sq.setPosition(pkt.currentPos);
        sq.setFillColor(c);
        target.draw(sq);
    }
    else {
        sf::CircleShape circle(8.0f);                       // was 5.5
        circle.setOrigin(sf::Vector2f(8.0f, 8.0f));
        circle.setPosition(pkt.currentPos);
        circle.setFillColor(c);
        target.draw(circle);
    }
}

//
std::vector<std::int16_t> makeTone(float freq, float durationSec, float volume = 0.3f,
                                    float sampleRate = 44100.0f, float freqSlideTo = -1.0f) {
    int sampleCount = (int)(durationSec * sampleRate);
    std::vector<std::int16_t> samples(sampleCount);
    float attack = 0.01f, release = 0.05f;
    for (int i = 0; i < sampleCount; i++) {
        float t = (float)i / sampleRate;
        float currentFreq = freq;
        if (freqSlideTo > 0.0f) {
            float progress = (float)i / (float)sampleCount;
            currentFreq = freq + (freqSlideTo - freq) * progress;
        }
        float envelope = 1.0f;
        if (t < attack) envelope = t / attack;
        else if (t > durationSec - release) envelope = std::max(0.0f, (durationSec - t) / release);

        float sample = std::sin(2.0f * 3.14159265f * currentFreq * t) * volume * envelope;
        samples[i] = (std::int16_t)(sample * 32767.0f);
    }
    return samples;
}

// A soft, calming low pad designed to LOOP seamlessly: two detuned sines
// plus a slow tremolo. Frequencies and the tremolo are whole-cycle over the
// duration so the end meets the start with no click. Used while placing.
std::vector<std::int16_t> makeAmbient(float durationSec = 4.0f, float sampleRate = 44100.0f) {
    int sampleCount = (int)(durationSec * sampleRate);
    std::vector<std::int16_t> samples(sampleCount);
    const float f1 = 110.0f, f2 = 165.0f, lfo = 0.5f;   // 110*4, 165*4, 0.5*4 all integer
    for (int i = 0; i < sampleCount; i++) {
        float t = (float)i / sampleRate;
        float trem = 0.55f + 0.45f * std::sin(2.0f * 3.14159265f * lfo * t);
        float s = 0.18f * trem * (0.62f * std::sin(2.0f * 3.14159265f * f1 * t)
                                 + 0.38f * std::sin(2.0f * 3.14159265f * f2 * t));
        samples[i] = (std::int16_t)(s * 32767.0f);
    }
    return samples;
}

// Continuous background bed: a soft gusting "wind" (one-pole low-passed noise,
// windowed to silence at the loop ends so it loops seamlessly) over a calm low
// drone (whole-cycle sines, also seamless). Kept very quiet - presence, not
// melody. Plays for the whole session under everything else.
std::vector<std::int16_t> makeBackgroundAmbient(float durationSec = 8.0f, float sampleRate = 44100.0f) {
    int sc = (int)(durationSec * sampleRate);
    std::vector<std::int16_t> samples(sc);
    const float f1 = 55.0f, f2 = 82.5f, droneLfo = 0.25f;   // 55*8, 82.5*8, 0.25*8 all integer
    float lp = 0.0f;                 // one-pole low-pass state for the wind
    const float alpha = 0.02f;       // smaller => darker, softer air
    const float PI = 3.14159265f;
    for (int i = 0; i < sc; i++) {
        float t = (float)i / sampleRate;
        float noise = ((float)(rand() % 2000) / 1000.0f - 1.0f);  // white noise -1..1
        lp += alpha * (noise - lp);                               // low-passed -> airy
        float win = 0.5f - 0.5f * std::cos(2.0f * PI * ((float)i / (float)sc)); // 0..1..0
        float wind = lp * win * 0.5f;
        float trem = 0.6f + 0.4f * std::sin(2.0f * PI * droneLfo * t);
        float drone = trem * (0.6f * std::sin(2.0f * PI * f1 * t)
                            + 0.4f * std::sin(2.0f * PI * f2 * t));
        float s = 0.11f * (0.55f * drone + 0.9f * wind);
        if (s >  1.0f) s =  1.0f;
        if (s < -1.0f) s = -1.0f;
        samples[i] = (std::int16_t)(s * 32767.0f);
    }
    return samples;
}

bool buildAllTones(sf::SoundBuffer& sendBuf, sf::SoundBuffer& deliverBuf,
                    sf::SoundBuffer& deathBuf, sf::SoundBuffer& dropBuf,
                    sf::SoundBuffer& disasterBuf) {
    auto send     = makeTone(880.0f,  0.10f, 0.30f);
    auto deliver  = makeTone(1046.0f, 0.18f, 0.32f, 44100.0f, 1318.0f);
    auto death    = makeTone(110.0f,  0.30f, 0.30f, 44100.0f, 70.0f);
    auto drop     = makeTone(140.0f,  0.14f, 0.28f, 44100.0f, 60.0f);
    auto disaster = makeTone(90.0f,   0.45f, 0.40f, 44100.0f, 35.0f);

    std::vector<sf::SoundChannel> mono{ sf::SoundChannel::Mono };
    bool ok = true;
    ok = ok && sendBuf.loadFromSamples(send.data(), send.size(), 1, 44100, mono);
    ok = ok && deliverBuf.loadFromSamples(deliver.data(), deliver.size(), 1, 44100, mono);
    ok = ok && deathBuf.loadFromSamples(death.data(), death.size(), 1, 44100, mono);
    ok = ok && dropBuf.loadFromSamples(drop.data(), drop.size(), 1, 44100, mono);
    ok = ok && disasterBuf.loadFromSamples(disaster.data(), disaster.size(), 1, 44100, mono);
    return ok;
}

bool loadSystemFont(sf::Font& font) {
    std::vector<std::string> candidates = {
        "../assets/font.ttf",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
        "/Library/Fonts/Arial.ttf",
        "C:/Windows/Fonts/arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    };
    for (const auto& path : candidates) {
        if (font.openFromFile(path)) {
            cout << "[HUD] Loaded font: " << path << "\n";
            return true;
        }
    }
    cout << "[HUD] WARNING: No system font found. HUD/popups/log text disabled.\n"
         << "      Drop any .ttf file at '../assets/font.ttf' to enable it.\n";
    return false;
}

//
// Camera framing - computes the bounding box of every node and
// fits the world view around it with breathing room, so a tightly
// clustered config never reads as visually cramped on load.
//
sf::FloatRect computeDeviceBounds(World& world) {
    const auto& devices = world.getDevices();
    if (devices.empty())
        return sf::FloatRect({0.f, 0.f}, {(float)WINDOW_W, (float)WINDOW_H});

    float minX = devices[0]->getPosX(), maxX = minX;
    float minY = devices[0]->getPosY(), maxY = minY;
    for (Node* d : devices) {
        minX = std::min(minX, d->getPosX());
        maxX = std::max(maxX, d->getPosX());
        minY = std::min(minY, d->getPosY());
        maxY = std::max(maxY, d->getPosY());
    }
    return sf::FloatRect({minX, minY}, {maxX - minX, maxY - minY});
}

struct CameraFit { sf::Vector2f center; sf::Vector2f size; };

CameraFit computeCameraFit(World& world) {
    sf::FloatRect bounds = computeDeviceBounds(world);
    const float PADDING  = 160.0f;   // breathing room around outermost nodes
    const float MIN_SPAN = 360.0f;   // never frame tighter than this

    float spanX = std::max(bounds.size.x + PADDING * 2.0f, MIN_SPAN);
    float spanY = std::max(bounds.size.y + PADDING * 2.0f, MIN_SPAN);

    // Preserve the window's aspect ratio so nodes never look stretched.
    float windowAspect = (float)WINDOW_W / (float)WINDOW_H;
    if (spanX / spanY > windowAspect) spanY = spanX / windowAspect;
    else                              spanX = spanY * windowAspect;

    CameraFit fit;
    fit.center = sf::Vector2f(bounds.position.x + bounds.size.x / 2.0f,
                               bounds.position.y + bounds.size.y / 2.0f);
    fit.size = sf::Vector2f(spanX, spanY);
    return fit;
}

// Keeps panning from drifting off into the empty void - the camera
// center is allowed to roam a generous margin past the outermost
// nodes, but no further.
sf::Vector2f clampCameraCenter(sf::Vector2f center, World& world) {
    sf::FloatRect b = computeDeviceBounds(world);
    const float MARGIN = 500.0f;
    center.x = std::clamp(center.x, b.position.x - MARGIN, b.position.x + b.size.x + MARGIN);
    center.y = std::clamp(center.y, b.position.y - MARGIN, b.position.y + b.size.y + MARGIN);
    return center;
}

// Shrinks a string (with a trailing "...") until it fits maxWidth,
// so a long route/log line can never spill past its panel's edge.
std::string fitTextToWidth(const std::string& s, sf::Text& measuringText, float maxWidth) {
    measuringText.setString(s);
    if (measuringText.getLocalBounds().size.x <= maxWidth) return s;

    std::string truncated = s;
    while (!truncated.empty()) {
        truncated.pop_back();
        measuringText.setString(truncated + "...");
        if (measuringText.getLocalBounds().size.x <= maxWidth) break;
    }
    return truncated + "...";
}

#if ENABLE_SHADERS
// Gravity dot-grid background. A dense screen-space lattice of dots; each
// dot's color = a slowly drifting rainbow blended with color bled from
// nearby gravity wells. The sampling coordinate is warped toward the wells
// so the dots visibly clump inward around them. Wells are passed as fixed
// arrays (unused slots have mass 0) to keep the loop constant-bound, which
// is the portable/compatible way to do this in GLSL.
static const std::string GRID_SHADER = R"(
uniform float u_time;
uniform vec2  u_res;
uniform vec2  u_well[24];
uniform float u_mass[24];
uniform vec3  u_wellCol[24];

vec3 hsv2rgb(vec3 c){
    vec4 K = vec4(1.0, 2.0/3.0, 1.0/3.0, 3.0);
    vec3 p = abs(fract(c.xxx + K.xyz) * 6.0 - K.www);
    return c.z * mix(K.xxx, clamp(p - K.xxx, 0.0, 1.0), c.y);
}

void main(){
    // Flip Y so fragment coords match SFML's top-left screen space.
    vec2 p = vec2(gl_FragCoord.x, u_res.y - gl_FragCoord.y);

    vec2  warp  = vec2(0.0);
    vec3  tint  = vec3(0.0);
    float tintW = 0.0;
    for (int i = 0; i < 24; i++){
        float m  = u_mass[i];
        vec2  to = u_well[i] - p;
        float d  = length(to) + 1.0;
        float pull = m * 30.0 / (d*d/(160.0*160.0) + 1.0);
        warp += (to / d) * min(pull, d * 0.9);      // pull sampling toward wells
        float w = m / (d/110.0 + 1.0);
        tint  += u_wellCol[i] * w;
        tintW += w;
    }

    vec2 gp = p + warp;                              // warped => dots clump inward

    float spacing = 19.0;                            // dense fine grid
    vec2  cell = gp / spacing;
    vec2  f = (fract(cell) - 0.5) * spacing;
    float dist = length(f);
    float dotR = 1.15;
    float dotMask = smoothstep(dotR + 1.1, dotR - 0.35, dist);

    vec2  cid = floor(cell);
    float hue = fract(cid.x * 0.035 + cid.y * 0.055 + u_time * 0.04);
    vec3  rainbow = hsv2rgb(vec3(hue, 0.55, 1.0));

    vec3  tintc   = (tintW > 0.001) ? (tint / tintW) : vec3(0.0);
    float tintAmt = clamp(tintW * 0.65, 0.0, 0.9);
    vec3  col = mix(rainbow, tintc, tintAmt);

    float clump  = clamp(length(warp) / 24.0, 0.0, 1.0);
    float bright = 0.42 + 0.85 * clump;              // brighter where clumped
    float alpha  = dotMask * (0.32 + 0.55 * clump);

    gl_FragColor = vec4(col * bright, alpha);
}
)";

// Final-grade overlay: a soft cosmic vignette + faint grain. Generated from
// screen coords only (no scene sampling) and alpha-blended over everything.
static const std::string OVERLAY_SHADER = R"(
uniform float u_time;
uniform vec2  u_res;
float hash(vec2 p){ return fract(sin(dot(p, vec2(127.1,311.7)))*43758.5453); }
void main(){
    vec2 uv = gl_FragCoord.xy / u_res.xy;
    float d = length(uv - 0.5);
    float vig = smoothstep(0.95, 0.32, d);          // 1 center -> 0 edges
    float darken = (1.0 - vig) * 0.62;              // soft cosmic edge falloff
    float grain = abs(hash(uv * u_res.xy + u_time) - 0.5) * 0.035;
    float a = darken + grain;
    gl_FragColor = vec4(0.0, 0.0, 0.02, clamp(a, 0.0, 0.72));
}
)";
#endif

//
// "Char Blur" streaming text. Each glyph resolves from an offset cluster
// of faint ghost copies that tighten and fade upward as the reveal sweep
// passes over it - an approximation of the web char-blur reveal (true
// per-glyph gaussian blur isn't cheap in SFML). letterSpacing is added on
// top of each glyph's advance for the airy "cosmic" tracking.
//
static float charBlurWidth(const sf::Font& font, const std::string& str,
                           unsigned size, float letterSpacing) {
    float x = 0.0f;
    for (char c : str) x += font.getGlyph((unsigned char)c, size, false).advance + letterSpacing;
    return x - letterSpacing;
}

// Translucent capsule (rounded-end pill): rectangle body + two end circles.
static void drawPill(sf::RenderWindow& win, sf::Vector2f topLeft, float w, float h, sf::Color c) {
    float r = h * 0.5f;
    if (w < h) w = h;
    sf::RectangleShape body(sf::Vector2f(w - h, h));
    body.setPosition(sf::Vector2f(topLeft.x + r, topLeft.y));
    body.setFillColor(c);
    win.draw(body);
    sf::CircleShape lc(r), rc(r);
    lc.setOrigin(sf::Vector2f(r, r)); rc.setOrigin(sf::Vector2f(r, r));
    lc.setPosition(sf::Vector2f(topLeft.x + r, topLeft.y + r));
    rc.setPosition(sf::Vector2f(topLeft.x + w - r, topLeft.y + r));
    lc.setFillColor(c); rc.setFillColor(c);
    win.draw(lc); win.draw(rc);
}

static void drawCharBlur(sf::RenderWindow& win, const sf::Font& font,
                         const std::string& str, sf::Vector2f pos,
                         unsigned size, sf::Color color, float reveal,
                         float letterSpacing = 3.0f) {
    sf::RenderStates add; add.blendMode = sf::BlendAdd;
    float x = pos.x;
    int n = (int)str.size();
    float baseA = (float)color.a;
    for (int i = 0; i < n; ++i) {
        const sf::Glyph& g = font.getGlyph((unsigned char)str[i], size, false);
        float cp = std::clamp(reveal * (float)n - (float)i, 0.0f, 1.0f);
        if (cp > 0.004f && str[i] != ' ') {
            float spread = (1.0f - cp) * 6.0f;
            float dy     = (1.0f - cp) * 5.0f;
            sf::Text t(font, std::string(1, str[i]), size);
            if (spread > 0.4f) {
                const float ox[4] = { -spread, spread, 0.0f, 0.0f };
                const float oy[4] = { 0.0f, 0.0f, -spread, spread };
                for (int k = 0; k < 4; ++k) {
                    t.setFillColor(sf::Color(color.r, color.g, color.b,
                                   (std::uint8_t)(baseA * cp * 0.16f)));
                    t.setPosition(sf::Vector2f(x + ox[k], pos.y + dy + oy[k]));
                    win.draw(t, add);
                }
            }
            t.setFillColor(sf::Color(color.r, color.g, color.b, (std::uint8_t)(baseA * cp)));
            t.setPosition(sf::Vector2f(x, pos.y + dy));
            win.draw(t);
        }
        x += g.advance + letterSpacing;
    }
}

// "Decrypt" reveal: each glyph flickers through random characters (tinted a
// cold cyan, as if being deciphered) before locking left-to-right into the
// real letter. `seed` should change every frame so the scramble animates.
static void drawCharScramble(sf::RenderWindow& win, const sf::Font& font,
                             const std::string& str, sf::Vector2f pos,
                             unsigned size, sf::Color color, float reveal,
                             int seed, float letterSpacing = 3.0f) {
    static const std::string GLY = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#%&@/\\<>*+=?";
    int gn = (int)GLY.size();
    sf::RenderStates add; add.blendMode = sf::BlendAdd;
    float x = pos.x;
    int n = (int)str.size();
    for (int i = 0; i < n; ++i) {
        char real = str[i];
        const sf::Glyph& g = font.getGlyph((unsigned char)real, size, false);
        if (real != ' ') {
            float cp = std::clamp(reveal * (float)(n + 5) - (float)i, 0.0f, 1.6f);
            bool resolved = cp >= 1.0f;
            char shown = real;
            float jitter = 0.0f;
            if (!resolved) {
                unsigned r = (unsigned)(seed * 131 + i * 92821) ^ 0x9e3779b9u;
                shown  = GLY[r % gn];
                jitter = ((float)((r >> 9) % 100) / 100.0f - 0.5f) * 4.0f;
            }
            float aMul = resolved ? 1.0f : std::clamp(cp + 0.25f, 0.0f, 0.85f);
            sf::Color base = resolved ? color : sf::Color(120, 235, 205, color.a);  // cyan while decrypting
            sf::Text t(font, std::string(1, shown), size);
            if (resolved) {   // a faint additive ghost gives the locked title a glow
                t.setFillColor(sf::Color(color.r, color.g, color.b, (std::uint8_t)(color.a * 0.30f)));
                t.setPosition(sf::Vector2f(x, pos.y));
                win.draw(t, add);
            }
            t.setFillColor(sf::Color(base.r, base.g, base.b, (std::uint8_t)(base.a * aMul)));
            t.setPosition(sf::Vector2f(x, pos.y + jitter));
            win.draw(t);
        }
        x += g.advance + letterSpacing;
    }
}

#if ENABLE_BLOOM
// Bright-pass: keep only the luminous parts of the scene (the glows).
static const std::string BRIGHT_SHADER = R"(
uniform sampler2D u_tex;
void main(){
    vec4 c = texture2D(u_tex, gl_TexCoord[0].xy);
    float b = max(c.r, max(c.g, c.b));
    float k = smoothstep(0.50, 0.85, b);
    gl_FragColor = vec4(c.rgb * k, 1.0);
}
)";
// Separable 9-tap Gaussian blur (run once per axis).
static const std::string BLUR_SHADER = R"(
uniform sampler2D u_tex;
uniform vec2 u_texel;   // 1.0 / texture size
uniform vec2 u_dir;     // (radius,0) or (0,radius)
void main(){
    vec2 uv = gl_TexCoord[0].xy;
    vec2 o  = u_texel * u_dir;
    vec4 s  = texture2D(u_tex, uv) * 0.2270270270;
    s += texture2D(u_tex, uv + o*1.3846153846) * 0.3162162162;
    s += texture2D(u_tex, uv - o*1.3846153846) * 0.3162162162;
    s += texture2D(u_tex, uv + o*3.2307692308) * 0.0702702703;
    s += texture2D(u_tex, uv - o*3.2307692308) * 0.0702702703;
    gl_FragColor = s;
}
)";
#endif

int main() {
    srand((unsigned)time(nullptr));

    World world;
    // CRUD build mode: the network starts as just the Emergency Base -
    // the one piece of infrastructure that survives the disaster. Every
    // other node is created at runtime by the user (CREATE), matching the
    // report's "the network is the devices themselves" build-up story.
    // Press R to instead load the full sample topology from disk.
    world.addDevice(new EmergencyBase("B1", (float)WINDOW_W / 2.0f, (float)WINDOW_H / 2.0f));
    world.connectNeighbors();

    sf::RenderWindow window(sf::VideoMode(sf::Vector2u(WINDOW_W, WINDOW_H)), "Guardian Mesh: Tactical Command");
    window.setFramerateLimit(60);

    // Camera system
    // worldView pans/zooms over the mesh. uiView stays a fixed 1:1
    // mapping to window pixels, so HUD/log/popups stay put and
    // legible no matter how far worldView is zoomed.
    // Zoom and recenter both work as target + live-eased value, so
    // wheel notches / Q-E / F glide smoothly instead of snapping.
    sf::View worldView(sf::FloatRect({0.f, 0.f}, {(float)WINDOW_W, (float)WINDOW_H}));
    sf::View uiView = window.getDefaultView();

    // Keep a fixed 1000x800 logical canvas and present it aspect-correct with
    // black bars, so resizing or going fullscreen never stretches circles into
    // ellipses or shifts the layout. This viewport is shared by every view.
    auto computeLetterbox = [](sf::Vector2u ws) {
        float target = (float)WINDOW_W / (float)WINDOW_H;
        float got    = (ws.y == 0) ? target : (float)ws.x / (float)ws.y;
        float vw = 1.0f, vh = 1.0f, vx = 0.0f, vy = 0.0f;
        if (got > target) { vw = target / got; vx = (1.0f - vw) / 2.0f; }   // pillarbox
        else              { vh = got / target; vy = (1.0f - vh) / 2.0f; }   // letterbox
        return sf::FloatRect({vx, vy}, {vw, vh});
    };
    auto applyLetterbox = [&]() {
        sf::FloatRect vp = computeLetterbox(window.getSize());
        worldView.setViewport(vp);
        uiView.setViewport(vp);
    };

    CameraFit initialFit = computeCameraFit(world);
    worldView.setSize(initialFit.size);
    worldView.setCenter(initialFit.center);
    applyLetterbox();

    sf::Vector2f baselineViewSize = initialFit.size;   // size that represents 100% zoom
    float        targetZoomFactor = 1.0f;
    float        zoomFactorLive   = 1.0f;
    sf::Vector2f targetViewCenter = initialFit.center;

    const float MIN_ZOOM = 0.35f, MAX_ZOOM = 3.0f;
    const float ZOOM_EASE_SPEED = 10.0f;   // higher = snappier convergence
    const float PAN_EASE_SPEED  = 8.0f;

    bool isPanning = false;
    sf::Vector2f panStartMouse, panStartCenter;

    // Right-click is dual-purpose: a quick click cancels the current
    // flow (existing behavior); dragging promotes it into a camera pan.
    bool rightDragCandidate = false;
    sf::Vector2f rightPressScreenPos;

    auto retargetCamera = [&]() {
        CameraFit fit = computeCameraFit(world);
        baselineViewSize = fit.size;
        targetZoomFactor = 1.0f;
        targetViewCenter = fit.center;
    };

    // Refined colour palette
    // More vivid, saturated - closer to the luminous Breakbot aesthetic.
    sf::Color colorSageGreen(60,  210, 175);   // vivid teal-mint  (was 136,175,138)
    sf::Color colorCreamWhite(255, 248, 218);   // warm ivory       (was 245,245,235)
    sf::Color colorMattePurple(165, 125, 235);  // vivid lavender   (was 120,100,150)
    sf::Color colorDeadGrey(52,   52,  62);     // cool-dark grey   (was 80,80,80)

    sf::Color logInfo(190, 195, 205);
    sf::Color logSuccess(130, 210, 130);
    sf::Color logWarn(230, 190, 90);
    sf::Color logError(235, 90,  80);
    sf::Color logCyan(120,  200, 230);

    sf::Clock clock;
    float globalTime = 0.0f;
    vector<VisualPacket>  activePackets;
    // Guaranteed delivery: messages that died to a mid-route relay failure are
    // re-sent along a freshly computed path, up to MAX_RETRIES times.
    struct PendingRetry { std::string fromID, toID, content; MessageType type; int attempts; float timer; };
    vector<PendingRetry> retries;
    const int   MAX_RETRIES = 3;
    const float RETRY_DELAY = 1.4f;
    vector<DroppedEvent>  droppedEvents;
    vector<DisasterEvent> disasterEvents;
    vector<LogEntry>      eventLog;

    // Expanding ring shown briefly where an auto-deployed relay appears.
    struct RelaySpawnPulse { sf::Vector2f pos; float age; sf::Color color = sf::Color(255, 215, 120); };
    vector<RelaySpawnPulse> relaySpawnPulses;

    // Fast map-wide radar ring (Target Sweep) / reassurance ring (Beacon).
    struct SweepRing { sf::Vector2f pos; float age; sf::Color color = sf::Color(140, 215, 255);
                       float life = 1.15f; float maxR = 2200.0f; };
    vector<SweepRing> sweeps;

    // Additive spark bursts (delivery, spawn, strike, send).
    vector<Spark> sparks;
    auto spawnBurst = [&](sf::Vector2f origin, sf::Color color, int count, float speed) {
        for (int i = 0; i < count; ++i) {
            float ang = (float)(rand() % 628) / 100.0f;
            float spd = speed * (0.35f + (float)(rand() % 100) / 100.0f);
            Spark s;
            s.pos     = origin;
            s.vel     = sf::Vector2f(std::cos(ang) * spd, std::sin(ang) * spd);
            s.maxLife = 0.5f + (float)(rand() % 60) / 100.0f;
            s.life    = s.maxLife;
            s.radius  = 1.5f + (float)(rand() % 25) / 10.0f;
            s.color   = color;
            sparks.push_back(s);
        }
    };

    int messagesDelivered        = 0;
    int messagesDropped          = 0;
    int disasterStrikesTriggered = 0;

    const bool ENABLE_AMBIENT_SUCK = true;
    float ambientTimer = 0.0f;

    // Ambient background particles
    // 55 slowly-drifting blue specks - Breakbot-style depth layer.
    std::vector<AmbientParticle> ambientParticles;
    for (int i = 0; i < 55; ++i) {
        AmbientParticle p;
        p.pos       = sf::Vector2f((float)(rand() % 1000), (float)(rand() % 800));
        float ang   = (float)(rand() % 628) / 100.0f;
        float spd   = 5.0f + (float)(rand() % 14);
        p.vel       = sf::Vector2f(std::cos(ang) * spd, std::sin(ang) * spd);
        p.baseAlpha = 12.0f + (float)(rand() % 24);
        p.radius    = 0.7f + (float)(rand() % 16) / 10.0f;
        p.phase     = (float)(rand() % 628) / 100.0f;
        ambientParticles.push_back(p);
    }

    // HUD / popup / log font
    sf::Font font;
    bool fontOk = loadSystemFont(font);

    // Procedural audio
    sf::SoundBuffer sendBuf, deliverBuf, deathBuf, dropBuf, disasterBuf;
    bool audioOk = buildAllTones(sendBuf, deliverBuf, deathBuf, dropBuf, disasterBuf);
    std::optional<sf::Sound> sendSound, deliverSound, deathSound, dropSound, disasterSound;
    if (audioOk) {
        sendSound.emplace(sendBuf);         sendSound->setVolume(70.f);
        deliverSound.emplace(deliverBuf);   deliverSound->setVolume(70.f);
        deathSound.emplace(deathBuf);       deathSound->setVolume(70.f);
        dropSound.emplace(dropBuf);         dropSound->setVolume(70.f);
        disasterSound.emplace(disasterBuf); disasterSound->setVolume(80.f);
        cout << "[AUDIO] Procedural tones generated successfully.\n";
    } else {
        cout << "[AUDIO] WARNING: Tone generation failed - running without sound.\n";
    }

    // Extended SFX bank: a distinct voice for each action
    // Pre-sized vectors so each SoundBuffer keeps a stable address (sf::Sound
    // holds a pointer to its buffer - a resize would dangle it).
    enum Sfx { SfxPlace, SfxRelay, SfxRemove, SfxClear, SfxSweep, SfxBeacon,
               SfxAck, SfxPopup, SfxClick, SfxHover, SfxMode, SFX_COUNT };
    std::vector<sf::SoundBuffer>          sfxBuf(SFX_COUNT);
    std::vector<std::optional<sf::Sound>> sfx(SFX_COUNT);
    std::vector<sf::SoundChannel>         monoCh{ sf::SoundChannel::Mono };
    auto loadTone = [&](int id, const std::vector<std::int16_t>& s, float vol) {
        if (sfxBuf[id].loadFromSamples(s.data(), s.size(), 1, 44100, monoCh)) {
            sfx[id].emplace(sfxBuf[id]);
            sfx[id]->setVolume(vol);
        }
    };
    if (audioOk) {
        loadTone(SfxPlace,  makeTone(660.0f, 0.09f, 0.28f, 44100.0f, 880.0f),  55.f);
        loadTone(SfxRelay,  makeTone(520.0f, 0.12f, 0.26f, 44100.0f, 760.0f),  50.f);
        loadTone(SfxRemove, makeTone(420.0f, 0.12f, 0.26f, 44100.0f, 210.0f),  55.f);
        loadTone(SfxClear,  makeTone(320.0f, 0.26f, 0.26f, 44100.0f, 120.0f),  55.f);
        loadTone(SfxSweep,  makeTone(220.0f, 0.50f, 0.26f, 44100.0f, 1500.0f), 50.f);
        loadTone(SfxBeacon, makeTone(523.0f, 0.42f, 0.26f, 44100.0f, 784.0f),  55.f);
        loadTone(SfxAck,    makeTone(1318.0f,0.22f, 0.24f, 44100.0f, 1568.0f), 48.f);
        loadTone(SfxPopup,  makeTone(740.0f, 0.10f, 0.20f, 44100.0f, 980.0f),  42.f);
        loadTone(SfxClick,  makeTone(1000.0f,0.05f, 0.18f),                    42.f);
        loadTone(SfxHover,  makeTone(1500.0f,0.035f,0.12f),                    26.f);
        loadTone(SfxMode,   makeTone(720.0f, 0.07f, 0.18f, 44100.0f, 900.0f),  38.f);
    }
    auto playSfx = [&](int id) {
        if (audioOk && id >= 0 && id < SFX_COUNT && sfx[id]) { sfx[id]->stop(); sfx[id]->play(); }
    };

    // Calming ambient pad - loops while you decide where to place a node
    sf::SoundBuffer ambientBuf;
    std::optional<sf::Sound> ambientSound;
    bool ambientPlaying = false;
    if (audioOk) {
        auto amb = makeAmbient(4.0f);
        if (ambientBuf.loadFromSamples(amb.data(), amb.size(), 1, 44100, monoCh)) {
            ambientSound.emplace(ambientBuf);
            ambientSound->setVolume(45.f);
            ambientSound->setLooping(true);
        }
    }

    // Continuous background bed - soft wind + low drone, on all session
    sf::SoundBuffer bgBuf;
    std::optional<sf::Sound> bgSound;
    if (audioOk) {
        auto bg = makeBackgroundAmbient(8.0f);
        if (bgBuf.loadFromSamples(bg.data(), bg.size(), 1, 44100, monoCh)) {
            bgSound.emplace(bgBuf);
            bgSound->setVolume(30.f);
            bgSound->setLooping(true);
            bgSound->play();                 // starts now, never stops
        }
    }

    // Post-processing shaders (optional, guarded)
    bool fxEnabled = true;     // toggled live with B
    bool shadersOK = false;

    // Floating node inspector (follows the cursor with a leader line)
    sf::Vector2f inspectorPos(0, 0);     // eased screen position of the panel
    float        inspectorAlpha = 0.0f;  // fade in/out
    bool         inspectorInit  = false; // first-frame snap guard
    std::string  inspectorText;          // cached so a node deleted mid-fade can't dangle
    sf::Color    inspectorAccent(110, 225, 255);

    // One-time intro overlay timer (never resets, even on R reload)
    float introAge = 0.0f;
#if ENABLE_SHADERS
    std::optional<sf::Shader> gridShader, overlayShader;
    if (sf::Shader::isAvailable()) {
        sf::Shader gr, ov;
        bool g = gr.loadFromMemory(GRID_SHADER, sf::Shader::Type::Fragment);
        bool o = ov.loadFromMemory(OVERLAY_SHADER, sf::Shader::Type::Fragment);
        if (g) gridShader.emplace(std::move(gr));
        if (o) overlayShader.emplace(std::move(ov));
        shadersOK = (g || o);
        if (shadersOK) cout << "[FX] GLSL active" << (g ? " - gravity dot-grid" : "")
                            << (o ? " + cinematic grade" : "") << ".\n";
        else           cout << "[FX] Shaders failed to compile - procedural fallbacks active.\n";
    } else {
        cout << "[FX] GPU has no shader support - procedural fallbacks active.\n";
    }
#endif

#if ENABLE_BLOOM
    // Bloom resources: full-res scene target + two half-res ping-pong targets.
    sf::RenderTexture sceneRT, bloomA, bloomB;
    sf::Shader brightShader, blurShader;
    bool bloomReady = false;
    if (sf::Shader::isAvailable()
        && sceneRT.resize(sf::Vector2u(WINDOW_W, WINDOW_H))
        && bloomA.resize(sf::Vector2u(WINDOW_W / 2, WINDOW_H / 2))
        && bloomB.resize(sf::Vector2u(WINDOW_W / 2, WINDOW_H / 2))
        && brightShader.loadFromMemory(BRIGHT_SHADER, sf::Shader::Type::Fragment)
        && blurShader.loadFromMemory(BLUR_SHADER, sf::Shader::Type::Fragment)) {
        sceneRT.setSmooth(true); bloomA.setSmooth(true); bloomB.setSmooth(true);
        bloomReady = true;
        cout << "[FX] Bloom pipeline ready.\n";
    } else {
        cout << "[FX] Bloom unavailable - rendering direct to window.\n";
    }
#endif

    // On-screen event log
    auto logEvent = [&](const std::string& text, sf::Color color = sf::Color(190,195,205)) {
        cout << text << "\n";
        LogEntry e;
        e.text = text;
        e.color = color;
        e.spawnTime = globalTime;
        eventLog.push_back(e);
        if (eventLog.size() > 60) eventLog.erase(eventLog.begin());
    };

    // Compose-message flow state
    FlowState flowState = FlowState::None;
    Node* pendingSender   = nullptr;
    Node* pendingReceiver = nullptr;
    MessageType pendingType = MessageType::SOS;
    std::string typedMessage;

    // CRUD build-mode state
    // None: normal (message/drag). AddStudent: click empty space to CREATE
    // a student. Delete: click a node to DELETE it.
    enum class BuildMode { None, AddStudent, Delete };
    BuildMode buildMode = BuildMode::None;

    // Drag state
    bool isPotentialDrag = false;
    bool isDragging       = false;
    Node* dragNode         = nullptr;
    Node* pendingClickNode = nullptr;
    sf::Vector2f pressWorldPos;

    bool disasterArmed = false;

    // Auto-bridge tuning. SAFE_HOP stays under the student's 200 range so
    // every hop in an auto-built chain is guaranteed two-way; capping the
    // relay count is what makes a placement that's WAY too far simply
    // refuse to connect (dead zone) instead of carpeting the map in relays.
    const float SAFE_HOP        = 185.0f;
    const int   MAX_AUTO_RELAYS = 3;

    // Lowest unused numeric ID for a given prefix, scanning live devices -
    // collision-proof even after reloading the sample (which has S1..S4).
    auto nextFreeID = [&](const std::string& prefix) {
        for (int n = 1; ; ++n) {
            std::string candidate = prefix + std::to_string(n);
            bool taken = false;
            for (Node* d : world.getDevices())
                if (d->getDeviceID() == candidate) { taken = true; break; }
            if (!taken) return candidate;
        }
    };

    // Nearest currently-working node to a world position (ignores the
    // optional 'except' node, used while previewing a not-yet-real student).
    auto nearestWorkingNode = [&](sf::Vector2f p, Node* except) -> Node* {
        Node* best = nullptr; float bestD = 0.0f;
        for (Node* d : world.getDevices()) {
            if (d == except || !d->isWorking()) continue;
            float dx = d->getPosX() - p.x, dy = d->getPosY() - p.y;
            float dist = std::sqrt(dx*dx + dy*dy);
            if (!best || dist < bestD) { best = d; bestD = dist; }
        }
        return best;
    };

    // Predicts what dropping a student at 'p' would do, WITHOUT mutating
    // the world - drives both the live placement preview and the actual
    // add, so what you see is exactly what you get.
    struct Placement { int relaysNeeded; bool deadZone; Node* anchor; };
    auto predictPlacement = [&](sf::Vector2f p) -> Placement {
        Node* anchor = nearestWorkingNode(p, nullptr);
        if (!anchor) return { 0, true, nullptr };
        float dx = anchor->getPosX() - p.x, dy = anchor->getPosY() - p.y;
        float gap = std::sqrt(dx*dx + dy*dy);
        if (gap <= 200.0f) return { 0, false, anchor };            // direct two-way link
        int segments = (int)std::ceil(gap / SAFE_HOP);
        int relays   = segments - 1;
        if (relays > MAX_AUTO_RELAYS) return { relays, true, anchor }; // too far -> dead zone
        return { relays, false, anchor };
    };

    auto cancelFlow = [&]() {
        if (flowState != FlowState::None)
            logEvent("[CMD] Send cancelled.", logWarn);
        flowState = FlowState::None;
        pendingSender = nullptr;
        pendingReceiver = nullptr;
        typedMessage.clear();
    };

    // TARGET SWEEP - for a stranded node: fire a fast map-wide radar ring,
    // find the nearest reachable entity, and relocate the node to JUST
    // inside the largest distance that still forms a two-way link (the
    // smaller of the two signal ranges), pulling it home along the line.
    auto targetSweep = [&](Node* s) {
        if (!s) return;
        sf::Vector2f sp(s->getPosX(), s->getPosY());
        Node* best = nearestWorkingNode(sp, s);
        sweeps.push_back({ sp, 0.0f });                       // the sweep always fires
        spawnBurst(sp, sf::Color(150, 210, 255), 20, 170.0f);
        if (!best) {
            logEvent("[SWEEP] " + s->getDeviceID() + " swept - but no infrastructure exists to reach.", logError);
            return;
        }
        sf::Vector2f bp(best->getPosX(), best->getPosY());
        float linkD = std::min(s->getSignalRange(), best->getSignalRange()) * 0.92f;
        sf::Vector2f dir = sp - bp;
        float d = std::sqrt(dir.x*dir.x + dir.y*dir.y);
        if (d < 1.0f) { dir = sf::Vector2f(1.0f, 0.0f); d = 1.0f; }
        dir /= d;
        sf::Vector2f np = bp + dir * std::min(linkD, d);      // pulled inward, kept on its own side
        world.updateDevice(s->getDeviceID(), np.x, np.y, s->getBatteryLevel());
        spawnBurst(np, sf::Color(150, 235, 210), 26, 150.0f);
        relaySpawnPulses.push_back({ np, 0.0f, sf::Color(150, 235, 210) });
        // Hopeful "found you" cue - a soft warm pulse blooms at the node it
        // locked onto, and a gentle chime answers the sweep's whoosh.
        relaySpawnPulses.push_back({ bp, 0.0f, sf::Color(255, 220, 150) });
        spawnBurst(bp, sf::Color(255, 225, 165), 14, 95.0f);
        logEvent("[SWEEP] " + s->getDeviceID() + " locked onto " + best->getDeviceID()
                 + " and pulled into range.", logCyan);
        playSfx(SfxSweep);
        playSfx(SfxAck);   // gentle hopeful chime layered under the whoosh
        flowState = FlowState::None;
        pendingSender = nullptr;
        pendingReceiver = nullptr;
    };

    auto handleNodeClickForFlow = [&](Node* clicked) {
        if (flowState == FlowState::None) {
            if (clicked->getDeviceType() == "StudentNode") {
                pendingSender = clicked;
                bool linked = false;
                for (Node* nb : clicked->getNeighbors())
                    if (nb->isWorking()) { linked = true; break; }
                if (!linked) {
                    // Stranded: skip target selection - only Target Sweep applies.
                    if (!fontOk) { targetSweep(clicked); return; }
                    pendingReceiver = nullptr;                 // receiver==null => sweep-only popup
                    flowState = FlowState::ChoosingType;
                    playSfx(SfxPopup);
                    logEvent("[CMD] " + clicked->getDeviceID() + " is STRANDED - Target Sweep available.", logWarn);
                } else {
                    flowState = FlowState::AwaitingTarget;
                    logEvent("[CMD] Sender locked: " + clicked->getDeviceID() + ". Choose a target.", logInfo);
                }
            } else {
                logEvent("[CMD ERROR] Only Students can originate messages!", logError);
            }
        }
        else if (flowState == FlowState::AwaitingTarget) {
            if (clicked == pendingSender) {
                logEvent("[CMD ERROR] Cannot target yourself.", logError);
                return;
            }
            pendingReceiver = clicked;

            if (!fontOk) {
                spawnPacket(pendingSender, pendingReceiver, MessageType::StatusUpdate,
                           "(auto - no font available)", activePackets, droppedEvents,
                           nullptr, messagesDropped, "CMD", logEvent);
                flowState = FlowState::None;
                pendingSender = nullptr;
                pendingReceiver = nullptr;
                return;
            }

            flowState = FlowState::ChoosingType;
            playSfx(SfxPopup);
            logEvent("[CMD] Target locked: " + clicked->getDeviceID() + ". Choose message type.", logInfo);
        }
    };

    auto finalizeSend = [&](Node* baseStationPtr,
                            const std::function<void(const std::string&, sf::Color)>& log) {
        if (typedMessage.empty()) return;
        Node* sender   = pendingSender;
        Node* receiver = pendingReceiver;
        bool ok = spawnPacket(pendingSender, pendingReceiver, pendingType, typedMessage,
                              activePackets, droppedEvents, baseStationPtr,
                              messagesDropped, "CMD", log);
        if (ok && audioOk) { sendSound->stop(); sendSound->play(); }
        else if (!ok) {
            // No route to the chosen target - say so plainly, then self-heal by
            // pulling the stranded endpoint into range so a path can exist.
            auto hasLink = [](Node* n) {
                if (!n) return true;
                for (Node* nb : n->getNeighbors()) if (nb->isWorking()) return true;
                return false;
            };
            Node* iso = (sender && !hasLink(sender)) ? sender
                      : (receiver && !hasLink(receiver)) ? receiver
                      : receiver;
            log("[NO TARGET] No one is in range to receive - auto-establishing a link...", sf::Color(240, 200, 110));
            if (iso) targetSweep(iso);   // fires the sweep + relocates into range
        }
        flowState = FlowState::None;
        pendingSender = nullptr;
        pendingReceiver = nullptr;
        typedMessage.clear();
    };

    // Topology bootstrap
    Node* baseStationPtr = nullptr;
    for (Node* d : world.getDevices())
        if (d->getDeviceType() == "EmergencyBase") baseStationPtr = d;

    auto collectStudents = [&]() {
        std::vector<Node*> students;
        for (Node* d : world.getDevices())
            if (d->getDeviceType() == "StudentNode" && d->isWorking())
                students.push_back(d);
        return students;
    };

    std::vector<Node*> studentPool = collectStudents();
    auto directPair    = findDirectStudentPair(studentPool);
    auto multiHopPair  = findMultiHopStudentPair(studentPool);

    bool demo1Fired = false;
    bool demo2Fired = false;

    // Any structural edit can free the memory that flying packets and the
    // selection/drag state still point at, so we always purge those after
    // a CREATE/DELETE/CLEAR and refresh the cached base pointer.
    auto invalidateAfterStructuralChange = [&]() {
        activePackets.clear();
        cancelFlow();
        isPotentialDrag = false; isDragging = false;
        dragNode = nullptr; pendingClickNode = nullptr;
        baseStationPtr = nullptr;
        for (Node* d : world.getDevices())
            if (d->getDeviceType() == "EmergencyBase") baseStationPtr = d;
    };

    // CREATE - drop a student and, if it lands out of range, auto-deploy
    // relays evenly along the line to the nearest node so the SOS can hop.
    auto addStudentAt = [&](sf::Vector2f p) {
        Placement plan = predictPlacement(p);
        std::string sid = nextFreeID("S");
        world.addDevice(new StudentNode(sid, p.x, p.y));

        if (!plan.anchor) {
            logEvent("[CREATE] " + sid + " placed. No infrastructure to link to yet.", logWarn);
        }
        else if (plan.deadZone) {
            logEvent("[CREATE] " + sid + " placed in a DEAD ZONE - too far to bridge.", logError);
        }
        else if (plan.relaysNeeded == 0) {
            logEvent("[CREATE] " + sid + " linked directly to " + plan.anchor->getDeviceID() + ".", logSuccess);
        }
        else {
            // Evenly space relays from the anchor toward the new student.
            sf::Vector2f a(plan.anchor->getPosX(), plan.anchor->getPosY());
            int segments = plan.relaysNeeded + 1;
            std::string spawned;
            for (int k = 1; k <= plan.relaysNeeded; ++k) {
                float t = (float)k / (float)segments;
                sf::Vector2f rp = a + (p - a) * t;
                std::string rid = nextFreeID("R");
                world.addDevice(new StaticRelay(rid, rp.x, rp.y));
                relaySpawnPulses.push_back({ rp, 0.0f });
                spawnBurst(rp, sf::Color(255, 215, 120), 18, 130.0f);
                if (!spawned.empty()) spawned += ", ";
                spawned += rid;
            }
            logEvent("[CREATE] " + sid + " out of range - auto-deployed relay(s): " + spawned + ".", logCyan);
        }

        playSfx(plan.anchor && plan.relaysNeeded > 0 && !plan.deadZone ? SfxRelay : SfxPlace);
        invalidateAfterStructuralChange();
        retargetCamera();   // smoothly reframe so the growing mesh stays in view
    };

    // DELETE - remove a node (the base is the network anchor and is protected).
    auto deleteNode = [&](Node* n) {
        if (!n) return;
        if (n->getDeviceType() == "EmergencyBase") {
            logEvent("[DELETE] The Emergency Base is the network anchor - cannot delete.", logError);
            return;
        }
        std::string id = n->getDeviceID();
        world.removeDevice(id);
        logEvent("[DELETE] " + id + " removed. Mesh recalculated.", logWarn);
        playSfx(SfxRemove);
        invalidateAfterStructuralChange();
    };

    // CLEAR - tear everything down back to the lone Emergency Base.
    auto clearToBase = [&]() {
        std::vector<std::string> ids;
        for (Node* d : world.getDevices())
            if (d->getDeviceType() != "EmergencyBase") ids.push_back(d->getDeviceID());
        for (const auto& id : ids) world.removeDevice(id);
        if (world.getDevices().empty())
            world.addDevice(new EmergencyBase("B1", (float)WINDOW_W / 2.0f, (float)WINDOW_H / 2.0f));
        world.connectNeighbors();
        invalidateAfterStructuralChange();
        retargetCamera();
        logEvent("[CLEAR] Network reset to Emergency Base only.", logCyan);
        playSfx(SfxClear);
    };

    // Command dispatcher: one place that performs every global action, so
    // the top toolbar and the (optional) keyboard shortcuts can't drift apart.
    enum Cmd { CmdZoomIn, CmdZoomOut, CmdAdd, CmdDel, CmdClear, CmdLoad, CmdRecenter,
               CmdDisaster, CmdDrain, CmdBeacon, CmdFlood, CmdTap, CmdFx, CmdSweepAll };
    auto runCommand = [&](int cmd) {
        switch (cmd) {
        case CmdZoomIn:  targetZoomFactor = std::clamp(targetZoomFactor * 0.80f, MIN_ZOOM, MAX_ZOOM); break;
        case CmdZoomOut: targetZoomFactor = std::clamp(targetZoomFactor * 1.25f, MIN_ZOOM, MAX_ZOOM); break;
        case CmdAdd:
            cancelFlow(); disasterArmed = false;
            buildMode = (buildMode == BuildMode::AddStudent) ? BuildMode::None : BuildMode::AddStudent;
            logEvent(buildMode == BuildMode::AddStudent ? "[CREATE] Add-Student mode - click empty space."
                                                        : "[CREATE] Add-Student mode off.", logCyan);
            playSfx(SfxMode); break;
        case CmdDel:
            cancelFlow(); disasterArmed = false;
            buildMode = (buildMode == BuildMode::Delete) ? BuildMode::None : BuildMode::Delete;
            logEvent(buildMode == BuildMode::Delete ? "[DELETE] Delete mode - click a node."
                                                    : "[DELETE] Delete mode off.", logWarn);
            playSfx(SfxMode); break;
        case CmdClear: clearToBase(); break;
        case CmdLoad:
            world.loadDevicesFromFile("../data/nodes_config.txt");
            world.connectNeighbors();
            activePackets.clear(); droppedEvents.clear(); disasterEvents.clear(); relaySpawnPulses.clear();
            cancelFlow(); buildMode = BuildMode::None;
            isPotentialDrag = false; isDragging = false; dragNode = nullptr; pendingClickNode = nullptr; isPanning = false;
            globalTime = 0.0f; demo1Fired = false; demo2Fired = false; disasterArmed = false;
            messagesDelivered = 0; messagesDropped = 0; disasterStrikesTriggered = 0;
            baseStationPtr = nullptr;
            for (Node* d : world.getDevices()) if (d->getDeviceType() == "EmergencyBase") baseStationPtr = d;
            studentPool = collectStudents(); directPair = findDirectStudentPair(studentPool);
            multiHopPair = findMultiHopStudentPair(studentPool);
            retargetCamera();
            logEvent("[RELOAD] Network reloaded. New demo pairs resolved.", logCyan); break;
        case CmdRecenter: retargetCamera(); logEvent("[CAMERA] Recentering on network.", logCyan); break;
        case CmdDisaster:
            cancelFlow(); buildMode = BuildMode::None; disasterArmed = !disasterArmed;
            logEvent(disasterArmed ? "[DISASTER] Strike mode ARMED - click anywhere to deploy EMP."
                                   : "[DISASTER] Strike mode disarmed.", logWarn); break;
        case CmdDrain:
            world.runSimulation(1); world.connectNeighbors();
            logEvent("[GUI] Batteries drained. Mesh recalculated.", logWarn); break;
        case CmdBeacon:
            if (baseStationPtr && baseStationPtr->isWorking()) {
                sf::Vector2f bp(baseStationPtr->getPosX(), baseStationPtr->getPosY());
                sweeps.push_back({ bp, 0.0f, sf::Color(255, 205, 120), 1.7f, 2700.0f });
                spawnBurst(bp, sf::Color(255, 205, 120), 26, 150.0f);
                logEvent("[BEACON] Command is online - hold on, help is coming.", logCyan);
                playSfx(SfxBeacon);
            } break;
        case CmdFlood: {
            std::vector<Node*> students;
            for (Node* d : world.getDevices())
                if (d->isWorking() && d->getDeviceType() == "StudentNode") students.push_back(d);
            if (!students.empty() && baseStationPtr) {
                int n = 12;
                for (int i = 0; i < n; ++i) {
                    Node* s = students[rand() % students.size()];
                    MessageType jt = (rand() % 2) ? MessageType::SupplyRequest : MessageType::StatusUpdate;
                    spawnPacket(s, baseStationPtr, jt, "flood", activePackets, droppedEvents,
                                baseStationPtr, messagesDropped, "ATTACK", logEvent);
                }
                logEvent("[ATTACK] Inbound flood - " + std::to_string(n) +
                         " spoofed packets. Relays shedding non-SOS load.", logError);
                if (audioOk) { disasterSound->stop(); disasterSound->play(); }
            }
        } break;
        case CmdTap: {
            VisualPacket* cap = nullptr;
            for (auto& p : activePackets) if (p.active && !p.isAck) { cap = &p; break; }
            if (cap)
                logEvent("[INTERCEPT] Relay tapped the wire - no endpoint key, ciphertext only: "
                         + cipherSnippet(cap->content) + "(sealed " + clearanceName(cap->clearance) + ")", logWarn);
            else
                logEvent("[INTERCEPT] Wire tapped - no traffic in flight to capture.", logCyan);
        } break;
        case CmdFx:
            fxEnabled = !fxEnabled;
            logEvent(fxEnabled ? "[FX] Cinematic effects ON." : "[FX] Cinematic effects OFF.", logCyan); break;
        case CmdSweepAll: {
            int n = 0;
            for (Node* d : world.getDevices()) {
                if (!d->isWorking() || d->getDeviceType() == "EmergencyBase") continue;
                bool linked = false;
                for (Node* nb : d->getNeighbors()) if (nb->isWorking()) { linked = true; break; }
                if (!linked) { targetSweep(d); n++; }
            }
            if (n == 0) logEvent("[SWEEP] Every node already has a link.", logCyan);
        } break;
        }
    };

    // Top toolbar: every global command as a clickable pill
    struct TBtn { sf::FloatRect rect; int cmd; std::string label; };
    auto getToolbar = [&]() {
        std::vector<TBtn> btns;
        struct Def { int cmd; const char* label; };
        static const Def defs[] = {
            {CmdZoomIn,"+"}, {CmdZoomOut,"-"}, {CmdAdd,"Add"}, {CmdDel,"Del"}, {CmdClear,"Clr"},
            {CmdLoad,"Load"}, {CmdRecenter,"Center"}, {CmdSweepAll,"Sweep"}, {CmdBeacon,"Beacon"},
            {CmdDisaster,"Kill"}, {CmdDrain,"Drain"}, {CmdFlood,"Flood"}, {CmdTap,"Tap"}, {CmdFx,"FX"}
        };
        float x = 12.0f, y = 10.0f, h = 27.0f;
        for (const auto& d : defs) {
            float w = 30.0f;
            if (fontOk) { sf::Text t(font, std::string(d.label), 13); w = t.getLocalBounds().size.x + 24.0f; }
            if (w < 30.0f) w = 30.0f;
            btns.push_back({ sf::FloatRect(sf::Vector2f(x, y), sf::Vector2f(w, h)), d.cmd, d.label });
            x += w + 6.0f;
        }
        return btns;
    };

    // Smoothly-eased "on" amount per command, so a toggle pill deepens into its
    // colour instead of snapping. Indexed by Cmd.
    std::vector<float> pillAnim(CmdSweepAll + 1, 0.0f);
    // One muted accent per pill, drawn from a single cohesive palette so the
    // bar reads as a set and never glares. Creation = teal, danger = warm red,
    // signals = cyan/amber, utilities = cool slate.
    auto pillAccent = [](int cmd) -> sf::Color {
        switch (cmd) {
            case CmdZoomIn: case CmdZoomOut: return sf::Color(120, 140, 180);  // slate
            case CmdAdd:                     return sf::Color( 70, 210, 160);  // teal-green
            case CmdDel:                     return sf::Color(225, 120, 130);  // soft rose
            case CmdClear:                   return sf::Color(150, 160, 195);  // cool grey
            case CmdLoad:                    return sf::Color(110, 165, 235);  // blue
            case CmdRecenter:                return sf::Color(135, 175, 205);  // steel
            case CmdSweepAll:                return sf::Color(100, 200, 230);  // cyan
            case CmdBeacon:                  return sf::Color(245, 195, 120);  // warm amber
            case CmdDisaster:                return sf::Color(235, 115, 95);   // ember red
            case CmdDrain:                   return sf::Color(210, 180, 110);  // dim gold
            case CmdFlood:                   return sf::Color(195, 120, 215);  // violet
            case CmdTap:                     return sf::Color(160, 150, 215);  // periwinkle
            case CmdFx:                      return sf::Color(140, 130, 235);  // indigo
        }
        return sf::Color(150, 160, 195);
    };

    cout << "\n=== TACTICAL COMMAND ONLINE ===\n";
    logEvent("[SETUP] Emergency Base online. Press A to add students and build the mesh.", logCyan);
    logEvent("[SETUP] Out-of-range students auto-deploy relays. Press R to load the sample.", logInfo);

    cout << "Build mode ready. (A add, D delete, C clear, R load sample)\n";

    // Layout constants
    const sf::Vector2f HOVER_SIZE(286, 190);   // floating node-inspector size

    // Glassmorphic panel: dark translucent body, a glowing animated accent
    // bar along the top, and tactical corner brackets. Used for every HUD
    // surface so the UI reads as one cohesive sci-fi system.
    auto drawGlassPanel = [&](sf::Vector2f pos, sf::Vector2f size, sf::Color accent, float glow) {
        sf::RenderStates add; add.blendMode = sf::BlendAdd;

        // Body.
        sf::RectangleShape body(size);
        body.setPosition(pos);
        body.setFillColor(sf::Color(10, 12, 20, 205));
        body.setOutlineColor(sf::Color(accent.r, accent.g, accent.b, 60));
        body.setOutlineThickness(1.0f);
        window.draw(body);

        // Soft inner top sheen.
        sf::RectangleShape sheen(sf::Vector2f(size.x, 22.0f));
        sheen.setPosition(pos);
        sheen.setFillColor(sf::Color(accent.r, accent.g, accent.b, 16));
        window.draw(sheen, add);

        // Glowing accent bar along the very top.
        float pulse = 0.6f + 0.4f * std::sin(globalTime * 2.5f + pos.x * 0.01f);
        sf::RectangleShape bar(sf::Vector2f(size.x, 2.5f));
        bar.setPosition(pos);
        bar.setFillColor(sf::Color(accent.r, accent.g, accent.b, (std::uint8_t)(180 * glow * pulse)));
        window.draw(bar, add);

        // Corner brackets.
        float L = 14.0f, th = 2.0f;
        sf::Color cb(accent.r, accent.g, accent.b, 200);
        auto rect = [&](float x, float y, float w, float h) {
            sf::RectangleShape r(sf::Vector2f(w, h));
            r.setPosition(sf::Vector2f(x, y));
            r.setFillColor(cb);
            window.draw(r, add);
        };
        float x0 = pos.x, y0 = pos.y, x1 = pos.x + size.x, y1 = pos.y + size.y;
        rect(x0, y0, L, th); rect(x0, y0, th, L);                  // TL
        rect(x1 - L, y0, L, th); rect(x1 - th, y0, th, L);          // TR
        rect(x0, y1 - th, L, th); rect(x0, y1 - L, th, L);          // BL
        rect(x1 - L, y1 - th, L, th); rect(x1 - th, y1 - L, th, L); // BR
    };

    while (window.isOpen()) {
        float dt = clock.restart().asSeconds();
        globalTime += dt;
        introAge += dt;   // one-time intro clock - never reset, even on R reload

        // Calming ambient pad: on while deciding where to place a node.
        if (audioOk && ambientSound) {
            bool want = (buildMode == BuildMode::AddStudent);
            if (want && !ambientPlaying)      { ambientSound->play();  ambientPlaying = true;  }
            else if (!want && ambientPlaying) { ambientSound->stop();  ambientPlaying = false; }
        }

        // Security: enroll any new nodes with the base CA, refill flood tokens.
        for (Node* d : world.getDevices())
            sec.enroll(d->getDeviceID(),
                       d->getDeviceType() == "EmergencyBase" ? Clearance::Government : Clearance::Civilian);
        sec.refill(dt);

        // Automated demos
        if (globalTime > 1.0f && !demo1Fired) {
            if (directPair.first)
                spawnPacket(directPair.first, directPair.second, MessageType::SOS,
                           "Automated direct-link demo", activePackets, droppedEvents,
                           baseStationPtr, messagesDropped, "DEMO 1", logEvent);
            demo1Fired = true;
        }
        if (globalTime > 3.0f && !demo2Fired) {
            if (multiHopPair.first)
                spawnPacket(multiHopPair.first, multiHopPair.second, MessageType::SupplyRequest,
                           "Automated multi-hop relay demo", activePackets, droppedEvents,
                           baseStationPtr, messagesDropped, "DEMO 2", logEvent);
            demo2Fired = true;
        }

        // Ambient base "black hole" trickle
        if (ENABLE_AMBIENT_SUCK && baseStationPtr) {
            ambientTimer += dt;
            if (ambientTimer > 0.35f) {
                ambientTimer = 0.0f;
                float angle = (float)(rand() % 360) * 3.14159f / 180.0f;
                float spawnRadius = baseStationPtr->getSignalRange() * 0.35f;
                sf::Vector2f basePos(baseStationPtr->getPosX(), baseStationPtr->getPosY());
                sf::Vector2f spawnPos = basePos +
                    sf::Vector2f(std::cos(angle), std::sin(angle)) * spawnRadius;

                DroppedEvent amb;
                amb.origin     = spawnPos;
                amb.baseTarget = basePos;
                amb.lifespan   = 0.6f;
                droppedEvents.push_back(amb);
            }
        }

        // Ambient particle update (wrapping)
        for (auto& p : ambientParticles) {
            p.pos += p.vel * dt;
            if (p.pos.x < -2.0f)    p.pos.x += 1002.0f;
            if (p.pos.x > 1002.0f)  p.pos.x -= 1002.0f;
            if (p.pos.y < -2.0f)    p.pos.y +=  802.0f;
            if (p.pos.y >  802.0f)  p.pos.y -=  802.0f;
        }

        // ═══════════════════════════════════════════════════
        // EVENTS
        // ═══════════════════════════════════════════════════
        while (std::optional<sf::Event> event = window.pollEvent()) {
            if (event->is<sf::Event::Closed>()) {
                window.close();
            }
            else if (event->is<sf::Event::Resized>()) {
                applyLetterbox();   // re-fit the aspect-correct viewport, no stretching
            }
            else if (const auto* keyPressed = event->getIf<sf::Event::KeyPressed>()) {
                using Key = sf::Keyboard::Key;

                if (keyPressed->code == Key::Space && flowState == FlowState::None) {
                    world.runSimulation(1);
                    world.connectNeighbors();
                    logEvent("[GUI] Batteries drained. Mesh recalculated.", logWarn);
                }
                else if (keyPressed->code == Key::R && flowState == FlowState::None) {
                    world.loadDevicesFromFile("../data/nodes_config.txt");
                    world.connectNeighbors();

                    activePackets.clear();
                    droppedEvents.clear();
                    disasterEvents.clear();
                    relaySpawnPulses.clear();
                    cancelFlow();
                    buildMode = BuildMode::None;
                    isPotentialDrag = false; isDragging = false;
                    dragNode = nullptr; pendingClickNode = nullptr;
                    isPanning = false;

                    globalTime = 0.0f;
                    demo1Fired = false;
                    demo2Fired = false;
                    disasterArmed = false;
                    messagesDelivered = 0;
                    messagesDropped = 0;
                    disasterStrikesTriggered = 0;

                    baseStationPtr = nullptr;
                    for (Node* d : world.getDevices())
                        if (d->getDeviceType() == "EmergencyBase") baseStationPtr = d;

                    studentPool  = collectStudents();
                    directPair   = findDirectStudentPair(studentPool);
                    multiHopPair = findMultiHopStudentPair(studentPool);

                    retargetCamera();

                    logEvent("[RELOAD] Network reloaded. New demo pairs resolved.", logCyan);
                }
                else if (keyPressed->code == Key::X && flowState == FlowState::None) {
                    cancelFlow();
                    buildMode = BuildMode::None;
                    disasterArmed = !disasterArmed;
                    logEvent(disasterArmed
                        ? "[DISASTER] Strike mode ARMED - click anywhere to deploy EMP."
                        : "[DISASTER] Strike mode disarmed.", logWarn);
                }
                else if (keyPressed->code == Key::A && flowState == FlowState::None) {
                    cancelFlow(); disasterArmed = false;
                    buildMode = (buildMode == BuildMode::AddStudent) ? BuildMode::None : BuildMode::AddStudent;
                    logEvent(buildMode == BuildMode::AddStudent
                        ? "[CREATE] Add-Student mode - click empty space to drop a node."
                        : "[CREATE] Add-Student mode off.", buildMode == BuildMode::AddStudent ? logCyan : logWarn);
                    playSfx(SfxMode);
                }
                else if (keyPressed->code == Key::D && flowState == FlowState::None) {
                    cancelFlow(); disasterArmed = false;
                    buildMode = (buildMode == BuildMode::Delete) ? BuildMode::None : BuildMode::Delete;
                    logEvent(buildMode == BuildMode::Delete
                        ? "[DELETE] Delete mode - click a node to remove it."
                        : "[DELETE] Delete mode off.", buildMode == BuildMode::Delete ? logWarn : logWarn);
                    playSfx(SfxMode);
                }
                else if (keyPressed->code == Key::C && flowState == FlowState::None) {
                    clearToBase();
                    buildMode = BuildMode::None;
                }
                else if (keyPressed->code == Key::Escape) {
                    cancelFlow();
                    if (buildMode != BuildMode::None) {
                        buildMode = BuildMode::None;
                        logEvent("[BUILD] Mode cancelled.", logWarn);
                    }
                    disasterArmed = false;
                }
                else if (keyPressed->code == Key::F && flowState == FlowState::None) {
                    retargetCamera();
                    logEvent("[CAMERA] Recentering on network.", logCyan);
                }
                else if (keyPressed->code == Key::B && flowState == FlowState::None) {
                    fxEnabled = !fxEnabled;
                    logEvent(fxEnabled ? "[FX] Cinematic effects ON." : "[FX] Cinematic effects OFF.", logCyan);
                }
                else if (keyPressed->code == Key::G && flowState == FlowState::None && buildMode == BuildMode::None) {
                    // Beacon: command reaches outward to reassure the network.
                    if (baseStationPtr && baseStationPtr->isWorking()) {
                        sf::Vector2f bp(baseStationPtr->getPosX(), baseStationPtr->getPosY());
                        sweeps.push_back({ bp, 0.0f, sf::Color(255, 205, 120), 1.7f, 2700.0f });
                        spawnBurst(bp, sf::Color(255, 205, 120), 26, 150.0f);
                        logEvent("[BEACON] Command is online - hold on, help is coming.", logCyan);
                        playSfx(SfxBeacon);
                    }
                }
                else if (keyPressed->code == Key::J && flowState == FlowState::None && buildMode == BuildMode::None) {
                    // ADVERSARIAL FLOOD: inject a burst of spoofed low-priority
                    // traffic to show the rate-limiter / battery refusal triage.
                    std::vector<Node*> students;
                    for (Node* d : world.getDevices())
                        if (d->isWorking() && d->getDeviceType() == "StudentNode") students.push_back(d);
                    if (!students.empty() && baseStationPtr) {
                        int n = 12;
                        for (int i = 0; i < n; ++i) {
                            Node* s = students[rand() % students.size()];
                            MessageType jt = (rand() % 2) ? MessageType::SupplyRequest : MessageType::StatusUpdate;
                            spawnPacket(s, baseStationPtr, jt, "flood", activePackets, droppedEvents,
                                        baseStationPtr, messagesDropped, "ATTACK", logEvent);
                        }
                        logEvent("[ATTACK] Inbound flood - " + std::to_string(n) +
                                 " spoofed packets. Relays shedding non-SOS load.", logError);
                        if (audioOk) { disasterSound->stop(); disasterSound->play(); }
                    }
                }
                else if (keyPressed->code == Key::K && flowState == FlowState::None) {
                    // WIRE TAP: prove a relay on the path can't read the payload.
                    VisualPacket* cap = nullptr;
                    for (auto& p : activePackets) if (p.active && !p.isAck) { cap = &p; break; }
                    if (cap)
                        logEvent("[INTERCEPT] Relay tapped the wire - no endpoint key, ciphertext only: "
                                 + cipherSnippet(cap->content) + "(sealed " + clearanceName(cap->clearance) + ")", logWarn);
                    else
                        logEvent("[INTERCEPT] Wire tapped - no traffic in flight to capture.", logCyan);
                }
                else if (flowState == FlowState::ChoosingType) {
                    if (pendingReceiver == nullptr) {
                        // Stranded / sweep mode: any of [1] or Enter fires the sweep.
                        if (keyPressed->code == Key::Num1 || keyPressed->code == Key::Enter)
                            targetSweep(pendingSender);
                    }
                    else if (keyPressed->code == Key::Num1) {
                        pendingType = MessageType::SOS;
                        flowState = FlowState::TypingMessage;
                        typedMessage.clear();
                        logEvent("[CMD] Type: SOS. Type your message.", logInfo);
                        playSfx(SfxClick);
                    }
                    else if (keyPressed->code == Key::Num2) {
                        pendingType = MessageType::SupplyRequest;
                        flowState = FlowState::TypingMessage;
                        typedMessage.clear();
                        logEvent("[CMD] Type: SupplyRequest. Type your message.", logInfo);
                        playSfx(SfxClick);
                    }
                    else if (keyPressed->code == Key::Num3) {
                        pendingType = MessageType::StatusUpdate;
                        flowState = FlowState::TypingMessage;
                        typedMessage.clear();
                        logEvent("[CMD] Type: StatusUpdate. Type your message.", logInfo);
                        playSfx(SfxClick);
                    }
                }
                else if (flowState == FlowState::TypingMessage) {
                    if (keyPressed->code == Key::Backspace) {
                        if (!typedMessage.empty()) typedMessage.pop_back();
                    }
                    else if (keyPressed->code == Key::Enter) {
                        finalizeSend(baseStationPtr, logEvent);
                    }
                }
            }
            else if (const auto* textEntered = event->getIf<sf::Event::TextEntered>()) {
                if (flowState == FlowState::TypingMessage) {
                    std::uint32_t u = textEntered->unicode;
                    if (u >= 32 && u < 127 && typedMessage.size() < 80) {
                        typedMessage += static_cast<char>(u);
                    }
                }
            }
            else if (const auto* mouseBtn = event->getIf<sf::Event::MouseButtonPressed>()) {
                sf::Vector2i pixelPos(mouseBtn->position.x, mouseBtn->position.y);
                sf::Vector2f screenPos((float)pixelPos.x, (float)pixelPos.y);
                sf::Vector2f worldPos = window.mapPixelToCoords(pixelPos, worldView);

                if (mouseBtn->button == sf::Mouse::Button::Right) {
                    rightDragCandidate = true;
                    rightPressScreenPos = screenPos;
                }
                else if (mouseBtn->button == sf::Mouse::Button::Middle) {
                    isPanning = true;
                    panStartMouse  = screenPos;
                    panStartCenter = worldView.getCenter();
                }
                else if (mouseBtn->button == sf::Mouse::Button::Left) {
                    // Toolbar first: a pill click never falls through to the world.
                    // Map to UI space so it stays correct when letterboxed.
                    sf::Vector2f uiPos = window.mapPixelToCoords(pixelPos, uiView);
                    bool onToolbar = false;
                    for (const auto& b : getToolbar())
                        if (b.rect.contains(uiPos)) { runCommand(b.cmd); onToolbar = true; break; }
                    if (onToolbar) {
                        // consume - do nothing else this click
                    }
                    else if (buildMode == BuildMode::AddStudent) {
                        addStudentAt(worldPos);
                        // stay in Add mode for rapid placement; ESC to exit
                    }
                    else if (buildMode == BuildMode::Delete) {
                        Node* victim = findNodeAt(world, worldPos, /*requireWorking=*/false);
                        if (victim) deleteNode(victim);
                    }
                    else if (disasterArmed) {
                        flowState = FlowState::None;
                        float strikeRadius = 90.0f;
                        int hits = 0;
                        for (Node* d : world.getDevices()) {
                            if (d->getDeviceType() == "EmergencyBase") continue;
                            float dx = d->getPosX() - worldPos.x, dy = d->getPosY() - worldPos.y;
                            if (std::sqrt(dx*dx + dy*dy) <= strikeRadius && d->isWorking()) {
                                d->setBatteryLevel(0.0f);
                                hits++;
                            }
                        }
                        if (hits > 0) world.connectNeighbors();

                        disasterStrikesTriggered++;
                        DisasterEvent de; de.center = worldPos; de.hitCount = hits;
                        disasterEvents.push_back(de);
                        spawnBurst(worldPos, sf::Color(255, 120, 70), 46, 320.0f);

                        logEvent("[DISASTER STRIKE] " + std::to_string(hits) + " node(s) disabled.",
                                sf::Color(255, 140, 90));
                        if (audioOk) { disasterSound->stop(); disasterSound->play(); }

                        disasterArmed = false;
                        isPotentialDrag = false; isDragging = false;
                        dragNode = nullptr; pendingClickNode = nullptr;
                    }
                    else if (flowState == FlowState::ChoosingType) {
                        if (pendingReceiver == nullptr) {
                            // Sweep mode: one full-width card occupying the first button slot.
                            auto sb = getTypeButtons()[0].bounds;
                            sf::FloatRect sweepBtn(sb.position, sf::Vector2f(TypePanel::W - 40.0f, sb.size.y));
                            if (sweepBtn.contains(screenPos)) targetSweep(pendingSender);
                        } else {
                            auto buttons = getTypeButtons();
                            for (auto& b : buttons) {
                                if (b.bounds.contains(screenPos)) {
                                    pendingType = b.type;
                                    flowState = FlowState::TypingMessage;
                                    typedMessage.clear();
                                    logEvent("[CMD] Type selected: " + msgTypeName(pendingType) + ". Type your message.", logInfo);
                                    playSfx(SfxClick);
                                    break;
                                }
                            }
                        }
                    }
                    else if (flowState == FlowState::TypingMessage) {
                        // modal - ignore map clicks while typing
                    }
                    else {
                        Node* candidate = findNodeAt(world, worldPos, /*requireWorking=*/true);
                        if (candidate) {
                            dragNode = candidate;
                            pendingClickNode = candidate;
                            isPotentialDrag = (flowState == FlowState::None);
                            isDragging = false;
                            pressWorldPos = worldPos;
                        } else {
                            dragNode = nullptr;
                            pendingClickNode = nullptr;
                            isPotentialDrag = false;
                        }
                    }
                }
            }
            else if (const auto* mouseRel = event->getIf<sf::Event::MouseButtonReleased>()) {
                if (mouseRel->button == sf::Mouse::Button::Middle) {
                    isPanning = false;
                }
                else if (mouseRel->button == sf::Mouse::Button::Right) {
                    if (rightDragCandidate) {
                        // Never crossed the drag threshold - treat as a click.
                        cancelFlow();
                        isPotentialDrag = false; isDragging = false;
                        dragNode = nullptr; pendingClickNode = nullptr;
                    }
                    rightDragCandidate = false;
                    isPanning = false;
                }
                else if (mouseRel->button == sf::Mouse::Button::Left) {
                    if (disasterArmed) {
                        // handled on press
                    }
                    else if (flowState == FlowState::ChoosingType || flowState == FlowState::TypingMessage) {
                        // handled on press / via keyboard
                    }
                    else if (pendingClickNode != nullptr) {
                        if (isPotentialDrag && isDragging) {
                            world.connectNeighbors();
                            logEvent("[DRAG] " + dragNode->getDeviceID() + " repositioned.", logCyan);
                        } else {
                            handleNodeClickForFlow(pendingClickNode);
                        }
                    }
                    isPotentialDrag = false; isDragging = false;
                    dragNode = nullptr; pendingClickNode = nullptr;
                }
            }
            else if (const auto* wheel = event->getIf<sf::Event::MouseWheelScrolled>()) {
                if (wheel->wheel == sf::Mouse::Wheel::Vertical && flowState == FlowState::None) {
                    float step = (wheel->delta > 0) ? 0.90f : 1.10f;
                    targetZoomFactor = std::clamp(targetZoomFactor * step, MIN_ZOOM, MAX_ZOOM);
                }
            }
        }

        // ═══════════════════════════════════════════════════
        // CAMERA - smooth zoom, smooth recenter, direct pan
        // ═══════════════════════════════════════════════════
        sf::Vector2i mousePixelNow = sf::Mouse::getPosition(window);
        sf::Vector2f mouseScreenPos((float)mousePixelNow.x, (float)mousePixelNow.y);

        // Right-mouse is dual-purpose: a quick click still cancels the
        // current flow (handled on release below), but dragging past a
        // small threshold promotes it into a camera pan - same pattern
        // used for node-dragging just below.
        if (rightDragCandidate) {
            float rdx = mouseScreenPos.x - rightPressScreenPos.x, rdy = mouseScreenPos.y - rightPressScreenPos.y;
            if (std::sqrt(rdx * rdx + rdy * rdy) > 6.0f) {
                rightDragCandidate = false;
                isPanning = true;
                panStartMouse  = mouseScreenPos;
                panStartCenter = worldView.getCenter();
            }
        }

        if (isPanning) {
            sf::Vector2f deltaScreen = panStartMouse - mouseScreenPos;
            // The drawn content only fills the letterbox viewport, so convert
            // pixels to world units using that actual on-screen size.
            sf::FloatRect vp = worldView.getViewport();
            sf::Vector2u ws = window.getSize();
            float contentW = std::max(1.0f, vp.size.x * (float)ws.x);
            float contentH = std::max(1.0f, vp.size.y * (float)ws.y);
            sf::Vector2f scale(worldView.getSize().x / contentW,
                               worldView.getSize().y / contentH);
            sf::Vector2f newCenter = panStartCenter +
                sf::Vector2f(deltaScreen.x * scale.x, deltaScreen.y * scale.y);
            newCenter = clampCameraCenter(newCenter, world);
            worldView.setCenter(newCenter);
            targetViewCenter = newCenter;   // keep target in sync - no leftover glide once released
        } else {
            // Smooth glide toward the last requested recenter target (F / reload).
            sf::Vector2f curCenter = worldView.getCenter();
            worldView.setCenter(curCenter + (targetViewCenter - curCenter) * std::min(1.0f, dt * PAN_EASE_SPEED));
        }

        // Continuous zoom: hold Q to zoom in, E to zoom out.
        if (flowState == FlowState::None) {
            using Key = sf::Keyboard::Key;
            if (sf::Keyboard::isKeyPressed(Key::Q)) targetZoomFactor *= (1.0f - 1.1f * dt);
            if (sf::Keyboard::isKeyPressed(Key::E)) targetZoomFactor *= (1.0f + 1.1f * dt);
            targetZoomFactor = std::clamp(targetZoomFactor, MIN_ZOOM, MAX_ZOOM);
        }

        // Ease the live zoom toward its target every frame. This is what
        // turns wheel notches (and held Q/E) into a smooth glide instead
        // of the previous instant per-tick jump.
        zoomFactorLive += (targetZoomFactor - zoomFactorLive) * std::min(1.0f, dt * ZOOM_EASE_SPEED);
        worldView.setSize(baselineViewSize * zoomFactorLive);

        sf::Vector2f mouseWorldPos = window.mapPixelToCoords(mousePixelNow, worldView);

        // ═══════════════════════════════════════════════════
        // CONTINUOUS DRAG + HOVER
        // ═══════════════════════════════════════════════════
        if (isPotentialDrag) {
            if (sf::Mouse::isButtonPressed(sf::Mouse::Button::Left)) {
                float dx = mouseWorldPos.x - pressWorldPos.x, dy = mouseWorldPos.y - pressWorldPos.y;
                if (!isDragging && std::sqrt(dx*dx + dy*dy) > 12.0f) isDragging = true;
                if (isDragging && dragNode) {
                    dragNode->setPosX(mouseWorldPos.x);
                    dragNode->setPosY(mouseWorldPos.y);
                }
            } else {
                if (isDragging && dragNode) {
                    world.connectNeighbors();
                    logEvent("[DRAG] " + dragNode->getDeviceID() + " repositioned.", logCyan);
                } else if (pendingClickNode) {
                    handleNodeClickForFlow(pendingClickNode);
                }
                isPotentialDrag = false; isDragging = false;
                dragNode = nullptr; pendingClickNode = nullptr;
            }
        }

        Node* hoveredNode = nullptr;
        if (!isDragging && flowState != FlowState::ChoosingType && flowState != FlowState::TypingMessage) {
            hoveredNode = findNodeAt(world, mouseWorldPos, /*requireWorking=*/false);
        }
        {
            // Soft tick when the cursor lands on a new node (pointer compare
            // only - never dereferenced, so a since-deleted node is harmless).
            static Node* prevHovered = nullptr;
            if (hoveredNode && hoveredNode != prevHovered) playSfx(SfxHover);
            prevHovered = hoveredNode;
        }

        // ═══════════════════════════════════════════════════
        // PACKET ANIMATION
        // ═══════════════════════════════════════════════════
        std::vector<VisualPacket> pendingAcks;   // appended after the loop (safe)
        for (auto& pkt : activePackets) {
            if (!pkt.active) continue;

            int logicalIdx = pkt.waypointLogicalIndex[pkt.currentTargetIndex];
            Node* nextNode = (logicalIdx >= 0) ? pkt.routeNodes[logicalIdx] : nullptr;

            if (nextNode && !nextNode->isWorking()) {
                spawnDroppedEvent(pkt.currentPos, droppedEvents, baseStationPtr, messagesDropped);
                if (!pkt.isAck && pkt.attempts < MAX_RETRIES) {
                    // Decrypt the payload and queue a retry along a new path.
                    std::string from = pkt.routeNodes.front()->getDeviceID();
                    std::string to   = pkt.routeNodes.back()->getDeviceID();
                    std::string plain = sec.cipher(pkt.content, sec.pairKey(from, to));
                    retries.push_back({ from, to, plain, pkt.msgType, pkt.attempts + 1, RETRY_DELAY });
                    logEvent("[RETRY] route broke at " + nextNode->getDeviceID() +
                             " - recomputing a path (attempt " + std::to_string(pkt.attempts + 1) + ").", logWarn);
                } else if (!pkt.isAck) {
                    logEvent("[LOST] a sealed " + msgTypeName(pkt.msgType) +
                             " packet - no path survived after " + std::to_string(MAX_RETRIES) + " tries.", logError);
                }
                if (audioOk) { dropSound->stop(); dropSound->play(); }
                pkt.active = false;
                continue;
            }

            sf::Vector2f target = pkt.waypoints[pkt.currentTargetIndex];
            sf::Vector2f dir    = target - pkt.currentPos;
            float dist  = std::sqrt(dir.x * dir.x + dir.y * dir.y);
            float speed = pkt.isAck ? 320.0f : 240.0f;  // brisk enough to hold interest

            if (dist < 5.0f) {
                bool isFinalWaypoint = (pkt.currentTargetIndex == (int)pkt.waypoints.size() - 1);

                if (isFinalWaypoint) {
                    if (pkt.willExpire) {
                        spawnDroppedEvent(pkt.currentPos, droppedEvents, baseStationPtr, messagesDropped);
                        logEvent("[DROPPED] a sealed " + msgTypeName(pkt.msgType) + " packet - TTL exceeded before arrival.", logError);
                        if (audioOk) { dropSound->stop(); dropSound->play(); }
                    } else if (pkt.isAck) {
                        // The answer made it home to whoever first called out.
                        Node* home = pkt.routeNodes.back();
                        std::string homeID = home->getDeviceID();
                        // Hope as energy: knowing help is coming restores a little.
                        if (home->isWorking() && home->getDeviceType() == "StudentNode")
                            home->setBatteryLevel(std::min(100.0f, home->getBatteryLevel() + 1.0f));
                        logEvent("[ANSWERED] " + homeID + " heard back - help is on the way.", logSuccess);
                        spawnBurst(pkt.currentPos, sf::Color(150, 235, 210), 30, 150.0f);
                        relaySpawnPulses.push_back({ pkt.currentPos, 0.0f, sf::Color(150, 235, 210) });
                        playSfx(SfxAck);
                    } else {
                        messagesDelivered++;
                        std::string toID   = pkt.routeNodes.back()->getDeviceID();
                        std::string fromID = pkt.routeNodes.front()->getDeviceID();
                        // Decrypt with the endpoint pairwise key, then check clearance.
                        std::string plain = sec.cipher(pkt.content, sec.pairKey(fromID, toID));
                        bool authorized = sec.canRead(sec.clearanceOf(toID), pkt.clearance);
                        if (authorized)
                            logEvent("[DELIVERED - DECRYPTED] \"" + plain + "\" reached " + toID +
                                     " (" + clearanceName(pkt.clearance) + ").", logSuccess);
                        else
                            logEvent("[DELIVERED - ACCESS DENIED] " + toID + " lacks clearance for "
                                     + clearanceName(pkt.clearance) + " traffic - payload sealed.", logWarn);
                        spawnBurst(pkt.currentPos, pkt.color, 28, 200.0f);
                        if (audioOk) { deliverSound->stop(); deliverSound->play(); }

                        // The answer: a response retraces the path back to the
                        // sender, hop by hop, so they know they were heard.
                        if (pkt.routeNodes.size() >= 2) {
                            std::vector<Node*> back(pkt.routeNodes.rbegin(), pkt.routeNodes.rend());
                            VisualPath vp = buildVisualPath(back, baseStationPtr);
                            VisualPacket ack;
                            ack.routeNodes           = back;
                            ack.waypoints            = vp.points;
                            ack.waypointLogicalIndex = vp.logicalIndex;
                            ack.currentPos           = ack.waypoints[0];
                            ack.currentTargetIndex   = 1;
                            ack.isAck                = true;
                            ack.color                = sf::Color(150, 235, 210);
                            ack.content              = "ACK";
                            ack.trail.push_back(ack.currentPos);
                            pendingAcks.push_back(std::move(ack));
                        }
                    }
                    pkt.active = false;
                } else {
                    if (logicalIdx >= 0 && !pkt.isAck) {
                        Node* forwardingNode = pkt.routeNodes[logicalIdx];
                        std::string fwdID = forwardingNode->getDeviceID();
                        bool isSOS = (pkt.msgType == MessageType::SOS);

                        // Availability defenses (SOS pre-empts both)
                        // 1. Battery-aware refusal: a near-dead relay forwards only SOS.
                        if (!isSOS && forwardingNode->getBatteryLevel() < 15.0f) {
                            spawnDroppedEvent(pkt.currentPos, droppedEvents, baseStationPtr, messagesDropped);
                            logEvent("[REFUSED] " + fwdID + " is low on power - forwards SOS only.", logWarn);
                            if (audioOk) { dropSound->stop(); dropSound->play(); }
                            pkt.active = false;
                        }
                        // 2. Token-bucket rate limit: a flooded relay sheds non-SOS load.
                        else if (!isSOS && !sec.consume(fwdID)) {
                            spawnDroppedEvent(pkt.currentPos, droppedEvents, baseStationPtr, messagesDropped);
                            logEvent("[FLOOD DROP] " + fwdID + " saturated - non-SOS shed to stay alive.", logError);
                            if (audioOk) { dropSound->stop(); dropSound->play(); }
                            pkt.active = false;
                        }
                        else {
                            if (isSOS) sec.consume(fwdID);   // SOS still costs a token if available
                            float before = forwardingNode->getBatteryLevel();
                            drainNodeBattery(forwardingNode);
                            if (before > 0.0f && forwardingNode->getBatteryLevel() <= 0.0f) {
                                logEvent("[BATTERY] " + fwdID + " ran out of power.", logWarn);
                                if (audioOk) { deathSound->stop(); deathSound->play(); }
                            }
                        }
                    }
                    if (pkt.active) pkt.currentTargetIndex++;
                }
            } else {
                dir /= dist;
                pkt.currentPos += dir * speed * dt;
            }

            pkt.trail.push_back(pkt.currentPos);
            if (pkt.trail.size() > 22) pkt.trail.erase(pkt.trail.begin()); // was 14
        }
        // Append acknowledgments staged during the loop (safe now the loop is done).
        for (auto& a : pendingAcks) activePackets.push_back(std::move(a));

        // Guaranteed delivery: fire due retransmissions
        if (!retries.empty()) {
            std::vector<PendingRetry> requeue;
            for (auto& r : retries) {
                r.timer -= dt;
                if (r.timer > 0.0f) { requeue.push_back(r); continue; }
                Node* from = nullptr; Node* to = nullptr;
                for (Node* d : world.getDevices()) {
                    if (d->getDeviceID() == r.fromID) from = d;
                    if (d->getDeviceID() == r.toID)   to   = d;
                }
                if (from && to && from->isWorking()) {
                    bool ok = spawnPacket(from, to, r.type, r.content, activePackets, droppedEvents,
                                          baseStationPtr, messagesDropped, "RETRY", logEvent);
                    if (ok) {
                        activePackets.back().attempts = r.attempts;   // carry the count forward
                    } else if (r.attempts < MAX_RETRIES) {
                        r.timer = RETRY_DELAY; requeue.push_back(r);   // still no path - wait and retry
                    } else {
                        logEvent("[LOST] " + r.fromID + "'s message could not reach " + r.toID +
                                 " - network too broken.", logError);
                    }
                }
                // if endpoints vanished/died, the retry is silently abandoned
            }
            retries.swap(requeue);
        }

        // Dropped/shatter events
        for (auto& ev : droppedEvents) {
            if (!ev.active) continue;
            ev.age += dt;
            for (auto& s : ev.shards) {
                s.pos += s.vel * dt;
                s.vel *= 0.94f;
                s.life = std::max(0.0f, 1.0f - ev.age / ev.lifespan);
            }
            if (ev.age >= ev.lifespan) ev.active = false;
        }
        droppedEvents.erase(
            std::remove_if(droppedEvents.begin(), droppedEvents.end(),
                           [](const DroppedEvent& e) { return !e.active; }),
            droppedEvents.end());

        // Disaster shockwaves
        for (auto& de : disasterEvents) {
            if (!de.active) continue;
            de.age += dt;
            if (de.age >= de.lifespan) de.active = false;
        }
        disasterEvents.erase(
            std::remove_if(disasterEvents.begin(), disasterEvents.end(),
                           [](const DisasterEvent& e) { return !e.active; }),
            disasterEvents.end());

        // Relay-spawn pulses
        for (auto& rp : relaySpawnPulses) rp.age += dt;
        relaySpawnPulses.erase(
            std::remove_if(relaySpawnPulses.begin(), relaySpawnPulses.end(),
                           [](const RelaySpawnPulse& r) { return r.age > 0.6f; }),
            relaySpawnPulses.end());

        // Target Sweep rings
        for (auto& sw : sweeps) sw.age += dt;
        sweeps.erase(std::remove_if(sweeps.begin(), sweeps.end(),
                     [](const SweepRing& s) { return s.age > s.life; }), sweeps.end());

        // Spark bursts
        for (auto& s : sparks) {
            s.pos  += s.vel * dt;
            s.vel  *= 0.90f;          // drag
            s.life -= dt;
        }
        sparks.erase(std::remove_if(sparks.begin(), sparks.end(),
                     [](const Spark& s) { return s.life <= 0.0f; }), sparks.end());

        // Event lifetime: drop entries older than 8s
        eventLog.erase(std::remove_if(eventLog.begin(), eventLog.end(), [&](const LogEntry& e) {
            return (globalTime - e.spawnTime) > 8.0f;
        }), eventLog.end());

        // ═══════════════════════════════════════════════════
        // RENDER
        // ═══════════════════════════════════════════════════
#if ENABLE_BLOOM
        // The whole world (background grid + scene + glows) renders into a
        // render-texture when bloom is active; UI is drawn straight to the
        // window after compositing so it never blooms into mush.
        bool bloomActive = bloomReady && fxEnabled;
        sf::RenderTarget& scene = bloomActive ? static_cast<sf::RenderTarget&>(sceneRT)
                                              : static_cast<sf::RenderTarget&>(window);
        // The bloom RT is a fixed-size canvas, so it wants full viewports; the
        // letterbox is applied only when we present to the real window.
        if (bloomActive) {
            worldView.setViewport(sf::FloatRect({0.f, 0.f}, {1.f, 1.f}));
            uiView.setViewport(sf::FloatRect({0.f, 0.f}, {1.f, 1.f}));
        } else applyLetterbox();
#else
        sf::RenderTarget& scene = window;
        applyLetterbox();
#endif
        scene.clear(sf::Color(5, 6, 11));

        // Gravity Dot-Grid background (GLSL, screen space)
        // A dense field of dots, each with a drifting rainbow hue blended
        // with color bled from nearby gravity wells. Wells = nodes (mapped
        // to their on-screen position, weighted by type, the hovered one
        // heavier) + the cursor. Dots clump inward toward wells. The whole
        // field is one fullscreen GPU pass - no CPU geometry.
        scene.setView(uiView);
        const std::vector<Node*>& devices = world.getDevices();
        bool gridDrawn = false;
#if ENABLE_SHADERS
        if (shadersOK && fxEnabled && gridShader) {
            const int MAXW = 24;
            std::vector<sf::Glsl::Vec2> wpos(MAXW);
            std::vector<float>          wmass(MAXW, 0.0f);
            std::vector<sf::Glsl::Vec3> wcol(MAXW);
            int wi = 0;
            for (Node* d : devices) {
                if (wi >= MAXW - 1) break;          // keep a slot for the cursor
                if (!d->isWorking()) continue;
                std::string t = d->getDeviceType();
                sf::Vector2i px = scene.mapCoordsToPixel(
                    sf::Vector2f(d->getPosX(), d->getPosY()), worldView);
                wpos[wi]  = sf::Glsl::Vec2((float)px.x, (float)px.y);
                float m   = (t == "EmergencyBase") ? 1.9f : (t == "StaticRelay") ? 1.1f : 0.7f;
                if (d == hoveredNode) m *= 1.9f;    // hovered well bleeds stronger
                wcol[wi]  = (t == "EmergencyBase") ? sf::Glsl::Vec3(0.667f, 0.47f, 0.96f) :
                            (t == "StaticRelay")   ? sf::Glsl::Vec3(0.94f, 0.80f, 0.43f) :
                                                     sf::Glsl::Vec3(0.27f, 0.90f, 0.65f);
                wmass[wi] = m;
                wi++;
            }
            sf::Vector2i curPx = scene.mapCoordsToPixel(mouseWorldPos, worldView);
            wpos[wi]  = sf::Glsl::Vec2((float)curPx.x, (float)curPx.y);
            wmass[wi] = 0.8f;
            wcol[wi]  = sf::Glsl::Vec3(0.40f, 0.80f, 1.0f);

            gridShader->setUniform("u_time", globalTime);
            gridShader->setUniform("u_res", sf::Glsl::Vec2((float)WINDOW_W, (float)WINDOW_H));
            gridShader->setUniformArray("u_well", wpos.data(), MAXW);
            gridShader->setUniformArray("u_mass", wmass.data(), MAXW);
            gridShader->setUniformArray("u_wellCol", wcol.data(), MAXW);

            sf::RectangleShape full(sf::Vector2f((float)WINDOW_W, (float)WINDOW_H));
            sf::RenderStates st; st.shader = &*gridShader;
            scene.draw(full, st);
            gridDrawn = true;
        }
#endif
        if (!gridDrawn) {
            // Fallback: faint static screen-space dot grid (no shader/RGB).
            sf::RenderStates add; add.blendMode = sf::BlendAdd;
            const float sp = 21.0f;
            for (float gy = 0; gy <= WINDOW_H; gy += sp)
                for (float gx = 0; gx <= WINDOW_W; gx += sp) {
                    sf::CircleShape dot(1.2f);
                    dot.setOrigin(sf::Vector2f(1.2f, 1.2f));
                    dot.setPosition(sf::Vector2f(gx, gy));
                    dot.setFillColor(sf::Color(70, 100, 160, 32));
                    scene.draw(dot, add);
                }
        }

        scene.setView(worldView);

        // The unheard: searching pings from nodes with no path to base
        // Reachability = DFS from the base across the two-way, working-node
        // mesh. Any working node NOT in that set is cut off and "calls out"
        // with a slow cold ring that expands and fades, unanswered. Bridge
        // it into the network and the pinging simply stops.
        std::vector<const Node*> reach;
        auto inReach = [&](const Node* n) {
            for (auto* r : reach) if (r == n) return true;
            return false;
        };
        if (baseStationPtr && baseStationPtr->isWorking()) {
            std::vector<const Node*> stack{ baseStationPtr };
            reach.push_back(baseStationPtr);
            while (!stack.empty()) {
                const Node* n = stack.back(); stack.pop_back();
                for (const Node* nb : n->getNeighbors())
                    if (nb->isWorking() && !inReach(nb)) { reach.push_back(nb); stack.push_back(nb); }
            }
        }
        {
            const float PERIOD = 2.8f;
            for (size_t di = 0; di < devices.size(); ++di) {
                const Node* d = devices[di];
                if (!d->isWorking() || d->getDeviceType() == "EmergencyBase" || inReach(d)) continue;
                float maxR = d->getSignalRange() * 0.85f;
                for (int k = 0; k < 2; ++k) {
                    float t = std::fmod(globalTime + di * 0.7f + k * (PERIOD * 0.5f), PERIOD) / PERIOD;
                    float radius = 9.0f + t * maxR;
                    float a = (1.0f - t); a *= a;          // fade out as it expands
                    sf::CircleShape ring(radius);
                    ring.setOrigin(sf::Vector2f(radius, radius));
                    ring.setPosition(sf::Vector2f(d->getPosX(), d->getPosY()));
                    ring.setFillColor(sf::Color::Transparent);
                    ring.setOutlineColor(sf::Color(120, 150, 190, (std::uint8_t)(115 * a)));
                    ring.setOutlineThickness(1.4f);
                    scene.draw(ring);
                }
            }
        }

        // Connection lines + flowing energy pulses
        // Base line stays subtle; bright additive dots stream along each
        // link so the whole mesh reads as "live" rather than static wires.
        {
            sf::RenderStates add; add.blendMode = sf::BlendAdd;
            for (const Node* device : devices) {
                if (!device->isWorking()) continue;
                for (const Node* neighbor : device->getNeighbors()) {
                    if (!neighbor->isWorking()) continue;
                    sf::Vector2f A(device->getPosX(),   device->getPosY());
                    sf::Vector2f B(neighbor->getPosX(), neighbor->getPosY());

                    // Draw each undirected pair only once (by pointer order).
                    if (device > neighbor) continue;

                    sf::Vertex line[2];
                    line[0].position = A; line[0].color = sf::Color(70, 150, 255, 50);
                    line[1].position = B; line[1].color = sf::Color(70, 150, 255, 50);
                    scene.draw(line, 2, sf::PrimitiveType::Lines);

                    // Two energy dots phased apart, looping along the link.
                    sf::Vector2f AB = B - A;
                    for (int q = 0; q < 2; ++q) {
                        float phase = std::fmod(globalTime * 0.45f + q * 0.5f, 1.0f);
                        sf::Vector2f p = A + AB * phase;
                        float r = 3.2f;
                        sf::CircleShape dot(r);
                        dot.setOrigin(sf::Vector2f(r, r));
                        dot.setPosition(p);
                        dot.setFillColor(sf::Color(120, 200, 255, 150));
                        scene.draw(dot, add);
                    }
                }
            }
        }

        // Drag connectivity preview
        if (isDragging && dragNode) {
            for (Node* other : devices) {
                if (other == dragNode || !other->isWorking()) continue;
                if (dragNode->canReach(other) || other->canReach(dragNode)) {
                    sf::Vertex line[2];
                    line[0].position = sf::Vector2f(dragNode->getPosX(), dragNode->getPosY());
                    line[0].color    = sf::Color(120, 220, 255, 160);
                    line[1].position = sf::Vector2f(other->getPosX(),   other->getPosY());
                    line[1].color    = sf::Color(120, 220, 255, 160);
                    scene.draw(line, 2, sf::PrimitiveType::Lines);
                }
            }
        }

        // Nodes
        for (const Node* device : devices) {
            float x     = device->getPosX(), y = device->getPosY();
            float range = device->getSignalRange();
            string type = device->getDeviceType();
            bool isAlive = device->isWorking();

            // Selection / drag highlight rings (bigger to match bigger nodes)
            if (device == pendingSender) {
                float pulse = 0.5f + 0.5f * std::sin(globalTime * 5.0f);
                sf::CircleShape highlight(24.0f);              // was 18
                highlight.setOrigin(sf::Vector2f(24.0f, 24.0f));
                highlight.setPosition(sf::Vector2f(x, y));
                highlight.setFillColor(sf::Color::Transparent);
                highlight.setOutlineColor(sf::Color(200, 40, 70, (std::uint8_t)(140 + 115 * pulse)));
                highlight.setOutlineThickness(2.0f + pulse);
                scene.draw(highlight);
            }
            if (device == pendingReceiver &&
                (flowState == FlowState::ChoosingType || flowState == FlowState::TypingMessage)) {
                float pulse = 0.5f + 0.5f * std::sin(globalTime * 5.0f + 1.6f);
                sf::CircleShape highlight(24.0f);              // was 18
                highlight.setOrigin(sf::Vector2f(24.0f, 24.0f));
                highlight.setPosition(sf::Vector2f(x, y));
                highlight.setFillColor(sf::Color::Transparent);
                highlight.setOutlineColor(sf::Color(80, 210, 130, (std::uint8_t)(140 + 115 * pulse)));
                highlight.setOutlineThickness(2.0f + pulse);
                scene.draw(highlight);
            }
            if (device == dragNode && isDragging) {
                sf::CircleShape highlight(28.0f);              // was 20
                highlight.setOrigin(sf::Vector2f(28.0f, 28.0f));
                highlight.setPosition(sf::Vector2f(x, y));
                highlight.setFillColor(sf::Color::Transparent);
                highlight.setOutlineColor(sf::Color(120, 220, 255));
                highlight.setOutlineThickness(2.0f);
                scene.draw(highlight);
            }
            // Hover ring, color-coded per node type
            if (device == hoveredNode && device != pendingSender && device != pendingReceiver && !isDragging) {
                sf::Color hc = (type == "EmergencyBase") ? sf::Color(180, 140, 245) :
                               (type == "StaticRelay")   ? sf::Color(235, 205, 100) :
                                                            sf::Color(110, 225, 255);
                float hr = 22.0f + 2.0f * std::sin(globalTime * 6.0f);
                sf::CircleShape hoverRing(hr);
                hoverRing.setOrigin(sf::Vector2f(hr, hr));
                hoverRing.setPosition(sf::Vector2f(x, y));
                hoverRing.setFillColor(sf::Color::Transparent);
                hoverRing.setOutlineColor(sf::Color(hc.r, hc.g, hc.b, 175));
                hoverRing.setOutlineThickness(2.0f);
                scene.draw(hoverRing);
            }

            // Signal ripple
            if (isAlive) {
                float rippleRadius = std::fmod(globalTime * 40.0f, range);
                float alpha = 100.0f * (1.0f - (rippleRadius / range)); // was 120
                sf::CircleShape ripple(rippleRadius);
                ripple.setOrigin(sf::Vector2f(rippleRadius, rippleRadius));
                ripple.setPosition(sf::Vector2f(x, y));
                ripple.setFillColor(sf::Color::Transparent);
                ripple.setOutlineColor(sf::Color(150, 180, 255, (std::uint8_t)std::max(0.0f, alpha)));
                ripple.setOutlineThickness(1.5f);
                scene.draw(ripple);
            }

            // Soft glow halo (alive nodes only), gently breathing
            if (isAlive) {
                sf::Color gc = (type == "EmergencyBase") ? colorMattePurple :
                               (type == "StaticRelay")   ? colorCreamWhite  : colorSageGreen;
                float gr     = (type == "EmergencyBase") ? 21.0f :
                               (type == "StaticRelay")   ? 11.0f : 12.0f;
                float breathe = 0.85f + 0.25f * std::sin(globalTime * 2.2f + x * 0.01f);
                float intensity = (type == "EmergencyBase") ? 1.6f * breathe : breathe;
                drawGlow(scene, sf::Vector2f(x, y), gr, gc, intensity);
            }

            // Node shape: dark core + bright thin rim so it reads as a
            // luminous ring and never camouflages against the tinted grid
            auto darkCore = [](sf::Color c) {
                return sf::Color((std::uint8_t)(c.r * 0.30f), (std::uint8_t)(c.g * 0.30f),
                                 (std::uint8_t)(c.b * 0.30f));
            };
            if (type == "EmergencyBase") {
                sf::ConvexShape star = createStar(21.0f);
                star.setPosition(sf::Vector2f(x, y));
                star.setFillColor(isAlive ? darkCore(colorMattePurple) : colorDeadGrey);
                star.setOutlineColor(isAlive ? colorMattePurple : sf::Color(90, 90, 100));
                star.setOutlineThickness(2.0f);
                scene.draw(star);

                // Slow pulsing orbital ring around the base
                if (isAlive) {
                    float pr = 30.0f + 5.0f * std::sin(globalTime * 2.3f);
                    sf::CircleShape pulse(pr);
                    pulse.setOrigin(sf::Vector2f(pr, pr));
                    pulse.setPosition(sf::Vector2f(x, y));
                    pulse.setFillColor(sf::Color::Transparent);
                    pulse.setOutlineColor(sf::Color(colorMattePurple.r, colorMattePurple.g,
                                                    colorMattePurple.b, 65));
                    pulse.setOutlineThickness(1.5f);
                    scene.draw(pulse);
                }
            }
            else if (type == "StaticRelay") {
                sf::RectangleShape square(sf::Vector2f(22.0f, 22.0f));
                square.setOrigin(sf::Vector2f(11.0f, 11.0f));
                square.setPosition(sf::Vector2f(x, y));
                square.setFillColor(isAlive ? darkCore(colorCreamWhite) : colorDeadGrey);
                square.setOutlineColor(isAlive ? colorCreamWhite : sf::Color(90, 90, 100));
                square.setOutlineThickness(2.0f);
                scene.draw(square);
            }
            else {  // StudentNode
                sf::CircleShape circle(11.0f);
                circle.setOrigin(sf::Vector2f(11.0f, 11.0f));
                circle.setPosition(sf::Vector2f(x, y));
                circle.setFillColor(isAlive ? darkCore(colorSageGreen) : colorDeadGrey);
                circle.setOutlineColor(isAlive ? colorSageGreen : sf::Color(90, 90, 100));
                circle.setOutlineThickness(2.0f);
                scene.draw(circle);
            }

            // Battery bar (wider, same y-offset as before)
            if (type != "EmergencyBase") {
                float pct = std::min(1.0f, std::max(0.0f, device->getBatteryLevel() / 100.0f));
                float barWidth = 36.0f, barHeight = 5.0f;          // was 26×4
                sf::Vector2f barPos(x - barWidth / 2.0f, y + 16.0f);

                sf::RectangleShape barBg(sf::Vector2f(barWidth, barHeight));
                barBg.setPosition(barPos);
                barBg.setFillColor(sf::Color(255, 255, 255, 28));
                scene.draw(barBg);

                sf::Color fillColor = pct > 0.5f ? sf::Color(80, 210, 140) :
                                      pct > 0.2f ? sf::Color(220, 185, 70) :
                                                   sf::Color(215, 75,  75);
                sf::RectangleShape barFill(sf::Vector2f(barWidth * pct, barHeight));
                barFill.setPosition(barPos);
                barFill.setFillColor(fillColor);
                scene.draw(barFill);
            }

            // Node ID label (with a small backing plate for legibility
            // against bright connection lines / ambient particles)
            if (fontOk) {
                sf::Text nlabel(font);
                nlabel.setCharacterSize(10);
                sf::Color lc(210, 210, 222, isAlive ? 230 : 90);
                nlabel.setFillColor(lc);
                nlabel.setString(device->getDeviceID());
                sf::FloatRect lb = nlabel.getLocalBounds();
                nlabel.setOrigin(sf::Vector2f(lb.position.x + lb.size.x / 2.0f, 0.0f));
                float labelY = (type != "EmergencyBase") ? (y + 24.0f) : (y + 26.0f);
                nlabel.setPosition(sf::Vector2f(x, labelY));

                sf::RectangleShape plate(sf::Vector2f(lb.size.x + 10.0f, 14.0f));
                plate.setOrigin(sf::Vector2f(plate.getSize().x / 2.0f, 2.0f));
                plate.setPosition(sf::Vector2f(x, labelY));
                plate.setFillColor(sf::Color(8, 8, 12, isAlive ? 140 : 90));
                scene.draw(plate);
                scene.draw(nlabel);
            }
        }

        // Packets: glow -> trail -> shape (order matters for layering)
        for (const auto& pkt : activePackets) if (pkt.active) drawPacketGlow(scene, pkt, 1.0f + 0.4f * std::sin(globalTime * 11.0f));
        for (const auto& pkt : activePackets) if (pkt.active) drawTrail(scene, pkt);
        for (const auto& pkt : activePackets) if (pkt.active) drawPacketShape(scene, pkt, globalTime);

        // Shatter + "sucked into base" remnants
        for (const auto& ev : droppedEvents) {
            for (const auto& s : ev.shards) {
                sf::RectangleShape shard(sf::Vector2f(4.0f, 4.0f));
                shard.setOrigin(sf::Vector2f(2.0f, 2.0f));
                shard.setPosition(s.pos);
                shard.setRotation(sf::degrees(s.life * 180.0f));
                shard.setFillColor(sf::Color(220, 60, 60, (std::uint8_t)(s.life * 255)));
                scene.draw(shard);
            }
            float t = std::min(1.0f, ev.age / ev.lifespan);
            float easedT = t * t;
            sf::Vector2f suckPos = ev.origin + (ev.baseTarget - ev.origin) * easedT;
            float suckRadius = 5.0f * (1.0f - t);
            if (suckRadius > 0.3f) {
                sf::CircleShape remnant(suckRadius);
                remnant.setOrigin(sf::Vector2f(suckRadius, suckRadius));
                remnant.setPosition(suckPos);
                remnant.setFillColor(sf::Color(120, 100, 150, (std::uint8_t)(255 * (1.0f - t))));
                scene.draw(remnant);
            }
        }

        // Disaster strike shockwaves
        for (const auto& de : disasterEvents) {
            float t = de.age / de.lifespan;
            float radius = t * 220.0f;
            std::uint8_t alpha = (std::uint8_t)(255 * (1.0f - t));

            sf::CircleShape ring(radius);
            ring.setOrigin(sf::Vector2f(radius, radius));
            ring.setPosition(de.center);
            ring.setFillColor(sf::Color::Transparent);
            ring.setOutlineColor(sf::Color(255, 80, 80, alpha));
            ring.setOutlineThickness(3.0f);
            scene.draw(ring);

            float flashT = std::min(1.0f, de.age / 0.15f);
            if (flashT < 1.0f) {
                float flashRadius = 90.0f * (1.0f - flashT);
                sf::CircleShape flash(flashRadius);
                flash.setOrigin(sf::Vector2f(flashRadius, flashRadius));
                flash.setPosition(de.center);
                flash.setFillColor(sf::Color(255, 255, 255, (std::uint8_t)(180 * (1.0f - flashT))));
                scene.draw(flash);
            }
        }

        // Target Sweep: fast map-wide radar ring(s)
        {
            sf::RenderStates add; add.blendMode = sf::BlendAdd;
            for (const auto& sw : sweeps) {
                float t = sw.age / sw.life;
                for (int k = 0; k < 2; ++k) {
                    float tk = t - k * 0.16f;
                    if (tk <= 0.0f) continue;
                    float radius = tk * sw.maxR;              // races across the whole map
                    std::uint8_t a = (std::uint8_t)(160 * (1.0f - t));
                    sf::CircleShape ring(radius);
                    ring.setOrigin(sf::Vector2f(radius, radius));
                    ring.setPosition(sw.pos);
                    ring.setFillColor(sf::Color::Transparent);
                    ring.setOutlineColor(sf::Color(sw.color.r, sw.color.g, sw.color.b, a));
                    ring.setOutlineThickness(2.5f);
                    scene.draw(ring, add);
                }
            }
        }

        // Relay-spawn pulses (expanding gold ring where a relay appeared)
        for (const auto& rp : relaySpawnPulses) {
            float t = rp.age / 0.6f;
            float radius = 6.0f + t * 40.0f;
            std::uint8_t a = (std::uint8_t)(200 * (1.0f - t));
            sf::CircleShape ring(radius);
            ring.setOrigin(sf::Vector2f(radius, radius));
            ring.setPosition(rp.pos);
            ring.setFillColor(sf::Color::Transparent);
            ring.setOutlineColor(sf::Color(rp.color.r, rp.color.g, rp.color.b, a));
            ring.setOutlineThickness(2.0f);
            scene.draw(ring);
        }

        // Spark bursts (additive, fade + shrink)
        {
            sf::RenderStates add; add.blendMode = sf::BlendAdd;
            for (const auto& s : sparks) {
                float k = std::max(0.0f, s.life / s.maxLife);
                float r = s.radius * (0.4f + 0.6f * k);
                sf::CircleShape dot(r);
                dot.setOrigin(sf::Vector2f(r, r));
                dot.setPosition(s.pos);
                dot.setFillColor(sf::Color(s.color.r, s.color.g, s.color.b,
                                           (std::uint8_t)(235 * k)));
                scene.draw(dot, add);
            }
        }

        // Placement preview (AddStudent mode)
        // Shows, before you click, exactly what will happen: a green link
        // (direct), an amber dashed line through where a relay will drop,
        // or a red line meaning dead zone.
        if (buildMode == BuildMode::AddStudent && !isPanning) {
            Placement plan = predictPlacement(mouseWorldPos);
            sf::Color ghostCol = plan.deadZone        ? sf::Color(235, 90, 80) :
                                 (plan.relaysNeeded>0)? sf::Color(235, 190, 90) :
                                                         sf::Color(80, 210, 140);

            if (plan.anchor) {
                sf::Vector2f a(plan.anchor->getPosX(), plan.anchor->getPosY());
                sf::Vertex line[2];
                line[0].position = a;            line[0].color = sf::Color(ghostCol.r, ghostCol.g, ghostCol.b, 150);
                line[1].position = mouseWorldPos; line[1].color = sf::Color(ghostCol.r, ghostCol.g, ghostCol.b, 150);
                scene.draw(line, 2, sf::PrimitiveType::Lines);

                // Mark where each auto-relay would land.
                if (plan.relaysNeeded > 0 && !plan.deadZone) {
                    int segments = plan.relaysNeeded + 1;
                    for (int k = 1; k <= plan.relaysNeeded; ++k) {
                        float tt = (float)k / (float)segments;
                        sf::Vector2f rp = a + (mouseWorldPos - a) * tt;
                        sf::RectangleShape r(sf::Vector2f(16, 16));
                        r.setOrigin(sf::Vector2f(8, 8));
                        r.setPosition(rp);
                        r.setFillColor(sf::Color(255, 248, 218, 70));
                        r.setOutlineColor(sf::Color(235, 190, 90, 180));
                        r.setOutlineThickness(1.0f);
                        scene.draw(r);
                    }
                }
            }

            // Ghost student at the cursor.
            sf::CircleShape ghost(12.0f);
            ghost.setOrigin(sf::Vector2f(12.0f, 12.0f));
            ghost.setPosition(mouseWorldPos);
            ghost.setFillColor(sf::Color(ghostCol.r, ghostCol.g, ghostCol.b, 110));
            ghost.setOutlineColor(sf::Color(ghostCol.r, ghostCol.g, ghostCol.b, 220));
            ghost.setOutlineThickness(2.0f);
            scene.draw(ghost);
        }

#if ENABLE_BLOOM
        if (bloomActive) {
            sceneRT.display();
            const float radius = 1.6f;
            sf::Vector2f halfTexel(1.0f / (WINDOW_W / 2.0f), 1.0f / (WINDOW_H / 2.0f));

            // Bright-pass: downscale full scene into half-res bloomA.
            bloomA.clear(sf::Color(0, 0, 0, 0));
            { sf::Sprite s(sceneRT.getTexture()); s.setScale(sf::Vector2f(0.5f, 0.5f));
              sf::RenderStates st; st.shader = &brightShader;
              brightShader.setUniform("u_tex", sf::Shader::CurrentTexture);
              bloomA.draw(s, st); }
            bloomA.display();

            // Horizontal blur: bloomA -> bloomB.
            bloomB.clear(sf::Color(0, 0, 0, 0));
            { sf::Sprite s(bloomA.getTexture());
              sf::RenderStates st; st.shader = &blurShader;
              blurShader.setUniform("u_tex", sf::Shader::CurrentTexture);
              blurShader.setUniform("u_texel", sf::Glsl::Vec2(halfTexel));
              blurShader.setUniform("u_dir", sf::Glsl::Vec2(radius, 0.0f));
              bloomB.draw(s, st); }
            bloomB.display();

            // Vertical blur: bloomB -> bloomA.
            bloomA.clear(sf::Color(0, 0, 0, 0));
            { sf::Sprite s(bloomB.getTexture());
              sf::RenderStates st; st.shader = &blurShader;
              blurShader.setUniform("u_tex", sf::Shader::CurrentTexture);
              blurShader.setUniform("u_texel", sf::Glsl::Vec2(halfTexel));
              blurShader.setUniform("u_dir", sf::Glsl::Vec2(0.0f, radius));
              bloomA.draw(s, st); }
            bloomA.display();

            // Composite: present the fixed canvas into the letterboxed window.
            applyLetterbox();
            window.setView(uiView);
            { sf::Sprite s(sceneRT.getTexture()); window.draw(s); }
            { sf::Sprite s(bloomA.getTexture()); s.setScale(sf::Vector2f(2.0f, 2.0f));
              sf::RenderStates st; st.blendMode = sf::BlendAdd;
              window.draw(s, st); }
        }
#endif

        // HUD  (switch to the fixed UI view so panels/text stay
        // crisp and correctly placed regardless of world zoom/pan)
        window.setView(uiView);
        if (fontOk) {
            // Top toolbar: clickable command pills
            {
                sf::Vector2f uiMouse = window.mapPixelToCoords(mousePixelNow, uiView);
                auto blend = [](sf::Color a, sf::Color b, float t) {
                    return sf::Color(
                        (std::uint8_t)(a.r + (b.r - a.r) * t),
                        (std::uint8_t)(a.g + (b.g - a.g) * t),
                        (std::uint8_t)(a.b + (b.b - a.b) * t),
                        (std::uint8_t)(a.a + (b.a - a.a) * t));
                };
                const sf::Color DARK(15, 17, 25, 235), DEEP(9, 10, 16, 245);
                for (const auto& b : getToolbar()) {
                    bool hov = b.rect.contains(uiMouse);
                    bool active = (b.cmd == CmdAdd && buildMode == BuildMode::AddStudent)
                               || (b.cmd == CmdDel && buildMode == BuildMode::Delete)
                               || (b.cmd == CmdDisaster && disasterArmed)
                               || (b.cmd == CmdFx && fxEnabled);
                    sf::Color accent = pillAccent(b.cmd);

                    // ease the "on" amount toward its target so it deepens in
                    float& an = pillAnim[b.cmd];
                    an += ((active ? 1.0f : 0.0f) - an) * std::min(1.0f, dt * 9.0f);

                    // idle = faint accent tint; hover = a touch brighter; on = a
                    // deep, richer accent that gently breathes.
                    sf::Color idle  = blend(DARK, accent, 0.16f);
                    sf::Color hover = blend(DARK, accent, 0.34f);
                    float pulse = 0.5f + 0.5f * std::sin(globalTime * 2.4f);
                    sf::Color onCol = blend(DEEP, accent, 0.42f + 0.10f * pulse);
                    sf::Color base  = hov ? hover : idle;
                    sf::Color fill  = blend(base, onCol, an);

                    // soft accent halo behind the pill when it's on
                    if (an > 0.02f) {
                        float pad = 3.0f + 1.5f * pulse;
                        sf::Color halo = accent; halo.a = (std::uint8_t)(70 * an);
                        drawPill(window, sf::Vector2f(b.rect.position.x - pad, b.rect.position.y - pad),
                                 b.rect.size.x + pad * 2.0f, b.rect.size.y + pad * 2.0f, halo);
                    }

                    drawPill(window, b.rect.position, b.rect.size.x, b.rect.size.y, fill);

                    // thin top sheen -> subtle top-lit gradient feel
                    sf::Color sheen(255, 255, 255, (std::uint8_t)(26 + 24 * an));
                    drawPill(window, sf::Vector2f(b.rect.position.x + 3.0f, b.rect.position.y + 2.0f),
                             b.rect.size.x - 6.0f, 3.0f, sheen);

                    sf::Color tc = an > 0.5f ? blend(sf::Color(245, 250, 255), accent, 0.15f)
                                 : hov       ? blend(sf::Color(225, 233, 247), accent, 0.30f)
                                             : blend(sf::Color(160, 172, 196), accent, 0.35f);
                    sf::Text t(font, b.label, 13);
                    sf::FloatRect lb = t.getLocalBounds();
                    t.setFillColor(tc);
                    t.setPosition(sf::Vector2f(
                        b.rect.position.x + (b.rect.size.x - lb.size.x) / 2.0f - lb.position.x,
                        b.rect.position.y + (b.rect.size.y - lb.size.y) / 2.0f - lb.position.y));
                    window.draw(t);
                }
            }

            // Event stream (lower-left, char-blur, no panel)
            // Each event sentence resolves in with the char-blur reveal,
            // stacks upward (newest at the bottom), then fades away.
            {
                const float baseY = (float)WINDOW_H - 44.0f;
                const float lineH = 22.0f;
                int n = (int)eventLog.size();
                int shown = 0;
                for (int i = n - 1; i >= 0 && shown < 10; --i, ++shown) {
                    const auto& e = eventLog[i];
                    float age = globalTime - e.spawnTime;
                    float reveal = std::clamp(age / 0.5f, 0.0f, 1.0f);
                    float a = 1.0f;
                    if (age < 0.18f)      a = age / 0.18f;
                    else if (age > 6.5f)  a = std::max(0.0f, (8.0f - age) / 1.5f);
                    float y = baseY - shown * lineH;
                    if (y < 120.0f) break;

                    // Pill grows with revealed text width so it never lags the stream.
                    float fullW = charBlurWidth(font, e.text, 13, 1.6f);
                    float pillW = (12.0f + fullW * reveal + 12.0f);
                    drawPill(window, sf::Vector2f(22.0f - 12.0f, y - 3.0f),
                             pillW, 21.0f, sf::Color(6, 8, 14, (std::uint8_t)(150 * a)));

                    sf::Color col = e.color; col.a = (std::uint8_t)(235 * a);
                    drawCharBlur(window, font, e.text, sf::Vector2f(22.0f, y), 13, col, reveal, 1.6f);
                }
            }

            // Floating node inspector
            // Caches its text (so a node deleted mid-fade can't dangle),
            // eases toward an offset from the cursor, clamps on-screen, and
            // draws a faint leader line from the cursor to the nearest corner.
            {
                if (hoveredNode) {
                    std::string htype = hoveredNode->getDeviceType();
                    inspectorAccent = (htype == "EmergencyBase") ? sf::Color(180, 140, 245) :
                                      (htype == "StaticRelay")   ? sf::Color(235, 205, 100) :
                                                                    sf::Color(110, 225, 255);
                    std::ostringstream hoss;
                    hoss << "NODE INSPECTOR\n"
                         << "ID: " << hoveredNode->getDeviceID()
                         << "   Type: " << hoveredNode->getDeviceType() << "\n"
                         << "Position: (" << (int)hoveredNode->getPosX() << ", " << (int)hoveredNode->getPosY() << ")\n"
                         << "Battery: " << std::fixed << std::setprecision(1) << hoveredNode->getBatteryLevel()
                         << "%   Range: " << (int)hoveredNode->getSignalRange() << "\n"
                         << "Status: " << (hoveredNode->isWorking() ? "ONLINE" : "OFFLINE") << "\n"
                         << "Neighbors (" << hoveredNode->getNeighbors().size() << "): "
                         << joinNeighborIDs(hoveredNode) << "\n"
                         << "Inbox: " << hoveredNode->getInboxSize() << " / " << hoveredNode->getInboxLimit();
                    inspectorText = hoss.str();
                }

                float targetA = hoveredNode ? 1.0f : 0.0f;
                inspectorAlpha += (targetA - inspectorAlpha) * std::min(1.0f, dt * 14.0f);

                if (hoveredNode) {
                    // Default offset: lower-right of cursor; flip near edges.
                    sf::Vector2f off(22.0f, 18.0f);
                    sf::Vector2f target = mouseScreenPos + off;
                    if (target.x + HOVER_SIZE.x > WINDOW_W - 8)
                        target.x = mouseScreenPos.x - HOVER_SIZE.x - off.x;
                    if (target.y + HOVER_SIZE.y > WINDOW_H - 8)
                        target.y = mouseScreenPos.y - HOVER_SIZE.y - off.y;
                    target.x = std::max(8.0f, target.x);
                    target.y = std::max(8.0f, target.y);

                    if (!inspectorInit || inspectorAlpha < 0.06f) { inspectorPos = target; inspectorInit = true; }
                    else inspectorPos += (target - inspectorPos) * std::min(1.0f, dt * 16.0f);
                }

                if (inspectorAlpha > 0.02f) {
                    float a = inspectorAlpha;
                    sf::Vector2f pos = inspectorPos;

                    // Leader line: cursor tip -> nearest corner of the panel.
                    sf::Vector2f corners[4] = {
                        pos, {pos.x + HOVER_SIZE.x, pos.y},
                        {pos.x, pos.y + HOVER_SIZE.y}, {pos.x + HOVER_SIZE.x, pos.y + HOVER_SIZE.y}
                    };
                    sf::Vector2f best = corners[0]; float bd = 1e9f;
                    for (auto& c : corners) {
                        float dx = c.x - mouseScreenPos.x, dy = c.y - mouseScreenPos.y;
                        float d = dx*dx + dy*dy;
                        if (d < bd) { bd = d; best = c; }
                    }
                    sf::RenderStates add; add.blendMode = sf::BlendAdd;
                    if (hoveredNode) {
                        sf::Vertex leader[2];
                        sf::Color lc(inspectorAccent.r, inspectorAccent.g, inspectorAccent.b, (std::uint8_t)(150 * a));
                        leader[0].position = mouseScreenPos; leader[0].color = lc;
                        leader[1].position = best;           leader[1].color = lc;
                        window.draw(leader, 2, sf::PrimitiveType::Lines, add);
                        // little node at the cursor end
                        float r = 3.0f;
                        sf::CircleShape tip(r); tip.setOrigin(sf::Vector2f(r, r));
                        tip.setPosition(mouseScreenPos);
                        tip.setFillColor(lc);
                        window.draw(tip, add);
                    }
                    sf::Color lc(inspectorAccent.r, inspectorAccent.g, inspectorAccent.b, (std::uint8_t)(150 * a));

                    // Panel (alpha-scaled glass) + corner-anchor dot.
                    sf::RectangleShape body(HOVER_SIZE);
                    body.setPosition(pos);
                    body.setFillColor(sf::Color(10, 12, 20, (std::uint8_t)(212 * a)));
                    body.setOutlineColor(sf::Color(inspectorAccent.r, inspectorAccent.g, inspectorAccent.b, (std::uint8_t)(120 * a)));
                    body.setOutlineThickness(1.0f);
                    window.draw(body);

                    sf::RectangleShape bar(sf::Vector2f(HOVER_SIZE.x, 2.5f));
                    bar.setPosition(pos);
                    bar.setFillColor(sf::Color(inspectorAccent.r, inspectorAccent.g, inspectorAccent.b, (std::uint8_t)(190 * a)));
                    window.draw(bar, add);

                    float cr = 3.0f;
                    sf::CircleShape anchor(cr); anchor.setOrigin(sf::Vector2f(cr, cr));
                    anchor.setPosition(best);
                    anchor.setFillColor(lc);
                    window.draw(anchor, add);

                    sf::Text ht(font);
                    ht.setCharacterSize(13);
                    ht.setFillColor(sf::Color(228, 230, 238, (std::uint8_t)(255 * a)));
                    ht.setString(inspectorText);
                    ht.setPosition(sf::Vector2f(pos.x + 10, pos.y + 10));
                    window.draw(ht);
                }
            }

            // One-time intro: just the title, decrypting into place
            // Glyphs scramble through random characters, then lock in, hold,
            // and dissolve forever (introAge is immune to R reload).
            {
                const float STREAM = 2.2f, HOLD = 3.2f, FADE = 2.0f;
                if (introAge < HOLD + FADE) {
                    float reveal = std::clamp(introAge / STREAM, 0.0f, 1.0f);
                    float a = introAge < HOLD ? 1.0f
                            : std::max(0.0f, 1.0f - (introAge - HOLD) / FADE);
                    std::string title = "GUARDIAN MESH";
                    unsigned sz = 54; float ls = 12.0f;
                    float w = charBlurWidth(font, title, sz, ls);
                    sf::Color c(230, 240, 255); c.a = (std::uint8_t)(255 * a);
                    int seed = (int)(introAge * 24.0f);
                    drawCharScramble(window, font, title,
                                     sf::Vector2f((WINDOW_W - w) / 2.0f, WINDOW_H * 0.16f),
                                     sz, c, reveal, seed, ls);
                }
            }

            // Top-center mode banner (only when a special mode is active)
            {
                std::string banner;
                sf::Color   bannerCol(120, 200, 230);
                if (disasterArmed)                       { banner = "DISASTER STRIKE ARMED  -  click to deploy EMP   (ESC cancels)"; bannerCol = sf::Color(255, 140, 90); }
                else if (buildMode == BuildMode::AddStudent) { banner = "ADD STUDENT  -  click empty space to place   (ESC exits)"; bannerCol = sf::Color(90, 210, 150); }
                else if (buildMode == BuildMode::Delete)     { banner = "DELETE  -  click a node to remove it   (ESC exits)"; bannerCol = sf::Color(235, 150, 90); }

                if (!banner.empty()) {
                    sf::Text bt(font);
                    bt.setCharacterSize(15);
                    bt.setString(banner);
                    sf::FloatRect bb = bt.getLocalBounds();
                    float bx = (WINDOW_W - bb.size.x) / 2.0f, by = 52.0f;
                    sf::RectangleShape bg(sf::Vector2f(bb.size.x + 28, 30));
                    bg.setOrigin(sf::Vector2f(bg.getSize().x / 2.0f, 0));
                    bg.setPosition(sf::Vector2f(WINDOW_W / 2.0f, by - 6));
                    bg.setFillColor(sf::Color(14, 14, 20, 225));
                    bg.setOutlineColor(sf::Color(bannerCol.r, bannerCol.g, bannerCol.b, 160));
                    bg.setOutlineThickness(1.0f);
                    window.draw(bg);
                    bt.setFillColor(bannerCol);
                    bt.setPosition(sf::Vector2f(bx, by));
                    window.draw(bt);
                }
            }

            // Modal dim overlay
            if (flowState == FlowState::ChoosingType || flowState == FlowState::TypingMessage) {
                sf::RectangleShape dim(sf::Vector2f((float)WINDOW_W, (float)WINDOW_H));
                dim.setPosition(sf::Vector2f(0, 0));
                dim.setFillColor(sf::Color(0, 0, 0, 120));
                window.draw(dim);
            }

            // Shared cosmic panel: additive glow halo, deep-glass body, top
            // sheen, pulsing border, and corner brackets.
            auto cosmicPanel = [&](sf::Vector2f pPos, sf::Vector2f pSize, sf::Color accent) {
                float pulse = 0.5f + 0.5f * std::sin(globalTime * 2.2f);
                sf::RenderStates add; add.blendMode = sf::BlendAdd;
                for (int g = 0; g < 4; ++g) {
                    float ex = 7.0f + g * 11.0f;
                    sf::RectangleShape h(sf::Vector2f(pSize.x + ex*2, pSize.y + ex*2));
                    h.setPosition(sf::Vector2f(pPos.x - ex, pPos.y - ex));
                    h.setFillColor(sf::Color(accent.r, accent.g, accent.b, (std::uint8_t)(11 * (1.0f - g/4.0f))));
                    window.draw(h, add);
                }
                sf::RectangleShape body(pSize);
                body.setPosition(pPos);
                body.setFillColor(sf::Color(9, 12, 20, 240));
                window.draw(body);
                sf::RectangleShape sheen(sf::Vector2f(pSize.x, 28));
                sheen.setPosition(pPos);
                sheen.setFillColor(sf::Color(accent.r, accent.g, accent.b, 18));
                window.draw(sheen, add);
                sf::RectangleShape bd(pSize);
                bd.setPosition(pPos);
                bd.setFillColor(sf::Color::Transparent);
                bd.setOutlineColor(sf::Color(accent.r, accent.g, accent.b, (std::uint8_t)(110 + 90*pulse)));
                bd.setOutlineThickness(1.5f);
                window.draw(bd);
                float L = 18.0f, th = 2.0f;
                sf::Color cb(accent.r, accent.g, accent.b, 230);
                auto rc = [&](float x, float y, float w, float h) {
                    sf::RectangleShape r(sf::Vector2f(w, h)); r.setPosition(sf::Vector2f(x, y));
                    r.setFillColor(cb); window.draw(r, add);
                };
                float x0=pPos.x, y0=pPos.y, x1=pPos.x+pSize.x, y1=pPos.y+pSize.y;
                rc(x0,y0,L,th); rc(x0,y0,th,L); rc(x1-L,y0,L,th); rc(x1-th,y0,th,L);
                rc(x0,y1-th,L,th); rc(x0,y1-L,th,L); rc(x1-L,y1-th,L,th); rc(x1-th,y1-L,th,L);
            };
            auto centerText = [&](sf::Text& t, float cx, float y) {
                sf::FloatRect b = t.getLocalBounds();
                t.setPosition(sf::Vector2f(cx - b.size.x / 2.0f, y));
            };

            if (flowState == FlowState::ChoosingType && pendingReceiver == nullptr) {
                // STRANDED: Target Sweep only
                using namespace TypePanel;
                sf::Vector2f pPos(X, Y), pSize(W, H);
                sf::Color accent(255, 165, 95);
                cosmicPanel(pPos, pSize, accent);

                sf::Text title(font);
                title.setCharacterSize(15);
                title.setLetterSpacing(2.4f);
                title.setFillColor(sf::Color(255, 210, 180));
                title.setString("STRANDED  -  NO LINK");
                centerText(title, pPos.x + pSize.x/2.0f, pPos.y + 16);
                window.draw(title);

                std::string s = (pendingSender ? pendingSender->getDeviceID() : "node");
                s += "  has no path home";
                sf::Text sub(font);
                sub.setCharacterSize(12);
                sub.setLetterSpacing(1.6f);
                sub.setFillColor(sf::Color(accent.r, accent.g, accent.b, 210));
                sub.setString(s);
                centerText(sub, pPos.x + pSize.x/2.0f, pPos.y + 42);
                window.draw(sub);

                sf::Vector2f cp = getTypeButtons()[0].bounds.position;
                sf::Vector2f cs(W - 40.0f, BtnH);
                bool hov = sf::FloatRect(cp, cs).contains(mouseScreenPos);
                sf::Color sc(120, 210, 255);
                sf::RenderStates add; add.blendMode = sf::BlendAdd;
                if (hov)
                    for (int g = 0; g < 3; ++g) {
                        float ex = 4.0f + g * 6.0f;
                        sf::RectangleShape h(sf::Vector2f(cs.x + ex*2, cs.y + ex*2));
                        h.setPosition(sf::Vector2f(cp.x - ex, cp.y - ex));
                        h.setFillColor(sf::Color(sc.r, sc.g, sc.b, (std::uint8_t)(22 * (1.0f - g/3.0f))));
                        window.draw(h, add);
                    }
                sf::RectangleShape card(cs);
                card.setPosition(cp);
                card.setFillColor(hov ? sf::Color(26, 33, 46, 252) : sf::Color(16, 21, 30, 236));
                card.setOutlineColor(sf::Color(sc.r, sc.g, sc.b, hov ? 235 : 110));
                card.setOutlineThickness(hov ? 1.8f : 1.0f);
                window.draw(card);

                // radar-ring icon
                float ir = 7.0f + 3.0f * (0.5f + 0.5f * std::sin(globalTime * 4.0f));
                sf::CircleShape ring(ir);
                ring.setOrigin(sf::Vector2f(ir, ir));
                ring.setPosition(sf::Vector2f(cp.x + 30, cp.y + cs.y/2.0f));
                ring.setFillColor(sf::Color::Transparent);
                ring.setOutlineColor(sf::Color(sc.r, sc.g, sc.b, 220));
                ring.setOutlineThickness(2.0f);
                window.draw(ring, add);

                sf::Text label(font);
                label.setCharacterSize(15);
                label.setLetterSpacing(1.4f);
                label.setFillColor(hov ? sf::Color(245, 250, 255) : sf::Color(210, 230, 245));
                label.setString("[1]  TARGET SWEEP");
                label.setPosition(sf::Vector2f(cp.x + 52, cp.y + 9));
                window.draw(label);

                sf::Text desc(font);
                desc.setCharacterSize(11);
                desc.setFillColor(sf::Color(150, 175, 195, hov ? 235 : 185));
                desc.setString("scan the map, then pull into range of the nearest node");
                desc.setPosition(sf::Vector2f(cp.x + 52, cp.y + 31));
                window.draw(desc);
            }
            else if (flowState == FlowState::ChoosingType) {
                using namespace TypePanel;
                sf::Vector2f pPos(X, Y), pSize(W, H);
                sf::Color accent(120, 175, 255);
                cosmicPanel(pPos, pSize, accent);

                sf::Text title(font);
                title.setCharacterSize(15);
                title.setLetterSpacing(2.4f);
                title.setFillColor(sf::Color(225, 235, 255));
                title.setString("SELECT TRANSMISSION");
                centerText(title, pPos.x + pSize.x/2.0f, pPos.y + 16);
                window.draw(title);

                std::string s = pendingSender->getDeviceID() + "   \xE2\x86\x92   " + pendingReceiver->getDeviceID();
                sf::Text sub(font);
                sub.setCharacterSize(12);
                sub.setLetterSpacing(1.6f);
                sub.setFillColor(sf::Color(accent.r, accent.g, accent.b, 210));
                sub.setString(sf::String::fromUtf8(s.begin(), s.end()));
                centerText(sub, pPos.x + pSize.x/2.0f, pPos.y + 42);
                window.draw(sub);

                auto buttons = getTypeButtons();
                for (auto& b : buttons) {
                    bool hov = b.bounds.contains(mouseScreenPos);
                    float lift = hov ? 2.0f : 0.0f;
                    sf::Vector2f cp(b.bounds.position.x, b.bounds.position.y - lift);
                    sf::Vector2f cs(b.bounds.size.x, b.bounds.size.y);
                    sf::RenderStates add; add.blendMode = sf::BlendAdd;

                    if (hov) {
                        for (int g = 0; g < 3; ++g) {
                            float ex = 4.0f + g * 6.0f;
                            sf::RectangleShape h(sf::Vector2f(cs.x + ex*2, cs.y + ex*2));
                            h.setPosition(sf::Vector2f(cp.x - ex, cp.y - ex));
                            h.setFillColor(sf::Color(b.color.r, b.color.g, b.color.b, (std::uint8_t)(22 * (1.0f - g/3.0f))));
                            window.draw(h, add);
                        }
                    }

                    sf::RectangleShape card(cs);
                    card.setPosition(cp);
                    card.setFillColor(hov ? sf::Color(26, 31, 44, 252) : sf::Color(16, 19, 28, 236));
                    card.setOutlineColor(sf::Color(b.color.r, b.color.g, b.color.b, hov ? 230 : 90));
                    card.setOutlineThickness(hov ? 1.7f : 1.0f);
                    window.draw(card);

                    sf::RectangleShape bar(sf::Vector2f(4.0f, cs.y - 16.0f));
                    bar.setPosition(sf::Vector2f(cp.x + 9, cp.y + 8));
                    bar.setFillColor(b.color);
                    window.draw(bar, add);

                    float ir = (hov ? 7.0f : 6.0f) + 0.8f * std::sin(globalTime * 4.0f);
                    sf::CircleShape icon(ir);
                    icon.setOrigin(sf::Vector2f(ir, ir));
                    icon.setPosition(sf::Vector2f(cp.x + 32, cp.y + cs.y/2.0f));
                    icon.setFillColor(sf::Color(b.color.r, b.color.g, b.color.b, hov ? 255 : 190));
                    window.draw(icon, add);

                    sf::Text label(font);
                    label.setCharacterSize(14);
                    label.setLetterSpacing(1.3f);
                    label.setFillColor(hov ? sf::Color(245, 248, 255) : sf::Color(205, 212, 225));
                    label.setString(b.label);
                    label.setPosition(sf::Vector2f(cp.x + 52, cp.y + 9));
                    window.draw(label);

                    sf::Text desc(font);
                    desc.setCharacterSize(11);
                    desc.setFillColor(sf::Color(140, 150, 168, hov ? 235 : 180));
                    desc.setString(b.description);
                    desc.setPosition(sf::Vector2f(cp.x + 52, cp.y + 31));
                    window.draw(desc);
                }
            }
            else if (flowState == FlowState::TypingMessage) {
                sf::Vector2f pPos(250, 300), pSize(500, 196);
                sf::Color accent = colorForType(pendingType);
                cosmicPanel(pPos, pSize, accent);

                sf::Text title(font);
                title.setCharacterSize(15);
                title.setLetterSpacing(2.2f);
                title.setFillColor(sf::Color(230, 236, 248));
                std::string tn = msgTypeName(pendingType);
                for (auto& ch : tn) ch = (char)std::toupper((unsigned char)ch);
                title.setString("COMPOSE  -  " + tn);
                centerText(title, pPos.x + pSize.x/2.0f, pPos.y + 16);
                window.draw(title);

                std::string s = pendingSender->getDeviceID() + "   \xE2\x86\x92   " + pendingReceiver->getDeviceID();
                sf::Text sub(font);
                sub.setCharacterSize(12);
                sub.setLetterSpacing(1.6f);
                sub.setFillColor(sf::Color(accent.r, accent.g, accent.b, 210));
                sub.setString(sf::String::fromUtf8(s.begin(), s.end()));
                centerText(sub, pPos.x + pSize.x/2.0f, pPos.y + 42);
                window.draw(sub);

                // Input field
                sf::Vector2f ib(pPos.x + 26, pPos.y + 78), is(pSize.x - 52, 44);
                sf::RectangleShape field(is);
                field.setPosition(ib);
                field.setFillColor(sf::Color(6, 8, 14, 240));
                field.setOutlineColor(sf::Color(accent.r, accent.g, accent.b, 90));
                field.setOutlineThickness(1.0f);
                window.draw(field);
                // glowing underline
                {
                    sf::RenderStates add; add.blendMode = sf::BlendAdd;
                    float gl = 0.5f + 0.5f * std::sin(globalTime * 3.0f);
                    sf::RectangleShape ul(sf::Vector2f(is.x, 2.0f));
                    ul.setPosition(sf::Vector2f(ib.x, ib.y + is.y - 2));
                    ul.setFillColor(sf::Color(accent.r, accent.g, accent.b, (std::uint8_t)(120 + 110*gl)));
                    window.draw(ul, add);
                }

                sf::Text input(font);
                input.setCharacterSize(15);
                input.setFillColor(sf::Color(232, 236, 244));
                if (typedMessage.empty()) {
                    input.setFillColor(sf::Color(120, 128, 145, 170));
                    input.setString("type your message...");
                } else {
                    input.setString(typedMessage);
                }
                input.setPosition(sf::Vector2f(ib.x + 12, ib.y + 12));
                window.draw(input);

                // glowing block caret right after the typed text
                if (std::fmod(globalTime, 1.0f) < 0.55f && !typedMessage.empty()) {
                    sf::Text meas(font); meas.setCharacterSize(15); meas.setString(typedMessage);
                    float tw = meas.getLocalBounds().size.x;
                    sf::RenderStates add; add.blendMode = sf::BlendAdd;
                    sf::RectangleShape caret(sf::Vector2f(2.5f, 20.0f));
                    caret.setPosition(sf::Vector2f(ib.x + 13 + tw, ib.y + 12));
                    caret.setFillColor(sf::Color(accent.r, accent.g, accent.b, 230));
                    window.draw(caret, add);
                }

                // char count (right) + hint (left)
                sf::Text count(font);
                count.setCharacterSize(11);
                count.setFillColor(sf::Color(130, 138, 155, 200));
                count.setString(std::to_string(typedMessage.size()));
                {
                    sf::FloatRect cb = count.getLocalBounds();
                    count.setPosition(sf::Vector2f(ib.x + is.x - cb.size.x - 6, ib.y + is.y + 8));
                }
                window.draw(count);

                sf::Text hint(font);
                hint.setCharacterSize(11);
                hint.setLetterSpacing(1.3f);
                hint.setFillColor(sf::Color(140, 148, 165, 200));
                hint.setString("ENTER  send      ESC  cancel");
                hint.setPosition(sf::Vector2f(ib.x, ib.y + is.y + 8));
                window.draw(hint);
            }
        }

        // Final cinematic grade (drawn last, over everything)
        window.setView(uiView);
        bool overlayDrawn = false;
#if ENABLE_SHADERS
        if (shadersOK && fxEnabled && overlayShader) {
            overlayShader->setUniform("u_time", globalTime);
            overlayShader->setUniform("u_res", sf::Glsl::Vec2((float)WINDOW_W, (float)WINDOW_H));
            sf::RectangleShape full(sf::Vector2f((float)WINDOW_W, (float)WINDOW_H));
            sf::RenderStates st; st.shader = &*overlayShader;
            window.draw(full, st);
            overlayDrawn = true;
        }
#endif
        if (!overlayDrawn && fxEnabled) {
            // Minimal procedural vignette: thin darkened frame on each edge.
            const float t = 70.0f;
            sf::Color e(0, 0, 4, 70);
            sf::RectangleShape top(sf::Vector2f((float)WINDOW_W, t));   top.setPosition(sf::Vector2f(0, 0));                       top.setFillColor(e); window.draw(top);
            sf::RectangleShape bot(sf::Vector2f((float)WINDOW_W, t));   bot.setPosition(sf::Vector2f(0, (float)WINDOW_H - t));     bot.setFillColor(e); window.draw(bot);
            sf::RectangleShape lft(sf::Vector2f(t, (float)WINDOW_H));   lft.setPosition(sf::Vector2f(0, 0));                       lft.setFillColor(e); window.draw(lft);
            sf::RectangleShape rgt(sf::Vector2f(t, (float)WINDOW_H));   rgt.setPosition(sf::Vector2f((float)WINDOW_W - t, 0));     rgt.setFillColor(e); window.draw(rgt);
        }

        window.display();
    }

    // PERSIST (report's "Save & Exit")
    // On close, write the current device layout and the accumulated logs to
    // disk so a session's hand-built topology and routing history survive.
    world.saveNetworkConfig("../data/nodes_session.txt");
    world.saveAllLogs();
    cout << "[EXIT] Session topology saved to data/nodes_session.txt; logs flushed.\n";
    return 0;
}