# Guardian Mesh

**A decentralized emergency communication network simulator.**

When an earthquake takes out cell towers, phones can still talk to each other through passing messages hop by hop through short-range radio until an SOS reaches a command center. No central server. No single point of failure. The network *is* the devices.

Guardian Mesh simulates this. You build the mesh, send messages, watch them travel, and see what happens when things break.

## What It Does

You start with a single Emergency Base at the center of the screen. From there, you build outward, dropping student nodes, watching relay bridges auto-deploy to fill gaps, and wiring up a living mesh network.

Click two nodes. Pick a message type. Type your SOS. Hit enter. Then watch:

- The **packet hops** from node to node, visibly traveling the route the mesh computed
- On delivery, an **acknowledgment travels back** to the sender so they know they were heard
- If a relay **dies mid-route**, the network doesn't give up, it just recomputes a fresh path and retries up to 3 times
- **Encrypted end-to-end**: tap the wire and all you see is ciphertext
- **Flood the network** with 12 spoofed packets and watch SOS traffic survive while junk gets dropped
- Nodes with **no connection** send out cold searching pings and the base can fire a warm **beacon** across the entire map

The whole thing runs on a GPU-rendered gravity dot-grid with real bloom, procedural audio, and a title that decrypts itself on launch.

---

## The Story

This started as a second semester OOP course assignment (CS112L). The brief: model a mesh network in C++. Abstract classes, inheritance, polymorphic routing, hop-count TTL, dynamic memory, file I/O.

The CLI version did what the rubric asked. Then a professor pointed out the security was missing: "anyone on the network could read anyone's messages, and anyone can flood your system". That comment stuck.

The current version is a live immersive simulator with end-to-end encryption, clearance levels, rate-limiting, flood defense, guaranteed delivery, procedural sound, and a cosmic interface. The terminal output became a real-time visualization you can actually watch and interact with.

---

## Controls

Everything is in the **pill toolbar** at the top of the screen:

| Button | What it does |
|---|---|
| **+** / **-** | Zoom in / out |
| **Add** | Place student nodes (click empty space) |
| **Del** | Delete mode (click a node to remove it) |
| **Clr** | Reset to base only |
| **Load** | Load sample network from config file |
| **Center** | Re-center camera on the network |
| **Sweep** | Reconnect all stranded nodes |
| **Beacon** | Fire a signal of hope from the base |
| **Kill** | Arm disaster mode (click to deploy EMP) |
| **Drain** | Drain batteries across the network |
| **Flood** | Inject 12 spoofed packets (flood attack) |
| **Tap** | Intercept a packet in flight (shows ciphertext) |
| **FX** | Toggle bloom and cinematic effects |

**Sending a message:** Click a student node, click a target, pick a message type (SOS / Supply Request / Status Update), type your message, press Enter.

**Navigation:** Right-drag or middle-drag to pan. Scroll wheel to zoom.

---

## Architecture

```
Node (abstract base)
├── StudentNode      — phones, range 200, battery drains on send
├── StaticRelay      — rooftop repeaters, range 380, auto-forward everything
└── EmergencyBase    — command center, range 500, infinite battery, receives only

Packet — carries sender, receiver, content, type, hop count, TTL
Battery — composition, encapsulated charge with controlled drain
World — manages all devices, CRUD, neighbor graph, routing, simulation
SecurityManager — per-node keys, XOR cipher, clearance gating, token-bucket rate limiting
```

The GUI (`Main.cpp`) sits on top of the backend without modifying it. All routing, neighbor computation, and device management happen through the existing `World` / `Node` API.

Key systems:
- **Routing** uses BFS through the neighbor graph with two way reachability (both nodes must be in each other's range)
- **Anti-loop** via hop-count TTL (max 10), sender-ID echo check, and duplicate detection
- **Auto-relay bridging**: when you place a student too far from the mesh, relays are automatically inserted to bridge the gap
- **Guaranteed delivery**: if a relay dies mid-route, the message is re-sent along a new path (up to 3 retries)
- **Security**: FNV-hash derived keys, XOR keystream cipher, clearance levels (Civilian / Government / SOS), SOS-priority preemption, token-bucket flood defense

---

## Build

**Requirements:** C++17 compiler, CMake 3.16+, SFML 3.0 (via Homebrew on macOS)

```bash
# Install SFML (macOS)
brew install sfml

# Clone and build
git clone https://github.com/FahadRahman5/Guardian_Mesh_OOPS_Project.git
cd Guardian_Mesh_OOPS_Project
mkdir build && cd build
cmake .. -DCMAKE_PREFIX_PATH=/opt/homebrew/lib/cmake/SFML
make
./GuardianMesh
```

The `data/nodes_config.txt` file contains a sample network topology. Press **Load** in the toolbar to load it, or build your own from scratch with **Add**.

---

## Project Structure

```
├── Main.cpp              — GUI, rendering, input, audio, security layer
├── CMakeLists.txt        — build config (SFML 3, C++17)
├── include/
│   ├── Node.h            — abstract base class
│   ├── StudentNode.h
│   ├── StaticRelay.h
│   ├── EmergencyBase.h
│   ├── Packet.h          — message container with TTL
│   ├── Battery.h         — composition-based power model
│   └── World.h           — network manager, CRUD, routing
├── src/
│   ├── Node.cpp
│   ├── StudentNode.cpp
│   ├── StaticRelay.cpp
│   ├── EmergencyBase.cpp
│   ├── Packet.cpp
│   ├── Battery.cpp
│   └── World.cpp
└── data/
    └── nodes_config.txt  — sample network topology
```

---

## What I Learned

This project hit every major OOP concept and made each one feel necessary rather than academic:

- **Abstract classes** because "a device on the network" is a concept, not a concrete thing
- **Inheritance** because a phone, a relay box, and a command tent genuinely behave differently
- **Polymorphism** because the routing algorithm calls `receiveMessage()` and doesn't care what it's talking to
- **Encapsulation** because if battery charge were public, nothing would stop it going to -50%
- **Composition** because a device *has* a battery, it isn't one
- **Dynamic memory** because you can't know at compile time how many phones are in a disaster zone

---

## Acknowledgments

Built for CS112L, Spring 2026. The CLI backend was a collaborative project. The GUI, security layer, and everything visual was built on top of it as a solo extension.

Inspired by real-world mesh networking projects like [Meshtastic](https://meshtastic.org/), [goTenna](https://gotenna.com/), and the [Serval Project](http://www.servalproject.org/).
