# Require a modern version of CMake
cmake_minimum_required(VERSION 3.15)

# Name your project
project(GuardianMesh)

# Specify C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Tell CMake where your header files are
include_directories(include)

# Tell CMake where Homebrew installed SFML on your Apple Silicon Mac
set(SFML_DIR "/opt/homebrew/lib/cmake/SFML")

# Find the SFML library components (CAPITALIZED FOR SFML 3)
find_package(SFML 3 REQUIRED COMPONENTS Graphics Window System Audio)

# Gather all your .cpp files
set(SOURCES
    Main.cpp
    src/Battery.cpp
    src/EmergencyBase.cpp
    src/Node.cpp
    src/Packet.cpp
    src/StaticRelay.cpp
    src/StudentNode.cpp
    src/World.cpp
)

# Build the executable
add_executable(GuardianMesh ${SOURCES})

# Link SFML to your executable (SFML 3 Uses Namespaced Targets)
target_link_libraries(GuardianMesh PRIVATE SFML::Graphics SFML::Window SFML::System SFML::Audio)