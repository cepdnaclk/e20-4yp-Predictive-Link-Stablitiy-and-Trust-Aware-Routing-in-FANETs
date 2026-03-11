#ifndef FANET_REPOSITORIES_H
#define FANET_REPOSITORIES_H

#include <ns3/ipv4-address.h>
#include <ns3/simulator.h>
#include <cstdint>
#include <vector>
#include <map>
#include <set>

namespace ns3 {

// =====================
// PROTOCOL CONSTANTS
// =====================
inline constexpr uint16_t FANET_UDP_PORT = 9900;
inline constexpr double HELLO_INTERVAL = 0.5;
inline constexpr double TC_INTERVAL = 0.1;
inline constexpr double NEIGHBOR_TIMEOUT = 1.0;
inline constexpr double TOPOLOGY_TIMEOUT = 1.0;

// =====================
// PROTOCOL DATA STRUCTURES
// =====================

// 1-hop neighbor information
struct NeighborInfo
{
    uint32_t interface; // Incoming interface index
    Time lastSeen;      // Timestamp of the most recent HELLO received
};

// Local interface state used by routing
struct FanetInterface
{
    uint32_t ifIndex;  // Interface index
    Ipv4Address local; // Local IP address of this interface
};

// Global topology entry learned via TC
struct TopologyEntry
{
    Ipv4Address origin;                 // Node that sent the TC
    std::vector<Ipv4Address> neighbors; // Node's advertised 1-hop neighbors
    Time lastUpdate;                    // Timestamp of last TC received
};

// Routing table entry
struct RouteEntry
{
    Ipv4Address destination; // Destination IP address
    Ipv4Address nextHop;     // Next hop IP address
    uint32_t interface;      // Outgoing interface index used to reach nextHop
};

// Socket bound to a specific interface
struct InterfaceSocket
{
    Ptr<Socket> socket; // UDP socket
    uint32_t interface; // Interface index
    Ipv4Address local;  // Local IP bound to this socket
};

// =====================
// LINK METRICS
// =====================
struct LinkMetric
{
    double helloRate;    // HELLO reception ratio
    double stability;    // Neighbor lifetime
    double successRatio; // Forwarding success
    Time firstSeen;      // Timestamp of the first HELLO received     
    uint32_t helloCount; // Number of hello messages   
    uint32_t helloExpected; // Number of hello messages expected

    // Dynamic Metrics
    uint32_t txPackets = 0;      // Total data packets sent to this neighbor
    uint32_t rxPackets = 0;      // Total data packets successfully acknowledged/received
    Time totalDelay;             // Cumulative delay for latency calculation
    Time lastDelay;              // Delay of the last packet for jitter
    double jitter = 0.0;
    uint64_t totalBytes = 0;     // For throughput
    Time lastByteTime;           // Timestamp of last received byte
    
    // Calculated Getters
    double GetPDR() const { return txPackets > 0 ? (double)rxPackets / txPackets : 0.0; }
    double GetLatencyMs() const { return rxPackets > 0 ? totalDelay.GetMilliSeconds() / rxPackets : 0.0; }
    double GetThroughputKbps() const {
        double duration = (Simulator::Now() - firstSeen).GetSeconds();
        return duration > 0 ? (totalBytes * 8.0) / (duration * 1000.0) : 0.0;
    }
};

} // namespace ns3

#endif // FANET_REPOSITORIES_H
