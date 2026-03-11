#ifndef FANET_ROUTING_PROTOCOL_H
#define FANET_ROUTING_PROTOCOL_H

#include "FanetHeader.h"
#include "FanetState.h"
#include <ns3/ipv4-routing-protocol.h>
#include <ns3/ipv4-address.h>
#include <ns3/ipv4.h>
#include <ns3/socket.h>
#include <ns3/ptr.h>
#include <ns3/net-device.h>
#include <ns3/output-stream-wrapper.h>
#include <ns3/callback.h>
#include <ns3/random-variable-stream.h>

#include <map>
#include <vector>
#include <set>
#include <cstdint>
#include <cmath>
#include <ostream>
#include <memory>

namespace ns3 {

// constant definitions reused by routing and simulation
inline constexpr uint16_t FANET_UDP_PORT = 9900;
inline constexpr double HELLO_INTERVAL = 0.5;
inline constexpr double TC_INTERVAL = 0.1;
inline constexpr double NEIGHBOR_TIMEOUT = 1.0;
inline constexpr double TOPOLOGY_TIMEOUT = 1.0;

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

    // New Dynamic Metrics
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

// =====================================================================
// FANET Routing protocol declaration
// =====================================================================
class FanetRoutingProtocol : public Ipv4RoutingProtocol
{
  public:
    static TypeId GetTypeId(void);

    FanetRoutingProtocol();
    virtual ~FanetRoutingProtocol();

    // Ipv4RoutingProtocol overrides
    virtual void NotifyInterfaceUp(uint32_t interface) override;
    virtual void NotifyInterfaceDown(uint32_t interface) override;
    virtual void NotifyAddAddress(uint32_t interface, Ipv4InterfaceAddress address) override;
    virtual void NotifyRemoveAddress(uint32_t interface, Ipv4InterfaceAddress address) override;

    virtual Ptr<Ipv4Route> RouteOutput(Ptr<Packet> p,
                                       const Ipv4Header& header,
                                       Ptr<NetDevice> oif,
                                       Socket::SocketErrno& sockerr) override;

    virtual bool RouteInput(Ptr<const Packet> p,
                            const Ipv4Header& header,
                            Ptr<const NetDevice> idev,
                            const UnicastForwardCallback& ucb,
                            const MulticastForwardCallback& mcb,
                            const LocalDeliverCallback& lcb,
                            const ErrorCallback& ecb) override;

    virtual void PrintRoutingTable(Ptr<OutputStreamWrapper> stream,
                                   Time::Unit unit = Time::S) const override;

    // Initialization
    void SetIpv4(Ptr<Ipv4> ipv4);
    void InitializeInterfaces();

    // Packet handling
    void ReceiveFanetPacket(Ptr<Socket> socket);
    void ProcessFanetPacket(Ptr<Packet> packet, Ipv4Address senderIp, uint32_t incomingIface);

    // Periodic control message handling
    void SendHello();
    void SendTC();

    // Neighbor and topology Management
    void ExpireNeighbors();    // Remove stale neighbor and topology entries
    void UpdateRoutingTable(); // Build routing table using neighbor + TC info
    void OnTopologyChange();   // Triggered after topology changes

    // Q-Learning
    Ipv4Address SelectNextHopQ(Ipv4Address destination);
    void UpdateQValue(Ipv4Address dest, Ipv4Address action, double reward);
    double ComputeReward(Ipv4Address nextHop);

  private:
    // Protocol state
    Ptr<Ipv4> m_ipv4;
    std::unique_ptr<FanetState> m_state;  // Central state management (delegates all data storage)

    std::map<Ptr<Socket>, Ipv4InterfaceAddress> m_sendSockets; // One send socket per interface
    Ptr<Socket> m_recvSocket;                                  // Single receive socket

    void ComputeMprSet();

    // Lookup route to a destination
    Ptr<Ipv4Route> Lookup(Ipv4Address dest);

    // Learning parameters
    double m_alpha;
    double m_gamma;
    double m_epsilon;
};

// Helper to install the routing protocol on nodes
class FanetRoutingHelper : public Ipv4RoutingHelper
{
  public:
    FanetRoutingHelper* Copy(void) const override;
    Ptr<Ipv4RoutingProtocol> Create(Ptr<Node> node) const override;
};

} // namespace ns3

#endif // FANET_ROUTING_PROTOCOL_H
