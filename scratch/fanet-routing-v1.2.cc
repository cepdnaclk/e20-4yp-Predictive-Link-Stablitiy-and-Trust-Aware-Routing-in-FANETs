#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-packet-info-tag.h"
#include "ns3/ipv4-route.h"
#include "ns3/ipv4-routing-protocol.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"
#include "ns3/network-module.h"
#include "ns3/wifi-module.h"

using namespace ns3;

// Use the following command to run:
//      NS_LOG="FanetCustomRouting=level_all|prefix_time" ./ns3 run fanet-routing-v1.1
NS_LOG_COMPONENT_DEFINE("FanetCustomRouting");

// =====================
// PROTOCOL CONSTANTS
// =====================
static constexpr uint16_t FANET_UDP_PORT = 9900;
static constexpr double HELLO_INTERVAL = 0.5;   // Interval between HELLO packets
static constexpr double TC_INTERVAL = 0.1;      // Interval between TC packets
static constexpr double NEIGHBOR_TIMEOUT = 1.0; // Time after which a neighbor is considered stale
static constexpr double TOPOLOGY_TIMEOUT = 1.0; // Frequency to recalculate the routing table

// =====================
// PROTOCOL DATA STRUCTURES
// =====================
// Packet types exchanged by the FANET protocol
enum FanetPacketType
{
    HELLO = 1, // Neighbor discovery
    TC = 2,    // Topology control
    DATA = 3   // TODO: Data packet not implemented yet
};

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
};

// =====================
// FANET CONTROL PACKET HEADER
// =====================
struct FanetHeader : public Header
{
    uint8_t type;                       // HELLO, TC
    uint32_t seq;                       // sequence number
    uint32_t nodeId;                    // optional node identifier
    uint8_t neighborCount;              // Number of 1-hopneighbors
    std::vector<Ipv4Address> neighbors; // topology discovery
    std::vector<Ipv4Address> mprSelectorList; // Nodes that chose THIS node as MPR

    static TypeId GetTypeId(void);
    virtual TypeId GetInstanceTypeId(void) const override;
    virtual void Serialize(
        Buffer::Iterator start) const override; // Serialize header fields into packet buffer
    virtual uint32_t Deserialize(
        Buffer::Iterator start) override; // Deserialize header fields from packet buffer
    virtual uint32_t GetSerializedSize(void) const override; // Compute total serialized size
    virtual void Print(std::ostream& os) const override;     // Print for logging/debugging
};

TypeId
FanetHeader::GetTypeId(void)
{
    static TypeId tid = TypeId("FanetHeader").SetParent<Header>().AddConstructor<FanetHeader>();
    return tid;
}

TypeId
FanetHeader::GetInstanceTypeId(void) const
{
    return GetTypeId();
}

void
FanetHeader::Serialize(Buffer::Iterator start) const
{
    start.WriteU8(type);
    start.WriteHtonU32(seq);
    start.WriteHtonU32(nodeId);

    start.WriteU8(neighbors.size());
    for (auto& n : neighbors)
    {
        start.WriteHtonU32(n.Get());
    }

    // MPR - minimize the overhead of flooding
    start.WriteU8(mprSelectorList.size());
    for (auto& m : mprSelectorList) start.WriteHtonU32(m.Get());
}

uint32_t
FanetHeader::Deserialize(Buffer::Iterator start)
{
    uint32_t bytesRead = 0;
    type = start.ReadU8();
    bytesRead += 1;
    seq = start.ReadNtohU32();
    bytesRead += 4;
    nodeId = start.ReadNtohU32();
    bytesRead += 4;
    neighborCount = start.ReadU8();
    bytesRead += 1;

    neighbors.clear();
    neighbors.reserve(neighborCount);
    for (uint8_t i = 0; i < neighborCount; i++)
    {
        neighbors.push_back(Ipv4Address(start.ReadNtohU32()));
        bytesRead += 4;
    }
    // Read MPR list
    uint8_t mprCount = start.ReadU8(); bytesRead += 1;
    mprSelectorList.clear();
    mprSelectorList.reserve(mprCount);
    for (uint8_t i = 0; i < mprCount; i++)
    {
        mprSelectorList.push_back(Ipv4Address(start.ReadNtohU32()));
        bytesRead += 4;
    }
    return bytesRead;
}
// MPR - minimize the overhead of flooding
uint32_t
FanetHeader::GetSerializedSize(void) const
{
    return 1 + 4 + 4 + 1 + (4 * neighbors.size()) + 1 + (4 * mprSelectorList.size()); // type + seq + nodeId + neighborCount + neighbors
}

void
FanetHeader::Print(std::ostream& os) const
{
    os << "[FanetHeader type=" << (uint32_t)type << " seq=" << seq << " nodeId=" << nodeId << "]";
}

// =====================================================================
// FANET ROUTING PROTOCOL
// =====================================================================
//

/*
 * Features:
 * - Periodically sends HELLO messages to discover 1-hop neighbors.
 * - Periodically sends TC messages to advertise 1-hop neighbors to multi-hop nodes.
 * - Maintains a neighbor table and a multi-hop topology table.
 * - Builds a simple routing table based on neighbor and TC information using BFS.
 * - Forwards packets using the routing table.
 *
 * TODO:
 * - Implement MPR to control flooding
 * - Add link state matrices
 * - Update the roting table calculation
 */

class FanetRoutingProtocol : public Ipv4RoutingProtocol
{
  public:
    static TypeId GetTypeId(void);

    FanetRoutingProtocol()
    {
    }

    virtual ~FanetRoutingProtocol()
    {
    }

    // Ipv4RoutingProtocol overrides
    virtual void NotifyInterfaceUp(uint32_t interface) override
    {
    }

    virtual void NotifyInterfaceDown(uint32_t interface) override
    {
    }

    virtual void NotifyAddAddress(uint32_t interface, Ipv4InterfaceAddress address) override
    {
    }

    virtual void NotifyRemoveAddress(uint32_t interface, Ipv4InterfaceAddress address) override
    {
    }

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

    std::vector<FanetInterface> m_interfaces;                  // Per-interface information
    std::map<Ptr<Socket>, Ipv4InterfaceAddress> m_sendSockets; // One send socket per interface
    Ptr<Socket> m_recvSocket;                                  // Single receive socket

    std::map<Ipv4Address, NeighborInfo> m_neighborTable;  // 1-hop neighbors for HELLO
    std::map<Ipv4Address, TopologyEntry> m_topologyTable; // Neighbors of neighbors for TC
    std::map<Ipv4Address, RouteEntry> m_routingTable;     // Current routing table
    std::map<Ipv4Address, uint32_t> m_lastTcSeq;          // Last received TC sequence per node

    // MPR - minimize the overhead of flooding
    std::map<Ipv4Address, std::vector<Ipv4Address>> m_twoHopNeighbors; // 2-hop topology (1-hop neighbor -> list of their neighbors)
    std::set<Ipv4Address> m_mprSet;       // Neighbors THIS node selected to be relays
    std::set<Ipv4Address> m_mprSelectors; // Neighbors that selected THIS node as a relay

    uint32_t m_helloSeq = 0; // HELLO sequence counter
    uint32_t m_tcSeq = 0;    // TC sequence counter

    void ComputeMprSet();

    // Lookup route to a destination
    Ptr<Ipv4Route> Lookup(Ipv4Address dest);

    // Link matrics of each interface
    std::map<Ipv4Address, LinkMetric> m_linkMetrics;

    // Q-Learning state
    std::map<Ipv4Address, std::map<Ipv4Address, double>> m_qTable;

    // Learning parameters
    double m_alpha = 0.5;   // learning rate
    double m_gamma = 0.8;   // discount factor
    double m_epsilon = 0.1; // exploration probability
};

NS_OBJECT_ENSURE_REGISTERED(FanetRoutingProtocol);

// Select 1-hop neighbors that are the only way to reach a specific 2-hop neighbor
// While there are uncovered 2-hop neighbors, select the 1-hop neighbor that covers the maximum number of uncovered 2-hop nodes
void 
FanetRoutingProtocol::ComputeMprSet() {
    m_mprSet.clear();
    std::set<Ipv4Address> uncoveredTwoHop;
    // 1. Identify all 2-hop neighbors not reachable via 1-hop
    for (auto const& [neighbor, twoHopList] : m_twoHopNeighbors) {
        for (auto const& twoHop : twoHopList) {
            if (twoHop != m_interfaces[0].local && m_neighborTable.find(twoHop) == m_neighborTable.end()) {
                uncoveredTwoHop.insert(twoHop);
            }
        }
    }
    // 2. Greedy Selection
    while (!uncoveredTwoHop.empty()) {
        Ipv4Address bestNbr;
        uint32_t maxCovered = 0;
        for (auto const& [neighbor, _] : m_neighborTable) {
            uint32_t coverage = 0;
            for (auto const& target : m_twoHopNeighbors[neighbor]) {
                if (uncoveredTwoHop.count(target)) coverage++;
            }
            if (coverage > maxCovered) {
                maxCovered = coverage;
                bestNbr = neighbor;
            }
        }
        if (maxCovered == 0) break;
        m_mprSet.insert(bestNbr);
        // Remove covered nodes from the set
        for (auto const& target : m_twoHopNeighbors[bestNbr]) {
            uncoveredTwoHop.erase(target);
        }
    }
}

// Print the current routing table for debugging
void
FanetRoutingProtocol::PrintRoutingTable(Ptr<OutputStreamWrapper> stream, Time::Unit unit) const
{
    for (const auto& [dest, entry] : m_routingTable)
    {
        *stream->GetStream() << "Dest: " << dest << " NextHop: " << entry.nextHop
                             << " Interface: " << entry.interface << std::endl;
    }
}

// Set the Ipv4 object for this node and start protocol timers
void
FanetRoutingProtocol::SetIpv4(Ptr<Ipv4> ipv4)
{
    m_ipv4 = ipv4;
    Ptr<Node> node = ipv4->GetObject<Node>();
    NS_ASSERT(node);

    // 1. Initialize interfaces immediately
    Simulator::Schedule(Seconds(0.0), &FanetRoutingProtocol::InitializeInterfaces, this);

    // 2. Start HELLO messages periodically once interfaces exist
    Simulator::Schedule(Seconds(0.0), &FanetRoutingProtocol::SendHello, this);

    // 3. Start neighbor and topology expiry process
    ExpireNeighbors();
}

// Initialize sockets and interface information
// Creates a single receive socket and one send socket per interface
void
FanetRoutingProtocol::InitializeInterfaces()
{
    m_interfaces.clear();
    m_sendSockets.clear();

    for (uint32_t i = 0; i < m_ipv4->GetNInterfaces(); ++i)
    {
        // Skip loopback
        if (!m_ipv4->IsUp(i) || m_ipv4->GetNAddresses(i) == 0 || i == 0)
        {
            continue;
        }

        FanetInterface iface;
        iface.ifIndex = i;
        iface.local = m_ipv4->GetAddress(i, 0).GetLocal();
        m_interfaces.push_back(iface);

        // Create a single receive socket for all interfaces (only once)
        if (!m_recvSocket)
        {
            m_recvSocket = Socket::CreateSocket(m_ipv4->GetObject<Node>(),
                                                TypeId::LookupByName("ns3::UdpSocketFactory"));
            m_recvSocket->SetAllowBroadcast(true);
            InetSocketAddress inetAddr(Ipv4Address::GetAny(), FANET_UDP_PORT);
            m_recvSocket->SetRecvCallback(
                MakeCallback(&FanetRoutingProtocol::ReceiveFanetPacket, this));
            if (m_recvSocket->Bind(inetAddr))
            {
                NS_FATAL_ERROR("Failed to bind() FANET receive socket");
            }
            m_recvSocket->SetRecvPktInfo(true);
            NS_LOG_INFO("FANET receive socket created on node "
                        << m_ipv4->GetObject<Node>()->GetId());
        }

        // Create a send socket for each interface
        Ptr<Socket> sendSocket =
            Socket::CreateSocket(m_ipv4->GetObject<Node>(),
                                 TypeId::LookupByName("ns3::UdpSocketFactory"));
        sendSocket->SetAllowBroadcast(true);
        InetSocketAddress sendAddr(m_ipv4->GetAddress(i, 0).GetLocal(), FANET_UDP_PORT);
        sendSocket->BindToNetDevice(m_ipv4->GetNetDevice(i));
        if (sendSocket->Bind(sendAddr))
        {
            NS_FATAL_ERROR("Failed to bind() FANET send socket on interface " << i);
        }
        sendSocket->SetRecvPktInfo(true);
        m_sendSockets[sendSocket] = m_ipv4->GetAddress(i, 0);

        NS_LOG_INFO("Send socket created on node " << m_ipv4->GetObject<Node>()->GetId()
                                                   << " for interface " << i << " with IP "
                                                   << iface.local);
    }
}

// Periodically remove stale neighbors and topology entries
void
FanetRoutingProtocol::ExpireNeighbors()
{
    Time now = Simulator::Now();
    bool changed = false;

    // Expire neighbors
    for (auto it = m_neighborTable.begin(); it != m_neighborTable.end();)
    {
        auto& metric = m_linkMetrics[it->first];
        Time lifetime = Simulator::Now() - metric.firstSeen;
        metric.stability = lifetime.GetSeconds();

        if (now - it->second.lastSeen > Seconds(3))
        {
            // penalize expired neighbor
            metric.successRatio *= 0.7;

            it = m_neighborTable.erase(it);
            continue;
        }
        else
        {
            ++it;
        }
    }

    // Expire topology entries
    for (auto it = m_topologyTable.begin(); it != m_topologyTable.end();)
    {
        if (now - it->second.lastUpdate > Seconds(3))
        {
            it = m_topologyTable.erase(it);
            changed = true;
        }
        else
        {
            ++it;
        }
    }

    if (changed)
    {
        UpdateRoutingTable();
    }

    // Reschedule
    Simulator::Schedule(Seconds(NEIGHBOR_TIMEOUT), &FanetRoutingProtocol::ExpireNeighbors, this);
}

// Periodically send HELLO messages to discover neighbors
void
FanetRoutingProtocol::SendHello()
{
    for (auto& [nbr, metric] : m_linkMetrics)
    {
        metric.helloExpected++;
    }

    for (const auto& [sock, addr] : m_sendSockets)
    {
        Ptr<Packet> packet = Create<Packet>();
        FanetHeader header;
        header.type = HELLO;
        header.seq = m_helloSeq++;
        header.nodeId = m_ipv4->GetObject<Node>()->GetId();
        packet->AddHeader(header);

        InetSocketAddress dst(Ipv4Address::GetBroadcast(), FANET_UDP_PORT);
        sock->SendTo(packet, 0, dst);

        NS_LOG_INFO("Node " << addr.GetLocal() << " sent HELLO");
    }

    // Reschedule automatically
    Simulator::Schedule(Seconds(HELLO_INTERVAL), &FanetRoutingProtocol::SendHello, this);
}

// Periodically send TC messages to advertise its 1-hop neighbors
void
FanetRoutingProtocol::SendTC()
{
    if (m_neighborTable.empty())
    {
        // No neighbor yet, try again later
        Simulator::Schedule(Seconds(TC_INTERVAL), &FanetRoutingProtocol::SendTC, this);
        return;
    }

    for (const auto& [sock, addr] : m_sendSockets)
    {
        Ptr<Packet> packet = Create<Packet>();
        FanetHeader header;
        header.type = TC;
        header.seq = m_tcSeq++;
        header.nodeId = m_ipv4->GetObject<Node>()->GetId();

        // Copy direct neighbors
        for (const auto& [neighborIp, _] : m_neighborTable)
        {
            header.neighbors.push_back(neighborIp);
        }

        packet->AddHeader(header);
        InetSocketAddress dst(Ipv4Address::GetBroadcast(), FANET_UDP_PORT);
        sock->SendTo(packet, 0, dst);

        NS_LOG_INFO("Node " << addr.GetLocal() << " sent TC");
    }

    // Reschedule automatically
    Simulator::Schedule(Seconds(TC_INTERVAL), &FanetRoutingProtocol::SendTC, this);
}

// Receive a packet from the network and process it
void
FanetRoutingProtocol::ReceiveFanetPacket(Ptr<Socket> socket)
{
    Address from;
    Ptr<Packet> packet = socket->RecvFrom(from);
    if (!packet)
    {
        return;
    }

    InetSocketAddress sender = InetSocketAddress::ConvertFrom(from);
    Ipv4Address senderIp = sender.GetIpv4();

    // Extract incoming interface from packet tag (set by SetRecvPktInfo)
    Ipv4PacketInfoTag interfaceInfo;
    uint32_t incomingIface = UINT32_MAX;

    if (packet->RemovePacketTag(interfaceInfo))
    {
        Ptr<Node> node = m_ipv4->GetObject<Node>();
        Ptr<NetDevice> dev = node->GetDevice(interfaceInfo.GetRecvIf());
        incomingIface = m_ipv4->GetInterfaceForDevice(dev);
    }

    if (incomingIface == UINT32_MAX)
    {
        NS_LOG_WARN("Unknown incoming interface");
        return;
    }

    // Ignore packets from ourselves
    int32_t interfaceForAddress = m_ipv4->GetInterfaceForAddress(senderIp);
    if (interfaceForAddress != -1)
    {
        NS_LOG_LOGIC("Ignoring a packet sent by myself.");
        return;
    }

    ProcessFanetPacket(packet, senderIp, incomingIface);
}

// Parse a FANET packet and update neighbor/topology info
void
FanetRoutingProtocol::ProcessFanetPacket(Ptr<Packet> packet,
                                         Ipv4Address senderIp,
                                         uint32_t incomingIface)
{
    NS_LOG_INFO("Process fanet packets");
    FanetHeader fanet;
    if (!packet->PeekHeader(fanet))
    {
        NS_LOG_WARN("Failed to peek FANET header");
        return;
    }
    packet->RemoveHeader(fanet);

    if (fanet.type == HELLO)
    {
        bool changed = false;
        auto& metric = m_linkMetrics[senderIp];
        if (metric.helloCount == 0)
        {
            metric.firstSeen = Simulator::Now();
        }

        metric.helloCount++;
        metric.helloExpected++;

        metric.helloRate =
            static_cast<double>(metric.helloCount) / std::max(1u, metric.helloExpected);

        auto it = m_neighborTable.find(senderIp);
        if (it == m_neighborTable.end())
        {
            NeighborInfo info;
            info.interface = incomingIface;
            info.lastSeen = Simulator::Now();
            m_neighborTable[senderIp] = info;
            changed = true;

            NS_LOG_INFO("Discovered new neighbor " << senderIp << " on iface " << incomingIface);
        }
        else
        {
            it->second.lastSeen = Simulator::Now();
        }

        if (changed)
        {
            UpdateRoutingTable();
        }
    }
    else if (fanet.type == TC)
    {
        auto lastSeqIt = m_lastTcSeq.find(senderIp);
        if (lastSeqIt != m_lastTcSeq.end() && fanet.seq <= lastSeqIt->second)
        {
            return;
        }

        m_lastTcSeq[senderIp] = fanet.seq;

        TopologyEntry& entry = m_topologyTable[senderIp];
        entry.origin = senderIp;
        entry.neighbors = fanet.neighbors;
        entry.lastUpdate = Simulator::Now();

        // MPR FLOODING CONTROL
        // Only forward TC if the sender is someone who selected US as an MPR
        if (m_mprSelectors.find(senderIp) == m_mprSelectors.end()) 
        {
            NS_LOG_INFO("TC from " << senderIp << " ignored for forwarding (not an MPR selector).");
            UpdateRoutingTable();
            return; 
        }
        NS_LOG_INFO("Forwarding TC from " << senderIp << " as MPR relay.");
        // Forward TC packets to all interfaces except the incoming one
        for (const auto& [sock, addr] : m_sendSockets)
        {
            uint32_t sockInterface = m_ipv4->GetInterfaceForAddress(addr.GetLocal());
            if (sockInterface == incomingIface)
            {
                continue;
            }

            Ptr<Packet> fwd = packet->Copy();
            fwd->AddHeader(fanet);
            InetSocketAddress dst(Ipv4Address::GetBroadcast(), FANET_UDP_PORT);
            sock->SendTo(fwd, 0, dst);
        }

        UpdateRoutingTable();
    }
}

// Build or rebuild the routing table using neighbor + TC info
// TODO: Use Q-Learning instead of BFS traversal
void
FanetRoutingProtocol::UpdateRoutingTable()
{
    m_routingTable.clear();

    for (const auto& [dest, topo] : m_topologyTable)
    {
        if (m_neighborTable.empty())
        {
            continue;
        }

        Ipv4Address nextHop = SelectNextHopQ(dest);

        auto nbrIt = m_neighborTable.find(nextHop);
        if (nbrIt == m_neighborTable.end())
        {
            continue;
        }

        RouteEntry entry;
        entry.destination = dest;
        entry.nextHop = nextHop;
        entry.interface = nbrIt->second.interface;

        m_routingTable[dest] = entry;
    }
}

// Lookup route to a destination
// Checks neighbors first, then routing table
Ptr<Ipv4Route>
FanetRoutingProtocol::Lookup(Ipv4Address dest)
{
    // 1. Check Neighbor Table First (Direct 1-Hop)
    auto neighborIt = m_neighborTable.find(dest);
    if (neighborIt != m_neighborTable.end())
    {
        NS_LOG_LOGIC("Lookup: " << dest << " found in Neighbor Table.");

        uint32_t iface = neighborIt->second.interface;

        Ptr<Ipv4Route> route = Create<Ipv4Route>();
        route->SetDestination(dest);
        route->SetGateway(dest); // Next hop is the destination itself
        route->SetSource(m_ipv4->GetAddress(iface, 0).GetLocal());
        route->SetOutputDevice(m_ipv4->GetNetDevice(iface));
        return route;
    }

    // 2. Check Routing Table (Multi-Hop)
    auto routeIt = m_routingTable.find(dest);
    if (routeIt != m_routingTable.end())
    {
        NS_LOG_LOGIC("Lookup: " << dest << " found in Routing Table.");
        RouteEntry entry = routeIt->second;
        Ptr<Ipv4Route> route = Create<Ipv4Route>();
        route->SetDestination(entry.destination);
        route->SetGateway(entry.nextHop);
        route->SetSource(m_ipv4->GetAddress(entry.interface, 0).GetLocal());
        route->SetOutputDevice(m_ipv4->GetNetDevice(entry.interface));
        return route;
    }

    return nullptr;
}

TypeId
FanetRoutingProtocol::GetTypeId(void)
{
    static TypeId tid = TypeId("ns3::FanetRoutingProtocol")
                            .SetParent<Ipv4RoutingProtocol>()
                            .SetGroupName("Internet")
                            .AddConstructor<FanetRoutingProtocol>();
    return tid;
}

// Forward packets from local stack
Ptr<Ipv4Route>
FanetRoutingProtocol::RouteOutput(Ptr<Packet> p,
                                  const Ipv4Header& header,
                                  Ptr<NetDevice> oif,
                                  Socket::SocketErrno& sockerr)
{
    Ipv4Address dest = header.GetDestination();

    // 1. Check the Routing Table
    Ptr<Ipv4Route> route = Lookup(dest);

    if (route)
    {
        NS_LOG_INFO("Node " << m_ipv4->GetAddress(1, 0).GetLocal() << " sending packet to " << dest
                            << " via gateway " << route->GetGateway() << " on interface "
                            << route->GetOutputDevice()->GetIfIndex());
        sockerr = Socket::ERROR_NOTERROR;
        return route;
    }

    // 2. Fallback: If no route exists
    NS_LOG_DEBUG("No route found for " << dest);
    sockerr = Socket::ERROR_NOROUTETOHOST;
    return nullptr;
}

// Handle packets received from the network
bool
FanetRoutingProtocol::RouteInput(Ptr<const Packet> p,
                                 const Ipv4Header& header,
                                 Ptr<const NetDevice> idev,
                                 const UnicastForwardCallback& ucb,
                                 const MulticastForwardCallback& mcb,
                                 const LocalDeliverCallback& lcb,
                                 const ErrorCallback& ecb)
{
    NS_LOG_FUNCTION(this << header.GetDestination());

    Ipv4Address dest = header.GetDestination();

    // Get the incoming interface index
    NS_ASSERT(m_ipv4->GetInterfaceForDevice(idev) >= 0);
    uint32_t iif = m_ipv4->GetInterfaceForDevice(idev);

    // Local Delivery Check: includes broadcasts and node's own addresses
    if (m_ipv4->IsDestinationAddress(dest, iif))
    {
        if (!lcb.IsNull())
        {
            NS_LOG_LOGIC("Local delivery to " << dest << " on interface " << iif);
            lcb(p, header, iif);
            return true;
        }
        else
        {
            // Null local delivery callback - let other protocols handle it
            return false;
        }
    }

    // Forwarding Check (Using the Routing Table)
    Ptr<Ipv4Route> route = Lookup(dest);

    if (!route)
    {
        ecb(p, header, Socket::ERROR_NOROUTETOHOST);
        return false;
    }

    if (route)
    {
        NS_LOG_INFO("Node " << m_ipv4->GetAddress(1, 0).GetLocal() << " forwarding packet to "
                            << dest << " via gateway " << route->GetGateway() << " on interface "
                            << route->GetOutputDevice()->GetIfIndex());
        auto& metric = m_linkMetrics[route->GetGateway()];
        metric.successRatio = 0.9 * metric.successRatio + 0.1;
        double reward = ComputeReward(route->GetGateway());
        UpdateQValue(dest, route->GetGateway(), reward);
        ucb(route, p, header);
        return true;
    }

    // No route found
    NS_LOG_DEBUG("No route for " << dest << ". Dropping.");
    return false;
}

// Helper class to install the protocol
class FanetRoutingHelper : public Ipv4RoutingHelper
{
  public:
    FanetRoutingHelper* Copy(void) const override
    {
        return new FanetRoutingHelper(*this);
    }

    Ptr<Ipv4RoutingProtocol> Create(Ptr<Node> node) const override
    {
        return CreateObject<FanetRoutingProtocol>();
    }
};

// Choose Action (ε-greedy)
Ipv4Address
FanetRoutingProtocol::SelectNextHopQ(Ipv4Address destination)
{
    // Exploration
    if (UniformRandomVariable().GetValue() < m_epsilon)
    {
        auto it = m_neighborTable.begin();
        std::advance(it, rand() % m_neighborTable.size());
        return it->first;
    }

    // Exploitation
    double bestQ = -1e9;
    Ipv4Address bestNbr = Ipv4Address::GetZero();

    for (const auto& [nbr, info] : m_neighborTable)
    {
        double q = m_qTable[destination][nbr];
        if (q > bestQ)
        {
            bestQ = q;
            bestNbr = nbr;
        }
    }

    return bestNbr;
}

// Q-value Update Rule
void
FanetRoutingProtocol::UpdateQValue(Ipv4Address dest, Ipv4Address action, double reward)
{
    double& q = m_qTable[dest][action];

    // Find max Q for next state (same destination)
    double maxNextQ = 0.0;
    for (const auto& [nbr, _] : m_neighborTable)
    {
        maxNextQ = std::max(maxNextQ, m_qTable[dest][nbr]);
    }

    q = q + m_alpha * (reward + m_gamma * maxNextQ - q);
}

double
FanetRoutingProtocol::ComputeReward(Ipv4Address nextHop)
{
    const auto& m = m_linkMetrics[nextHop];

    double r = 0.5 * m.helloRate + 0.3 * m.successRatio + 0.2 * std::min(1.0, m.stability / 5.0);

    return r;
}

// Triggered after a topology change like neighbor expired or TC update
void
FanetRoutingProtocol::OnTopologyChange()
{
    ExpireNeighbors();
    UpdateRoutingTable();
}

// =====================================================================
// SIMULATION (Not part of the routing protocol)
// =====================================================================
int
main(int argc, char* argv[])
{
    // 1. Logging Configuration
    LogComponentEnable("FanetCustomRouting", LOG_LEVEL_ALL);
    LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);

    // 2. Network Topology (3 Nodes for Step 3a)
    NodeContainer nodes;
    nodes.Create(3);

    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);

    // 3. WiFi Physical & MAC Layer
    WifiHelper wifi;
    YansWifiPhyHelper phy;
    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    channel.AddPropagationLoss("ns3::FriisPropagationLossModel",
                               "Frequency",
                               DoubleValue(2.4e9),
                               "SystemLoss",
                               DoubleValue(1));
    phy.SetChannel(channel.Create());
    // phy.SetChannel(YansWifiChannelHelper::Default().Create());
    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");
    NetDeviceContainer devices = wifi.Install(phy, mac, nodes);

    // 4. Internet Stack with Custom Routing
    FanetRoutingHelper fanetHelper;
    InternetStackHelper internet;
    internet.SetRoutingHelper(fanetHelper);
    internet.Install(nodes);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = ipv4.Assign(devices);

    // 5. Application Setup
    uint16_t port = 9;

    // --- Servers on Node 1 and Node 2 ---
    UdpEchoServerHelper echoServer(port);

    ApplicationContainer serverApps;
    serverApps.Add(echoServer.Install(nodes.Get(1))); // Server 1
    serverApps.Add(echoServer.Install(nodes.Get(2))); // Server 2

    serverApps.Start(Seconds(0.4));
    serverApps.Stop(Seconds(5.0));

    // --- Clients on Node 0 ---

    // Client A: Node 0 -> Node 1 (10.1.1.2)
    UdpEchoClientHelper echoClient1(interfaces.GetAddress(1), port);
    echoClient1.SetAttribute("MaxPackets", UintegerValue(1));
    echoClient1.SetAttribute("Interval", TimeValue(Seconds(0.1)));
    echoClient1.SetAttribute("PacketSize", UintegerValue(64));

    ApplicationContainer clientApps1 = echoClient1.Install(nodes.Get(0));
    clientApps1.Start(Seconds(3));
    clientApps1.Stop(Seconds(5.0));

    // Client B: Node 0 -> Node 2 (10.1.1.3)
    UdpEchoClientHelper echoClient2(interfaces.GetAddress(2), port);
    echoClient2.SetAttribute("MaxPackets", UintegerValue(1));
    echoClient2.SetAttribute("Interval", TimeValue(Seconds(0.1)));
    echoClient2.SetAttribute("PacketSize", UintegerValue(64));

    ApplicationContainer clientApps2 = echoClient2.Install(nodes.Get(0));
    clientApps2.Start(Seconds(3.1)); // Staggered start time
    clientApps2.Stop(Seconds(5.0));

    // 6. NetAnim Configuration
    AnimationInterface anim("xml/fanet-custom.xml");
    anim.SetMobilityPollInterval(Seconds(0.5));
    anim.EnablePacketMetadata(true);

    for (uint32_t i = 0; i < nodes.GetN(); ++i)
    {
        anim.UpdateNodeDescription(nodes.Get(i), "UAV-" + std::to_string(i));
        anim.UpdateNodeColor(nodes.Get(i), 0, 255, 0);
    }

    // 7. Simulation Run
    Simulator::Stop(Seconds(5.0));
    Simulator::Run();
    Simulator::Destroy();
    return 0;
}
