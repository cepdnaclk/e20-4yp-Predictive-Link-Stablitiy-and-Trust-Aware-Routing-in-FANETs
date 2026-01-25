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
#include <iomanip>

using namespace ns3;

// Use the following command to run:
//      NS_LOG="FanetCustomRouting=level_all|prefix_time" ./ns3 run fanet-routing
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

// ******************************************************************************
// Q-Learning specific: Link metrics for each neighbor
struct LinkMetrics
{
    double delay = 0.0;               // Link delay in milliseconds
    double packetDeliveryRatio = 1.0; // PDR (0.0 to 1.0)
    double rssi = -100.0;             // Received Signal Strength Indicator (dBm)
    double snr = 0.0;                 // Signal-to-Noise Ratio (dB)
    double jitter = 0.0;              // Jitter in milliseconds
    Time lastUpdate;                  // Timestamp of last metric update
    uint32_t packetsReceived = 0;     // Total packets received from this neighbor
    uint32_t packetsSent = 0;         // Total packets sent to this neighbor
};

// Q-Learning state: (source, destination, next_hop)
// Action: choosing which neighbor (next_hop) to forward packet to
struct QLearningState
{
    Ipv4Address source;
    Ipv4Address destination;
    // Action space is the set of direct neighbors
};

// Q-value entry
struct QValue
{
    double value = 0.0;
    Time lastUpdate;
};
// ******************************************************************************

// ******************************************************************************
// TRUST-BASED ATTACK DETECTION
// Detect and mitigate: Blackhole, Grayhole, and Jamming attacks
// ******************************************************************************

// Attack types
enum AttackType
{
    NO_ATTACK = 0,
    BLACKHOLE = 1,     // Node drops all packets
    GRAYHOLE = 2,      // Node selectively drops packets
    JAMMING = 3,       // Node causes excessive collisions/interference
    SUSPICIOUS = 4     // Suspicious behavior detected
};

// Trust metrics for each neighbor
struct TrustMetrics
{
    double trustValue = 1.0;           // Trust score [0.0, 1.0], 1.0 = fully trusted
    double forwardingRatio = 1.0;      // Ratio of packets forwarded vs received
    double reliabilityScore = 1.0;     // Reliability based on delivery success
    double pathQuality = 1.0;          // Quality of paths through this node
    double jitterVariance = 0.0;       // Variance in packet delays
    
    uint32_t packetsForwarded = 0;     // Packets successfully forwarded
    uint32_t packetsReceived = 0;      // Packets received for forwarding
    uint32_t packetsDropped = 0;       // Estimated packets dropped
    uint32_t successfulRoutes = 0;     // Routes that delivered packets
    uint32_t failedRoutes = 0;         // Routes that failed
    
    AttackType detectedAttack = NO_ATTACK;
    double attackConfidence = 0.0;     // Confidence of attack detection [0.0, 1.0]
    Time lastAttackTime;               // When attack was detected
    Time lastGoodBehavior;             // When node showed good behavior
    
    uint32_t suspiciousEvents = 0;     // Count of suspicious activities
    std::vector<Time> recentFailures;  // Recent packet loss timestamps
};

// Blackhole attack detector
struct BlackholeDetector
{
    // Monitor if node drops all packets routed through it
    std::map<Ipv4Address, uint32_t> expectedPackets;  // Packets that should be forwarded
    std::map<Ipv4Address, uint32_t> forwardedPackets; // Packets actually forwarded
    std::map<Ipv4Address, Time> lastCheck;
    
    // Threshold: if forwarding ratio < 5% over threshold window, suspect blackhole
    static constexpr double BLACKHOLE_THRESHOLD = 0.05;    // 5% forwarding = suspicious
    static constexpr double BLACKHOLE_CONFIDENCE = 0.85;   // Confidence threshold
};

// Grayhole attack detector  
struct GrayholeDetector
{
    // Monitor selective packet dropping patterns
    std::map<Ipv4Address, std::vector<uint32_t>> forwardingPatterns; // Drop patterns per destination
    std::map<Ipv4Address, uint32_t> dropCount;
    std::map<Ipv4Address, Time> lastCheck;
    
    // Threshold: if forwarding ratio 20-80% with variance, suspect grayhole
    static constexpr double GRAYHOLE_MIN_THRESHOLD = 0.20;  // 20% min
    static constexpr double GRAYHOLE_MAX_THRESHOLD = 0.80;  // 80% max
    static constexpr double GRAYHOLE_CONFIDENCE = 0.75;
};

// Jamming attack detector
struct JammingDetector
{
    // Monitor excessive collisions, high jitter, and sudden link quality degradation
    std::map<Ipv4Address, std::vector<double>> jitterHistory;
    std::map<Ipv4Address, std::vector<double>> rssiHistory;
    std::map<Ipv4Address, uint32_t> collisionCount;
    std::map<Ipv4Address, Time> lastCheck;
    
    // Threshold: sudden drops in RSSI + high jitter = jamming
    static constexpr double RSSI_DROP_THRESHOLD = -15.0;   // 15 dBm sudden drop
    static constexpr double JITTER_THRESHOLD = 25.0;       // 25ms jitter
    static constexpr double JAMMING_CONFIDENCE = 0.80;
};

// Socket bound to a specific interface
struct InterfaceSocket
{
    Ptr<Socket> socket; // UDP socket
    uint32_t interface; // Interface index
    Ipv4Address local;  // Local IP bound to this socket
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
    std::vector<Ipv4Address> neighbors; // 1-hop neighbors of this node
    
    // ****************************************************************
    // Link metrics for Q-Learning
    double rssi = -100.0;               // Received Signal Strength Indicator (dBm)
    double snr = 10.0;                  // Signal-to-Noise Ratio (dB)
    double delay = 0.0;                 // Propagation delay (ms)
    // ****************************************************************

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
    //*************************************************************** 
    // Serialize link metrics
    uint32_t rssiInt = (uint32_t)((int32_t)rssi);
    start.WriteHtonU32(rssiInt);
    uint32_t snrInt = (uint32_t)((int32_t)(snr * 100)); // Store with 2 decimal precision
    start.WriteHtonU32(snrInt);
    uint32_t delayInt = (uint32_t)((int32_t)(delay * 100)); // Store delay with 2 decimal precision
    start.WriteHtonU32(delayInt);
    //*************************************************************** 
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
    //*************************************************************** 
    // Deserialize link metrics
    uint32_t rssiInt = start.ReadNtohU32();
    rssi = (double)((int32_t)rssiInt);
    bytesRead += 4;
    
    uint32_t snrInt = start.ReadNtohU32();
    snr = ((double)((int32_t)snrInt)) / 100.0;
    bytesRead += 4;
    
    uint32_t delayInt = start.ReadNtohU32();
    delay = ((double)((int32_t)delayInt)) / 100.0;
    bytesRead += 4;
    //*************************************************************** 
    return bytesRead;
}

uint32_t
FanetHeader::GetSerializedSize(void) const
{
    return 1 + 4 + 4 + 1 + 4 * neighbors.size() + 4 + 4 + 4; // type + seq + nodeId + neighborCount + neighbors + rssi + snr + delay
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
    
    // Trust-based attack detection and mitigation
    void UpdateTrustMetrics(Ipv4Address neighbor, bool packetForwarded);
    void DetectAttacks();
    void DetectBlackholeAttack(Ipv4Address node);
    void DetectGrayholeAttack(Ipv4Address node);
    void DetectJammingAttack(Ipv4Address node);
    void MitigateAttack(Ipv4Address attackerNode, AttackType attack);
    void IsolateSuspiciousNode(Ipv4Address node);
    void RecoverTrust(Ipv4Address node);
    bool IsTrusted(Ipv4Address node) const;
    void LogTrustEvent(Ipv4Address node, const std::string& event);

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

    uint32_t m_helloSeq = 0; // HELLO sequence counter
    uint32_t m_tcSeq = 0;    // TC sequence counter

    // Q-Learning parameters
    std::map<Ipv4Address, LinkMetrics> m_linkMetrics; // Link quality metrics per neighbor
    std::map<std::pair<Ipv4Address, Ipv4Address>, 
             std::map<Ipv4Address, QValue>> m_qTable; // Q-table: (src, dest) -> (next_hop, Q-value)
    
    // Q-Learning hyperparameters
    double m_learningRate = 0.1;      // Alpha: learning rate
    double m_discountFactor = 0.9;    // Gamma: discount factor
    double m_epsilon = 0.1;           // Epsilon: exploration rate
    double m_explicitRewardWeight = 0.6;  // Weight for explicit link quality
    double m_implicitRewardWeight = 0.4;  // Weight for path length
    
    // Trust-based attack detection members
    std::map<Ipv4Address, TrustMetrics> m_trustMetrics;       // Trust score per neighbor
    BlackholeDetector m_blackholeDetector;                     // Blackhole attack detection
    GrayholeDetector m_grayholeDetector;                       // Grayhole attack detection
    JammingDetector m_jammingDetector;                         // Jamming attack detection
    
    // Trust management parameters
    static constexpr double TRUST_DECAY_RATE = 0.02;           // Trust decays 2% per update
    static constexpr double TRUST_RECOVERY_RATE = 0.01;        // Recovery: 1% trust increase per good behavior
    static constexpr double MINIMUM_TRUST_THRESHOLD = 0.3;     // Minimum trust to be considered
    static constexpr uint32_t ATTACK_DETECTION_WINDOW = 50;    // Check last 50 packets
    static constexpr double ISOLATION_DURATION = 10.0;         // Isolate attacker for 10 seconds
    
    std::map<Ipv4Address, Time> m_isolationTime;               // When node was isolated
    std::map<Ipv4Address, uint32_t> m_packetTracePerNeighbor;  // Track packets per neighbor

    
    Ptr<Ipv4Route> Lookup(Ipv4Address dest);
    
    // Q-Learning methods
    double CalculateReward(Ipv4Address nextHop);
    Ipv4Address SelectBestAction(Ipv4Address dest, bool explore = false);
    void UpdateQValue(Ipv4Address src, Ipv4Address dest, Ipv4Address nextHop, 
                      Ipv4Address futureNextHop, double reward);
    void UpdateLinkMetrics(Ipv4Address neighbor, const FanetHeader& header);
    double EvaluateLink(const LinkMetrics& metrics) const;
};

NS_OBJECT_ENSURE_REGISTERED(FanetRoutingProtocol);

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
        if (now - it->second.lastSeen > Seconds(3))
        {
            it = m_neighborTable.erase(it);
            changed = true;
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
    for (const auto& [sock, addr] : m_sendSockets)
    {
        Ptr<Packet> packet = Create<Packet>();
        FanetHeader header;
        header.type = HELLO;
        header.seq = m_helloSeq++;
        header.nodeId = m_ipv4->GetObject<Node>()->GetId();
        
        // Set link metrics for HELLO packet
        // In a real scenario, these would be measured from the wireless channel
        header.rssi = -70.0;   // Default RSSI value (dBm)
        header.snr = 20.0;     // Default SNR value (dB)
        header.delay = 0.1;    // Default propagation delay (ms)
        
        packet->AddHeader(header);

        InetSocketAddress dst(Ipv4Address::GetBroadcast(), FANET_UDP_PORT);
        sock->SendTo(packet, 0, dst);

        NS_LOG_INFO("Node " << addr.GetLocal() << " sent HELLO with metrics - RSSI: " 
                   << header.rssi << " dBm, SNR: " << header.snr << " dB");
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
        
        // Update link metrics from HELLO packet
        UpdateLinkMetrics(senderIp, fanet);

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

        // Forward TC packets to all interfaces except the incoming one
        for (const auto& [sock, addr] : m_sendSockets)
        {
            uint32_t sockInterface = m_ipv4->GetInterfaceForAddress(addr.GetLocal());
            if (sockInterface == incomingIface)
            {
                continue;
            }

            Ptr<Packet> fwd = packet->Copy();
            InetSocketAddress dst(Ipv4Address::GetBroadcast(), FANET_UDP_PORT);
            sock->SendTo(fwd, 0, dst);
        }

        UpdateRoutingTable();
    }
}

// Update link metrics from received HELLO/TC packets with RSSI, SNR, and delay
void
FanetRoutingProtocol::UpdateLinkMetrics(Ipv4Address neighbor, const FanetHeader& header)
{
    LinkMetrics& metrics = m_linkMetrics[neighbor];
    
    // Update RSSI (Received Signal Strength Indicator)
    metrics.rssi = header.rssi;
    
    // Update SNR (Signal-to-Noise Ratio)
    metrics.snr = header.snr;
    
    // Update delay (propagation delay)
    metrics.delay = header.delay;
    
    // Track packet delivery for PDR calculation
    metrics.packetsReceived++;
    
    // Update timestamp
    metrics.lastUpdate = Simulator::Now();
    
    NS_LOG_DEBUG("Updated link metrics for neighbor " << neighbor 
                 << " - RSSI: " << metrics.rssi << " dBm, SNR: " << metrics.snr 
                 << " dB, Delay: " << metrics.delay << " ms, PDR: " << metrics.packetDeliveryRatio);
}

// Evaluate link quality based on collected metrics
// Returns a normalized quality score (0 to 1, where 1 is best)
double
FanetRoutingProtocol::EvaluateLink(const LinkMetrics& metrics) const
{
    // Normalize individual metrics to [0, 1] range
    
    // RSSI: -100 dBm (worst) to -30 dBm (best)
    double rssiScore = std::min(1.0, std::max(0.0, (metrics.rssi + 100.0) / 70.0));
    
    // SNR: 0 dB (worst) to 30 dB (best)
    double snrScore = std::min(1.0, std::max(0.0, metrics.snr / 30.0));
    
    // Delay: 0 ms (best) to 100 ms (worst) - lower is better
    double delayScore = std::min(1.0, std::max(0.0, 1.0 - (metrics.delay / 100.0)));
    
    // PDR: 0 (worst) to 1 (best)
    double pdrScore = metrics.packetDeliveryRatio;
    
    // Jitter: 0 ms (best) to 50 ms (worst) - lower is better
    double jitterScore = std::min(1.0, std::max(0.0, 1.0 - (metrics.jitter / 50.0)));
    
    // Weighted combination of metrics
    double quality = 0.25 * rssiScore + 0.25 * snrScore + 0.2 * delayScore + 
                    0.2 * pdrScore + 0.1 * jitterScore;
    
    return quality;
}

// Calculate immediate reward for selecting a next hop
// Reward considers link quality and path efficiency
double
FanetRoutingProtocol::CalculateReward(Ipv4Address nextHop)
{
    auto metricsIt = m_linkMetrics.find(nextHop);
    if (metricsIt == m_linkMetrics.end())
    {
        return 0.0; // No metrics available
    }
    
    // Explicit reward: link quality assessment
    double linkQuality = EvaluateLink(metricsIt->second);
    
    // Implicit reward: prefer direct neighbors (fewer hops = higher reward)
    double hopReward = 1.0; // Direct neighbor gets bonus
    
    // Combine explicit and implicit rewards
    double reward = m_explicitRewardWeight * linkQuality + m_implicitRewardWeight * hopReward;
    
    NS_LOG_DEBUG("Calculated reward for next hop " << nextHop << ": " << reward);
    
    return reward;
}

// Select the best next hop for destination using epsilon-greedy strategy
// explore=true: select action with probability epsilon (exploration), else exploitation
Ipv4Address
FanetRoutingProtocol::SelectBestAction(Ipv4Address dest, bool explore)
{
    if (m_neighborTable.empty())
    {
        return Ipv4Address(); // No neighbors available
    }
    
    // Epsilon-greedy action selection
    if (explore && (rand() % 100) < (int)(m_epsilon * 100))
    {
        // Exploration: select random neighbor
        auto it = m_neighborTable.begin();
        std::advance(it, rand() % m_neighborTable.size());
        NS_LOG_DEBUG("Exploring: selected random neighbor " << it->first);
        return it->first;
    }
    
    // Exploitation: select best neighbor based on Q-values
    Ipv4Address bestAction;
    double bestQValue = -std::numeric_limits<double>::infinity();
    
    auto qStateIt = m_qTable.find(std::make_pair(m_ipv4->GetAddress(1, 0).GetLocal(), dest));
    
    for (const auto& [neighborIp, _] : m_neighborTable)
    {
        double qValue = 0.0;
        
        if (qStateIt != m_qTable.end())
        {
            auto qActionIt = qStateIt->second.find(neighborIp);
            if (qActionIt != qStateIt->second.end())
            {
                qValue = qActionIt->second.value;
            }
        }
        
        // Add immediate reward for link quality
        qValue += CalculateReward(neighborIp);
        
        if (qValue > bestQValue)
        {
            bestQValue = qValue;
            bestAction = neighborIp;
        }
    }
    
    NS_LOG_DEBUG("Exploitation: selected best neighbor " << bestAction << " with Q-value " << bestQValue);
    
    return bestAction;
}

// Update Q-value using Q-Learning update rule
// Q(s,a) = Q(s,a) + alpha * [r + gamma * max Q(s',a') - Q(s,a)]
void
FanetRoutingProtocol::UpdateQValue(Ipv4Address src, Ipv4Address dest, Ipv4Address nextHop,
                                    Ipv4Address futureNextHop, double reward)
{
    auto stateKey = std::make_pair(src, dest);
    
    // Get current Q-value
    double currentQ = 0.0;
    if (m_qTable[stateKey].find(nextHop) != m_qTable[stateKey].end())
    {
        currentQ = m_qTable[stateKey][nextHop].value;
    }
    
    // Get maximum Q-value for future state
    double maxFutureQ = 0.0;
    if (!futureNextHop.IsAny())
    {
        for (const auto& [neighborIp, _] : m_neighborTable)
        {
            if (m_qTable[stateKey].find(neighborIp) != m_qTable[stateKey].end())
            {
                maxFutureQ = std::max(maxFutureQ, m_qTable[stateKey][neighborIp].value);
            }
        }
    }
    
    // Q-Learning update rule
    double newQ = currentQ + m_learningRate * (reward + m_discountFactor * maxFutureQ - currentQ);
    
    m_qTable[stateKey][nextHop].value = newQ;
    m_qTable[stateKey][nextHop].lastUpdate = Simulator::Now();
    
    NS_LOG_DEBUG("Updated Q(" << src << ", " << dest << ", " << nextHop 
                 << ") from " << currentQ << " to " << newQ << " with reward " << reward);
}

// Build or rebuild the routing table using Q-Learning for optimal path selection
// Q-Learning considers: delay, packet delivery ratio, RSSI, SNR, and jitter
// Also performs trust-based attack detection
void
FanetRoutingProtocol::UpdateRoutingTable()
{
    // Run attack detection before updating routing table
    DetectAttacks();
    
    std::map<Ipv4Address, RouteEntry> newTable;
    Ipv4Address myAddress = m_ipv4->GetAddress(1, 0).GetLocal();

    // 1. Seed Q-table and routes with direct neighbors (HELLO)
    std::queue<Ipv4Address> q;
    std::map<Ipv4Address, Ipv4Address> firstHop;

    for (const auto& [nbr, info] : m_neighborTable)
    {
        // Direct neighbors are best known routes
        RouteEntry entry;
        entry.destination = nbr;
        entry.nextHop = nbr;
        entry.interface = info.interface;
        newTable[nbr] = entry;

        // Initialize Q-values for this neighbor
        double immediateReward = CalculateReward(nbr);
        m_qTable[std::make_pair(myAddress, nbr)][nbr].value = immediateReward;
        m_qTable[std::make_pair(myAddress, nbr)][nbr].lastUpdate = Simulator::Now();

        q.push(nbr);
        firstHop[nbr] = nbr;
        
        NS_LOG_INFO("Direct route to neighbor " << nbr << " with reward " << immediateReward);
    }

    // 2. Multi-hop routing using BFS with Q-Learning refinement
    // For each learned multi-hop destination, use Q-Learning to select best next hop
    while (!q.empty())
    {
        Ipv4Address current = q.front();
        q.pop();

        auto topoIt = m_topologyTable.find(current);
        if (topoIt == m_topologyTable.end())
        {
            continue;
        }

        for (const auto& advertisedNbr : topoIt->second.neighbors)
        {
            // Skip self and loopback
            if (advertisedNbr == myAddress)
            {
                continue;
            }

            if (newTable.find(advertisedNbr) != newTable.end())
            {
                continue;
            }

            // Use Q-Learning to select best next hop for this destination
            Ipv4Address bestNextHop = SelectBestAction(advertisedNbr, false); // Exploitation only
            
            if (bestNextHop.IsAny() || bestNextHop == myAddress)
            {
                // Fallback to first hop if no good action selected
                bestNextHop = firstHop[current];
            }

            RouteEntry entry;
            entry.destination = advertisedNbr;
            entry.nextHop = bestNextHop;
            entry.interface = newTable[bestNextHop].interface;

            newTable[advertisedNbr] = entry;

            // Update Q-values for this route
            Ipv4Address futureHop = SelectBestAction(current, false);
            double reward = CalculateReward(bestNextHop);
            UpdateQValue(myAddress, advertisedNbr, bestNextHop, futureHop, reward);

            firstHop[advertisedNbr] = firstHop[current];
            q.push(advertisedNbr);
            
            NS_LOG_INFO("Multi-hop route to " << advertisedNbr << " via " << bestNextHop 
                       << " (first hop: " << firstHop[current] << ")");
        }
    }

    m_routingTable = newTable;

    NS_LOG_INFO("Routing table updated with " << newTable.size() << " entries using Q-Learning");

    Simulator::Schedule(Seconds(TOPOLOGY_TIMEOUT), &FanetRoutingProtocol::UpdateRoutingTable, this);
}

// =====================================================================
// TRUST-BASED ATTACK DETECTION AND MITIGATION
// =====================================================================

// Update trust metrics for a neighbor based on packet forwarding
void
FanetRoutingProtocol::UpdateTrustMetrics(Ipv4Address neighbor, bool packetForwarded)
{
    TrustMetrics& trust = m_trustMetrics[neighbor];
    
    if (packetForwarded)
    {
        trust.packetsForwarded++;
        trust.successfulRoutes++;
        // Increase trust on good behavior
        trust.trustValue = std::min(1.0, trust.trustValue + TRUST_RECOVERY_RATE);
        trust.lastGoodBehavior = Simulator::Now();
    }
    else
    {
        trust.packetsDropped++;
        trust.failedRoutes++;
        // Decrease trust when packets are dropped
        trust.trustValue = std::max(0.0, trust.trustValue - TRUST_DECAY_RATE * 5);
    }
    
    // Update forwarding ratio
    if (trust.packetsReceived > 0)
    {
        trust.forwardingRatio = (double)trust.packetsForwarded / (double)trust.packetsReceived;
    }
    
    // Update reliability score
    uint32_t totalAttempts = trust.successfulRoutes + trust.failedRoutes;
    if (totalAttempts > 0)
    {
        trust.reliabilityScore = (double)trust.successfulRoutes / (double)totalAttempts;
    }
    
    NS_LOG_DEBUG("Updated trust for " << neighbor << ": trustValue=" << trust.trustValue 
                 << " forwardingRatio=" << trust.forwardingRatio 
                 << " reliabilityScore=" << trust.reliabilityScore);
}

// Detect all types of attacks
void
FanetRoutingProtocol::DetectAttacks()
{
    for (const auto& [neighbor, metrics] : m_linkMetrics)
    {
        // Check if node is currently isolated
        if (m_isolationTime.find(neighbor) != m_isolationTime.end())
        {
            Time isolatedFor = Simulator::Now() - m_isolationTime[neighbor];
            if (isolatedFor > Seconds(ISOLATION_DURATION))
            {
                // Try recovery after isolation period
                RecoverTrust(neighbor);
            }
            else
            {
                continue; // Still isolated
            }
        }
        
        DetectBlackholeAttack(neighbor);
        DetectGrayholeAttack(neighbor);
        DetectJammingAttack(neighbor);
    }
}

// Detect blackhole attacks (node drops all packets)
void
FanetRoutingProtocol::DetectBlackholeAttack(Ipv4Address node)
{
    auto trustIt = m_trustMetrics.find(node);
    if (trustIt == m_trustMetrics.end())
        return;
    
    TrustMetrics& trust = trustIt->second;
    
    // Blackhole: forwarding ratio near 0
    if (trust.packetsReceived >= 10 && trust.forwardingRatio < BlackholeDetector::BLACKHOLE_THRESHOLD)
    {
        trust.suspiciousEvents++;
        trust.detectedAttack = BLACKHOLE;
        trust.attackConfidence = std::min(1.0, trust.attackConfidence + 0.15);
        
        if (trust.attackConfidence >= BlackholeDetector::BLACKHOLE_CONFIDENCE)
        {
            NS_LOG_WARN("BLACKHOLE ATTACK DETECTED on node " << node 
                       << " - Confidence: " << trust.attackConfidence 
                       << " - ForwardingRatio: " << trust.forwardingRatio);
            MitigateAttack(node, BLACKHOLE);
        }
    }
    else if (trust.forwardingRatio > 0.5)
    {
        // Good behavior reduces suspicion
        trust.attackConfidence = std::max(0.0, trust.attackConfidence - 0.10);
    }
}

// Detect grayhole attacks (selective packet dropping)
void
FanetRoutingProtocol::DetectGrayholeAttack(Ipv4Address node)
{
    auto trustIt = m_trustMetrics.find(node);
    if (trustIt == m_trustMetrics.end())
        return;
    
    TrustMetrics& trust = trustIt->second;
    
    // Grayhole: forwarding ratio between 20-80% with suspicious pattern
    if (trust.packetsReceived >= 15 && 
        trust.forwardingRatio > GrayholeDetector::GRAYHOLE_MIN_THRESHOLD &&
        trust.forwardingRatio < GrayholeDetector::GRAYHOLE_MAX_THRESHOLD)
    {
        // Check for pattern: if reliability varies significantly by destination
        if (trust.successfulRoutes > 0 && trust.failedRoutes > 0)
        {
            double variance = (trust.successfulRoutes - trust.failedRoutes) / 
                            (double)(trust.successfulRoutes + trust.failedRoutes);
            
            if (std::abs(variance) > 0.3)  // Significant variance = suspicious
            {
                trust.suspiciousEvents++;
                trust.detectedAttack = GRAYHOLE;
                trust.attackConfidence = std::min(1.0, trust.attackConfidence + 0.12);
                
                if (trust.attackConfidence >= GrayholeDetector::GRAYHOLE_CONFIDENCE)
                {
                    NS_LOG_WARN("GRAYHOLE ATTACK DETECTED on node " << node 
                               << " - Confidence: " << trust.attackConfidence 
                               << " - ForwardingRatio: " << trust.forwardingRatio
                               << " - Variance: " << variance);
                    MitigateAttack(node, GRAYHOLE);
                }
            }
        }
    }
}

// Detect jamming attacks (excessive collisions, high jitter, RSSI degradation)
void
FanetRoutingProtocol::DetectJammingAttack(Ipv4Address node)
{
    auto metricsIt = m_linkMetrics.find(node);
    auto trustIt = m_trustMetrics.find(node);
    
    if (metricsIt == m_linkMetrics.end() || trustIt == m_trustMetrics.end())
        return;
    
    const LinkMetrics& metrics = metricsIt->second;
    TrustMetrics& trust = trustIt->second;
    
    // Jamming indicators:
    // 1. Sudden RSSI drop (interference)
    // 2. High jitter (unstable link)
    // 3. Poor packet delivery ratio without being blackhole
    
    double jitterScore = 0.0;
    double rssiScore = 0.0;
    double pdrScore = 0.0;
    
    // Check jitter
    if (metrics.jitter > JammingDetector::JITTER_THRESHOLD)
    {
        jitterScore = 1.0;
    }
    
    // Check RSSI drop
    if (metrics.rssi < -90.0)  // Very weak signal
    {
        rssiScore = 1.0;
    }
    
    // Check PDR without blackhole pattern
    if (metrics.packetDeliveryRatio < 0.6 && trust.forwardingRatio > 0.5)
    {
        pdrScore = 1.0;  // Link is unreliable despite node forwarding
    }
    
    double jammingIndicator = (jitterScore + rssiScore + pdrScore) / 3.0;
    
    if (jammingIndicator > 0.5)
    {
        trust.suspiciousEvents++;
        trust.detectedAttack = JAMMING;
        trust.attackConfidence = std::min(1.0, trust.attackConfidence + 0.18);
        
        if (trust.attackConfidence >= JammingDetector::JAMMING_CONFIDENCE)
        {
            NS_LOG_WARN("JAMMING ATTACK DETECTED on node " << node 
                       << " - Confidence: " << trust.attackConfidence 
                       << " - Jitter: " << metrics.jitter 
                       << " ms - RSSI: " << metrics.rssi << " dBm");
            MitigateAttack(node, JAMMING);
        }
    }
}

// Mitigate attack by isolating the attacker node
void
FanetRoutingProtocol::MitigateAttack(Ipv4Address attackerNode, AttackType attack)
{
    // Isolate the attacker
    IsolateSuspiciousNode(attackerNode);
    
    // Set isolation time
    m_isolationTime[attackerNode] = Simulator::Now();
    
    // Log the attack
    std::string attackName;
    switch (attack)
    {
        case BLACKHOLE:
            attackName = "BLACKHOLE";
            break;
        case GRAYHOLE:
            attackName = "GRAYHOLE";
            break;
        case JAMMING:
            attackName = "JAMMING";
            break;
        default:
            attackName = "UNKNOWN";
    }
    
    LogTrustEvent(attackerNode, "ATTACK_MITIGATED: " + attackName);
    
    NS_LOG_ERROR("MITIGATING ATTACK: " << attackName << " from node " << attackerNode 
                 << " - Isolation period: " << ISOLATION_DURATION << " seconds");
}

// Isolate suspicious node by removing it from routing table
void
FanetRoutingProtocol::IsolateSuspiciousNode(Ipv4Address node)
{
    // Remove all routes through this node
    std::map<Ipv4Address, RouteEntry> newTable;
    
    for (const auto& [dest, entry] : m_routingTable)
    {
        if (entry.nextHop != node)
        {
            newTable[dest] = entry;
        }
    }
    
    m_routingTable = newTable;
    
    // Reduce trust significantly
    if (m_trustMetrics.find(node) != m_trustMetrics.end())
    {
        m_trustMetrics[node].trustValue = 0.0;
    }
    
    NS_LOG_INFO("Isolated suspicious node " << node << " from routing");
}

// Recover trust for node after isolation period
void
FanetRoutingProtocol::RecoverTrust(Ipv4Address node)
{
    auto trustIt = m_trustMetrics.find(node);
    if (trustIt == m_trustMetrics.end())
        return;
    
    TrustMetrics& trust = trustIt->second;
    
    // Gradually recover trust
    trust.trustValue = std::min(0.5, trust.trustValue + TRUST_RECOVERY_RATE * 10);
    trust.attackConfidence = std::max(0.0, trust.attackConfidence - 0.15);
    trust.detectedAttack = NO_ATTACK;
    trust.suspiciousEvents = 0;
    
    m_isolationTime.erase(node);
    
    LogTrustEvent(node, "TRUST_RECOVERY_INITIATED");
    
    NS_LOG_INFO("Initiating trust recovery for node " << node 
               << " - New trust value: " << trust.trustValue);
}

// Check if a node is trusted
bool
FanetRoutingProtocol::IsTrusted(Ipv4Address node) const
{
    auto trustIt = m_trustMetrics.find(node);
    if (trustIt == m_trustMetrics.end())
    {
        return true;  // Unknown nodes are initially trusted
    }
    
    const TrustMetrics& trust = trustIt->second;
    
    // Check isolation status
    if (m_isolationTime.find(node) != m_isolationTime.end())
    {
        return false;  // Currently isolated
    }
    
    // Node is trusted if trust value > threshold and no active attack
    return trust.trustValue > MINIMUM_TRUST_THRESHOLD && 
           trust.detectedAttack == NO_ATTACK;
}

// Log trust-related events for debugging
void
FanetRoutingProtocol::LogTrustEvent(Ipv4Address node, const std::string& event)
{
    auto trustIt = m_trustMetrics.find(node);
    if (trustIt != m_trustMetrics.end())
    {
        const TrustMetrics& trust = trustIt->second;
        NS_LOG_INFO("TRUST_EVENT [" << node << "]: " << event 
                   << " | Trust=" << trust.trustValue
                   << " | ForwardingRatio=" << trust.forwardingRatio
                   << " | Suspicions=" << trust.suspiciousEvents);
    }
}



// Lookup route to a destination
// Checks neighbors first, then routing table (with trust verification)
Ptr<Ipv4Route>
FanetRoutingProtocol::Lookup(Ipv4Address dest)
{
    // 1. Check Neighbor Table First (Direct 1-Hop)
    auto neighborIt = m_neighborTable.find(dest);
    if (neighborIt != m_neighborTable.end())
    {
        // Check if neighbor is trusted
        if (!IsTrusted(dest))
        {
            NS_LOG_WARN("Lookup: Neighbor " << dest << " is NOT TRUSTED - rejecting route");
            return nullptr;
        }
        
        NS_LOG_LOGIC("Lookup: " << dest << " found in Neighbor Table (TRUSTED).");

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
        RouteEntry entry = routeIt->second;
        
        // Check if next hop is trusted
        if (!IsTrusted(entry.nextHop))
        {
            NS_LOG_WARN("Lookup: Next hop " << entry.nextHop << " for destination " << dest 
                       << " is NOT TRUSTED - rejecting route");
            return nullptr;
        }
        
        NS_LOG_LOGIC("Lookup: " << dest << " found in Routing Table via TRUSTED next hop " 
                    << entry.nextHop);
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

    // 2. Network Topology (5 Nodes)
    NodeContainer nodes;
    nodes.Create(5);

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
