#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-helper.h"
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
// NS_LOG="FanetCustomRouting=level_all|prefix_time" ./ns3 run fanet-routing-v1.1
NS_LOG_COMPONENT_DEFINE("FanetCustomRouting");

// =====================
// PROTOCOL CONSTANTS
// =====================
static constexpr uint16_t FANET_UDP_PORT = 9900;
static constexpr double HELLO_INTERVAL_BASE = 0.5; // Base interval between HELLO packets
static constexpr double TC_INTERVAL_BASE = 0.1; // Base interval between TC packets
static constexpr double NEIGHBOR_TIMEOUT = 1.0; // Time after which a neighbor is considered stale
static constexpr double TOPOLOGY_TIMEOUT = 1.0; // Frequency to recalculate the routing table
static constexpr double EMA_BETA = 0.7; // For predictive metrics
static constexpr double TRUST_DECAY = 0.95; // Trust decay factor
static constexpr double EPSILON_DECAY = 0.995; // Epsilon decay per step
static constexpr double MIN_EPSILON = 0.01;
static constexpr double SNR_THRESHOLD = 30.0; // dB for normalization

// =====================
// PROTOCOL DATA STRUCTURES
// =====================
// Packet types exchanged by the FANET protocol
enum FanetPacketType
{
    HELLO = 1, // Neighbor discovery
    TC = 2,    // Topology control
    DATA = 3   // Data packet
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
    uint32_t ifIndex;   // Interface index
    Ipv4Address local;  // Local IP address of this interface
};

// Global topology entry learned via TC
struct TopologyEntry
{
    Ipv4Address origin; // Node that sent the TC
    std::vector<Ipv4Address> neighbors; // Node's advertised 1-hop neighbors
    Time lastUpdate; // Timestamp of last TC received
};

// Routing table entry
struct RouteEntry
{
    Ipv4Address destination; // Destination IP address
    Ipv4Address nextHop;     // Next hop IP address
    uint32_t interface;      // Outgoing interface index used to reach nextHop
    double cost;             // Composite cost for Dijkstra
};

// =====================
// LINK METRICS
// =====================
struct LinkMetric
{
    double helloRate = 0.0;    // HELLO reception ratio
    double stability = 0.0;    // Neighbor lifetime
    double predictedStability = 0.0; // Predicted stability
    double successRatio = 1.0; // Forwarding success
    double predictedPDR = 0.0; // Predicted PDR
    Time firstSeen;            // Timestamp of the first HELLO received
    uint32_t helloCount = 0;   // Number of hello messages
    uint32_t helloExpected = 0;// Number of hello messages expected
    // Dynamic Metrics
    uint32_t txPackets = 0;    // Total data packets sent to this neighbor
    uint32_t rxPackets = 0;    // Total data packets successfully acknowledged/received
    uint32_t ackPackets = 0;   // ACKs received (for trust)
    Time totalDelay;           // Cumulative delay for latency calculation
    Time lastDelay;            // Delay of the last packet for jitter
    double jitter = 0.0;
    uint64_t totalBytes = 0;   // For throughput
    Time lastByteTime;         // Timestamp of last received byte
    double avgSNR = 0.0;       // Average SNR (dB)
    uint32_t snrCount = 0;     // Number of SNR measurements
    double trustScore = 1.0;   // Trust score (0-1)

    // Calculated Getters
    double GetPDR() const { return txPackets > 0 ? (double)rxPackets / txPackets : 0.0; }
    double GetLatencyMs() const { return rxPackets > 0 ? totalDelay.GetMilliSeconds() / rxPackets : 0.0; }
    double GetThroughputKbps() const {
        double duration = (Simulator::Now() - firstSeen).GetSeconds();
        return duration > 0 ? (totalBytes * 8.0) / (duration * 1000.0) : 0.0;
    }
    double GetNormSNR() const { return std::min(1.0, avgSNR / SNR_THRESHOLD); }
    void UpdatePrediction() {
        predictedStability = EMA_BETA * stability + (1 - EMA_BETA) * predictedStability;
        predictedPDR = EMA_BETA * GetPDR() + (1 - EMA_BETA) * predictedPDR;
    }
    void UpdateTrust() {
        double forwardRatio = txPackets > 0 ? (double)ackPackets / txPackets : 1.0;
        trustScore = TRUST_DECAY * trustScore + (1 - TRUST_DECAY) * forwardRatio;
    }
};

// =====================
// FANET CONTROL PACKET HEADER
// =====================
struct FanetHeader : public Header
{
    uint8_t type; // HELLO, TC, DATA
    uint32_t seq; // sequence number
    uint32_t nodeId; // optional node identifier
    uint8_t neighborCount; // Number of 1-hop neighbors
    std::vector<Ipv4Address> neighbors; // topology discovery
    std::vector<Ipv4Address> mprSelectorList; // Nodes that chose THIS node as MPR
    uint64_t timestamp; // Time in microseconds
    uint8_t ttl = 255;  // TTL for flooding control
    // For DATA: Original source/dest
    Ipv4Address origSrc;
    Ipv4Address origDst;

    static TypeId GetTypeId(void);
    virtual TypeId GetInstanceTypeId(void) const override;
    virtual void Serialize(Buffer::Iterator start) const override;
    virtual uint32_t Deserialize(Buffer::Iterator start) override;
    virtual uint32_t GetSerializedSize(void) const override;
    virtual void Print(std::ostream& os) const override;
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
    start.WriteU8(neighborCount);
    for (auto& n : neighbors)
    {
        start.WriteHtonU32(n.Get());
    }
    start.WriteU8(mprSelectorList.size());
    for (auto& m : mprSelectorList)
    {
        start.WriteHtonU32(m.Get());
    }
    start.WriteHtonU64(timestamp);
    start.WriteU8(ttl);
    if (type == DATA) {
        start.WriteHtonU32(origSrc.Get());
        start.WriteHtonU32(origDst.Get());
    }
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
    uint8_t mprCount = start.ReadU8();
    bytesRead += 1;
    mprSelectorList.clear();
    for (uint8_t i = 0; i < mprCount; i++)
    {
        mprSelectorList.push_back(Ipv4Address(start.ReadNtohU32()));
        bytesRead += 4;
    }
    timestamp = start.ReadNtohU64();
    bytesRead += 8;
    ttl = start.ReadU8();
    bytesRead += 1;
    if (type == DATA) {
        origSrc = Ipv4Address(start.ReadNtohU32());
        origDst = Ipv4Address(start.ReadNtohU32());
        bytesRead += 8;
    }
    return bytesRead;
}

uint32_t
FanetHeader::GetSerializedSize(void) const
{
    uint32_t size = 1 + 4 + 4 + 1 + (4 * neighbors.size()) + 1 + (4 * mprSelectorList.size()) + 8 + 1;
    if (type == DATA) size += 8;
    return size;
}

void
FanetHeader::Print(std::ostream& os) const
{
    os << "[FanetHeader type=" << (uint32_t)type << " seq=" << seq << " nodeId=" << nodeId << " ttl=" << (uint32_t)ttl << "]";
}

// =====================================================================
// FANET ROUTING PROTOCOL
// =====================================================================
class FanetRoutingProtocol : public Ipv4RoutingProtocol
{
public:
    static TypeId GetTypeId(void);
    FanetRoutingProtocol() {}
    virtual ~FanetRoutingProtocol() {}
    // Ipv4RoutingProtocol overrides
    virtual void NotifyInterfaceUp(uint32_t interface) override {}
    virtual void NotifyInterfaceDown(uint32_t interface) override {}
    virtual void NotifyAddAddress(uint32_t interface, Ipv4InterfaceAddress address) override {}
    virtual void NotifyRemoveAddress(uint32_t interface, Ipv4InterfaceAddress address) override {}
    virtual Ptr<Ipv4Route> RouteOutput(Ptr<Packet> p, const Ipv4Header& header, Ptr<NetDevice> oif, Socket::SocketErrno& sockerr) override;
    virtual bool RouteInput(Ptr<const Packet> p, const Ipv4Header& header, Ptr<const NetDevice> idev,
                            const UnicastForwardCallback& ucb, const MulticastForwardCallback& mcb,
                            const LocalDeliverCallback& lcb, const ErrorCallback& ecb) override;
    virtual void PrintRoutingTable(Ptr<OutputStreamWrapper> stream, Time::Unit unit = Time::S) const override;
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
    void ExpireNeighbors(); // Remove stale neighbor and topology entries
    void UpdateRoutingTable(); // Build routing table using Dijkstra with composite costs
    void OnTopologyChange(); // Triggered after topology changes
    // Q-Learning
    Ipv4Address SelectNextHopQ(Ipv4Address destination);
    void UpdateQValue(Ipv4Address dest, Ipv4Address action, double reward);
    double ComputeReward(Ipv4Address nextHop);
    // SNR Callback
    void PhyRxBeginCallback(Ptr<const Packet> packet, double snr, WifiMode mode, WifiPreamble preamble);
    // Adaptive Intervals
    double GetAdaptiveHelloInterval() const;
    double GetAdaptiveTcInterval() const;
    double m_avgSpeed = 0.0; // Average node speed for adaptive intervals

private:
    // Protocol state
    Ptr<Ipv4> m_ipv4;
    std::vector<FanetInterface> m_interfaces; // Per-interface information
    std::map<Ptr<Socket>, Ipv4InterfaceAddress> m_sendSockets; // One send socket per interface
    Ptr<Socket> m_recvSocket; // Single receive socket
    std::map<Ipv4Address, NeighborInfo> m_neighborTable; // 1-hop neighbors
    std::map<Ipv4Address, TopologyEntry> m_topologyTable; // Multi-hop topology
    std::map<Ipv4Address, RouteEntry> m_routingTable; // Current routing table
    std::map<Ipv4Address, uint32_t> m_lastTcSeq; // Last received TC sequence per node
    // MPR
    std::map<Ipv4Address, std::vector<Ipv4Address>> m_twoHopNeighbors; // 2-hop topology
    std::set<Ipv4Address> m_mprSet; // Selected MPRs
    std::set<Ipv4Address> m_mprSelectors; // Selectors of this node
    uint32_t m_helloSeq = 0;
    uint32_t m_tcSeq = 0;
    void ComputeMprSet();
    // Link metrics
    std::map<Ipv4Address, LinkMetric> m_linkMetrics;
    // Q-Learning state
    std::map<Ipv4Address, std::map<Ipv4Address, double>> m_qTable;
    double m_alpha = 0.5; // learning rate
    double m_gamma = 0.8; // discount factor
    double m_epsilon = 0.1; // exploration probability (decays)
    // Lookup route
    Ptr<Ipv4Route> Lookup(Ipv4Address dest);
    // Graph for Dijkstra
    void BuildGraph(std::map<Ipv4Address, std::map<Ipv4Address, double>>& graph);
    // SNR last received per sender (temp for callback)
    std::map<Ipv4Address, double> m_lastSnr;
};

NS_OBJECT_ENSURE_REGISTERED(FanetRoutingProtocol);

// MPR Computation: Greedy + Symmetric Check
void
FanetRoutingProtocol::ComputeMprSet() {
    m_mprSet.clear();
    std::set<Ipv4Address> uncoveredTwoHop;
    // Identify unique 2-hop not 1-hop
    for (auto const& [neighbor, twoHopList] : m_twoHopNeighbors) {
        if (m_neighborTable.find(neighbor) == m_neighborTable.end()) continue; // Symmetric check
        for (auto const& twoHop : twoHopList) {
            if (twoHop != m_interfaces.front().local && m_neighborTable.find(twoHop) == m_neighborTable.end()) {
                uncoveredTwoHop.insert(twoHop);
            }
        }
    }
    // Greedy selection
    while (!uncoveredTwoHop.empty()) {
        Ipv4Address bestNbr;
        uint32_t maxCovered = 0;
        for (auto const& [neighbor, _] : m_neighborTable) {
            uint32_t coverage = 0;
            auto it = m_twoHopNeighbors.find(neighbor);
            if (it == m_twoHopNeighbors.end()) continue;
            for (auto const& target : it->second) {
                if (uncoveredTwoHop.count(target)) coverage++;
            }
            if (coverage > maxCovered) {
                maxCovered = coverage;
                bestNbr = neighbor;
            }
        }
        if (maxCovered == 0) break;
        m_mprSet.insert(bestNbr);
        auto it = m_twoHopNeighbors.find(bestNbr);
        if (it != m_twoHopNeighbors.end()) {
            for (auto const& target : it->second) {
                uncoveredTwoHop.erase(target);
            }
        }
    }
}

// Print Routing Table with Improvements
void
FanetRoutingProtocol::PrintRoutingTable(Ptr<OutputStreamWrapper> stream, Time::Unit unit) const
{
    std::ostream* os = stream->GetStream();
    *os << "\n--- FANET Routing Table (Node " << m_ipv4->GetObject<Node>()->GetId() << ") ---\n";
    *os << std::left << std::setw(15) << "Destination"
        << std::setw(15) << "NextHop"
        << std::setw(10) << "PDR"
        << std::setw(12) << "PredPDR"
        << std::setw(12) << "Latency(ms)"
        << std::setw(10) << "Jitter(ms)"
        << std::setw(10) << "Throughput"
        << std::setw(10) << "SNR(dB)"
        << std::setw(10) << "Trust"
        << std::setw(15) << "PredStability(s)" << std::endl;
    // Direct Neighbors
    for (const auto& [neighborIp, info] : m_neighborTable) {
        auto it = m_linkMetrics.find(neighborIp);
        if (it != m_linkMetrics.end()) {
            const auto& m = it->second;
            *os << std::left << std::setw(15) << neighborIp
                << std::setw(15) << "DIRECT"
                << std::setw(10) << std::fixed << std::setprecision(2) << m.GetPDR()
                << std::setw(12) << m.predictedPDR
                << std::setw(12) << m.GetLatencyMs()
                << std::setw(10) << (m.jitter * 1000.0)
                << std::setw(10) << m.GetThroughputKbps()
                << std::setw(10) << m.avgSNR
                << std::setw(10) << m.trustScore
                << std::setw(15) << m.predictedStability << std::endl;
        }
    }
    // Multi-hop Routes
    for (const auto& [dest, entry] : m_routingTable) {
        auto it = m_linkMetrics.find(entry.nextHop);
        if (it != m_linkMetrics.end()) {
            const auto& m = it->second;
            *os << std::left << std::setw(15) << dest
                << std::setw(15) << entry.nextHop
                << std::setw(10) << m.GetPDR()
                << std::setw(12) << m.predictedPDR
                << std::setw(12) << m.GetLatencyMs()
                << std::setw(10) << (m.jitter * 1000.0)
                << std::setw(10) << m.GetThroughputKbps()
                << std::setw(10) << m.avgSNR
                << std::setw(10) << m.trustScore
                << std::setw(15) << m.predictedStability << std::endl;
        }
    }
    *os << "------------------------------------------------------------\n";
}

// Set Ipv4 and Schedule Init
void
FanetRoutingProtocol::SetIpv4(Ptr<Ipv4> ipv4)
{
    m_ipv4 = ipv4;
    Simulator::Schedule(Seconds(0.0), &FanetRoutingProtocol::InitializeInterfaces, this);
    Simulator::Schedule(Seconds(0.0), &FanetRoutingProtocol::SendHello, this);
    Simulator::Schedule(Seconds(0.1), &FanetRoutingProtocol::SendTC, this);
    ExpireNeighbors();
}

// Initialize Interfaces and Sockets
void
FanetRoutingProtocol::InitializeInterfaces()
{
    m_interfaces.clear();
    m_sendSockets.clear();
    for (uint32_t i = 0; i < m_ipv4->GetNInterfaces(); ++i)
    {
        if (!m_ipv4->IsUp(i) || m_ipv4->GetNAddresses(i) == 0 || i == 0) continue;
        FanetInterface iface;
        iface.ifIndex = i;
        iface.local = m_ipv4->GetAddress(i, 0).GetLocal();
        m_interfaces.push_back(iface);
        // Receive Socket (once)
        if (!m_recvSocket) {
            m_recvSocket = Socket::CreateSocket(m_ipv4->GetObject<Node>(), UdpSocketFactory::GetTypeId());
            m_recvSocket->SetAllowBroadcast(true);
            InetSocketAddress inetAddr(Ipv4Address::GetAny(), FANET_UDP_PORT);
            m_recvSocket->SetRecvCallback(MakeCallback(&FanetRoutingProtocol::ReceiveFanetPacket, this));
            m_recvSocket->Bind(inetAddr);
            m_recvSocket->SetRecvPktInfo(true);
        }
        // Send Socket per Interface
        Ptr<Socket> sendSocket = Socket::CreateSocket(m_ipv4->GetObject<Node>(), UdpSocketFactory::GetTypeId());
        sendSocket->SetAllowBroadcast(true);
        InetSocketAddress sendAddr(m_ipv4->GetAddress(i, 0).GetLocal(), FANET_UDP_PORT);
        sendSocket->BindToNetDevice(m_ipv4->GetNetDevice(i));
        sendSocket->Bind(sendAddr);
        sendSocket->SetRecvPktInfo(true);
        m_sendSockets[sendSocket] = m_ipv4->GetAddress(i, 0);
    }
    // Register SNR Callback on Phy
    Ptr<NetDevice> dev = m_ipv4->GetNetDevice(1); // Assume wifi on iface 1
    Ptr<WifiNetDevice> wifiDev = DynamicCast<WifiNetDevice>(dev);
    if (wifiDev) {
        Ptr<WifiPhy> phy = wifiDev->GetPhy();
        phy->TraceConnectWithoutContext("MonitorSnifferRx", MakeCallback(&FanetRoutingProtocol::PhyRxBeginCallback, this));
    }
}

// Adaptive Intervals Based on Avg Speed
double
FanetRoutingProtocol::GetAdaptiveHelloInterval() const {
    return HELLO_INTERVAL_BASE * (1 + m_avgSpeed / 20.0); // Increase with speed
}

double
FanetRoutingProtocol::GetAdaptiveTcInterval() const {
    return TC_INTERVAL_BASE * (1 + m_avgSpeed / 20.0);
}

// Expire Neighbors and Update Predictions/Trust
void
FanetRoutingProtocol::ExpireNeighbors()
{
    Time now = Simulator::Now();
    bool changed = false;
    // Update Avg Speed (from Mobility)
    Ptr<MobilityModel> mob = m_ipv4->GetObject<MobilityModel>();
    if (mob) m_avgSpeed = 0.9 * m_avgSpeed + 0.1 * mob->GetVelocity().GetLength();
    // Expire Neighbors
    for (auto it = m_neighborTable.begin(); it != m_neighborTable.end();) {
        auto& metric = m_linkMetrics[it->first];
        Time lifetime = now - metric.firstSeen;
        metric.stability = lifetime.GetSeconds();
        metric.UpdatePrediction();
        metric.UpdateTrust();
        if (now - it->second.lastSeen > Seconds(NEIGHBOR_TIMEOUT)) {
            metric.successRatio *= 0.7;
            metric.trustScore *= 0.5; // Harsh trust penalty
            m_linkMetrics.erase(it->first); // Clean metrics
            it = m_neighborTable.erase(it);
            changed = true;
        } else {
            ++it;
        }
    }
    // Expire Topology
    for (auto it = m_topologyTable.begin(); it != m_topologyTable.end();) {
        if (now - it->second.lastUpdate > Seconds(TOPOLOGY_TIMEOUT)) {
            it = m_topologyTable.erase(it);
            changed = true;
        } else {
            ++it;
        }
    }
    if (changed) OnTopologyChange();
    Simulator::Schedule(Seconds(NEIGHBOR_TIMEOUT), &FanetRoutingProtocol::ExpireNeighbors, this);
}

// Send HELLO
void
FanetRoutingProtocol::SendHello()
{
    ComputeMprSet();
    for (auto& [nbr, metric] : m_linkMetrics) metric.helloExpected++;
    for (const auto& [sock, addr] : m_sendSockets) {
        Ptr<Packet> packet = Create<Packet>();
        FanetHeader header;
        header.type = HELLO;
        header.seq = m_helloSeq++;
        header.nodeId = m_ipv4->GetObject<Node>()->GetId();
        header.timestamp = Simulator::Now().GetMicroSeconds();
        header.mprSelectorList.assign(m_mprSet.begin(), m_mprSet.end());
        packet->AddHeader(header);
        InetSocketAddress dst(Ipv4Address::GetBroadcast(), FANET_UDP_PORT);
        sock->SendTo(packet, 0, dst);
    }
    Simulator::Schedule(Seconds(GetAdaptiveHelloInterval()), &FanetRoutingProtocol::SendHello, this);
}

// Send TC
void
FanetRoutingProtocol::SendTC()
{
    if (m_neighborTable.empty()) {
        Simulator::Schedule(Seconds(GetAdaptiveTcInterval()), &FanetRoutingProtocol::SendTC, this);
        return;
    }
    for (const auto& [sock, addr] : m_sendSockets) {
        Ptr<Packet> packet = Create<Packet>();
        FanetHeader header;
        header.type = TC;
        header.seq = m_tcSeq++;
        header.nodeId = m_ipv4->GetObject<Node>()->GetId();
        header.timestamp = Simulator::Now().GetMicroSeconds();
        for (const auto& [neighborIp, _] : m_neighborTable) {
            header.neighbors.push_back(neighborIp);
        }
        packet->AddHeader(header);
        InetSocketAddress dst(Ipv4Address::GetBroadcast(), FANET_UDP_PORT);
        sock->SendTo(packet, 0, dst);
    }
    Simulator::Schedule(Seconds(GetAdaptiveTcInterval()), &FanetRoutingProtocol::SendTC, this);
}

// Receive Packet
void
FanetRoutingProtocol::ReceiveFanetPacket(Ptr<Socket> socket)
{
    Address from;
    Ptr<Packet> packet = socket->RecvFrom(from);
    if (!packet) return;
    InetSocketAddress sender = InetSocketAddress::ConvertFrom(from);
    Ipv4Address senderIp = sender.GetIpv4();
    Ipv4PacketInfoTag interfaceInfo;
    uint32_t incomingIface = UINT32_MAX;
    if (packet->RemovePacketTag(interfaceInfo)) {
        incomingIface = interfaceInfo.GetRecvIf();
    }
    if (incomingIface == UINT32_MAX) return;
    if (m_ipv4->GetInterfaceForAddress(senderIp) != -1) return; // Self
    // Update SNR if available
    auto snrIt = m_lastSnr.find(senderIp);
    if (snrIt != m_lastSnr.end()) {
        auto& metric = m_linkMetrics[senderIp];
        metric.avgSNR = (metric.avgSNR * metric.snrCount + snrIt->second) / (metric.snrCount + 1);
        metric.snrCount++;
        m_lastSnr.erase(snrIt);
    }
    ProcessFanetPacket(packet, senderIp, incomingIface);
}

// Process Packet
void
FanetRoutingProtocol::ProcessFanetPacket(Ptr<Packet> packet, Ipv4Address senderIp, uint32_t incomingIface)
{
    FanetHeader fanet;
    if (!packet->RemoveHeader(fanet)) return;
    if (fanet.ttl == 0) return;
    fanet.ttl--;
    Time now = Simulator::Now();
    if (fanet.type == HELLO) {
        auto& metric = m_linkMetrics[senderIp];
        metric.rxPackets++;
        metric.totalBytes += packet->GetSize();
        Time sentTime = MicroSeconds(fanet.timestamp);
        Time currentDelay = now - sentTime;
        metric.totalDelay += currentDelay;
        if (metric.rxPackets > 1) {
            metric.jitter = 0.8 * metric.jitter + 0.2 * std::abs((currentDelay - metric.lastDelay).GetSeconds());
        }
        metric.lastDelay = currentDelay;
        if (metric.helloCount == 0) metric.firstSeen = now;
        metric.helloCount++;
        metric.helloRate = static_cast<double>(metric.helloCount) / std::max(1u, metric.helloExpected);
        bool selectedMe = false;
        for (auto const& selector : fanet.mprSelectorList) {
            if (selector == m_interfaces.front().local) { // Use front for multi-iface compat
                selectedMe = true;
                break;
            }
        }
        if (selectedMe) m_mprSelectors.insert(senderIp);
        else m_mprSelectors.erase(senderIp);
        auto it = m_neighborTable.find(senderIp);
        bool changed = false;
        if (it == m_neighborTable.end()) {
            NeighborInfo info;
            info.interface = incomingIface;
            info.lastSeen = now;
            m_neighborTable[senderIp] = info;
            changed = true;
        } else {
            it->second.lastSeen = now;
        }
        // Update 2-hop from HELLO (assume HELLO includes neighbors if extended, but here use TC for that)
        if (changed) OnTopologyChange();
    } else if (fanet.type == TC) {
        auto lastSeqIt = m_lastTcSeq.find(senderIp);
        if (lastSeqIt != m_lastTcSeq.end() && fanet.seq <= lastSeqIt->second) return;
        m_lastTcSeq[senderIp] = fanet.seq;
        TopologyEntry& entry = m_topologyTable[senderIp];
        entry.origin = senderIp;
        entry.neighbors = fanet.neighbors;
        entry.lastUpdate = now;
        // Update 2-hop
        m_twoHopNeighbors[senderIp] = fanet.neighbors;
        // MPR Forwarding
        if (m_mprSelectors.find(senderIp) != m_mprSelectors.end()) {
            Ptr<Packet> fwd = packet->Copy();
            fwd->AddHeader(fanet);
            for (const auto& [sock, addr] : m_sendSockets) {
                uint32_t sockIface = m_ipv4->GetInterfaceForAddress(addr.GetLocal());
                if (sockIface == incomingIface) continue;
                InetSocketAddress dst(Ipv4Address::GetBroadcast(), FANET_UDP_PORT);
                sock->SendTo(fwd->Copy(), 0, dst);
            }
        }
        OnTopologyChange();
    } else if (fanet.type == DATA) {
        // Decapsulate and local deliver or forward
        Ipv4Header innerHeader;
        packet->RemoveHeader(innerHeader); // Assume data has inner IP header
        if (fanet.origDst == m_interfaces.front().local) {
            // Local deliver (simulate)
            NS_LOG_INFO("Data delivered locally from " << fanet.origSrc);
            auto& metric = m_linkMetrics[senderIp];
            metric.rxPackets++;
            metric.ackPackets++; // Simulate ACK
        } else {
            // Forward
            Ptr<Ipv4Route> route = Lookup(fanet.origDst);
            if (route) {
                Ptr<Packet> fwd = packet->Copy();
                fwd->AddHeader(innerHeader);
                fwd->AddHeader(fanet);
                route->GetOutputDevice()->Send(fwd, route->GetDestination(), 0);
            }
        }
    }
}

// Build Graph for Dijkstra
void
FanetRoutingProtocol::BuildGraph(std::map<Ipv4Address, std::map<Ipv4Address, double>>& graph) {
    graph.clear();
    // Add 1-hop
    for (const auto& [nbr, _] : m_neighborTable) {
        double cost = 1.0 / (ComputeReward(nbr) + 1e-6); // Inverse reward as cost
        graph[m_interfaces.front().local][nbr] = cost;
        graph[nbr][m_interfaces.front().local] = cost; // Symmetric
    }
    // Add multi-hop from topology
    for (const auto& [origin, entry] : m_topologyTable) {
        for (const auto& nbr : entry.neighbors) {
            double cost = 1.0; // Default, or estimate
            graph[origin][nbr] = cost;
            graph[nbr][origin] = cost;
        }
    }
}

// Update Routing Table with Dijkstra
void
FanetRoutingProtocol::UpdateRoutingTable()
{
    m_routingTable.clear();
    std::map<Ipv4Address, std::map<Ipv4Address, double>> graph;
    BuildGraph(graph);
    // Dijkstra from local
    Ipv4Address local = m_interfaces.front().local;
    std::map<Ipv4Address, double> dist;
    std::map<Ipv4Address, Ipv4Address> prev;
    for (auto& [node, _] : graph) dist[node] = 1e9;
    dist[local] = 0.0;
    std::set<std::pair<double, Ipv4Address>> pq;
    pq.insert({0.0, local});
    while (!pq.empty()) {
        auto [cost, u] = *pq.begin();
        pq.erase(pq.begin());
        if (cost > dist[u]) continue;
        for (auto& [v, w] : graph[u]) {
            if (dist[v] > dist[u] + w) {
                pq.erase({dist[v], v});
                dist[v] = dist[u] + w;
                prev[v] = u;
                pq.insert({dist[v], v});
            }
        }
    }
    // Build routes
    for (auto& [dest, d] : dist) {
        if (dest == local || d == 1e9) continue;
        Ipv4Address hop = dest;
        while (prev[hop] != local) hop = prev[hop];
        auto nbrIt = m_neighborTable.find(hop);
        if (nbrIt == m_neighborTable.end()) continue;
        RouteEntry entry;
        entry.destination = dest;
        entry.nextHop = hop;
        entry.interface = nbrIt->second.interface;
        entry.cost = d;
        m_routingTable[dest] = entry;
    }
}

// Lookup Route
Ptr<Ipv4Route>
FanetRoutingProtocol::Lookup(Ipv4Address dest)
{
    // Neighbor first
    auto neighborIt = m_neighborTable.find(dest);
    if (neighborIt != m_neighborTable.end()) {
        uint32_t iface = neighborIt->second.interface;
        Ptr<Ipv4Route> route = Create<Ipv4Route>();
        route->SetDestination(dest);
        route->SetGateway(dest);
        route->SetSource(m_ipv4->GetAddress(iface, 0).GetLocal());
        route->SetOutputDevice(m_ipv4->GetNetDevice(iface));
        return route;
    }
    // Routing table
    auto routeIt = m_routingTable.find(dest);
    if (routeIt != m_routingTable.end()) {
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

// Route Output (Encapsulate Data)
Ptr<Ipv4Route>
FanetRoutingProtocol::RouteOutput(Ptr<Packet> p, const Ipv4Header& header, Ptr<NetDevice> oif, Socket::SocketErrno& sockerr)
{
    Ipv4Address dest = header.GetDestination();
    Ptr<Ipv4Route> route = Lookup(dest);
    if (route) {
        // Encapsulate as DATA
        FanetHeader fanet;
        fanet.type = DATA;
        fanet.seq = 0; // Data seq not used
        fanet.nodeId = m_ipv4->GetObject<Node>()->GetId();
        fanet.timestamp = Simulator::Now().GetMicroSeconds();
        fanet.origSrc = header.GetSource();
        fanet.origDst = dest;
        p->AddHeader(header); // Inner IP
        p->AddHeader(fanet);
        sockerr = Socket::ERROR_NOTERROR;
        return route;
    }
    sockerr = Socket::ERROR_NOROUTETOHOST;
    return nullptr;
}

// Route Input (Decapsulate/Forward)
bool
FanetRoutingProtocol::RouteInput(Ptr<const Packet> p, const Ipv4Header& header, Ptr<const NetDevice> idev,
                                 const UnicastForwardCallback& ucb, const MulticastForwardCallback& mcb,
                                 const LocalDeliverCallback& lcb, const ErrorCallback& ecb)
{
    Ipv4Address dest = header.GetDestination();
    uint32_t iif = m_ipv4->GetInterfaceForDevice(idev);
    if (m_ipv4->IsDestinationAddress(dest, iif)) {
        lcb(p, header, iif);
        return true;
    }
    Ptr<Ipv4Route> route = Lookup(dest);
    if (route) {
        Ipv4Address nextHop = route->GetGateway();
        auto& metric = m_linkMetrics[nextHop];
        metric.txPackets++;
        double reward = ComputeReward(nextHop);
        UpdateQValue(dest, nextHop, reward);
        ucb(route, ConstCast<Packet>(p), header);
        return true;
    }
    return false;
}

// Select Next Hop with Q (ε-greedy with decay)
Ipv4Address
FanetRoutingProtocol::SelectNextHopQ(Ipv4Address destination)
{
    if (UniformRandomVariable().GetValue() < m_epsilon) {
        if (m_neighborTable.empty()) return Ipv4Address::GetZero();
        auto it = m_neighborTable.begin();
        std::advance(it, rand() % m_neighborTable.size());
        return it->first;
    }
    double bestQ = -1e9;
    Ipv4Address bestNbr = Ipv4Address::GetZero();
    for (const auto& [nbr, _] : m_neighborTable) {
        double q = m_qTable[destination][nbr];
        if (q > bestQ) {
            bestQ = q;
            bestNbr = nbr;
        }
    }
    m_epsilon = std::max(MIN_EPSILON, m_epsilon * EPSILON_DECAY);
    return bestNbr;
}

// Update Q-Value
void
FanetRoutingProtocol::UpdateQValue(Ipv4Address dest, Ipv4Address action, double reward)
{
    double& q = m_qTable[dest][action];
    double maxNextQ = 0.0;
    for (const auto& [nbr, _] : m_neighborTable) {
        maxNextQ = std::max(maxNextQ, m_qTable[dest][nbr]);
    }
    q += m_alpha * (reward + m_gamma * maxNextQ - q);
}

// Compute Reward with Prediction/Trust/SNR
double
FanetRoutingProtocol::ComputeReward(Ipv4Address nextHop)
{
    const auto& m = m_linkMetrics[nextHop];
    double wPdr = 0.25;
    double wLatency = 0.15;
    double wThroughput = 0.15;
    double wStability = 0.2;
    double wSnr = 0.15;
    double wTrust = 0.1;
    double normLatency = std::exp(-m.GetLatencyMs() / 100.0);
    double normThroughput = std::min(1.0, m.GetThroughputKbps() / 54000.0);
    double r = (wPdr * m.predictedPDR) +
               (wLatency * normLatency) +
               (wThroughput * normThroughput) +
               (wStability * std::min(1.0, m.predictedStability / 10.0)) +
               (wSnr * m.GetNormSNR()) +
               (wTrust * m.trustScore);
    return r;
}

// On Topology Change
void
FanetRoutingProtocol::OnTopologyChange()
{
    ExpireNeighbors();
    UpdateRoutingTable();
}

// Phy Rx Callback for SNR
void
FanetRoutingProtocol::PhyRxBeginCallback(Ptr<const Packet> packet, double snr, WifiMode mode, WifiPreamble preamble)
{
    Ipv4Header ipHeader;
    if (packet->PeekHeader(ipHeader)) {
        m_lastSnr[ipHeader.GetSource()] = snr;
    }
}

// Helper
class FanetRoutingHelper : public Ipv4RoutingHelper
{
public:
    FanetRoutingHelper* Copy(void) const override { return new FanetRoutingHelper(*this); }
    Ptr<Ipv4RoutingProtocol> Create(Ptr<Node> node) const override { return CreateObject<FanetRoutingProtocol>(); }
};

// Main Simulation
int
main(int argc, char* argv[])
{
    bool useOlsr = false;
    CommandLine cmd;
    cmd.AddValue("useOlsr", "Use OLSR instead", useOlsr);
    cmd.Parse(argc, argv);

    uint32_t nNodes = 20; // Increased for scenario
    double simTime = 60.0;

    LogComponentEnable("FanetCustomRouting", LOG_LEVEL_ALL);
    LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);

    NodeContainer nodes;
    nodes.Create(nNodes);

    MobilityHelper mobility;
    Box areaBounds(0, 500, 0, 500, 0, 100);
    mobility.SetPositionAllocator("ns3::RandomRectanglePositionAllocator",
                                  "X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=500.0]"),
                                  "Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=500.0]"));
    mobility.SetMobilityModel("ns3::GaussMarkovMobilityModel",
                              "Bounds", BoxValue(areaBounds),
                              "TimeStep", TimeValue(Seconds(0.5)),
                              "Alpha", DoubleValue(0.85),
                              "MeanVelocity", StringValue("ns3::UniformRandomVariable[Min=10.0|Max=30.0]"),
                              "MeanDirection", StringValue("ns3::UniformRandomVariable[Min=0|Max=6.28]"),
                              "MeanPitch", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=0.0]"));
    mobility.Install(nodes);

    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    channel.AddPropagationLoss("ns3::FriisPropagationLossModel", "Frequency", DoubleValue(2.4e9));
    YansWifiPhyHelper phy;
    phy.SetChannel(channel.Create());
    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");
    WifiHelper wifi;
    NetDeviceContainer devices = wifi.Install(phy, mac, nodes);

    InternetStackHelper internet;
    if (useOlsr) {
        OlsrHelper olsr;
        internet.SetRoutingHelper(olsr);
    } else {
        FanetRoutingHelper fanet;
        internet.SetRoutingHelper(fanet);
    }
    internet.Install(nodes);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = ipv4.Assign(devices);

    uint16_t port = 9;
    UdpEchoServerHelper echoServer(port);
    ApplicationContainer serverApps = echoServer.Install(nodes.Get(nNodes - 1)); // Sink
    serverApps.Start(Seconds(0.4));
    serverApps.Stop(Seconds(simTime));

    // Clients to sink
    for (uint32_t i = 0; i < nNodes - 1; ++i) {
        UdpEchoClientHelper client(interfaces.GetAddress(nNodes - 1), port);
        client.SetAttribute("MaxPackets", UintegerValue(10000));
        client.SetAttribute("Interval", TimeValue(Seconds(0.5)));
        client.SetAttribute("PacketSize", UintegerValue(512));
        ApplicationContainer clientApp = client.Install(nodes.Get(i));
        clientApp.Start(Seconds(2.0 + i * 0.1));
        clientApp.Stop(Seconds(simTime));
    }

    // Stats Collection
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    AnimationInterface anim("fanet-custom.xml");

    Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper>("fanet-routing.tables", std::ios::out);
    for (double t = 1.0; t < simTime; t += 5.0) {
        if (!useOlsr) {
            internet.GetRoutingProtocol()->PrintRoutingTableAllAt(Seconds(t), routingStream);
        }
    }

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    // Output Stats
    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();
    double totalPdr = 0.0, totalDelay = 0.0;
    uint32_t flowCount = 0;
    for (auto& [id, fs] : stats) {
        if (fs.rxPackets > 0) {
            totalPdr += (double)fs.rxPackets / fs.txPackets;
            totalDelay += fs.delaySum.GetSeconds() / fs.rxPackets;
            flowCount++;
        }
    }
    std::cout << "Average PDR: " << (totalPdr / flowCount) << std::endl;
    std::cout << "Average Delay: " << (totalDelay / flowCount) << " s" << std::endl;

    Simulator::Destroy();
    return 0;
}
