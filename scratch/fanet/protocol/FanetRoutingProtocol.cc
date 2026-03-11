#include "FanetRoutingProtocol.h"
#include <ns3/log.h>
#include <ns3/ipv4-route.h>
#include <ns3/ipv4-packet-info-tag.h>
#include <ns3/udp-socket-factory.h>
#include <ns3/inet-socket-address.h>
#include <ns3/simulator.h>
#include <ns3/random-variable-stream.h>
#include <algorithm>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("FanetCustomRouting");
NS_OBJECT_ENSURE_REGISTERED(FanetRoutingProtocol);

// constructor / destructor
FanetRoutingProtocol::FanetRoutingProtocol()
    : m_ipv4(nullptr), m_state(std::make_unique<FanetState>()), m_alpha(0.5), m_gamma(0.8), m_epsilon(0.1)
{
}

FanetRoutingProtocol::~FanetRoutingProtocol()
{
}

// Notification stubs
void
FanetRoutingProtocol::NotifyInterfaceUp(uint32_t interface) {}
void
FanetRoutingProtocol::NotifyInterfaceDown(uint32_t interface) {}
void
FanetRoutingProtocol::NotifyAddAddress(uint32_t interface, Ipv4InterfaceAddress address) {}
void
FanetRoutingProtocol::NotifyRemoveAddress(uint32_t interface, Ipv4InterfaceAddress address) {}

Ptr<Ipv4Route>
FanetRoutingProtocol::RouteOutput(Ptr<Packet> p,
                                  const Ipv4Header& header,
                                  Ptr<NetDevice> oif,
                                  Socket::SocketErrno& sockerr)
{
    Ipv4Address dest = header.GetDestination();
    Ptr<Ipv4Route> route = Lookup(dest);
    if (route)
    {
        NS_LOG_INFO("Node " << m_ipv4->GetAddress(1, 0).GetLocal() << " sending packet to " << dest
                            << " via gateway " << route->GetGateway() << " on interface "
                            << route->GetOutputDevice()->GetIfIndex());
        sockerr = Socket::ERROR_NOTERROR;
        return route;
    }
    NS_LOG_DEBUG("No route found for " << dest);
    sockerr = Socket::ERROR_NOROUTETOHOST;
    return nullptr;
}

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
    uint32_t iif = m_ipv4->GetInterfaceForDevice(idev);
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
            return false;
        }
    }

    Ptr<Ipv4Route> route = Lookup(dest);
    if (!route)
    {
        ecb(p, header, Socket::ERROR_NOROUTETOHOST);
        return false;
    }
    NS_LOG_INFO("Node " << m_ipv4->GetAddress(1, 0).GetLocal() << " forwarding packet to "
                        << dest << " via gateway " << route->GetGateway() << " on interface "
                        << route->GetOutputDevice()->GetIfIndex());

    Ipv4Address nextHop = route->GetGateway();
    m_state->GetLinkMetric(nextHop).txPackets++;
    auto& metric = m_state->GetLinkMetric(nextHop);
    metric.successRatio = 0.9 * metric.successRatio + 0.1;
    double reward = ComputeReward(nextHop);
    UpdateQValue(dest, nextHop, reward);
    ucb(route, p, header);
    return true;
}

void
FanetRoutingProtocol::PrintRoutingTable(Ptr<OutputStreamWrapper> stream, Time::Unit unit) const
{
    std::ostream* os = stream->GetStream();
    *os << "\n--- FANET Routing Table (Node " << m_ipv4->GetObject<Node>()->GetId() << ") ---\n";
    *os << std::left << std::setw(15) << "Destination"
        << std::setw(15) << "NextHop"
        << std::setw(10) << "PDR"
        << std::setw(12) << "Latency(ms)"
        << std::setw(10) << "Jitter"
        << "Throughput(Kbps)" << std::endl;

    for (const auto& [neighborIp, info] : m_state->GetNeighbors()) {
        if (m_state->HasLinkMetric(neighborIp)) {
            const auto& metric = m_state->GetLinkMetric(neighborIp);
            *os << std::left << std::setw(15) << neighborIp
                << std::setw(15) << "DIRECT"
                << std::setw(10) << std::fixed << std::setprecision(2) << metric.GetPDR()
                << std::setw(12) << metric.GetLatencyMs()
                << metric.GetThroughputKbps() << std::endl;
        }
    }

    for (const auto& [dest, entry] : m_state->GetRoutingTable()) {
        if (m_state->HasLinkMetric(entry.nextHop)) {
            const auto& metric = m_state->GetLinkMetric(entry.nextHop);
            *os << std::left << std::setw(15) << dest
                << std::setw(15) << entry.nextHop
                << std::setw(10) << metric.GetPDR()
                << std::setw(12) << metric.GetLatencyMs()
                << metric.GetThroughputKbps() << std::endl;
        }
    }
    *os << "------------------------------------------------------------\n";
}

void
FanetRoutingProtocol::SetIpv4(Ptr<Ipv4> ipv4)
{
    m_ipv4 = ipv4;
    Ptr<Node> node = ipv4->GetObject<Node>();
    NS_ASSERT(node);
    Simulator::Schedule(Seconds(0.0), &FanetRoutingProtocol::InitializeInterfaces, this);
    Simulator::Schedule(Seconds(0.0), &FanetRoutingProtocol::SendHello, this);
    Simulator::Schedule(Seconds(0.1), &FanetRoutingProtocol::SendTC, this);
    ExpireNeighbors();
}

void
FanetRoutingProtocol::InitializeInterfaces()
{
    m_state->ClearInterfaces();
    m_sendSockets.clear();

    for (uint32_t i = 0; i < m_ipv4->GetNInterfaces(); ++i)
    {
        if (!m_ipv4->IsUp(i) || m_ipv4->GetNAddresses(i) == 0 || i == 0)
        {
            continue;
        }

        Ipv4Address local = m_ipv4->GetAddress(i, 0).GetLocal();
        m_state->AddInterface(i, local);

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
                                                   << local);
    }
}

void
FanetRoutingProtocol::ExpireNeighbors()
{
    Time now = Simulator::Now();
    bool changed = false;

    for (auto it = m_state->GetNeighbors().begin(); it != m_state->GetNeighbors().end();)
    {
        auto& metric = m_state->GetLinkMetric(it->first);
        Time lifetime = Simulator::Now() - metric.firstSeen;
        metric.stability = lifetime.GetSeconds();

        if (now - it->second.lastSeen > Seconds(3))
        {
            metric.successRatio *= 0.7;
            m_state->RemoveNeighbor(it->first);
            it = m_state->GetNeighbors().begin();
            changed = true;
            continue;
        }
        else
        {
            ++it;
        }
    }

    for (auto it = m_state->GetTopology().begin(); it != m_state->GetTopology().end();)
    {
        if (now - it->second.lastUpdate > Seconds(3))
        {
            m_state->RemoveTopologyEntry(it->first);
            it = m_state->GetTopology().begin();
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

    Simulator::Schedule(Seconds(NEIGHBOR_TIMEOUT), &FanetRoutingProtocol::ExpireNeighbors, this);
}

void
FanetRoutingProtocol::SendHello()
{
    ComputeMprSet();
    for (auto& [nbr, metric] : m_state->GetAllLinkMetrics())
    {
        metric.helloExpected++;
    }

    for (const auto& [sock, addr] : m_sendSockets)
    {
        Ptr<Packet> packet = Create<Packet>();
        FanetHeader header;
        header.type = HELLO;
        header.seq = m_state->GetNextHelloSeq();
        header.nodeId = m_ipv4->GetObject<Node>()->GetId();
        header.timestamp = Simulator::Now().GetMicroSeconds();
        for (auto const& mprAddr : m_state->GetMprSet()) {
            header.mprSelectorList.push_back(mprAddr);
        }
        packet->AddHeader(header);
        InetSocketAddress dst(Ipv4Address::GetBroadcast(), FANET_UDP_PORT);
        sock->SendTo(packet, 0, dst);

        NS_LOG_INFO("Node " << addr.GetLocal() << " sent HELLO");
    }

    Simulator::Schedule(Seconds(HELLO_INTERVAL), &FanetRoutingProtocol::SendHello, this);
}

void
FanetRoutingProtocol::SendTC()
{
    if (m_state->GetNeighbors().empty())
    {
        Simulator::Schedule(Seconds(TC_INTERVAL), &FanetRoutingProtocol::SendTC, this);
        return;
    }

    for (const auto& [sock, addr] : m_sendSockets)
    {
        Ptr<Packet> packet = Create<Packet>();
        FanetHeader header;
        header.type = TC;
        header.seq = m_state->GetNextTcSeq();
        header.nodeId = m_ipv4->GetObject<Node>()->GetId();
        header.timestamp = Simulator::Now().GetMicroSeconds();
        for (const auto& [neighborIp, _] : m_state->GetNeighbors())
        {
            header.neighbors.push_back(neighborIp);
        }

        packet->AddHeader(header);
        InetSocketAddress dst(Ipv4Address::GetBroadcast(), FANET_UDP_PORT);
        sock->SendTo(packet, 0, dst);

        NS_LOG_INFO("Node " << addr.GetLocal() << " sent TC");
    }

    Simulator::Schedule(Seconds(TC_INTERVAL), &FanetRoutingProtocol::SendTC, this);
}

void
FanetRoutingProtocol::ReceiveFanetPacket(Ptr<Socket> socket)
{
    Address from;
    Ptr<Packet> packet = socket->RecvFrom(from);
    if (!packet) { return; }

    InetSocketAddress sender = InetSocketAddress::ConvertFrom(from);
    Ipv4Address senderIp = sender.GetIpv4();

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

    int32_t interfaceForAddress = m_ipv4->GetInterfaceForAddress(senderIp);
    if (interfaceForAddress != -1)
    {
        NS_LOG_LOGIC("Ignoring a packet sent by myself.");
        return;
    }

    ProcessFanetPacket(packet, senderIp, incomingIface);
}

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
        auto& metric = m_state->GetLinkMetric(senderIp);
        metric.rxPackets++;
        metric.totalBytes += (packet->GetSize() + fanet.GetSerializedSize());

        Time sentTime = MicroSeconds(fanet.timestamp);
        Time currentDelay = Simulator::Now() - sentTime;
        metric.totalDelay += currentDelay;

        if (metric.rxPackets > 1) {
            metric.jitter = 0.8 * metric.jitter + 0.2 * std::abs((currentDelay - metric.lastDelay).GetSeconds());
        }
        metric.totalDelay += currentDelay;
        metric.lastDelay = currentDelay;

        NS_LOG_INFO("Metrics Update from " << senderIp 
                << " | PDR: " << metric.GetPDR() 
                << " | Latency: " << metric.GetLatencyMs() << " ms"
                << " | Jitter: " << metric.jitter << " s"
                << " | Throughput: " << metric.GetThroughputKbps() << " Kbps");

        if (metric.helloCount == 0)
        {
            metric.firstSeen = Simulator::Now();
        }

        metric.helloCount++;
        metric.helloExpected++;

        metric.helloRate =
            static_cast<double>(metric.helloCount) / std::max(1u, metric.helloExpected);

        bool selectedMe = false;
        for (auto const& selector : fanet.mprSelectorList) {
            if (selector == m_state->GetInterfaces()[0].local) {
                selectedMe = true;
                break;
            }
        }

        if (selectedMe) {
            m_state->AddMprSelector(senderIp);
        } else {
            m_state->RemoveMprSelector(senderIp);
        }

        if (!m_state->IsNeighbor(senderIp))
        {
            m_state->AddNeighbor(senderIp, incomingIface);
            changed = true;
            NS_LOG_INFO("Discovered new neighbor " << senderIp << " on iface " << incomingIface);
        }
        else
        {
            m_state->UpdateNeighborLastSeen(senderIp);
        }

        if (changed)
        {
            UpdateRoutingTable();
        }
    }
    else if (fanet.type == TC)
    {
        uint32_t lastSeq = m_state->GetLastTcSeq(senderIp);
        if (lastSeq != 0 && fanet.seq <= lastSeq)
        {
            return;
        }

        m_state->SetLastTcSeq(senderIp, fanet.seq);
        m_state->AddTopologyEntry(senderIp, fanet.neighbors);
        UpdateRoutingTable();

        if (m_state->GetMprSelectors().find(senderIp) == m_state->GetMprSelectors().end()) 
        {
            NS_LOG_INFO("TC from " << senderIp << " ignored for forwarding (not an MPR selector).");
            UpdateRoutingTable();
            return; 
        }
        NS_LOG_INFO("Forwarding TC from " << senderIp << " as MPR relay.");
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

void
FanetRoutingProtocol::UpdateRoutingTable()
{
    m_state->ClearRoutingTable();

    for (const auto& [dest, topo] : m_state->GetTopology())
    {
        if (m_state->GetNeighbors().empty())
        {
            continue;
        }

        Ipv4Address nextHop = SelectNextHopQ(dest);

        if (!m_state->IsNeighbor(nextHop))
        {
            continue;
        }

        const NeighborInfo& nbrInfo = m_state->GetNeighbors().at(nextHop);
        m_state->AddRoute(dest, nextHop, nbrInfo.interface);
    }
}

Ptr<Ipv4Route>
FanetRoutingProtocol::Lookup(Ipv4Address dest)
{
    auto& neighbors = m_state->GetNeighbors();
    auto neighborIt = neighbors.find(dest);
    if (neighborIt != neighbors.end())
    {
        NS_LOG_LOGIC("Lookup: " << dest << " found in Neighbor Table.");

        uint32_t iface = neighborIt->second.interface;

        Ptr<Ipv4Route> route = Create<Ipv4Route>();
        route->SetDestination(dest);
        route->SetGateway(dest);
        route->SetSource(m_ipv4->GetAddress(iface, 0).GetLocal());
        route->SetOutputDevice(m_ipv4->GetNetDevice(iface));
        return route;
    }

    const RouteEntry* routeEntry = m_state->GetRoute(dest);
    if (routeEntry != nullptr)
    {
        NS_LOG_LOGIC("Lookup: " << dest << " found in Routing Table.");
        Ptr<Ipv4Route> route = Create<Ipv4Route>();
        route->SetDestination(routeEntry->destination);
        route->SetGateway(routeEntry->nextHop);
        route->SetSource(m_ipv4->GetAddress(routeEntry->interface, 0).GetLocal());
        route->SetOutputDevice(m_ipv4->GetNetDevice(routeEntry->interface));
        return route;
    }

    return nullptr;
}

FanetRoutingHelper*
FanetRoutingHelper::Copy(void) const
{
    return new FanetRoutingHelper(*this);
}

Ptr<Ipv4RoutingProtocol>
FanetRoutingHelper::Create(Ptr<Node> node) const
{
    return CreateObject<FanetRoutingProtocol>();
}

Ipv4Address
FanetRoutingProtocol::SelectNextHopQ(Ipv4Address destination)
{
    auto& neighbors = m_state->GetNeighbors();
    if (neighbors.empty())
    {
        return Ipv4Address::GetZero();
    }

    if (UniformRandomVariable().GetValue() < m_epsilon)
    {
        auto it = neighbors.begin();
        std::advance(it, rand() % neighbors.size());
        return it->first;
    }

    double bestQ = -1e9;
    Ipv4Address bestNbr = Ipv4Address::GetZero();

    for (const auto& [nbr, info] : neighbors)
    {
        double q = m_state->GetQValue(destination, nbr);
        if (q > bestQ)
        {
            bestQ = q;
            bestNbr = nbr;
        }
    }

    return bestNbr;
}

void
FanetRoutingProtocol::UpdateQValue(Ipv4Address dest, Ipv4Address action, double reward)
{
    auto& qTable = m_state->GetQTable();
    double& q = qTable[dest][action];
    double maxNextQ = 0.0;
    for (const auto& [nbr, _] : m_state->GetNeighbors())
    {
        maxNextQ = std::max(maxNextQ, qTable[dest][nbr]);
    }
    q = q + m_alpha * (reward + m_gamma * maxNextQ - q);
}

double
FanetRoutingProtocol::ComputeReward(Ipv4Address nextHop)
{
    const auto& m = m_state->GetLinkMetric(nextHop);
    double wPdr = 0.3;
    double wLatency = 0.2;
    double wThroughput = 0.2;
    double wStability = 0.3;
    double normLatency = std::exp(-m.GetLatencyMs() / 100.0);
    double normThroughput = std::min(1.0, m.GetThroughputKbps() / 54000.0);
    double r = (wPdr * m.GetPDR()) +
               (wLatency * normLatency) +
               (wThroughput * normThroughput) +
               (wStability * std::min(1.0, m.stability / 10.0));
    return r;
}

void
FanetRoutingProtocol::OnTopologyChange()
{
    ExpireNeighbors();
    UpdateRoutingTable();
}

void
FanetRoutingProtocol::ComputeMprSet()
{
    std::set<Ipv4Address> mprSet;
    std::set<Ipv4Address> uncoveredTwoHop;
    
    for (auto const& [neighbor, twoHopList] : m_state->GetAllTwoHopNeighbors()) {
        for (auto const& twoHop : twoHopList) {
            if (twoHop != m_state->GetInterfaces()[0].local && 
                !m_state->IsNeighbor(twoHop)) {
                uncoveredTwoHop.insert(twoHop);
            }
        }
    }
    
    while (!uncoveredTwoHop.empty()) {
        Ipv4Address bestNbr;
        uint32_t maxCovered = 0;
        for (auto const& [neighbor, _] : m_state->GetNeighbors()) {
            uint32_t coverage = 0;
            for (auto const& target : m_state->GetTwoHopNeighbors(neighbor)) {
                if (uncoveredTwoHop.count(target)) coverage++;
            }
            if (coverage > maxCovered) {
                maxCovered = coverage;
                bestNbr = neighbor;
            }
        }
        if (maxCovered == 0) break;
        mprSet.insert(bestNbr);
        for (auto const& target : m_state->GetTwoHopNeighbors(bestNbr)) {
            uncoveredTwoHop.erase(target);
        }
    }
    
    m_state->SetMprSet(mprSet);
}

} // namespace ns3
