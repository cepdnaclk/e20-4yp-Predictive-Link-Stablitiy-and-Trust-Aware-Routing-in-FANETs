#include "FanetState.h"
#include <ns3/log.h>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("FanetState");

FanetState::FanetState() : m_helloSeq(0), m_tcSeq(0)
{
}

FanetState::~FanetState()
{
}

// =====================
// Neighbor Management
// =====================
void
FanetState::AddNeighbor(Ipv4Address neighborIp, uint32_t interface)
{
    if (m_neighborTable.find(neighborIp) == m_neighborTable.end())
    {
        NeighborInfo info;
        info.interface = interface;
        info.lastSeen = Simulator::Now();
        m_neighborTable[neighborIp] = info;
        NS_LOG_INFO("Neighbor " << neighborIp << " added on interface " << interface);
    }
}

void
FanetState::UpdateNeighborLastSeen(Ipv4Address neighborIp)
{
    auto it = m_neighborTable.find(neighborIp);
    if (it != m_neighborTable.end())
    {
        it->second.lastSeen = Simulator::Now();
    }
}

void
FanetState::RemoveNeighbor(Ipv4Address neighborIp)
{
    auto it = m_neighborTable.find(neighborIp);
    if (it != m_neighborTable.end())
    {
        m_neighborTable.erase(it);
        NS_LOG_INFO("Neighbor " << neighborIp << " removed");
    }
}

bool
FanetState::IsNeighbor(Ipv4Address addr) const
{
    return m_neighborTable.find(addr) != m_neighborTable.end();
}

std::map<Ipv4Address, NeighborInfo>&
FanetState::GetNeighbors()
{
    return m_neighborTable;
}

const std::map<Ipv4Address, NeighborInfo>&
FanetState::GetNeighbors() const
{
    return m_neighborTable;
}

// =====================
// Topology Management
// =====================
void
FanetState::AddTopologyEntry(Ipv4Address origin, const std::vector<Ipv4Address>& neighbors)
{
    TopologyEntry& entry = m_topologyTable[origin];
    entry.origin = origin;
    entry.neighbors = neighbors;
    entry.lastUpdate = Simulator::Now();
    NS_LOG_INFO("Topology entry for " << origin << " updated with " << neighbors.size() << " neighbors");
}

void
FanetState::RemoveTopologyEntry(Ipv4Address origin)
{
    auto it = m_topologyTable.find(origin);
    if (it != m_topologyTable.end())
    {
        m_topologyTable.erase(it);
        NS_LOG_INFO("Topology entry for " << origin << " removed");
    }
}

bool
FanetState::IsTopologyEntry(Ipv4Address origin) const
{
    return m_topologyTable.find(origin) != m_topologyTable.end();
}

std::map<Ipv4Address, TopologyEntry>&
FanetState::GetTopology()
{
    return m_topologyTable;
}

const std::map<Ipv4Address, TopologyEntry>&
FanetState::GetTopology() const
{
    return m_topologyTable;
}

// =====================
// Routing Table Management
// =====================
void
FanetState::AddRoute(Ipv4Address dest, Ipv4Address nextHop, uint32_t interface)
{
    RouteEntry entry;
    entry.destination = dest;
    entry.nextHop = nextHop;
    entry.interface = interface;
    m_routingTable[dest] = entry;
    NS_LOG_DEBUG("Route to " << dest << " via " << nextHop << " added");
}

void
FanetState::RemoveRoute(Ipv4Address dest)
{
    auto it = m_routingTable.find(dest);
    if (it != m_routingTable.end())
    {
        m_routingTable.erase(it);
    }
}

void
FanetState::ClearRoutingTable()
{
    m_routingTable.clear();
}

bool
FanetState::HasRoute(Ipv4Address dest) const
{
    return m_routingTable.find(dest) != m_routingTable.end();
}

const RouteEntry*
FanetState::GetRoute(Ipv4Address dest) const
{
    auto it = m_routingTable.find(dest);
    if (it != m_routingTable.end())
    {
        return &it->second;
    }
    return nullptr;
}

std::map<Ipv4Address, RouteEntry>&
FanetState::GetRoutingTable()
{
    return m_routingTable;
}

const std::map<Ipv4Address, RouteEntry>&
FanetState::GetRoutingTable() const
{
    return m_routingTable;
}

// =====================
// Link Metrics Management
// =====================
LinkMetric&
FanetState::GetLinkMetric(Ipv4Address neighbor)
{
    return m_linkMetrics[neighbor];
}

const LinkMetric&
FanetState::GetLinkMetric(Ipv4Address neighbor) const
{
    auto it = m_linkMetrics.find(neighbor);
    if (it != m_linkMetrics.end())
    {
        return it->second;
    }
    static LinkMetric dummy;
    return dummy;
}

bool
FanetState::HasLinkMetric(Ipv4Address neighbor) const
{
    return m_linkMetrics.find(neighbor) != m_linkMetrics.end();
}

void
FanetState::RemoveLinkMetric(Ipv4Address neighbor)
{
    auto it = m_linkMetrics.find(neighbor);
    if (it != m_linkMetrics.end())
    {
        m_linkMetrics.erase(it);
    }
}

std::map<Ipv4Address, LinkMetric>&
FanetState::GetAllLinkMetrics()
{
    return m_linkMetrics;
}

const std::map<Ipv4Address, LinkMetric>&
FanetState::GetAllLinkMetrics() const
{
    return m_linkMetrics;
}

// =====================
// Interface Management
// =====================
void
FanetState::AddInterface(uint32_t ifIndex, Ipv4Address local)
{
    FanetInterface iface;
    iface.ifIndex = ifIndex;
    iface.local = local;
    m_interfaces.push_back(iface);
    NS_LOG_INFO("Interface " << ifIndex << " (" << local << ") added");
}

std::vector<FanetInterface>&
FanetState::GetInterfaces()
{
    return m_interfaces;
}

const std::vector<FanetInterface>&
FanetState::GetInterfaces() const
{
    return m_interfaces;
}

void
FanetState::ClearInterfaces()
{
    m_interfaces.clear();
}

// =====================
// Two-Hop Neighbors
// =====================
void
FanetState::SetTwoHopNeighbors(Ipv4Address neighbor, const std::vector<Ipv4Address>& twoHops)
{
    m_twoHopNeighbors[neighbor] = twoHops;
}

std::vector<Ipv4Address>
FanetState::GetTwoHopNeighbors(Ipv4Address neighbor) const
{
    auto it = m_twoHopNeighbors.find(neighbor);
    if (it != m_twoHopNeighbors.end())
    {
        return it->second;
    }
    return std::vector<Ipv4Address>();
}

std::map<Ipv4Address, std::vector<Ipv4Address>>&
FanetState::GetAllTwoHopNeighbors()
{
    return m_twoHopNeighbors;
}

// =====================
// MPR Management
// =====================
void
FanetState::SetMprSet(const std::set<Ipv4Address>& mprSet)
{
    m_mprSet = mprSet;
}

std::set<Ipv4Address>&
FanetState::GetMprSet()
{
    return m_mprSet;
}

const std::set<Ipv4Address>&
FanetState::GetMprSet() const
{
    return m_mprSet;
}

void
FanetState::AddMprSelector(Ipv4Address mprSelector)
{
    m_mprSelectors.insert(mprSelector);
}

void
FanetState::RemoveMprSelector(Ipv4Address mprSelector)
{
    m_mprSelectors.erase(mprSelector);
}

std::set<Ipv4Address>&
FanetState::GetMprSelectors()
{
    return m_mprSelectors;
}

const std::set<Ipv4Address>&
FanetState::GetMprSelectors() const
{
    return m_mprSelectors;
}

// =====================
// Sequence Number Management
// =====================
uint32_t
FanetState::GetNextHelloSeq()
{
    return m_helloSeq++;
}

uint32_t
FanetState::GetNextTcSeq()
{
    return m_tcSeq++;
}

uint32_t
FanetState::GetLastTcSeq(Ipv4Address origin) const
{
    auto it = m_lastTcSeq.find(origin);
    if (it != m_lastTcSeq.end())
    {
        return it->second;
    }
    return 0;
}

void
FanetState::SetLastTcSeq(Ipv4Address origin, uint32_t seq)
{
    m_lastTcSeq[origin] = seq;
}

// =====================
// Q-Learning State
// =====================
double
FanetState::GetQValue(Ipv4Address dest, Ipv4Address action)
{
    return m_qTable[dest][action];
}

void
FanetState::SetQValue(Ipv4Address dest, Ipv4Address action, double value)
{
    m_qTable[dest][action] = value;
}

std::map<Ipv4Address, std::map<Ipv4Address, double>>&
FanetState::GetQTable()
{
    return m_qTable;
}

} // namespace ns3
