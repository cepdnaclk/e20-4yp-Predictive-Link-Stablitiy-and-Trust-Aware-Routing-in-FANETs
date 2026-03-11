///
/// @file qbr-routing-table.cc
/// @brief Implementation of RoutingTable — owns m_table, m_hnaRoutingTable,
///        m_routingTableAssociation, and all entry-level operations.
///
/// Methods split out from the original monolithic RoutingProtocol:
///   Clear, AddEntry (×2), RemoveEntry, Lookup, FindSendEntry,
///   GetEntries, SetRoutingTableAssociation, GetRoutingTableAssociation, Print
///

#include "qbr-routing-table.h"

#include "ns3/assert.h"
#include "ns3/ipv4.h"
#include "ns3/log.h"
#include "ns3/names.h"
#include "ns3/node.h"
#include "ns3/simulator.h"

#include <iomanip>
#include <sstream>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QbrRoutingTable");

namespace qbr
{

// -----------------------------------------------------------------------
// Association helpers
// -----------------------------------------------------------------------

void
RoutingTable::SetRoutingTableAssociation(Ptr<Ipv4StaticRouting> routingTable)
{
    m_routingTableAssociation = routingTable;
}

Ptr<const Ipv4StaticRouting>
RoutingTable::GetRoutingTableAssociation() const
{
    // Per the original RoutingProtocol::GetRoutingTableAssociation(), this
    // returns the HNA table (m_hnaRoutingTable), not the association pointer.
    return m_hnaRoutingTable;
}

// -----------------------------------------------------------------------
// Table-level operations
// -----------------------------------------------------------------------

void
RoutingTable::Clear()
{
    NS_LOG_FUNCTION_NOARGS();
    m_table.clear();
}

std::vector<RoutingTableEntry>
RoutingTable::GetEntries() const
{
    std::vector<RoutingTableEntry> retval;
    retval.reserve(m_table.size());
    for (const auto& kv : m_table)
    {
        retval.push_back(kv.second);
    }
    return retval;
}

// -----------------------------------------------------------------------
// Entry-level operations
// -----------------------------------------------------------------------

void
RoutingTable::RemoveEntry(const Ipv4Address& dest)
{
    m_table.erase(dest);
}

void
RoutingTable::AddEntry(const Ipv4Address& dest,
                       const Ipv4Address& next,
                       uint32_t           interface,
                       uint32_t           distance)
{
    NS_LOG_FUNCTION(dest << next << interface << distance);
    NS_ASSERT(distance > 0);

    RoutingTableEntry& entry = m_table[dest];
    entry.destAddr  = dest;
    entry.nextAddr  = next;
    entry.interface = interface;
    entry.distance  = distance;
}

void
RoutingTable::AddEntry(const Ipv4Address& dest,
                       const Ipv4Address& next,
                       const Ipv4Address& interfaceAddress,
                       uint32_t           distance)
{
    NS_LOG_FUNCTION(dest << next << interfaceAddress << distance);
    NS_ASSERT(distance > 0);

    // Resolve interface address → interface index via the stored Ipv4 pointer.
    // RoutingProtocol must call SetIpv4() on this object before using this overload.
    NS_ASSERT(m_ipv4);
    for (uint32_t i = 0; i < m_ipv4->GetNInterfaces(); i++)
    {
        for (uint32_t j = 0; j < m_ipv4->GetNAddresses(i); j++)
        {
            if (m_ipv4->GetAddress(i, j).GetLocal() == interfaceAddress)
            {
                AddEntry(dest, next, i, distance);
                return;
            }
        }
    }
    NS_ASSERT_MSG(false, "No interface found for address " << interfaceAddress);
    AddEntry(dest, next, 0, distance); // unreachable, satisfies compiler
}

bool
RoutingTable::Lookup(const Ipv4Address& dest, RoutingTableEntry& outEntry) const
{
    auto it = m_table.find(dest);
    if (it == m_table.end())
    {
        return false;
    }
    outEntry = it->second;
    return true;
}

bool
RoutingTable::FindSendEntry(const RoutingTableEntry& entry, RoutingTableEntry& outEntry) const
{
    outEntry = entry;
    while (outEntry.destAddr != outEntry.nextAddr)
    {
        if (!Lookup(outEntry.nextAddr, outEntry))
        {
            return false;
        }
    }
    return true;
}

// -----------------------------------------------------------------------
// Printing
// -----------------------------------------------------------------------

void
RoutingTable::Print(Ptr<OutputStreamWrapper> stream, Time::Unit unit) const
{
    std::ostream* os = stream->GetStream();

    // Save and reset stream formatting flags
    std::ios savedState(nullptr);
    savedState.copyfmt(*os);
    *os << std::resetiosflags(std::ios::adjustfield) << std::setiosflags(std::ios::left);

    *os << std::setw(16) << "Destination"
        << std::setw(16) << "NextHop"
        << std::setw(16) << "Interface"
        << "Distance" << std::endl;

    for (const auto& kv : m_table)
    {
        std::ostringstream dest;
        std::ostringstream nextHop;
        dest    << kv.first;
        nextHop << kv.second.nextAddr;
        *os << std::setw(16) << dest.str()
            << std::setw(16) << nextHop.str()
            << std::setw(16);

        if (m_ipv4)
        {
            const std::string devName =
                Names::FindName(m_ipv4->GetNetDevice(kv.second.interface));
            if (!devName.empty())
            {
                *os << devName;
            }
            else
            {
                *os << kv.second.interface;
            }
        }
        else
        {
            *os << kv.second.interface;
        }
        *os << kv.second.distance << std::endl;
    }
    *os << std::endl;

    // Restore stream state
    (*os).copyfmt(savedState);
}

} // namespace qbr
} // namespace ns3