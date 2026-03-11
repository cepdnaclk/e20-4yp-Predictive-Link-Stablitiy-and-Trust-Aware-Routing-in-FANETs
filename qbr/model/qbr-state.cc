#include "qbr-state.h"

namespace ns3
{
namespace qbr
{

/********** MPR Selector Set Manipulation **********/

MprSelectorTuple*
QbrState::FindMprSelectorTuple(const Ipv4Address& mainAddr)
{
    for (auto it = m_mprSelectorSet.begin(); it != m_mprSelectorSet.end(); it++)
    {
        if (it->mainAddr == mainAddr)
        {
            return &(*it);
        }
    }
    return nullptr;
}

void
QbrState::EraseMprSelectorTuple(const MprSelectorTuple& tuple)
{
    for (auto it = m_mprSelectorSet.begin(); it != m_mprSelectorSet.end(); it++)
    {
        if (*it == tuple)
        {
            m_mprSelectorSet.erase(it);
            break;
        }
    }
}

void
QbrState::EraseMprSelectorTuples(const Ipv4Address& mainAddr)
{
    for (auto it = m_mprSelectorSet.begin(); it != m_mprSelectorSet.end();)
    {
        if (it->mainAddr == mainAddr)
        {
            it = m_mprSelectorSet.erase(it);
        }
        else
        {
            it++;
        }
    }
}

void
QbrState::InsertMprSelectorTuple(const MprSelectorTuple& tuple)
{
    m_mprSelectorSet.push_back(tuple);
}

std::string
QbrState::PrintMprSelectorSet() const
{
    std::ostringstream os;
    os << "[";
    for (auto iter = m_mprSelectorSet.begin(); iter != m_mprSelectorSet.end(); iter++)
    {
        auto next = iter;
        next++;
        os << iter->mainAddr;
        if (next != m_mprSelectorSet.end())
        {
            os << ", ";
        }
    }
    os << "]";
    return os.str();
}

/********** Neighbor Set Manipulation **********/

NeighborTuple*
QbrState::FindNeighborTuple(const Ipv4Address& mainAddr)
{
    for (auto it = m_neighborSet.begin(); it != m_neighborSet.end(); it++)
    {
        if (it->neighborMainAddr == mainAddr)
        {
            return &(*it);
        }
    }
    return nullptr;
}

const NeighborTuple*
QbrState::FindSymNeighborTuple(const Ipv4Address& mainAddr) const
{
    for (auto it = m_neighborSet.begin(); it != m_neighborSet.end(); it++)
    {
        if (it->neighborMainAddr == mainAddr && it->status == NeighborTuple::STATUS_SYM)
        {
            return &(*it);
        }
    }
    return nullptr;
}

NeighborTuple*
QbrState::FindNeighborTuple(const Ipv4Address& mainAddr, Willingness willingness)
{
    for (auto it = m_neighborSet.begin(); it != m_neighborSet.end(); it++)
    {
        if (it->neighborMainAddr == mainAddr && it->willingness == willingness)
        {
            return &(*it);
        }
    }
    return nullptr;
}

void
QbrState::EraseNeighborTuple(const NeighborTuple& tuple)
{
    for (auto it = m_neighborSet.begin(); it != m_neighborSet.end(); it++)
    {
        if (*it == tuple)
        {
            m_neighborSet.erase(it);
            break;
        }
    }
}

void
QbrState::EraseNeighborTuple(const Ipv4Address& mainAddr)
{
    for (auto it = m_neighborSet.begin(); it != m_neighborSet.end(); it++)
    {
        if (it->neighborMainAddr == mainAddr)
        {
            it = m_neighborSet.erase(it);
            break;
        }
    }
}

void
QbrState::InsertNeighborTuple(const NeighborTuple& tuple)
{
    for (auto it = m_neighborSet.begin(); it != m_neighborSet.end(); it++)
    {
        if (it->neighborMainAddr == tuple.neighborMainAddr)
        {
            // Update it
            *it = tuple;
            return;
        }
    }
    m_neighborSet.push_back(tuple);
}

/********** Neighbor 2 Hop Set Manipulation **********/

TwoHopNeighborTuple*
QbrState::FindTwoHopNeighborTuple(const Ipv4Address& neighborMainAddr,
                                   const Ipv4Address& twoHopNeighborAddr)
{
    for (auto it = m_twoHopNeighborSet.begin(); it != m_twoHopNeighborSet.end(); it++)
    {
        if (it->neighborMainAddr == neighborMainAddr &&
            it->twoHopNeighborAddr == twoHopNeighborAddr)
        {
            return &(*it);
        }
    }
    return nullptr;
}

void
QbrState::EraseTwoHopNeighborTuple(const TwoHopNeighborTuple& tuple)
{
    for (auto it = m_twoHopNeighborSet.begin(); it != m_twoHopNeighborSet.end(); it++)
    {
        if (*it == tuple)
        {
            m_twoHopNeighborSet.erase(it);
            break;
        }
    }
}

void
QbrState::EraseTwoHopNeighborTuples(const Ipv4Address& neighborMainAddr,
                                     const Ipv4Address& twoHopNeighborAddr)
{
    for (auto it = m_twoHopNeighborSet.begin(); it != m_twoHopNeighborSet.end();)
    {
        if (it->neighborMainAddr == neighborMainAddr &&
            it->twoHopNeighborAddr == twoHopNeighborAddr)
        {
            it = m_twoHopNeighborSet.erase(it);
        }
        else
        {
            it++;
        }
    }
}

void
QbrState::EraseTwoHopNeighborTuples(const Ipv4Address& neighborMainAddr)
{
    for (auto it = m_twoHopNeighborSet.begin(); it != m_twoHopNeighborSet.end();)
    {
        if (it->neighborMainAddr == neighborMainAddr)
        {
            it = m_twoHopNeighborSet.erase(it);
        }
        else
        {
            it++;
        }
    }
}

void
QbrState::InsertTwoHopNeighborTuple(const TwoHopNeighborTuple& tuple)
{
    m_twoHopNeighborSet.push_back(tuple);
}

/********** MPR Set Manipulation **********/

bool
QbrState::FindMprAddress(const Ipv4Address& addr)
{
    auto it = m_mprSet.find(addr);
    return (it != m_mprSet.end());
}

void
QbrState::SetMprSet(MprSet mprSet)
{
    m_mprSet = mprSet;
}

MprSet
QbrState::GetMprSet() const
{
    return m_mprSet;
}

/********** Duplicate Set Manipulation **********/

DuplicateTuple*
QbrState::FindDuplicateTuple(const Ipv4Address& addr, uint16_t sequenceNumber)
{
    for (auto it = m_duplicateSet.begin(); it != m_duplicateSet.end(); it++)
    {
        if (it->address == addr && it->sequenceNumber == sequenceNumber)
        {
            return &(*it);
        }
    }
    return nullptr;
}

void
QbrState::EraseDuplicateTuple(const DuplicateTuple& tuple)
{
    for (auto it = m_duplicateSet.begin(); it != m_duplicateSet.end(); it++)
    {
        if (*it == tuple)
        {
            m_duplicateSet.erase(it);
            break;
        }
    }
}

void
QbrState::InsertDuplicateTuple(const DuplicateTuple& tuple)
{
    m_duplicateSet.push_back(tuple);
}

/********** Link Set Manipulation **********/

LinkTuple*
QbrState::FindLinkTuple(const Ipv4Address& ifaceAddr)
{
    for (auto it = m_linkSet.begin(); it != m_linkSet.end(); it++)
    {
        if (it->neighborIfaceAddr == ifaceAddr)
        {
            return &(*it);
        }
    }
    return nullptr;
}

LinkTuple*
QbrState::FindSymLinkTuple(const Ipv4Address& ifaceAddr, Time now)
{
    for (auto it = m_linkSet.begin(); it != m_linkSet.end(); it++)
    {
        if (it->neighborIfaceAddr == ifaceAddr)
        {
            if (it->symTime > now)
            {
                return &(*it);
            }
            else
            {
                break;
            }
        }
    }
    return nullptr;
}

void
QbrState::EraseLinkTuple(const LinkTuple& tuple)
{
    for (auto it = m_linkSet.begin(); it != m_linkSet.end(); it++)
    {
        if (*it == tuple)
        {
            m_linkSet.erase(it);
            break;
        }
    }
}

LinkTuple&
QbrState::InsertLinkTuple(const LinkTuple& tuple)
{
    m_linkSet.push_back(tuple);
    return m_linkSet.back();
}

/********** Topology Set Manipulation **********/

TopologyTuple*
QbrState::FindTopologyTuple(const Ipv4Address& destAddr, const Ipv4Address& lastAddr)
{
    for (auto it = m_topologySet.begin(); it != m_topologySet.end(); it++)
    {
        if (it->destAddr == destAddr && it->lastAddr == lastAddr)
        {
            return &(*it);
        }
    }
    return nullptr;
}

TopologyTuple*
QbrState::FindNewerTopologyTuple(const Ipv4Address& lastAddr, uint16_t ansn)
{
    for (auto it = m_topologySet.begin(); it != m_topologySet.end(); it++)
    {
        if (it->lastAddr == lastAddr && it->sequenceNumber > ansn)
        {
            return &(*it);
        }
    }
    return nullptr;
}

void
QbrState::EraseTopologyTuple(const TopologyTuple& tuple)
{
    for (auto it = m_topologySet.begin(); it != m_topologySet.end(); it++)
    {
        if (*it == tuple)
        {
            m_topologySet.erase(it);
            break;
        }
    }
}

void
QbrState::EraseOlderTopologyTuples(const Ipv4Address& lastAddr, uint16_t ansn)
{
    for (auto it = m_topologySet.begin(); it != m_topologySet.end();)
    {
        if (it->lastAddr == lastAddr && it->sequenceNumber < ansn)
        {
            it = m_topologySet.erase(it);
        }
        else
        {
            it++;
        }
    }
}

void
QbrState::InsertTopologyTuple(const TopologyTuple& tuple)
{
    m_topologySet.push_back(tuple);
}

void QbrState::UpdateTopologyMetrics(const Ipv4Address& dest, const Ipv4Address& last,
                                     double trust, double lq)
{
    auto tuple = FindTopologyTuple(dest, last);
    if (!tuple) return;
    tuple->trust = trust;
    tuple->linkQuality = lq;
}

/********** Interface Association Set Manipulation **********/

IfaceAssocTuple*
QbrState::FindIfaceAssocTuple(const Ipv4Address& ifaceAddr)
{
    for (auto it = m_ifaceAssocSet.begin(); it != m_ifaceAssocSet.end(); it++)
    {
        if (it->ifaceAddr == ifaceAddr)
        {
            return &(*it);
        }
    }
    return nullptr;
}

const IfaceAssocTuple*
QbrState::FindIfaceAssocTuple(const Ipv4Address& ifaceAddr) const
{
    for (auto it = m_ifaceAssocSet.begin(); it != m_ifaceAssocSet.end(); it++)
    {
        if (it->ifaceAddr == ifaceAddr)
        {
            return &(*it);
        }
    }
    return nullptr;
}

void
QbrState::EraseIfaceAssocTuple(const IfaceAssocTuple& tuple)
{
    for (auto it = m_ifaceAssocSet.begin(); it != m_ifaceAssocSet.end(); it++)
    {
        if (*it == tuple)
        {
            m_ifaceAssocSet.erase(it);
            break;
        }
    }
}

void
QbrState::InsertIfaceAssocTuple(const IfaceAssocTuple& tuple)
{
    m_ifaceAssocSet.push_back(tuple);
}

std::vector<Ipv4Address>
QbrState::FindNeighborInterfaces(const Ipv4Address& neighborMainAddr) const
{
    std::vector<Ipv4Address> retval;
    for (auto it = m_ifaceAssocSet.begin(); it != m_ifaceAssocSet.end(); it++)
    {
        if (it->mainAddr == neighborMainAddr)
        {
            retval.push_back(it->ifaceAddr);
        }
    }
    return retval;
}

/********** Host-Network Association Set Manipulation **********/

AssociationTuple*
QbrState::FindAssociationTuple(const Ipv4Address& gatewayAddr,
                                const Ipv4Address& networkAddr,
                                const Ipv4Mask& netmask)
{
    for (auto it = m_associationSet.begin(); it != m_associationSet.end(); it++)
    {
        if (it->gatewayAddr == gatewayAddr and it->networkAddr == networkAddr and
            it->netmask == netmask)
        {
            return &(*it);
        }
    }
    return nullptr;
}

void
QbrState::EraseAssociationTuple(const AssociationTuple& tuple)
{
    for (auto it = m_associationSet.begin(); it != m_associationSet.end(); it++)
    {
        if (*it == tuple)
        {
            m_associationSet.erase(it);
            break;
        }
    }
}

void
QbrState::InsertAssociationTuple(const AssociationTuple& tuple)
{
    m_associationSet.push_back(tuple);
}

void
QbrState::EraseAssociation(const Association& tuple)
{
    for (auto it = m_associations.begin(); it != m_associations.end(); it++)
    {
        if (*it == tuple)
        {
            m_associations.erase(it);
            break;
        }
    }
}

void
QbrState::InsertAssociation(const Association& tuple)
{
    m_associations.push_back(tuple);
}

} // namespace qbr
} // namespace ns3
