/*
 * Copyright (c) 2004 Francisco J. Ros
 * Copyright (c) 2007 INESC Porto
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Authors: Francisco J. Ros  <fjrm@dif.um.es>
 *          Gustavo J. A. M. Carneiro <gjc@inescporto.pt>
 */

///
/// \file olsr-state.cc
/// \brief Implementation of all functions needed for manipulating the internal
///        state of an olsr node.
///

#include "olsr-state.h"

namespace ns3
{
namespace olsr
{

/********** MPR Selector Set Manipulation **********/

MprSelectorTuple*
olsrState::FindMprSelectorTuple(const Ipv4Address& mainAddr)
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

/**********************************************************************************/

// Manage local GPS state
void
olsrState::SetPosition (float lat, float lon, int16_t alt)
{
  m_latitude = lat;
  m_longitude = lon;
  m_altitude = alt;
}

// Speed Prediction Logic
float
olsrState::CalculatePolsrSpeed (float currentDist, float prevDist, Time deltaT, float prevAvgSpeed, float gamma)
{
  double dT = deltaT.GetSeconds ();
  if (dT <= 0) return prevAvgSpeed;

  // Instantaneous relative velocity between nodes i and j (Eq 5) 
  float instantaneousV = (currentDist - prevDist) / dT;
  // Exponential moving average to smooth GPS errors and wind gusts (Eq 6) 
  float newAvgSpeed = (gamma * instantaneousV) + ((1 - gamma) * prevAvgSpeed);
  
  return newAvgSpeed;
}

/**********************************************************************************/

void
olsrState::EraseMprSelectorTuple(const MprSelectorTuple& tuple)
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
olsrState::EraseMprSelectorTuples(const Ipv4Address& mainAddr)
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
olsrState::InsertMprSelectorTuple(const MprSelectorTuple& tuple)
{
    m_mprSelectorSet.push_back(tuple);
}

std::string
olsrState::PrintMprSelectorSet() const
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
olsrState::FindNeighborTuple(const Ipv4Address& mainAddr)
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
olsrState::FindSymNeighborTuple(const Ipv4Address& mainAddr) const
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
olsrState::FindNeighborTuple(const Ipv4Address& mainAddr, Willingness willingness)
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
olsrState::EraseNeighborTuple(const NeighborTuple& tuple)
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
olsrState::EraseNeighborTuple(const Ipv4Address& mainAddr)
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
olsrState::InsertNeighborTuple(const NeighborTuple& tuple)
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
olsrState::FindTwoHopNeighborTuple(const Ipv4Address& neighborMainAddr,
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
olsrState::EraseTwoHopNeighborTuple(const TwoHopNeighborTuple& tuple)
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
olsrState::EraseTwoHopNeighborTuples(const Ipv4Address& neighborMainAddr,
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
olsrState::EraseTwoHopNeighborTuples(const Ipv4Address& neighborMainAddr)
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
olsrState::InsertTwoHopNeighborTuple(const TwoHopNeighborTuple& tuple)
{
    m_twoHopNeighborSet.push_back(tuple);
}

/********** MPR Set Manipulation **********/

bool
olsrState::FindMprAddress(const Ipv4Address& addr)
{
    auto it = m_mprSet.find(addr);
    return (it != m_mprSet.end());
}

void
olsrState::SetMprSet(MprSet mprSet)
{
    m_mprSet = mprSet;
}

MprSet
olsrState::GetMprSet() const
{
    return m_mprSet;
}

/********** Duplicate Set Manipulation **********/

DuplicateTuple*
olsrState::FindDuplicateTuple(const Ipv4Address& addr, uint16_t sequenceNumber)
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
olsrState::EraseDuplicateTuple(const DuplicateTuple& tuple)
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
olsrState::InsertDuplicateTuple(const DuplicateTuple& tuple)
{
    m_duplicateSet.push_back(tuple);
}

/********** Link Set Manipulation **********/

LinkTuple*
olsrState::FindLinkTuple(const Ipv4Address& ifaceAddr)
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
olsrState::FindSymLinkTuple(const Ipv4Address& ifaceAddr, Time now)
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
olsrState::EraseLinkTuple(const LinkTuple& tuple)
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
olsrState::InsertLinkTuple(const LinkTuple& tuple)
{
    m_linkSet.push_back(tuple);
    return m_linkSet.back();
}

/********** Topology Set Manipulation **********/

TopologyTuple*
olsrState::FindTopologyTuple(const Ipv4Address& destAddr, const Ipv4Address& lastAddr)
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
olsrState::FindNewerTopologyTuple(const Ipv4Address& lastAddr, uint16_t ansn)
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
olsrState::EraseTopologyTuple(const TopologyTuple& tuple)
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
olsrState::EraseOlderTopologyTuples(const Ipv4Address& lastAddr, uint16_t ansn)
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
olsrState::InsertTopologyTuple(const TopologyTuple& tuple)
{
    for (auto it = m_topologySet.begin (); it != m_topologySet.end (); it++)
    {
      if (it->destAddr == tuple.destAddr && it->lastAddr == tuple.lastAddr)
        {
          // Update standard fields
          *it = tuple;
          // P-olsr Extension: Update the speed weight from the TC message
          it->hasSpeedWeight = tuple.hasSpeedWeight;
          it->speedWeight = tuple.speedWeight;
          return;
        }
    }
    m_topologySet.push_back(tuple);
}

/********** Interface Association Set Manipulation **********/

IfaceAssocTuple*
olsrState::FindIfaceAssocTuple(const Ipv4Address& ifaceAddr)
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
olsrState::FindIfaceAssocTuple(const Ipv4Address& ifaceAddr) const
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
olsrState::EraseIfaceAssocTuple(const IfaceAssocTuple& tuple)
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
olsrState::InsertIfaceAssocTuple(const IfaceAssocTuple& tuple)
{
    m_ifaceAssocSet.push_back(tuple);
}

std::vector<Ipv4Address>
olsrState::FindNeighborInterfaces(const Ipv4Address& neighborMainAddr) const
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
olsrState::FindAssociationTuple(const Ipv4Address& gatewayAddr,
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
olsrState::EraseAssociationTuple(const AssociationTuple& tuple)
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
olsrState::InsertAssociationTuple(const AssociationTuple& tuple)
{
    m_associationSet.push_back(tuple);
}

void
olsrState::EraseAssociation(const Association& tuple)
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
olsrState::InsertAssociation(const Association& tuple)
{
    m_associations.push_back(tuple);
}

} // namespace olsr
} // namespace ns3
