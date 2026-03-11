///
/// @file qbr-tuple-manager.cc
/// @brief Implementation of TupleManager — owns m_ansn, m_linkTupleTimerFirstTime,
///        and a reference to QbrState. Contains all 18 Add*/Remove* tuple mutators,
///        all 7 timer-expiry handlers, NeighborLoss, and IncrementAnsn.
///
/// Methods split out from the original monolithic RoutingProtocol:
///   IncrementAnsn, NeighborLoss,
///   AddDuplicateTuple, RemoveDuplicateTuple,
///   LinkTupleAdded, RemoveLinkTuple, LinkTupleUpdated,
///   AddNeighborTuple, RemoveNeighborTuple,
///   AddTwoHopNeighborTuple, RemoveTwoHopNeighborTuple,
///   AddMprSelectorTuple, RemoveMprSelectorTuple,
///   AddTopologyTuple, RemoveTopologyTuple,
///   AddIfaceAssocTuple, RemoveIfaceAssocTuple,
///   AddAssociationTuple, RemoveAssociationTuple,
///   DupTupleTimerExpire, LinkTupleTimerExpire, Nb2hopTupleTimerExpire,
///   MprSelTupleTimerExpire, TopologyTupleTimerExpire,
///   IfaceAssocTupleTimerExpire, AssociationTupleTimerExpire
///

#define NS_LOG_APPEND_CONTEXT                                                                      \
    if (m_node)                                                                                    \
    {                                                                                              \
        std::clog << "[node " << m_node->GetId() << "] ";                                          \
    }

#include "qbr-tuple-manager.h"

#include "ns3/assert.h"
#include "ns3/log.h"
#include "ns3/simulator.h"

///
/// @brief Gets the delay between a given time and the current time.
/// If the given time is in the past, returns a tiny positive value so
/// that events can still be scheduled.
///
#define DELAY(time)                                                                                \
    (((time) < (Simulator::Now())) ? Seconds(0.000001)                                             \
                                   : (time - Simulator::Now() + Seconds(0.000001)))

/// Maximum allowed sequence number (wraps at 0xFFFF).
#define QBR_MAX_SEQ_NUM 65535

/// Duplicate-tuple holding time (RFC 3626 §3.4).
#define QBR_DUP_HOLD_TIME Seconds(30)

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QbrTupleManager");

namespace qbr
{

// -----------------------------------------------------------------------
// Construction
// -----------------------------------------------------------------------

TupleManager::TupleManager(QbrState& state)
    : m_ansn(QBR_MAX_SEQ_NUM),
      m_linkTupleTimerFirstTime(true),
      m_state(state),
      m_node(nullptr),
      m_mainAddress()
{
}

// -----------------------------------------------------------------------
// ANSN
// -----------------------------------------------------------------------

void
TupleManager::IncrementAnsn()
{
    m_ansn = (m_ansn + 1) % (QBR_MAX_SEQ_NUM + 1);
}

// -----------------------------------------------------------------------
// Neighbor loss
// -----------------------------------------------------------------------

void
TupleManager::NeighborLoss(const LinkTuple& tuple)
{
    NS_LOG_DEBUG(Simulator::Now().As(Time::S)
                 << ": QBR Node " << m_mainAddress << " LinkTuple "
                 << tuple.neighborIfaceAddr << " -> neighbor loss.");

    LinkTupleUpdated(tuple, Willingness::DEFAULT);
    m_state.EraseTwoHopNeighborTuples(GetMainAddress(tuple.neighborIfaceAddr));
    m_state.EraseMprSelectorTuples(GetMainAddress(tuple.neighborIfaceAddr));

    // Signal RoutingProtocol to recompute MPR set and routing table.
    // The callbacks must be wired up by RoutingProtocol after construction.
    if (m_onNeighborLoss)
    {
        m_onNeighborLoss();
    }
}

// -----------------------------------------------------------------------
// Duplicate tuple management
// -----------------------------------------------------------------------

void
TupleManager::AddDuplicateTuple(const DuplicateTuple& tuple)
{
    m_state.InsertDuplicateTuple(tuple);
}

void
TupleManager::RemoveDuplicateTuple(const DuplicateTuple& tuple)
{
    m_state.EraseDuplicateTuple(tuple);
}

// -----------------------------------------------------------------------
// Link tuple management
// -----------------------------------------------------------------------

void
TupleManager::LinkTupleAdded(const LinkTuple& tuple, Willingness willingness)
{
    // Creates the associated neighbor tuple.
    NeighborTuple nb_tuple;
    nb_tuple.neighborMainAddr = GetMainAddress(tuple.neighborIfaceAddr);
    nb_tuple.willingness      = willingness;
    nb_tuple.status = (tuple.symTime >= Simulator::Now())
                          ? NeighborTuple::STATUS_SYM
                          : NeighborTuple::STATUS_NOT_SYM;
    AddNeighborTuple(nb_tuple);
}

void
TupleManager::RemoveLinkTuple(const LinkTuple& tuple)
{
    NS_LOG_DEBUG(Simulator::Now().As(Time::S)
                 << ": QBR Node " << m_mainAddress << " LinkTuple " << tuple << " REMOVED.");

    m_state.EraseNeighborTuple(GetMainAddress(tuple.neighborIfaceAddr));
    m_state.EraseLinkTuple(tuple);
}

void
TupleManager::LinkTupleUpdated(const LinkTuple& tuple, Willingness willingness)
{
    NS_LOG_DEBUG(Simulator::Now().As(Time::S)
                 << ": QBR Node " << m_mainAddress << " LinkTuple " << tuple << " UPDATED.");

    NeighborTuple* nb_tuple =
        m_state.FindNeighborTuple(GetMainAddress(tuple.neighborIfaceAddr));

    if (nb_tuple == nullptr)
    {
        LinkTupleAdded(tuple, willingness);
        nb_tuple = m_state.FindNeighborTuple(GetMainAddress(tuple.neighborIfaceAddr));
    }

    if (nb_tuple != nullptr)
    {
        int statusBefore    = nb_tuple->status;
        bool hasSymmetricLink = false;

        for (const auto& link_tuple : m_state.GetLinks())
        {
            if (GetMainAddress(link_tuple.neighborIfaceAddr) == nb_tuple->neighborMainAddr &&
                link_tuple.symTime >= Simulator::Now())
            {
                hasSymmetricLink = true;
                break;
            }
        }

        if (hasSymmetricLink)
        {
            nb_tuple->status = NeighborTuple::STATUS_SYM;
            NS_LOG_DEBUG(*nb_tuple << "->status = STATUS_SYM; changed:"
                                   << int(statusBefore != nb_tuple->status));
        }
        else
        {
            nb_tuple->status = NeighborTuple::STATUS_NOT_SYM;
            NS_LOG_DEBUG(*nb_tuple << "->status = STATUS_NOT_SYM; changed:"
                                   << int(statusBefore != nb_tuple->status));
        }
    }
    else
    {
        NS_LOG_WARN("ERROR! Wanted to update a NeighborTuple but none was found!");
    }
}

// -----------------------------------------------------------------------
// Neighbor tuple management
// -----------------------------------------------------------------------

void
TupleManager::AddNeighborTuple(const NeighborTuple& tuple)
{
    m_state.InsertNeighborTuple(tuple);
    IncrementAnsn();
}

void
TupleManager::RemoveNeighborTuple(const NeighborTuple& tuple)
{
    m_state.EraseNeighborTuple(tuple);
    IncrementAnsn();
}

// -----------------------------------------------------------------------
// Two-hop neighbor tuple management
// -----------------------------------------------------------------------

void
TupleManager::AddTwoHopNeighborTuple(const TwoHopNeighborTuple& tuple)
{
    m_state.InsertTwoHopNeighborTuple(tuple);
}

void
TupleManager::RemoveTwoHopNeighborTuple(const TwoHopNeighborTuple& tuple)
{
    m_state.EraseTwoHopNeighborTuple(tuple);
}

// -----------------------------------------------------------------------
// MPR selector tuple management
// -----------------------------------------------------------------------

void
TupleManager::AddMprSelectorTuple(const MprSelectorTuple& tuple)
{
    m_state.InsertMprSelectorTuple(tuple);
    IncrementAnsn();
}

void
TupleManager::RemoveMprSelectorTuple(const MprSelectorTuple& tuple)
{
    m_state.EraseMprSelectorTuple(tuple);
    IncrementAnsn();
}

// -----------------------------------------------------------------------
// Topology tuple management
// -----------------------------------------------------------------------

void
TupleManager::AddTopologyTuple(const TopologyTuple& tuple)
{
    m_state.InsertTopologyTuple(tuple);
}

void
TupleManager::RemoveTopologyTuple(const TopologyTuple& tuple)
{
    m_state.EraseTopologyTuple(tuple);
}

// -----------------------------------------------------------------------
// Interface association tuple management
// -----------------------------------------------------------------------

void
TupleManager::AddIfaceAssocTuple(const IfaceAssocTuple& tuple)
{
    m_state.InsertIfaceAssocTuple(tuple);
}

void
TupleManager::RemoveIfaceAssocTuple(const IfaceAssocTuple& tuple)
{
    m_state.EraseIfaceAssocTuple(tuple);
}

// -----------------------------------------------------------------------
// Host-network association tuple management
// -----------------------------------------------------------------------

void
TupleManager::AddAssociationTuple(const AssociationTuple& tuple)
{
    m_state.InsertAssociationTuple(tuple);
}

void
TupleManager::RemoveAssociationTuple(const AssociationTuple& tuple)
{
    m_state.EraseAssociationTuple(tuple);
}

// -----------------------------------------------------------------------
// Timer expiry handlers
// -----------------------------------------------------------------------

void
TupleManager::DupTupleTimerExpire(Ipv4Address address, uint16_t sequenceNumber)
{
    DuplicateTuple* tuple = m_state.FindDuplicateTuple(address, sequenceNumber);
    if (tuple == nullptr)
    {
        return;
    }
    if (tuple->expirationTime < Simulator::Now())
    {
        RemoveDuplicateTuple(*tuple);
    }
    else
    {
        m_events.Track(
            Simulator::Schedule(DELAY(tuple->expirationTime),
                                &TupleManager::DupTupleTimerExpire,
                                this,
                                address,
                                sequenceNumber));
    }
}

void
TupleManager::LinkTupleTimerExpire(Ipv4Address neighborIfaceAddr)
{
    Time now = Simulator::Now();

    LinkTuple* tuple = m_state.FindLinkTuple(neighborIfaceAddr);
    if (tuple == nullptr)
    {
        return;
    }

    if (tuple->time < now)
    {
        RemoveLinkTuple(*tuple);
    }
    else if (tuple->symTime < now)
    {
        if (m_linkTupleTimerFirstTime)
        {
            m_linkTupleTimerFirstTime = false;
        }
        else
        {
            NeighborLoss(*tuple);
        }
        m_events.Track(
            Simulator::Schedule(DELAY(tuple->time),
                                &TupleManager::LinkTupleTimerExpire,
                                this,
                                neighborIfaceAddr));
    }
    else
    {
        m_events.Track(
            Simulator::Schedule(DELAY(std::min(tuple->time, tuple->symTime)),
                                &TupleManager::LinkTupleTimerExpire,
                                this,
                                neighborIfaceAddr));
    }
}

void
TupleManager::Nb2hopTupleTimerExpire(Ipv4Address neighborMainAddr,
                                     Ipv4Address twoHopNeighborAddr)
{
    TwoHopNeighborTuple* tuple =
        m_state.FindTwoHopNeighborTuple(neighborMainAddr, twoHopNeighborAddr);
    if (tuple == nullptr)
    {
        return;
    }
    if (tuple->expirationTime < Simulator::Now())
    {
        RemoveTwoHopNeighborTuple(*tuple);
    }
    else
    {
        m_events.Track(
            Simulator::Schedule(DELAY(tuple->expirationTime),
                                &TupleManager::Nb2hopTupleTimerExpire,
                                this,
                                neighborMainAddr,
                                twoHopNeighborAddr));
    }
}

void
TupleManager::MprSelTupleTimerExpire(Ipv4Address mainAddr)
{
    MprSelectorTuple* tuple = m_state.FindMprSelectorTuple(mainAddr);
    if (tuple == nullptr)
    {
        return;
    }
    if (tuple->expirationTime < Simulator::Now())
    {
        RemoveMprSelectorTuple(*tuple);
    }
    else
    {
        m_events.Track(
            Simulator::Schedule(DELAY(tuple->expirationTime),
                                &TupleManager::MprSelTupleTimerExpire,
                                this,
                                mainAddr));
    }
}

void
TupleManager::TopologyTupleTimerExpire(Ipv4Address destAddr, Ipv4Address lastAddr)
{
    TopologyTuple* tuple = m_state.FindTopologyTuple(destAddr, lastAddr);
    if (tuple == nullptr)
    {
        return;
    }
    if (tuple->expirationTime < Simulator::Now())
    {
        RemoveTopologyTuple(*tuple);
    }
    else
    {
        m_events.Track(
            Simulator::Schedule(DELAY(tuple->expirationTime),
                                &TupleManager::TopologyTupleTimerExpire,
                                this,
                                tuple->destAddr,
                                tuple->lastAddr));
    }
}

void
TupleManager::IfaceAssocTupleTimerExpire(Ipv4Address ifaceAddr)
{
    IfaceAssocTuple* tuple = m_state.FindIfaceAssocTuple(ifaceAddr);
    if (tuple == nullptr)
    {
        return;
    }
    if (tuple->time < Simulator::Now())
    {
        RemoveIfaceAssocTuple(*tuple);
    }
    else
    {
        m_events.Track(
            Simulator::Schedule(DELAY(tuple->time),
                                &TupleManager::IfaceAssocTupleTimerExpire,
                                this,
                                ifaceAddr));
    }
}

void
TupleManager::AssociationTupleTimerExpire(Ipv4Address gatewayAddr,
                                          Ipv4Address networkAddr,
                                          Ipv4Mask    netmask)
{
    AssociationTuple* tuple = m_state.FindAssociationTuple(gatewayAddr, networkAddr, netmask);
    if (tuple == nullptr)
    {
        return;
    }
    if (tuple->expirationTime < Simulator::Now())
    {
        RemoveAssociationTuple(*tuple);
    }
    else
    {
        m_events.Track(
            Simulator::Schedule(DELAY(tuple->expirationTime),
                                &TupleManager::AssociationTupleTimerExpire,
                                this,
                                gatewayAddr,
                                networkAddr,
                                netmask));
    }
}

// -----------------------------------------------------------------------
// Private helper — mirrors RoutingProtocol::GetMainAddress()
// -----------------------------------------------------------------------

Ipv4Address
TupleManager::GetMainAddress(Ipv4Address ifaceAddr) const
{
    const IfaceAssocTuple* tuple = m_state.FindIfaceAssocTuple(ifaceAddr);
    return (tuple != nullptr) ? tuple->mainAddr : ifaceAddr;
}

} // namespace qbr
} // namespace ns3