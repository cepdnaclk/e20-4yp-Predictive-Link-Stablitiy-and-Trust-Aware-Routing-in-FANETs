#ifndef QBR_TUPLE_MANAGER_H
#define QBR_TUPLE_MANAGER_H

/**
 * @file qbr-tuple-manager.h
 * @brief Owns all QBR tuple sets and the timers / callbacks that maintain them.
 *
 * TupleManager centralises the 18 Add/Remove tuple mutators, the 7 timer
 * expiry handlers, NeighborLoss, and IncrementAnsn — the largest coherent
 * cluster of private methods that existed in the original monolithic
 * RoutingProtocol class.
 *
 * Members migrated from RoutingProtocol (qbr-message-handler.h):
 *   Data:    m_ansn, m_linkTupleTimerFirstTime, QbrState& (reference)
 *   Methods: All 18 Add/Remove tuple mutators,
 *            7 timer-expiry handlers (Dup, LinkTuple, Nb2hop, MprSel,
 *            Topology, IfaceAssoc, Association),
 *            NeighborLoss, IncrementAnsn
 */

#include "qbr-repositories.h"
#include "qbr-state.h"

#include "ns3/event-garbage-collector.h"
#include "ns3/ipv4-address.h"
#include "ns3/node.h"
#include "ns3/nstime.h"

#include <functional>

namespace ns3
{
namespace qbr
{

/**
 * @ingroup qbr
 * @brief Manages all QBR tuple sets and the timers that expire them.
 *
 * RoutingProtocol holds a TupleManager instance (or inherits from it).
 * Every method here reads or writes QbrState exclusively through the
 * reference supplied at construction, keeping a clean separation between
 * the state store and the logic that drives it.
 */
class TupleManager
{
  public:
    // ------------------------------------------------------------------ //
    //  Construction / lifecycle
    // ------------------------------------------------------------------ //

    /**
     * @brief Constructs the manager with a reference to the shared QBR state.
     *
     * The caller (RoutingProtocol) owns @p state and must outlive this object.
     *
     * @param state Reference to the QbrState that holds all tuple sets.
     */
    explicit TupleManager(QbrState& state);
    ~TupleManager() = default;

    // ------------------------------------------------------------------ //
    //  Wiring helpers — called by RoutingProtocol after construction
    // ------------------------------------------------------------------ //

    /**
     * @brief Provides the Node pointer used for log context.
     * @param node The owning Node.
     */
    void SetNode(Ptr<Node> node) { m_node = node; }

    /**
     * @brief Provides the main address used in log messages.
     * @param addr The node's main QBR address.
     */
    void SetMainAddress(Ipv4Address addr) { m_mainAddress = addr; }

    /**
     * @brief Registers the callback RoutingProtocol uses to trigger
     *        MprComputation() + RoutingTableComputation() after a neighbor loss.
     * @param cb The callback to invoke.
     */
    void SetNeighborLossCallback(std::function<void()> cb)
    {
        m_onNeighborLoss = std::move(cb);
    }

    /**
     * @brief Exposes the internal EventGarbageCollector so RoutingProtocol
     *        can track tuple-deletion events scheduled inside this object.
     * @return Reference to the event collector.
     */
    EventGarbageCollector& GetEvents() { return m_events; }

    // ------------------------------------------------------------------ //
    //  ANSN management
    // ------------------------------------------------------------------ //

    /**
     * @brief Increments the Advertised Neighbor Set sequence number (ANSN).
     *
     * Must be called whenever the MPR selector set changes so that
     * downstream nodes can detect stale TC messages.
     */
    void IncrementAnsn();

    /**
     * @brief Resets the ANSN to a specific value (used during SetIpv4 initialisation).
     * @param value The value to set (typically QBR_MAX_SEQ_NUM so the first increment wraps to 0).
     */
    void ResetAnsn(uint16_t value) { m_ansn = value; }

    /**
     * @brief Returns the current ANSN value.
     * @return The current Advertised Neighbor Set sequence number.
     */
    uint16_t GetAnsn() const
    {
        return m_ansn;
    }

    // ------------------------------------------------------------------ //
    //  Neighbor loss
    // ------------------------------------------------------------------ //

    /**
     * @brief Performs all state updates required when a neighbor link is lost.
     *
     * Updates the Neighbor Set, 2-hop Neighbor Set, MPR Set and MPR
     * Selector Set in response to the loss of the link described by @p tuple.
     *
     * @param tuple The link tuple representing the lost link.
     */
    void NeighborLoss(const LinkTuple& tuple);

    // ------------------------------------------------------------------ //
    //  Duplicate tuple management
    // ------------------------------------------------------------------ //

    /**
     * @brief Adds a duplicate tuple to the Duplicate Set.
     * @param tuple The duplicate tuple to add.
     */
    void AddDuplicateTuple(const DuplicateTuple& tuple);

    /**
     * @brief Removes a duplicate tuple from the Duplicate Set.
     * @param tuple The duplicate tuple to remove.
     */
    void RemoveDuplicateTuple(const DuplicateTuple& tuple);

    // ------------------------------------------------------------------ //
    //  Link tuple management
    // ------------------------------------------------------------------ //

    /**
     * @brief Invoked when a new link tuple is created.
     *
     * Triggers any necessary updates to the Neighbor Set.
     *
     * @param tuple       The newly created link tuple.
     * @param willingness Willingness of the originating node.
     */
    void LinkTupleAdded(const LinkTuple& tuple, Willingness willingness);

    /**
     * @brief Removes a link tuple from the Link Set.
     * @param tuple The link tuple to remove.
     */
    void RemoveLinkTuple(const LinkTuple& tuple);

    /**
     * @brief Invoked when an existing link tuple is updated.
     *
     * Also updates the corresponding neighbor tuple when necessary.
     *
     * @param tuple       The updated link tuple.
     * @param willingness The (possibly new) willingness of the neighbor.
     */
    void LinkTupleUpdated(const LinkTuple& tuple, Willingness willingness);

    // ------------------------------------------------------------------ //
    //  Neighbor tuple management
    // ------------------------------------------------------------------ //

    /**
     * @brief Adds a neighbor tuple to the Neighbor Set.
     * @param tuple The neighbor tuple to add.
     */
    void AddNeighborTuple(const NeighborTuple& tuple);

    /**
     * @brief Removes a neighbor tuple from the Neighbor Set.
     * @param tuple The neighbor tuple to remove.
     */
    void RemoveNeighborTuple(const NeighborTuple& tuple);

    // ------------------------------------------------------------------ //
    //  Two-hop neighbor tuple management
    // ------------------------------------------------------------------ //

    /**
     * @brief Adds a 2-hop neighbor tuple to the 2-hop Neighbor Set.
     * @param tuple The 2-hop neighbor tuple to add.
     */
    void AddTwoHopNeighborTuple(const TwoHopNeighborTuple& tuple);

    /**
     * @brief Removes a 2-hop neighbor tuple from the 2-hop Neighbor Set.
     * @param tuple The 2-hop neighbor tuple to remove.
     */
    void RemoveTwoHopNeighborTuple(const TwoHopNeighborTuple& tuple);

    // ------------------------------------------------------------------ //
    //  MPR selector tuple management
    // ------------------------------------------------------------------ //

    /**
     * @brief Adds an MPR selector tuple to the MPR Selector Set.
     *
     * The ANSN is incremented automatically because the advertised
     * neighbor set has changed.
     *
     * @param tuple The MPR selector tuple to add.
     */
    void AddMprSelectorTuple(const MprSelectorTuple& tuple);

    /**
     * @brief Removes an MPR selector tuple from the MPR Selector Set.
     *
     * The ANSN is incremented automatically because the advertised
     * neighbor set has changed.
     *
     * @param tuple The MPR selector tuple to remove.
     */
    void RemoveMprSelectorTuple(const MprSelectorTuple& tuple);

    // ------------------------------------------------------------------ //
    //  Topology tuple management
    // ------------------------------------------------------------------ //

    /**
     * @brief Adds a topology tuple to the Topology Set.
     * @param tuple The topology tuple to add.
     */
    void AddTopologyTuple(const TopologyTuple& tuple);

    /**
     * @brief Removes a topology tuple from the Topology Set.
     * @param tuple The topology tuple to remove.
     */
    void RemoveTopologyTuple(const TopologyTuple& tuple);

    // ------------------------------------------------------------------ //
    //  Interface association tuple management
    // ------------------------------------------------------------------ //

    /**
     * @brief Adds an interface association tuple to the Interface Association Set.
     * @param tuple The interface association tuple to add.
     */
    void AddIfaceAssocTuple(const IfaceAssocTuple& tuple);

    /**
     * @brief Removes an interface association tuple from the Interface Association Set.
     * @param tuple The interface association tuple to remove.
     */
    void RemoveIfaceAssocTuple(const IfaceAssocTuple& tuple);

    // ------------------------------------------------------------------ //
    //  Host-network association tuple management
    // ------------------------------------------------------------------ //

    /**
     * @brief Adds a host-network association tuple to the Association Set.
     * @param tuple The host-network association tuple to add.
     */
    void AddAssociationTuple(const AssociationTuple& tuple);

    /**
     * @brief Removes a host-network association tuple from the Association Set.
     * @param tuple The host-network association tuple to remove.
     */
    void RemoveAssociationTuple(const AssociationTuple& tuple);

    // ------------------------------------------------------------------ //
    //  Timer expiry handlers  (7 handlers)
    // ------------------------------------------------------------------ //

    /**
     * @brief Expires or reschedules a duplicate tuple timer.
     *
     * If the tuple has expired it is removed; otherwise the timer is
     * rescheduled to fire at the tuple's expiration time.
     *
     * @param address        The originator address of the duplicate tuple.
     * @param sequenceNumber The sequence number of the duplicate tuple.
     */
    void DupTupleTimerExpire(Ipv4Address address, uint16_t sequenceNumber);

    /**
     * @brief Expires or reschedules a link tuple timer.
     *
     * If the symmetric time has passed but the tuple has not yet expired,
     * a neighbor loss is signalled before the timer is rescheduled.
     *
     * @param neighborIfaceAddr The neighbor interface address of the tuple.
     */
    void LinkTupleTimerExpire(Ipv4Address neighborIfaceAddr);

    /**
     * @brief Expires or reschedules a 2-hop neighbor tuple timer.
     *
     * @param neighborMainAddr   Main address of the one-hop neighbor.
     * @param twoHopNeighborAddr Address of the 2-hop neighbor.
     */
    void Nb2hopTupleTimerExpire(Ipv4Address neighborMainAddr,
                                Ipv4Address twoHopNeighborAddr);

    /**
     * @brief Expires or reschedules an MPR selector tuple timer.
     *
     * @param mainAddr The main address of the MPR selector.
     */
    void MprSelTupleTimerExpire(Ipv4Address mainAddr);

    /**
     * @brief Expires or reschedules a topology tuple timer.
     *
     * @param destAddr The destination address stored in the topology tuple.
     * @param lastAddr The last-hop address stored in the topology tuple.
     */
    void TopologyTupleTimerExpire(Ipv4Address destAddr, Ipv4Address lastAddr);

    /**
     * @brief Expires or reschedules an interface association tuple timer.
     *
     * @param ifaceAddr The interface address stored in the tuple.
     */
    void IfaceAssocTupleTimerExpire(Ipv4Address ifaceAddr);

    /**
     * @brief Expires or reschedules a host-network association tuple timer.
     *
     * @param gatewayAddr The gateway address stored in the tuple.
     * @param networkAddr The network address stored in the tuple.
     * @param netmask     The network mask stored in the tuple.
     */
    void AssociationTupleTimerExpire(Ipv4Address gatewayAddr,
                                     Ipv4Address networkAddr,
                                     Ipv4Mask    netmask);

  private:
    // ------------------------------------------------------------------ //
    //  Data members
    // ------------------------------------------------------------------ //

    /// Advertised Neighbor Set sequence number — incremented on MPR selector changes.
    uint16_t m_ansn{0};

    /**
     * @brief True only on the very first LinkTupleTimer firing.
     *
     * Used to suppress a spurious neighbor-loss notification that would
     * otherwise be generated before any real link state has been observed.
     */
    bool m_linkTupleTimerFirstTime{true};

    /// Reference to the shared QBR state that owns all tuple containers.
    QbrState& m_state;

    /// Tracks running timer events so they are cancelled on object destruction.
    EventGarbageCollector m_events;

    /// Invoked by NeighborLoss() to trigger MprComputation + RoutingTableComputation.
    std::function<void()> m_onNeighborLoss;

    /// Node pointer — used only for NS_LOG_APPEND_CONTEXT.
    Ptr<Node> m_node;

    /// Main address of this node — used in log messages and GetMainAddress().
    Ipv4Address m_mainAddress;

    // ------------------------------------------------------------------ //
    //  Private helpers
    // ------------------------------------------------------------------ //

    /**
     * @brief Resolves an interface address to the node's main address.
     *
     * Mirrors RoutingProtocol::GetMainAddress(): looks up the Interface
     * Association Set and returns the main address, or @p ifaceAddr itself
     * when no association exists.
     *
     * @param ifaceAddr The interface address to resolve.
     * @return The corresponding main address.
     */
    Ipv4Address GetMainAddress(Ipv4Address ifaceAddr) const;
};

} // namespace qbr
} // namespace ns3

#endif /* QBR_TUPLE_MANAGER_H */