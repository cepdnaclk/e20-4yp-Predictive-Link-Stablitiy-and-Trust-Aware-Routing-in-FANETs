#ifndef QBR_MESSAGE_HANDLER_H
#define QBR_MESSAGE_HANDLER_H

/**
 * @file qbr-message-handler.h
 * @brief Owns the QBR send/receive pipeline, packet/message sequence counters,
 *        the outbound message queue, socket handles, and Tx/Rx traced callbacks.
 *
 * MessageHandler is the "I/O front-end" of RoutingProtocol.  It handles
 * everything from raw socket I/O up to (and including) the four Process*
 * methods and the four HELLO sub-processors, but it deliberately knows
 * nothing about how routes are stored (RoutingTable) or how tuple lifetimes
 * are managed (TupleManager).
 *
 * Members migrated from RoutingProtocol (original qbr-message-handler.h):
 *   Data:    m_packetSequenceNumber, m_messageSequenceNumber,
 *            m_queuedMessages, m_queuedMessagesTimer,
 *            m_sendSockets, m_recvSocket,
 *            m_rxPacketTrace, m_txPacketTrace
 *   Methods: GetPacketSequenceNumber, GetMessageSequenceNumber,
 *            SendPacket, RecvQbr, ForwardDefault,
 *            QueueMessage, SendQueuedMessages,
 *            SendHello, SendTc, SendMid, SendHna,
 *            ProcessHello, ProcessTc, ProcessMid, ProcessHna,
 *            LinkSensing, PopulateNeighborSet,
 *            PopulateTwoHopNeighborSet, PopulateMprSelectorSet
 */

#include "qbr-header.h"
#include "qbr-metric-engine.h"
#include "qbr-repositories.h"
#include "qbr-state.h"

#include "ns3/ipv4-interface-address.h"
#include "ns3/ipv4.h"
#include "ns3/node.h"
#include "ns3/nstime.h"
#include "ns3/socket.h"
#include "ns3/timer.h"
#include "ns3/traced-callback.h"

#include <functional>
#include <map>
#include <set>

namespace ns3
{
namespace qbr
{

/**
 * @ingroup qbr
 * @brief Encapsulates the QBR packet/message I/O pipeline.
 *
 * RoutingProtocol holds a MessageHandler instance (or inherits from it).
 * The handler owns:
 *  - The packet and message sequence-number counters.
 *  - The outbound message queue and its throttle timer.
 *  - One send socket per interface plus the shared receive socket.
 *  - The Rx and Tx traced callbacks.
 *
 * All four Process* methods and all four HELLO sub-processors live here
 * because they transform raw QBR wire messages into state-store mutations —
 * they are the natural boundary between "network I/O" and "tuple management".
 */
class MessageHandler
{
  public:
    // ------------------------------------------------------------------ //
    //  TracedCallback signatures (re-exported for RoutingProtocol)
    // ------------------------------------------------------------------ //

    /**
     * @brief Signature for packet Tx and Rx trace sources.
     * @param header   The QBR packet header.
     * @param messages The list of QBR messages contained in the packet.
     */
    typedef void (*PacketTxRxTracedCallback)(const PacketHeader& header,
                                             const MessageList&  messages);

    // ------------------------------------------------------------------ //
    //  Construction / lifecycle
    // ------------------------------------------------------------------ //
    MessageHandler();
    ~MessageHandler() = default;

    // ------------------------------------------------------------------ //
    //  Sequence-number accessors (used by the send helpers)
    // ------------------------------------------------------------------ //

    /**
     * @brief Increments and returns the packet sequence number.
     *
     * Sequence numbers wrap at 0xFFFF per RFC 3626.
     *
     * @return The new packet sequence number.
     */
    uint16_t GetPacketSequenceNumber();

    /**
     * @brief Increments and returns the message sequence number.
     *
     * Sequence numbers wrap at 0xFFFF per RFC 3626.
     *
     * @return The new message sequence number.
     */
    uint16_t GetMessageSequenceNumber();

    // ------------------------------------------------------------------ //
    //  Raw send / receive
    // ------------------------------------------------------------------ //

    /**
     * @brief Transmits a QBR packet on all send sockets.
     *
     * The Tx traced callback is fired after the packet is handed to the
     * socket layer.
     *
     * @param packet            The fully serialised packet to send.
     * @param containedMessages The logical messages inside the packet
     *                          (used only for the Tx trace).
     */
    void SendPacket(Ptr<Packet> packet, const MessageList& containedMessages);

    /**
     * @brief Socket receive callback — entry point for all inbound QBR traffic.
     *
     * Deserialises the packet, fires the Rx trace, suppresses duplicates via
     * the Duplicate Set, dispatches each message to the appropriate Process*
     * method, and calls ForwardDefault when necessary.
     *
     * @param socket The socket on which the packet arrived.
     */
    void RecvQbr(Ptr<Socket> socket);

    // ------------------------------------------------------------------ //
    //  Forwarding
    // ------------------------------------------------------------------ //

    /**
     * @brief Implements QBR's default forwarding algorithm (RFC 3626 §3.4).
     *
     * @param qbrMessage    The QBR message to (potentially) forward.
     * @param duplicated    Null if the message has never been considered for
     *                      forwarding; otherwise the matching DuplicateTuple.
     * @param localIface    Address of the interface on which the message arrived.
     * @param senderAddress IPv4 address of the immediate sender.
     */
    void ForwardDefault(qbr::MessageHeader  qbrMessage,
                        DuplicateTuple*      duplicated,
                        const Ipv4Address&   localIface,
                        const Ipv4Address&   senderAddress);

    // ------------------------------------------------------------------ //
    //  Outbound message queue
    // ------------------------------------------------------------------ //

    /**
     * @brief Enqueues a QBR message for deferred transmission.
     *
     * The message will be sent within @p delay, potentially piggybacked
     * with other queued messages in a single QBR packet.
     *
     * @param message The QBR message to enqueue.
     * @param delay   Maximum delay before the message must be sent.
     */
    void QueueMessage(const qbr::MessageHeader& message, Time delay);

    /**
     * @brief Flushes the outbound queue by packing messages into packets.
     *
     * At most QBR_MAX_MSGS messages are placed in each packet.  Called
     * automatically when m_queuedMessagesTimer fires.
     */
    void SendQueuedMessages();

    // ------------------------------------------------------------------ //
    //  Periodic message builders
    // ------------------------------------------------------------------ //

    /**
     * @brief Builds and enqueues a HELLO message.
     *
     * Encodes the current Link Set and Neighbor Set following RFC 3626 §6.1.
     */
    void SendHello();

    /**
     * @brief Builds and enqueues a TC (Topology Control) message.
     *
     * Sent only when the MPR Selector Set is non-empty (RFC 3626 §9.2).
     */
    void SendTc();

    /**
     * @brief Builds and enqueues a MID (Multiple Interface Declaration) message.
     *
     * Sent only when the node has more than one QBR-enabled interface
     * (RFC 3626 §5.2).
     */
    void SendMid();

    /**
     * @brief Builds and enqueues an HNA (Host and Network Association) message.
     *
     * Sent only when the node has local HNA associations to advertise
     * (RFC 3626 §12.2).
     */
    void SendHna();

    // ------------------------------------------------------------------ //
    //  Message processors  (4 process + 4 HELLO sub-processors)
    // ------------------------------------------------------------------ //

    /**
     * @brief Processes an inbound HELLO message (RFC 3626 §6).
     *
     * Drives link sensing and updates the Neighbor Set, 2-hop Neighbor Set,
     * and MPR Selector Set by calling the four HELLO sub-processors below.
     *
     * @param msg           The QBR message wrapper containing the HELLO.
     * @param receiverIface Address of the interface that received the message.
     * @param senderIface   Address of the sender's interface.
     */
    void ProcessHello(const qbr::MessageHeader& msg,
                      const Ipv4Address&         receiverIface,
                      const Ipv4Address&         senderIface);

    /**
     * @brief Processes an inbound TC message (RFC 3626 §9.5).
     *
     * Updates the Topology Set with the advertised MPR selector set.
     *
     * @param msg         The QBR message wrapper containing the TC.
     * @param senderIface Address of the sender's interface.
     */
    void ProcessTc(const qbr::MessageHeader& msg, const Ipv4Address& senderIface);

    /**
     * @brief Processes an inbound MID message (RFC 3626 §5.4).
     *
     * Updates the Interface Association Set with the sender's interface list.
     *
     * @param msg         The QBR message wrapper containing the MID.
     * @param senderIface Address of the sender's interface.
     */
    void ProcessMid(const qbr::MessageHeader& msg, const Ipv4Address& senderIface);

    /**
     * @brief Processes an inbound HNA message (RFC 3626 §12.5).
     *
     * Updates the Host-Network Association Set with the sender's associations.
     *
     * @param msg         The QBR message wrapper containing the HNA.
     * @param senderIface Address of the sender's interface.
     */
    void ProcessHna(const qbr::MessageHeader& msg, const Ipv4Address& senderIface);

    // ------------------------------------------------------------------ //
    //  HELLO sub-processors (called exclusively from ProcessHello)
    // ------------------------------------------------------------------ //

    /**
     * @brief Updates the Link Set from a received HELLO (RFC 3626 §6.2).
     *
     * May also trigger Neighbor Set updates as a side-effect.
     *
     * @param msg           The enclosing QBR message (provides originator / time).
     * @param hello         The decoded HELLO sub-message.
     * @param receiverIface Local interface address that received the message.
     * @param senderIface   Interface address reported by the sender.
     */
    void LinkSensing(const qbr::MessageHeader&       msg,
                     const qbr::MessageHeader::Hello& hello,
                     const Ipv4Address&               receiverIface,
                     const Ipv4Address&               senderIface);

    /**
     * @brief Updates the Neighbor Set from a received HELLO (RFC 3626 §6.3).
     *
     * @param msg   The enclosing QBR message.
     * @param hello The decoded HELLO sub-message.
     */
    void PopulateNeighborSet(const qbr::MessageHeader&       msg,
                             const qbr::MessageHeader::Hello& hello);

    /**
     * @brief Updates the 2-hop Neighbor Set from a received HELLO (RFC 3626 §6.4).
     *
     * @param msg   The enclosing QBR message.
     * @param hello The decoded HELLO sub-message.
     */
    void PopulateTwoHopNeighborSet(const qbr::MessageHeader&       msg,
                                   const qbr::MessageHeader::Hello& hello);

    /**
     * @brief Updates the MPR Selector Set from a received HELLO (RFC 3626 §6.5).
     *
     * @param msg   The enclosing QBR message.
     * @param hello The decoded HELLO sub-message.
     */
    void PopulateMprSelectorSet(const qbr::MessageHeader&       msg,
                                const qbr::MessageHeader::Hello& hello);

    // ------------------------------------------------------------------ //
    //  Socket management (public so RoutingProtocol::DoInitialize populates them)
    // ------------------------------------------------------------------ //

    /**
     * @brief One send socket per QBR-enabled interface, mapped to its address.
     *
     * Populated by RoutingProtocol::DoInitialize() during NotifyInterfaceUp.
     */
    std::map<Ptr<Socket>, Ipv4InterfaceAddress> m_sendSockets;

    /// The single socket that receives all incoming QBR UDP packets.
    Ptr<Socket> m_recvSocket;

    // ------------------------------------------------------------------ //
    //  Wiring helpers — called by RoutingProtocol after construction
    // ------------------------------------------------------------------ //

    void SetNode(Ptr<Node> node)                { m_node = node; }
    void SetMainAddress(Ipv4Address addr)        { m_mainAddress = addr; }
    void SetState(QbrState* state)               { m_state = state; }
    void SetIpv4(Ptr<Ipv4> ipv4)                { m_ipv4 = ipv4; }
    void SetInterfaceExclusions(const std::set<uint32_t>* excl) { m_interfaceExclusions = excl; }
    void SetWillingness(Willingness w)           { m_willingness = w; }
    void SetHelloInterval(Time t)                { m_helloInterval = t; }
    void SetNeighHoldTime(Time t)                { m_neighHoldTime = t; }
    void SetTopHoldTime(Time t)                  { m_topHoldTime = t; }
    void SetMidHoldTime(Time t)                  { m_midHoldTime = t; }
    void SetHnaHoldTime(Time t)                  { m_hnaHoldTime = t; }

    /// The UDP port number QBR listens and sends on.  Provided by RoutingProtocol
    /// (which owns QBR_PORT_NUMBER) so MessageHandler never needs to reference it directly.
    void SetPortNumber(uint16_t port)            { m_portNumber = port; }

    /// Jitter generator — returns a random delay up to QBR_MAXJITTER.
    void SetJitterCallback(std::function<Time()> cb)         { m_jitter = std::move(cb); }
    /// Called after every RecvQbr() to trigger RoutingTableComputation().
    void SetRoutingTableComputationCallback(std::function<void()> cb)
    {
        m_onRoutingTableComputation = std::move(cb);
    }
    /// Called by ProcessHello() to trigger MprComputation().
    void SetMprComputationCallback(std::function<void()> cb) { m_onMprComputation = std::move(cb); }
    /// Provides the current ANSN value for SendTc().
    void SetGetAnsnCallback(std::function<uint16_t()> cb)   { m_getAnsn = std::move(cb); }

    /**
     * @brief Wires the Rx trace fire-callback.
     *
     * RoutingProtocol passes a lambda that calls m_rxPacketTrace(header, messages)
     * on itself, so the trace source remains bound to RoutingProtocol for ns-3's
     * attribute system while MessageHandler triggers it at the right moment.
     */
    void SetRxTraceCallback(std::function<void(const PacketHeader&, const MessageList&)> cb)
    {
        m_fireRxTrace = std::move(cb);
    }

    /**
     * @brief Wires the Tx trace fire-callback.  Same rationale as SetRxTraceCallback.
     */
    void SetTxTraceCallback(std::function<void(const PacketHeader&, const MessageList&)> cb)
    {
        m_fireTxTrace = std::move(cb);
    }

    // Tuple-mutation callbacks (forward to TupleManager methods):
    void SetAddDuplicateTupleCallback(std::function<void(const DuplicateTuple&)> cb)
    {
        m_onAddDuplicateTuple = std::move(cb);
    }
    void SetAddTopologyTupleCallback(std::function<void(const TopologyTuple&)> cb)
    {
        m_onAddTopologyTuple = std::move(cb);
    }
    void SetAddIfaceAssocTupleCallback(std::function<void(const IfaceAssocTuple&)> cb)
    {
        m_onAddIfaceAssocTuple = std::move(cb);
    }
    void SetAddAssociationTupleCallback(std::function<void(const AssociationTuple&)> cb)
    {
        m_onAddAssociationTuple = std::move(cb);
    }
    void SetAddTwoHopNeighborTupleCallback(std::function<void(const TwoHopNeighborTuple&)> cb)
    {
        m_onAddTwoHopNeighborTuple = std::move(cb);
    }
    void SetAddMprSelectorTupleCallback(std::function<void(const MprSelectorTuple&)> cb)
    {
        m_onAddMprSelectorTuple = std::move(cb);
    }
    void SetLinkTupleAddedCallback(
        std::function<void(const LinkTuple&, Willingness)> cb)
    {
        m_onLinkTupleAdded = std::move(cb);
    }
    void SetLinkTupleUpdatedCallback(
        std::function<void(const LinkTuple&, Willingness)> cb)
    {
        m_onLinkTupleUpdated = std::move(cb);
    }

    // Timer-scheduling callbacks (forward to EventGarbageCollector in RoutingProtocol):
    void SetScheduleDupExpireCallback(
        std::function<void(Ipv4Address, uint16_t, Time)> cb)
    {
        m_onScheduleDupExpire = std::move(cb);
    }
    void SetScheduleTopologyExpireCallback(
        std::function<void(Ipv4Address, Ipv4Address, Time)> cb)
    {
        m_onScheduleTopologyExpire = std::move(cb);
    }
    void SetScheduleIfaceAssocExpireCallback(
        std::function<void(Ipv4Address, Time)> cb)
    {
        m_onScheduleIfaceAssocExpire = std::move(cb);
    }
    void SetScheduleAssocExpireCallback(
        std::function<void(Ipv4Address, Ipv4Address, Ipv4Mask, Time)> cb)
    {
        m_onScheduleAssocExpire = std::move(cb);
    }
    void SetScheduleNb2hopExpireCallback(
        std::function<void(Ipv4Address, Ipv4Address, Time)> cb)
    {
        m_onScheduleNb2hopExpire = std::move(cb);
    }
    void SetScheduleMprSelExpireCallback(
        std::function<void(Ipv4Address, Time)> cb)
    {
        m_onScheduleMprSelExpire = std::move(cb);
    }
    void SetScheduleLinkTupleExpireCallback(
        std::function<void(Ipv4Address, Time)> cb)
    {
        m_onScheduleLinkTupleExpire = std::move(cb);
    }

  private:
    // ------------------------------------------------------------------ //
    //  Sequence-number counters
    // ------------------------------------------------------------------ //

    /// Monotonically increasing (wrapping) counter for QBR packet headers.
    uint16_t m_packetSequenceNumber{0};

    /// Monotonically increasing (wrapping) counter for individual QBR messages.
    uint16_t m_messageSequenceNumber{0};

    // ------------------------------------------------------------------ //
    //  Outbound message queue
    // ------------------------------------------------------------------ //

    /// Buffer of messages enqueued but not yet transmitted.
    qbr::MessageList m_queuedMessages;

    /// Timer that fires SendQueuedMessages() after a short random jitter.
    Timer m_queuedMessagesTimer;

    // ------------------------------------------------------------------ //
    //  Context provided by RoutingProtocol
    // ------------------------------------------------------------------ //

    Ptr<Node>                   m_node;
    Ipv4Address                 m_mainAddress;
    QbrState*                   m_state;
    Ptr<Ipv4>                   m_ipv4;
    const std::set<uint32_t>*   m_interfaceExclusions;
    Willingness                 m_willingness;
    Time                        m_helloInterval;
    Time                        m_neighHoldTime;
    Time                        m_topHoldTime;
    Time                        m_midHoldTime;
    Time                        m_hnaHoldTime;

    /// UDP port number, copied from RoutingProtocol::QBR_PORT_NUMBER via SetPortNumber().
    uint16_t                    m_portNumber{0};

    // ------------------------------------------------------------------ //
    //  Callbacks wired by RoutingProtocol
    // ------------------------------------------------------------------ //

    std::function<Time()>                                           m_jitter;
    std::function<void()>                                           m_onRoutingTableComputation;
    std::function<void()>                                           m_onMprComputation;
    std::function<uint16_t()>                                       m_getAnsn;
    /// Fires RoutingProtocol::m_rxPacketTrace — bound in SetIpv4().
    std::function<void(const PacketHeader&, const MessageList&)>    m_fireRxTrace;
    /// Fires RoutingProtocol::m_txPacketTrace — bound in SetIpv4().
    std::function<void(const PacketHeader&, const MessageList&)>    m_fireTxTrace;
    std::function<void(const DuplicateTuple&)>                      m_onAddDuplicateTuple;
    std::function<void(const TopologyTuple&)>                       m_onAddTopologyTuple;
    std::function<void(const IfaceAssocTuple&)>                     m_onAddIfaceAssocTuple;
    std::function<void(const AssociationTuple&)>                    m_onAddAssociationTuple;
    std::function<void(const TwoHopNeighborTuple&)>                 m_onAddTwoHopNeighborTuple;
    std::function<void(const MprSelectorTuple&)>                    m_onAddMprSelectorTuple;
    std::function<void(const LinkTuple&, Willingness)>              m_onLinkTupleAdded;
    std::function<void(const LinkTuple&, Willingness)>              m_onLinkTupleUpdated;
    std::function<void(Ipv4Address, uint16_t, Time)>                m_onScheduleDupExpire;
    std::function<void(Ipv4Address, Ipv4Address, Time)>             m_onScheduleTopologyExpire;
    std::function<void(Ipv4Address, Time)>                          m_onScheduleIfaceAssocExpire;
    std::function<void(Ipv4Address, Ipv4Address, Ipv4Mask, Time)>   m_onScheduleAssocExpire;
    std::function<void(Ipv4Address, Ipv4Address, Time)>             m_onScheduleNb2hopExpire;
    std::function<void(Ipv4Address, Time)>                          m_onScheduleMprSelExpire;
    std::function<void(Ipv4Address, Time)>                          m_onScheduleLinkTupleExpire;

    // ------------------------------------------------------------------ //
    //  Private helpers
    // ------------------------------------------------------------------ //

    /**
     * @brief Resolves an interface address to the node's main address.
     *
     * Mirrors RoutingProtocol::GetMainAddress().
     *
     * @param ifaceAddr The interface address to resolve.
     * @return The corresponding main address (or @p ifaceAddr if not found).
     */
    Ipv4Address GetMainAddress(Ipv4Address ifaceAddr) const;

    /**
     * @brief Link and neighbor type enumerations used in HELLO processing.
     *
     * These are file-local in the original .cc; redeclared here so the
     * HELLO sub-processors can reference them without a separate header.
     */
    enum class LinkType : uint8_t
    {
        UNSPEC_LINK = 0,
        ASYM_LINK   = 1,
        SYM_LINK    = 2,
        LOST_LINK   = 3,
    };

    enum class NeighborType : uint8_t
    {
        NOT_NEIGH = 0,
        SYM_NEIGH = 1,
        MPR_NEIGH = 2,
    };

    /**
     * @brief Persistent MetricEngine 
     */
    MetricEngine m_metricEngine;
};

} // namespace qbr
} // namespace ns3

#endif /* QBR_MESSAGE_HANDLER_H */