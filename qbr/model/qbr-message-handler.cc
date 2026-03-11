///
/// @file qbr-message-handler.cc
/// @brief Implementation of MessageHandler — owns the send/receive pipeline,
///        packet/message sequence counters, the outbound message queue,
///        socket handles, and Tx/Rx traced callbacks.
///
/// Methods split out from the original monolithic RoutingProtocol:
///   GetPacketSequenceNumber, GetMessageSequenceNumber,
///   SendPacket, RecvQbr, ForwardDefault,
///   QueueMessage, SendQueuedMessages,
///   SendHello, SendTc, SendMid, SendHna,
///   ProcessHello, ProcessTc, ProcessMid, ProcessHna,
///   LinkSensing, PopulateNeighborSet,
///   PopulateTwoHopNeighborSet, PopulateMprSelectorSet
///

#define NS_LOG_APPEND_CONTEXT                                                                      \
    if (m_node)                                                                                    \
    {                                                                                              \
        std::clog << "[node " << m_node->GetId() << "] ";                                          \
    }

#include "qbr-message-handler.h"

#include "qbr-header.h"
#include "qbr-metric-engine.h"

#include "ns3/assert.h"
#include "ns3/inet-socket-address.h"
#include "ns3/ipv4-packet-info-tag.h"
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

/// Maximum allowed sequence number.
#define QBR_MAX_SEQ_NUM 65535

/// Maximum number of messages packed into a single QBR packet.
#define QBR_MAX_MSGS 64

/// Duplicate-tuple holding time (RFC 3626 §3.4).
#define QBR_DUP_HOLD_TIME Seconds(30)

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QbrMessageHandler");

namespace qbr
{

// -----------------------------------------------------------------------
// Construction
// -----------------------------------------------------------------------

MessageHandler::MessageHandler()
    : m_recvSocket(nullptr),
      m_packetSequenceNumber(QBR_MAX_SEQ_NUM),
      m_messageSequenceNumber(QBR_MAX_SEQ_NUM),
      m_queuedMessagesTimer(Timer::CANCEL_ON_DESTROY),
      m_node(nullptr),
      m_mainAddress(),
      m_state(nullptr),
      m_ipv4(nullptr),
      m_interfaceExclusions(nullptr),
      m_willingness(Willingness::DEFAULT)
{
}

// -----------------------------------------------------------------------
// Sequence numbers
// -----------------------------------------------------------------------

uint16_t
MessageHandler::GetPacketSequenceNumber()
{
    m_packetSequenceNumber = (m_packetSequenceNumber + 1) % (QBR_MAX_SEQ_NUM + 1);
    return m_packetSequenceNumber;
}

uint16_t
MessageHandler::GetMessageSequenceNumber()
{
    m_messageSequenceNumber = (m_messageSequenceNumber + 1) % (QBR_MAX_SEQ_NUM + 1);
    return m_messageSequenceNumber;
}

// -----------------------------------------------------------------------
// Raw send
// -----------------------------------------------------------------------

void
MessageHandler::SendPacket(Ptr<Packet> packet, const MessageList& containedMessages)
{
    NS_LOG_DEBUG("QBR node " << m_mainAddress << " sending a QBR packet");

    qbr::PacketHeader header;
    header.SetPacketLength(header.GetSerializedSize() + packet->GetSize());
    header.SetPacketSequenceNumber(GetPacketSequenceNumber());
    packet->AddHeader(header);

    m_fireTxTrace(header, containedMessages);

    for (auto& [sock, ifaceAddr] : m_sendSockets)
    {
        Ptr<Packet> pkt = packet->Copy();
        Ipv4Address bcast = ifaceAddr.GetLocal().GetSubnetDirectedBroadcast(ifaceAddr.GetMask());
        sock->SendTo(pkt, 0, InetSocketAddress(bcast, m_portNumber));
    }
}

// -----------------------------------------------------------------------
// Raw receive
// -----------------------------------------------------------------------

void
MessageHandler::RecvQbr(Ptr<Socket> socket)
{
    NS_ASSERT(m_state && m_ipv4 && m_interfaceExclusions);

    Ptr<Packet> receivedPacket;
    Address sourceAddress;
    receivedPacket = socket->RecvFrom(sourceAddress);

    Ipv4PacketInfoTag interfaceInfo;
    if (!receivedPacket->RemovePacketTag(interfaceInfo))
    {
        NS_ABORT_MSG("No incoming interface on QBR message, aborting.");
    }

    uint32_t incomingIf = interfaceInfo.GetRecvIf();
    Ptr<NetDevice> dev = m_node->GetDevice(incomingIf);
    uint32_t recvInterfaceIndex = m_ipv4->GetInterfaceForDevice(dev);

    if (m_interfaceExclusions->count(recvInterfaceIndex))
    {
        return;
    }

    InetSocketAddress inetSourceAddr = InetSocketAddress::ConvertFrom(sourceAddress);
    Ipv4Address senderIfaceAddr = inetSourceAddr.GetIpv4();

    if (m_ipv4->GetInterfaceForAddress(senderIfaceAddr) != -1)
    {
        NS_LOG_LOGIC("Ignoring a packet sent by myself.");
        return;
    }

    m_metricEngine.InitNeighborStats(senderIfaceAddr);

    double snr = m_metricEngine.MeasureSnr(senderIfaceAddr);
    m_metricEngine.RecordPacketReception(senderIfaceAddr, snr, true);

    Ipv4Address receiverIfaceAddr = m_ipv4->GetAddress(recvInterfaceIndex, 0).GetLocal();
    NS_ASSERT(receiverIfaceAddr != Ipv4Address());
    NS_LOG_DEBUG("QBR node " << m_mainAddress << " received a QBR packet from " << senderIfaceAddr
                             << " to " << receiverIfaceAddr);

    NS_ASSERT(inetSourceAddr.GetPort() == m_portNumber);

    Ptr<Packet> packet = receivedPacket;
    qbr::PacketHeader qbrPacketHeader;
    packet->RemoveHeader(qbrPacketHeader);
    NS_ASSERT(qbrPacketHeader.GetPacketLength() >= qbrPacketHeader.GetSerializedSize());
    uint32_t sizeLeft = qbrPacketHeader.GetPacketLength() - qbrPacketHeader.GetSerializedSize();

    MessageList messages;
    while (sizeLeft)
    {
        MessageHeader messageHeader;
        if (packet->RemoveHeader(messageHeader) == 0)
        {
            NS_ASSERT(false);
        }
        sizeLeft -= messageHeader.GetSerializedSize();
        NS_LOG_DEBUG("Qbr Msg received with type "
                     << std::dec << int(messageHeader.GetMessageType())
                     << " TTL=" << int(messageHeader.GetTimeToLive())
                     << " origAddr=" << messageHeader.GetOriginatorAddress());
        messages.push_back(messageHeader);
    }

    m_fireRxTrace(qbrPacketHeader, messages);

    for (const auto& messageHeader : messages)
    {
        if (messageHeader.GetTimeToLive() == 0 ||
            messageHeader.GetOriginatorAddress() == m_mainAddress)
        {
            continue;
        }

        bool do_forwarding = true;
        DuplicateTuple* duplicated =
            m_state->FindDuplicateTuple(messageHeader.GetOriginatorAddress(),
                                        messageHeader.GetMessageSequenceNumber());

        if (duplicated == nullptr)
        {
            switch (messageHeader.GetMessageType())
            {
            case qbr::MessageHeader::HELLO_MESSAGE:
                NS_LOG_DEBUG(Simulator::Now().As(Time::S)
                             << " QBR node " << m_mainAddress << " received HELLO message of size "
                             << messageHeader.GetSerializedSize());
                ProcessHello(messageHeader, receiverIfaceAddr, senderIfaceAddr);
                break;
            case qbr::MessageHeader::TC_MESSAGE:
                NS_LOG_DEBUG(Simulator::Now().As(Time::S)
                             << " QBR node " << m_mainAddress << " received TC message of size "
                             << messageHeader.GetSerializedSize());
                ProcessTc(messageHeader, senderIfaceAddr);
                break;
            case qbr::MessageHeader::MID_MESSAGE:
                NS_LOG_DEBUG(Simulator::Now().As(Time::S)
                             << " QBR node " << m_mainAddress << " received MID message of size "
                             << messageHeader.GetSerializedSize());
                ProcessMid(messageHeader, senderIfaceAddr);
                break;
            case qbr::MessageHeader::HNA_MESSAGE:
                NS_LOG_DEBUG(Simulator::Now().As(Time::S)
                             << " QBR node " << m_mainAddress << " received HNA message of size "
                             << messageHeader.GetSerializedSize());
                ProcessHna(messageHeader, senderIfaceAddr);
                break;
            default:
                NS_LOG_DEBUG("QBR message type " << int(messageHeader.GetMessageType())
                                                 << " not implemented");
            }
        }
        else
        {
            NS_LOG_DEBUG("QBR message is duplicated, not reading it.");
            for (const auto& iface : duplicated->ifaceList)
            {
                if (iface == receiverIfaceAddr)
                {
                    do_forwarding = false;
                    break;
                }
            }
        }

        if (do_forwarding && messageHeader.GetMessageType() != qbr::MessageHeader::HELLO_MESSAGE)
        {
            ForwardDefault(messageHeader, duplicated, receiverIfaceAddr, inetSourceAddr.GetIpv4());
        }
    }

    // After processing all messages, trigger routing-table recomputation.
    if (m_onRoutingTableComputation)
    {
        m_onRoutingTableComputation();
    }
}

// -----------------------------------------------------------------------
// Forwarding
// -----------------------------------------------------------------------

void
MessageHandler::ForwardDefault(qbr::MessageHeader qbrMessage,
                               DuplicateTuple* duplicated,
                               const Ipv4Address& localIface,
                               const Ipv4Address& senderAddress)
{
    NS_ASSERT(m_state);
    Time now = Simulator::Now();

    const LinkTuple* linkTuple = m_state->FindSymLinkTuple(senderAddress, now);
    if (linkTuple == nullptr)
    {
        return;
    }

    if (duplicated != nullptr && duplicated->retransmitted)
    {
        NS_LOG_LOGIC(now << " Node " << m_mainAddress
                         << " does not forward a message received from "
                         << qbrMessage.GetOriginatorAddress() << " because it is duplicated");
        return;
    }

    bool retransmitted = false;
    if (qbrMessage.GetTimeToLive() > 1)
    {
        const MprSelectorTuple* mprselTuple =
            m_state->FindMprSelectorTuple(GetMainAddress(senderAddress));
        if (mprselTuple != nullptr)
        {
            qbrMessage.SetTimeToLive(qbrMessage.GetTimeToLive() - 1);
            qbrMessage.SetHopCount(qbrMessage.GetHopCount() + 1);
            QueueMessage(qbrMessage, m_jitter());
            retransmitted = true;
        }
    }

    if (duplicated != nullptr)
    {
        duplicated->expirationTime = now + QBR_DUP_HOLD_TIME;
        duplicated->retransmitted = retransmitted;
        duplicated->ifaceList.push_back(localIface);
    }
    else
    {
        DuplicateTuple newDup;
        newDup.address = qbrMessage.GetOriginatorAddress();
        newDup.sequenceNumber = qbrMessage.GetMessageSequenceNumber();
        newDup.expirationTime = now + QBR_DUP_HOLD_TIME;
        newDup.retransmitted = retransmitted;
        newDup.ifaceList.push_back(localIface);

        if (m_onAddDuplicateTuple)
        {
            m_onAddDuplicateTuple(newDup);
        }

        // Schedule dup tuple deletion via TupleManager callback.
        if (m_onScheduleDupExpire)
        {
            m_onScheduleDupExpire(newDup.address, newDup.sequenceNumber, QBR_DUP_HOLD_TIME);
        }
    }
}

// -----------------------------------------------------------------------
// Outbound queue
// -----------------------------------------------------------------------

void
MessageHandler::QueueMessage(const qbr::MessageHeader& message, Time delay)
{
    m_queuedMessages.push_back(message);
    if (!m_queuedMessagesTimer.IsRunning())
    {
        m_queuedMessagesTimer.SetFunction(&MessageHandler::SendQueuedMessages, this);
        m_queuedMessagesTimer.SetDelay(delay);
        m_queuedMessagesTimer.Schedule();
    }
}

void
MessageHandler::SendQueuedMessages()
{
    NS_LOG_DEBUG("QBR node " << m_mainAddress << ": SendQueuedMessages");

    Ptr<Packet> packet = Create<Packet>();
    int numMessages = 0;
    MessageList msglist;

    for (const auto& message : m_queuedMessages)
    {
        Ptr<Packet> p = Create<Packet>();
        p->AddHeader(message);
        packet->AddAtEnd(p);
        msglist.push_back(message);
        if (++numMessages == QBR_MAX_MSGS)
        {
            SendPacket(packet, msglist);
            msglist.clear();
            numMessages = 0;
            packet = Create<Packet>();
        }
    }

    if (packet->GetSize())
    {
        SendPacket(packet, msglist);
    }

    m_queuedMessages.clear();
}

// -----------------------------------------------------------------------
// Periodic message builders
// -----------------------------------------------------------------------

void
MessageHandler::SendHello()
{
    NS_LOG_FUNCTION(this);
    NS_ASSERT(m_state && m_ipv4);

    qbr::MessageHeader msg;
    Time now = Simulator::Now();

    msg.SetVTime(m_neighHoldTime);
    msg.SetOriginatorAddress(m_mainAddress);
    msg.SetTimeToLive(1);
    msg.SetHopCount(0);
    msg.SetMessageSequenceNumber(GetMessageSequenceNumber());

    qbr::MessageHeader::Hello& hello = msg.GetHello();
    hello.SetHTime(m_helloInterval);
    hello.willingness = m_willingness;

    std::vector<qbr::MessageHeader::Hello::LinkMessage>& linkMessages = hello.linkMessages;

    for (const auto& link_tuple : m_state->GetLinks())
    {
        if (!(GetMainAddress(link_tuple.localIfaceAddr) == m_mainAddress && link_tuple.time >= now))
        {
            continue;
        }

        LinkType linkType;
        NeighborType neighborType;

        if (link_tuple.symTime >= now)
        {
            linkType = LinkType::SYM_LINK;
        }
        else if (link_tuple.asymTime >= now)
        {
            linkType = LinkType::ASYM_LINK;
        }
        else
        {
            linkType = LinkType::LOST_LINK;
        }

        if (m_state->FindMprAddress(GetMainAddress(link_tuple.neighborIfaceAddr)))
        {
            neighborType = NeighborType::MPR_NEIGH;
            NS_LOG_DEBUG("I consider neighbor " << GetMainAddress(link_tuple.neighborIfaceAddr)
                                                << " to be MPR_NEIGH.");
        }
        else
        {
            bool ok = false;
            for (const auto& nb_tuple : m_state->GetNeighbors())
            {
                if (nb_tuple.neighborMainAddr == GetMainAddress(link_tuple.neighborIfaceAddr))
                {
                    if (nb_tuple.status == NeighborTuple::STATUS_SYM)
                    {
                        NS_LOG_DEBUG("I consider neighbor "
                                     << GetMainAddress(link_tuple.neighborIfaceAddr)
                                     << " to be SYM_NEIGH.");
                        neighborType = NeighborType::SYM_NEIGH;
                    }
                    else if (nb_tuple.status == NeighborTuple::STATUS_NOT_SYM)
                    {
                        neighborType = NeighborType::NOT_NEIGH;
                        NS_LOG_DEBUG("I consider neighbor "
                                     << GetMainAddress(link_tuple.neighborIfaceAddr)
                                     << " to be NOT_NEIGH.");
                    }
                    else
                    {
                        NS_FATAL_ERROR("There is a neighbor tuple with an unknown status!\n");
                    }
                    ok = true;
                    break;
                }
            }
            if (!ok)
            {
                NS_LOG_WARN("I don't know the neighbor "
                            << GetMainAddress(link_tuple.neighborIfaceAddr) << "!!!");
                continue;
            }
        }

        qbr::MessageHeader::Hello::LinkMessage linkMessage;
        linkMessage.linkCode = (static_cast<uint8_t>(linkType) & 0x03) |
                               ((static_cast<uint8_t>(neighborType) << 2) & 0x0f);
        linkMessage.neighborInterfaceAddresses.push_back(link_tuple.neighborIfaceAddr);

        std::vector<Ipv4Address> interfaces =
            m_state->FindNeighborInterfaces(link_tuple.neighborIfaceAddr);
        linkMessage.neighborInterfaceAddresses.insert(linkMessage.neighborInterfaceAddresses.end(),
                                                      interfaces.begin(),
                                                      interfaces.end());

        linkMessages.push_back(linkMessage);
    }

    NS_LOG_DEBUG("QBR HELLO message size: " << int(msg.GetSerializedSize()) << " (with "
                                            << int(linkMessages.size()) << " link messages)");
    QueueMessage(msg, m_jitter());
}

void
MessageHandler::SendTc()
{
    NS_LOG_FUNCTION(this);
    NS_ASSERT(m_state);

    qbr::MessageHeader msg;
    msg.SetVTime(m_topHoldTime);
    msg.SetOriginatorAddress(m_mainAddress);
    msg.SetTimeToLive(255);
    msg.SetHopCount(0);
    msg.SetMessageSequenceNumber(GetMessageSequenceNumber());

    qbr::MessageHeader::Tc& tc = msg.GetTc();
    tc.ansn = m_getAnsn();

    Time now = Simulator::Now();
    for (const auto& mprsel_tuple : m_state->GetMprSelectors())
    {
        qbr::MessageHeader::NeighborItem neighbor;
        neighbor.address = mprsel_tuple.mainAddr;

        const LinkTuple* link = m_state->FindSymLinkTuple(mprsel_tuple.mainAddr, now);
        if (link)
        {
            neighbor.metrics = link->metrics;
        }

        tc.advertisedNeighbors.push_back(neighbor);
    }

    QueueMessage(msg, m_jitter());
}

void
MessageHandler::SendMid()
{
    NS_ASSERT(m_ipv4 && m_interfaceExclusions);

    qbr::MessageHeader msg;
    qbr::MessageHeader::Mid& mid = msg.GetMid();

    Ipv4Address loopback("127.0.0.1");
    for (uint32_t i = 0; i < m_ipv4->GetNInterfaces(); i++)
    {
        Ipv4Address addr = m_ipv4->GetAddress(i, 0).GetLocal();
        if (addr != m_mainAddress && addr != loopback && !m_interfaceExclusions->count(i))
        {
            mid.interfaceAddresses.push_back(addr);
        }
    }
    if (mid.interfaceAddresses.empty())
    {
        return;
    }

    msg.SetVTime(m_midHoldTime);
    msg.SetOriginatorAddress(m_mainAddress);
    msg.SetTimeToLive(255);
    msg.SetHopCount(0);
    msg.SetMessageSequenceNumber(GetMessageSequenceNumber());

    QueueMessage(msg, m_jitter());
}

void
MessageHandler::SendHna()
{
    NS_ASSERT(m_state);

    qbr::MessageHeader msg;
    qbr::MessageHeader::Hna& hna = msg.GetHna();

    for (const auto& assoc : m_state->GetAssociations())
    {
        qbr::MessageHeader::Hna::Association a = {assoc.networkAddr, assoc.netmask};
        hna.associations.push_back(a);
    }
    if (hna.associations.empty())
    {
        return;
    }

    msg.SetVTime(m_hnaHoldTime);
    msg.SetOriginatorAddress(m_mainAddress);
    msg.SetTimeToLive(255);
    msg.SetHopCount(0);
    msg.SetMessageSequenceNumber(GetMessageSequenceNumber());

    QueueMessage(msg, m_jitter());
}

// -----------------------------------------------------------------------
// Message processors
// -----------------------------------------------------------------------

void
MessageHandler::ProcessHello(const qbr::MessageHeader& msg,
                             const Ipv4Address& receiverIface,
                             const Ipv4Address& senderIface)
{
    NS_LOG_FUNCTION(msg << receiverIface << senderIface);

    const qbr::MessageHeader::Hello& hello = msg.GetHello();
    LinkSensing(msg, hello, receiverIface, senderIface);

#ifdef NS3_LOG_ENABLE
    {
        const LinkSet& links = m_state->GetLinks();
        NS_LOG_DEBUG(Simulator::Now().As(Time::S)
                     << " ** BEGIN dump Link Set for QBR Node " << m_mainAddress);
        for (const auto& link : links)
        {
            NS_LOG_DEBUG(link);
        }
        NS_LOG_DEBUG("** END dump Link Set for QBR Node " << m_mainAddress);

        const NeighborSet& neighbors = m_state->GetNeighbors();
        NS_LOG_DEBUG(Simulator::Now().As(Time::S)
                     << " ** BEGIN dump Neighbor Set for QBR Node " << m_mainAddress);
        for (const auto& neighbor : neighbors)
        {
            NS_LOG_DEBUG(neighbor);
        }
        NS_LOG_DEBUG("** END dump Neighbor Set for QBR Node " << m_mainAddress);
    }
#endif

    PopulateNeighborSet(msg, hello);
    PopulateTwoHopNeighborSet(msg, hello);

#ifdef NS3_LOG_ENABLE
    {
        const TwoHopNeighborSet& twoHopNeighbors = m_state->GetTwoHopNeighbors();
        NS_LOG_DEBUG(Simulator::Now().As(Time::S)
                     << " ** BEGIN dump TwoHopNeighbor Set for QBR Node " << m_mainAddress);
        for (const auto& tuple : twoHopNeighbors)
        {
            NS_LOG_DEBUG(tuple);
        }
        NS_LOG_DEBUG("** END dump TwoHopNeighbor Set for QBR Node " << m_mainAddress);
    }
#endif

    if (m_onMprComputation)
    {
        m_onMprComputation();
    }
    PopulateMprSelectorSet(msg, hello);
}

void
MessageHandler::ProcessTc(const qbr::MessageHeader& msg, const Ipv4Address& senderIface)
{
    NS_ASSERT(m_state);

    const qbr::MessageHeader::Tc& tc = msg.GetTc();
    Time now = Simulator::Now();

    // 1. Discard if the sender is not a symmetric 1-hop neighbor.
    if (m_state->FindSymLinkTuple(senderIface, now) == nullptr)
    {
        return;
    }

    // 2. Discard if a newer sequence number for the same originator exists.
    if (m_state->FindNewerTopologyTuple(msg.GetOriginatorAddress(), tc.ansn) != nullptr)
    {
        return;
    }

    // 3. Remove older tuples for the same originator.
    m_state->EraseOlderTopologyTuples(msg.GetOriginatorAddress(), tc.ansn);

    // 4. Update or insert a topology tuple per advertised neighbor address.
    for (const auto& neighbor : tc.advertisedNeighbors)
    {
        TopologyTuple* topologyTuple =
            m_state->FindTopologyTuple(neighbor.address, msg.GetOriginatorAddress());

        if (topologyTuple != nullptr)
        {
            topologyTuple->expirationTime = now + msg.GetVTime();
            // Reset metrics before applying
            topologyTuple->linkQuality = 0;
            topologyTuple->trust = 0;

            // Loop through metrics reported by neighbor
            for (const auto& metric : neighbor.metrics)
            {
                switch (metric.type)
                {
                case LINK_QUALITY:
                    topologyTuple->linkQuality = metric.value;
                    break;
                case TRUST:
                    topologyTuple->trust = metric.value;
                    break;
                default:
                    NS_LOG_WARN("Unknown metric type " << int(metric.type));
                }
            }
        }
        else
        {
            TopologyTuple newTuple;
            newTuple.destAddr = neighbor.address;
            newTuple.lastAddr = msg.GetOriginatorAddress();
            newTuple.sequenceNumber = tc.ansn;
            newTuple.expirationTime = now + msg.GetVTime();

            // Fill metrics from first available neighbor metrics
            if (!neighbor.metrics.empty())
            {
                for (const auto& metric : neighbor.metrics)
                {
                    switch (metric.type)
                    {
                    case LINK_QUALITY:
                        newTuple.linkQuality = metric.value;
                        break;
                    case TRUST:
                        newTuple.trust = metric.value;
                        break;
                    default:
                        NS_LOG_WARN("Unknown metric type " << int(metric.type));
                    }
                }
            }

            if (m_onAddTopologyTuple)
            {
                m_onAddTopologyTuple(newTuple);
            }
            if (m_onScheduleTopologyExpire)
            {
                m_onScheduleTopologyExpire(newTuple.destAddr,
                                           newTuple.lastAddr,
                                           DELAY(newTuple.expirationTime));
            }
        }
    }

#ifdef NS3_LOG_ENABLE
    {
        const TopologySet& topology = m_state->GetTopologySet();
        NS_LOG_DEBUG(Simulator::Now().As(Time::S)
                     << " ** BEGIN dump TopologySet for QBR Node " << m_mainAddress);
        for (const auto& tuple : topology)
        {
            NS_LOG_DEBUG(tuple);
        }
        NS_LOG_DEBUG("** END dump TopologySet for QBR Node " << m_mainAddress);
    }
#endif
}

void
MessageHandler::ProcessMid(const qbr::MessageHeader& msg, const Ipv4Address& senderIface)
{
    NS_ASSERT(m_state);

    const qbr::MessageHeader::Mid& mid = msg.GetMid();
    Time now = Simulator::Now();

    NS_LOG_DEBUG("Node " << m_mainAddress << " ProcessMid from " << senderIface);

    if (m_state->FindSymLinkTuple(senderIface, now) == nullptr)
    {
        NS_LOG_LOGIC("Node " << m_mainAddress
                             << ": sender not in symmetric neighborhood => discarding.");
        return;
    }

    for (const auto& ifaceAddr : mid.interfaceAddresses)
    {
        bool updated = false;
        IfaceAssocSet& ifaceAssoc = m_state->GetIfaceAssocSetMutable();
        for (auto& tuple : ifaceAssoc)
        {
            if (tuple.ifaceAddr == ifaceAddr && tuple.mainAddr == msg.GetOriginatorAddress())
            {
                NS_LOG_LOGIC("IfaceAssoc updated: " << tuple);
                tuple.time = now + msg.GetVTime();
                updated = true;
            }
        }
        if (!updated)
        {
            IfaceAssocTuple tuple;
            tuple.ifaceAddr = ifaceAddr;
            tuple.mainAddr = msg.GetOriginatorAddress();
            tuple.time = now + msg.GetVTime();

            if (m_onAddIfaceAssocTuple)
            {
                m_onAddIfaceAssocTuple(tuple);
            }
            NS_LOG_LOGIC("New IfaceAssoc added: " << tuple);

            if (m_onScheduleIfaceAssocExpire)
            {
                m_onScheduleIfaceAssocExpire(tuple.ifaceAddr, DELAY(tuple.time));
            }
        }
    }

    // Update neighbor and two-hop neighbor address caches using the new MID info.
    for (auto& neighbor : m_state->GetNeighbors())
    {
        neighbor.neighborMainAddr = GetMainAddress(neighbor.neighborMainAddr);
    }
    for (auto& twoHopNeighbor : m_state->GetTwoHopNeighbors())
    {
        twoHopNeighbor.neighborMainAddr = GetMainAddress(twoHopNeighbor.neighborMainAddr);
        twoHopNeighbor.twoHopNeighborAddr = GetMainAddress(twoHopNeighbor.twoHopNeighborAddr);
    }

    NS_LOG_DEBUG("Node " << m_mainAddress << " ProcessMid from " << senderIface << " -> END.");
}

void
MessageHandler::ProcessHna(const qbr::MessageHeader& msg, const Ipv4Address& senderIface)
{
    NS_ASSERT(m_state);

    const qbr::MessageHeader::Hna& hna = msg.GetHna();
    Time now = Simulator::Now();

    if (m_state->FindSymLinkTuple(senderIface, now) == nullptr)
    {
        return;
    }

    for (const auto& assocEntry : hna.associations)
    {
        AssociationTuple* tuple = m_state->FindAssociationTuple(msg.GetOriginatorAddress(),
                                                                assocEntry.address,
                                                                assocEntry.mask);

        if (tuple != nullptr)
        {
            tuple->expirationTime = now + msg.GetVTime();
        }
        else
        {
            AssociationTuple newTuple{msg.GetOriginatorAddress(),
                                      assocEntry.address,
                                      assocEntry.mask,
                                      now + msg.GetVTime()};
            if (m_onAddAssociationTuple)
            {
                m_onAddAssociationTuple(newTuple);
            }
            if (m_onScheduleAssocExpire)
            {
                m_onScheduleAssocExpire(newTuple.gatewayAddr,
                                        newTuple.networkAddr,
                                        newTuple.netmask,
                                        DELAY(newTuple.expirationTime));
            }
        }
    }
}

// -----------------------------------------------------------------------
// HELLO sub-processors
// -----------------------------------------------------------------------

void
MessageHandler::LinkSensing(const qbr::MessageHeader& msg,
                            const qbr::MessageHeader::Hello& hello,
                            const Ipv4Address& receiverIface,
                            const Ipv4Address& senderIface)
{
    NS_ASSERT(m_state);

    Time now = Simulator::Now();
    bool updated = false;
    bool created = false;

    NS_LOG_DEBUG("@" << now.As(Time::S) << ": QBR node " << m_mainAddress
                     << ": LinkSensing(receiverIface=" << receiverIface
                     << ", senderIface=" << senderIface << ") BEGIN");

    NS_ASSERT(msg.GetVTime().IsStrictlyPositive());

    LinkTuple* link_tuple = m_state->FindLinkTuple(senderIface);
    if (link_tuple == nullptr)
    {
        LinkTuple newLinkTuple;
        newLinkTuple.neighborIfaceAddr = senderIface;
        newLinkTuple.localIfaceAddr = receiverIface;
        newLinkTuple.symTime = now - Seconds(1);
        newLinkTuple.time = now + msg.GetVTime();
        link_tuple = &m_state->InsertLinkTuple(newLinkTuple);
        created = true;
        NS_LOG_LOGIC("Existing link tuple did not exist => creating new one");
    }
    else
    {
        NS_LOG_LOGIC("Existing link tuple already exists => will update it");
        updated = true;
    }

    link_tuple->asymTime = now + msg.GetVTime();

    if (link_tuple->symTime >= now)
    {
        link_tuple->metrics.clear();

        auto metrics = m_metricEngine.ComputeMetrics(*link_tuple, m_state->GetTopologySet());

        link_tuple->metrics = metrics;
    }

    for (const auto& linkMessage : hello.linkMessages)
    {
        auto linkType = LinkType(linkMessage.linkCode & 0x03);
        auto neighborType = NeighborType((linkMessage.linkCode >> 2) & 0x03);

        NS_LOG_DEBUG("Looking at HELLO link messages with Link Type "
                     << static_cast<int>(linkType) << " and Neighbor Type "
                     << static_cast<int>(neighborType));

        if ((linkType == LinkType::SYM_LINK && neighborType == NeighborType::NOT_NEIGH) ||
            (neighborType != NeighborType::SYM_NEIGH && neighborType != NeighborType::MPR_NEIGH &&
             neighborType != NeighborType::NOT_NEIGH))
        {
            NS_LOG_LOGIC("HELLO link code is invalid => IGNORING");
            continue;
        }

        for (const auto& neighIfaceAddr : linkMessage.neighborInterfaceAddresses)
        {
            NS_LOG_DEBUG("   -> Neighbor: " << neighIfaceAddr);
            if (neighIfaceAddr == receiverIface)
            {
                if (linkType == LinkType::LOST_LINK)
                {
                    NS_LOG_LOGIC("link is LOST => expiring it");
                    link_tuple->symTime = now - Seconds(1);
                    updated = true;
                }
                else if (linkType == LinkType::SYM_LINK || linkType == LinkType::ASYM_LINK)
                {
                    NS_LOG_DEBUG(*link_tuple << ": link is SYM or ASYM => should become SYM now"
                                                " (symTime being increased to "
                                             << now + msg.GetVTime());
                    link_tuple->symTime = now + msg.GetVTime();
                    link_tuple->time = link_tuple->symTime + m_neighHoldTime;
                    updated = true;
                }
                else
                {
                    NS_FATAL_ERROR("bad link type");
                }
                break;
            }
            else
            {
                NS_LOG_DEBUG("     \\-> *neighIfaceAddr (" << neighIfaceAddr
                                                           << " != receiverIface (" << receiverIface
                                                           << ") => IGNORING!");
            }
        }
        NS_LOG_DEBUG("Link tuple updated: " << int(updated));
    }

    link_tuple->time = std::max(link_tuple->time, link_tuple->asymTime);

    if (updated && m_onLinkTupleUpdated)
    {
        m_onLinkTupleUpdated(*link_tuple, hello.willingness);
    }

    if (created)
    {
        if (m_onLinkTupleAdded)
        {
            m_onLinkTupleAdded(*link_tuple, hello.willingness);
        }
        if (m_onScheduleLinkTupleExpire)
        {
            m_onScheduleLinkTupleExpire(link_tuple->neighborIfaceAddr,
                                        DELAY(std::min(link_tuple->time, link_tuple->symTime)));
        }
    }

    NS_LOG_DEBUG("@" << now.As(Time::S) << ": QBR node " << m_mainAddress << ": LinkSensing END");
}

void
MessageHandler::PopulateNeighborSet(const qbr::MessageHeader& msg,
                                    const qbr::MessageHeader::Hello& hello)
{
    NS_ASSERT(m_state);

    NeighborTuple* nb_tuple = m_state->FindNeighborTuple(msg.GetOriginatorAddress());
    if (nb_tuple != nullptr)
    {
        nb_tuple->willingness = hello.willingness;
    }
}

void
MessageHandler::PopulateTwoHopNeighborSet(const qbr::MessageHeader& msg,
                                          const qbr::MessageHeader::Hello& hello)
{
    NS_ASSERT(m_state);

    Time now = Simulator::Now();
    NS_LOG_DEBUG("QBR node " << m_mainAddress << ": PopulateTwoHopNeighborSet BEGIN");

    for (const auto& link_tuple : m_state->GetLinks())
    {
        NS_LOG_LOGIC("Looking at link tuple: " << link_tuple);
        if (GetMainAddress(link_tuple.neighborIfaceAddr) != msg.GetOriginatorAddress())
        {
            NS_LOG_LOGIC("Link tuple ignored: main address mismatch.");
            continue;
        }
        if (link_tuple.symTime < now)
        {
            NS_LOG_LOGIC("Link tuple ignored: expired.");
            continue;
        }

        for (const auto& linkMessage : hello.linkMessages)
        {
            auto neighborType = NeighborType((linkMessage.linkCode >> 2) & 0x3);
            NS_LOG_DEBUG("Looking at Link Message from HELLO: neighborType="
                         << static_cast<int>(neighborType));

            for (const auto& nb2hop_addr_raw : linkMessage.neighborInterfaceAddresses)
            {
                Ipv4Address nb2hop_addr = GetMainAddress(nb2hop_addr_raw);
                NS_LOG_DEBUG("Looking at 2-hop neighbor: " << nb2hop_addr_raw
                                                           << " (main=" << nb2hop_addr << ")");

                if (neighborType == NeighborType::SYM_NEIGH ||
                    neighborType == NeighborType::MPR_NEIGH)
                {
                    if (nb2hop_addr == m_mainAddress)
                    {
                        NS_LOG_LOGIC("Ignoring 2-hop neighbor (it is the node itself)");
                        continue;
                    }

                    TwoHopNeighborTuple* nb2hop_tuple =
                        m_state->FindTwoHopNeighborTuple(msg.GetOriginatorAddress(), nb2hop_addr);
                    NS_LOG_LOGIC("Adding the 2-hop neighbor"
                                 << (nb2hop_tuple ? " (refreshing existing entry)" : ""));

                    if (nb2hop_tuple == nullptr)
                    {
                        TwoHopNeighborTuple newTuple;
                        newTuple.neighborMainAddr = msg.GetOriginatorAddress();
                        newTuple.twoHopNeighborAddr = nb2hop_addr;
                        newTuple.expirationTime = now + msg.GetVTime();

                        if (m_onAddTwoHopNeighborTuple)
                        {
                            m_onAddTwoHopNeighborTuple(newTuple);
                        }
                        if (m_onScheduleNb2hopExpire)
                        {
                            m_onScheduleNb2hopExpire(newTuple.neighborMainAddr,
                                                     newTuple.twoHopNeighborAddr,
                                                     DELAY(newTuple.expirationTime));
                        }
                    }
                    else
                    {
                        nb2hop_tuple->expirationTime = now + msg.GetVTime();
                    }
                }
                else if (neighborType == NeighborType::NOT_NEIGH)
                {
                    NS_LOG_LOGIC("2-hop neighbor is NOT_NEIGH => deleting matching state");
                    m_state->EraseTwoHopNeighborTuples(msg.GetOriginatorAddress(), nb2hop_addr);
                }
                else
                {
                    NS_LOG_LOGIC("*** WARNING *** bad neighbor type value: "
                                 << static_cast<int>(neighborType));
                }
            }
        }
    }

    NS_LOG_DEBUG("QBR node " << m_mainAddress << ": PopulateTwoHopNeighborSet END");
}

void
MessageHandler::PopulateMprSelectorSet(const qbr::MessageHeader& msg,
                                       const qbr::MessageHeader::Hello& hello)
{
    NS_LOG_FUNCTION(this);
    NS_ASSERT(m_state);

    Time now = Simulator::Now();

    for (const auto& linkMessage : hello.linkMessages)
    {
        auto neighborType = NeighborType(linkMessage.linkCode >> 2);
        if (neighborType != NeighborType::MPR_NEIGH)
        {
            continue;
        }

        NS_LOG_DEBUG("Processing a link message with neighbor type MPR_NEIGH");
        for (const auto& nb_iface_addr : linkMessage.neighborInterfaceAddresses)
        {
            if (GetMainAddress(nb_iface_addr) != m_mainAddress)
            {
                continue;
            }

            NS_LOG_DEBUG("Adding entry to mpr selector set for neighbor " << nb_iface_addr);
            MprSelectorTuple* existing = m_state->FindMprSelectorTuple(msg.GetOriginatorAddress());

            if (existing == nullptr)
            {
                MprSelectorTuple mprsel_tuple;
                mprsel_tuple.mainAddr = msg.GetOriginatorAddress();
                mprsel_tuple.expirationTime = now + msg.GetVTime();

                if (m_onAddMprSelectorTuple)
                {
                    m_onAddMprSelectorTuple(mprsel_tuple);
                }
                if (m_onScheduleMprSelExpire)
                {
                    m_onScheduleMprSelExpire(mprsel_tuple.mainAddr,
                                             DELAY(mprsel_tuple.expirationTime));
                }
            }
            else
            {
                existing->expirationTime = now + msg.GetVTime();
            }
        }
    }

    NS_LOG_DEBUG("Computed MPR selector set for node " << m_mainAddress << ": "
                                                       << m_state->PrintMprSelectorSet());
}

// -----------------------------------------------------------------------
// Private helper
// -----------------------------------------------------------------------

Ipv4Address
MessageHandler::GetMainAddress(Ipv4Address ifaceAddr) const
{
    NS_ASSERT(m_state);
    const IfaceAssocTuple* tuple = m_state->FindIfaceAssocTuple(ifaceAddr);
    return (tuple != nullptr) ? tuple->mainAddr : ifaceAddr;
}

} // namespace qbr
} // namespace ns3
