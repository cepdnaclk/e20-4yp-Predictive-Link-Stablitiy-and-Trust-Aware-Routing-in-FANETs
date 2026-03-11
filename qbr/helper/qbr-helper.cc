#include "qbr-helper.h"

#include "ns3/ipv4-list-routing.h"
#include "ns3/names.h"
#include "ns3/node-list.h"
#include "ns3/qbr-routing-protocol.h"
#include "ns3/ptr.h"

namespace ns3
{
QbrHelper::QbrHelper()
{
    m_agentFactory.SetTypeId("ns3::qbr::RoutingProtocol");
}

QbrHelper::QbrHelper(const QbrHelper& o)
    : m_agentFactory(o.m_agentFactory)
{
    m_interfaceExclusions = o.m_interfaceExclusions;
}

QbrHelper*
QbrHelper::Copy() const
{
    return new QbrHelper(*this);
}

void
QbrHelper::ExcludeInterface(Ptr<Node> node, uint32_t interface)
{
    auto it = m_interfaceExclusions.find(node);

    if (it == m_interfaceExclusions.end())
    {
        std::set<uint32_t> interfaces;
        interfaces.insert(interface);

        m_interfaceExclusions.insert(std::make_pair(node, std::set<uint32_t>(interfaces)));
    }
    else
    {
        it->second.insert(interface);
    }
}

Ptr<Ipv4RoutingProtocol>
QbrHelper::Create(Ptr<Node> node) const
{
    Ptr<qbr::RoutingProtocol> agent = m_agentFactory.Create<qbr::RoutingProtocol>();

    auto it = m_interfaceExclusions.find(node);

    if (it != m_interfaceExclusions.end())
    {
        agent->SetInterfaceExclusions(it->second);
    }

    node->AggregateObject(agent);
    return agent;
}

void
QbrHelper::Set(std::string name, const AttributeValue& value)
{
    m_agentFactory.Set(name, value);
}

int64_t
QbrHelper::AssignStreams(NodeContainer c, int64_t stream)
{
    int64_t currentStream = stream;
    Ptr<Node> node;
    for (auto i = c.Begin(); i != c.End(); ++i)
    {
        node = (*i);
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
        NS_ASSERT_MSG(ipv4, "Ipv4 not installed on node");
        Ptr<Ipv4RoutingProtocol> proto = ipv4->GetRoutingProtocol();
        NS_ASSERT_MSG(proto, "Ipv4 routing not installed on node");
        Ptr<qbr::RoutingProtocol> qbr = DynamicCast<qbr::RoutingProtocol>(proto);
        if (qbr)
        {
            currentStream += qbr->AssignStreams(currentStream);
            continue;
        }
        // Qbr may also be in a list
        Ptr<Ipv4ListRouting> list = DynamicCast<Ipv4ListRouting>(proto);
        if (list)
        {
            int16_t priority;
            Ptr<Ipv4RoutingProtocol> listProto;
            Ptr<qbr::RoutingProtocol> listQbr;
            for (uint32_t i = 0; i < list->GetNRoutingProtocols(); i++)
            {
                listProto = list->GetRoutingProtocol(i, priority);
                listQbr = DynamicCast<qbr::RoutingProtocol>(listProto);
                if (listQbr)
                {
                    currentStream += listQbr->AssignStreams(currentStream);
                    break;
                }
            }
        }
    }
    return (currentStream - stream);
}

} // namespace ns3
