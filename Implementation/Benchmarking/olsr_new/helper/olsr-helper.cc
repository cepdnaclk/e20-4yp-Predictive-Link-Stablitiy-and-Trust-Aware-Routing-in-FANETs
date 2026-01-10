/*
 * Copyright (c) 2008 INRIA
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */
#include "olsr-helper.h"

#include "ns3/ipv4-list-routing.h"
#include "ns3/names.h"
#include "ns3/node-list.h"
#include "ns3/olsr-routing-protocol.h"
#include "ns3/ptr.h"

namespace ns3
{

olsrHelper::olsrHelper()
{
    m_agentFactory.SetTypeId("ns3::olsr::RoutingProtocol");
}

olsrHelper::olsrHelper(const olsrHelper& o)
    : m_agentFactory(o.m_agentFactory)
{
    m_interfaceExclusions = o.m_interfaceExclusions;
}

olsrHelper*
olsrHelper::Copy() const
{
    return new olsrHelper(*this);
}

void
olsrHelper::ExcludeInterface(Ptr<Node> node, uint32_t interface)
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
olsrHelper::Create(Ptr<Node> node) const
{
    Ptr<olsr::RoutingProtocol> agent = m_agentFactory.Create<olsr::RoutingProtocol>();

    auto it = m_interfaceExclusions.find(node);

    if (it != m_interfaceExclusions.end())
    {
        agent->SetInterfaceExclusions(it->second);
    }

    node->AggregateObject(agent);
    return agent;
}

void
olsrHelper::Set(std::string name, const AttributeValue& value)
{
    m_agentFactory.Set(name, value);
}

int64_t
olsrHelper::AssignStreams(NodeContainer c, int64_t stream)
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
        Ptr<olsr::RoutingProtocol> olsr = DynamicCast<olsr::RoutingProtocol>(proto);
        if (olsr)
        {
            currentStream += olsr->AssignStreams(currentStream);
            continue;
        }
        // olsr may also be in a list
        Ptr<Ipv4ListRouting> list = DynamicCast<Ipv4ListRouting>(proto);
        if (list)
        {
            int16_t priority;
            Ptr<Ipv4RoutingProtocol> listProto;
            Ptr<olsr::RoutingProtocol> listolsr;
            for (uint32_t i = 0; i < list->GetNRoutingProtocols(); i++)
            {
                listProto = list->GetRoutingProtocol(i, priority);
                listolsr = DynamicCast<olsr::RoutingProtocol>(listProto);
                if (listolsr)
                {
                    currentStream += listolsr->AssignStreams(currentStream);
                    break;
                }
            }
        }
    }
    return (currentStream - stream);
}

} // namespace ns3
