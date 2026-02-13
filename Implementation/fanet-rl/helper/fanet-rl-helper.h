#pragma once
#include "ns3/ipv4-routing-helper.h"

namespace ns3 {

class FanetRlHelper : public Ipv4RoutingHelper
{
public:
  FanetRlHelper* Copy() const override { return new FanetRlHelper(*this); }
  Ptr<Ipv4RoutingProtocol> Create(Ptr<Node> node) const override;
};

} // namespace ns3
