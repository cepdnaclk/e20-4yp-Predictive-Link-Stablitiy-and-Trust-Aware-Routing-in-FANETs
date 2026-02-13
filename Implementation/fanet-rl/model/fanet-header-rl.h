#pragma once
#include "ns3/header.h"
#include "ns3/ipv4-address.h"
#include <vector>

namespace ns3 {

enum FanetRlPacketType : uint8_t
{
  FANET_HELLO = 1,
  FANET_TC    = 2
};

// Keep control packets small. Do NOT shove raw metrics in every packet.
// Send only what’s needed: IDs + optional trust advertisement.
class FanetRlHeader : public Header
{
public:
  uint8_t type = 0;
  uint32_t seq = 0;
  uint32_t nodeId = 0;

  // topology
  std::vector<Ipv4Address> neighbors;

  // optional: trust advertisement (coarse)
  double advertisedTrust = 1.0;

  static TypeId GetTypeId();
  TypeId GetInstanceTypeId() const override;

  void Serialize(Buffer::Iterator start) const override;
  uint32_t Deserialize(Buffer::Iterator start) override;
  uint32_t GetSerializedSize() const override;
  void Print(std::ostream& os) const override;
};

} // namespace ns3
