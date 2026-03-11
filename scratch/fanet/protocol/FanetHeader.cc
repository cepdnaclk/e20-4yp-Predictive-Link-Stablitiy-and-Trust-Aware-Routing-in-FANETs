#include "FanetHeader.h"
#include <ns3/log.h>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("FanetHeader");

TypeId
FanetHeader::GetTypeId(void)
{
    static TypeId tid = TypeId("ns3::FanetHeader").SetParent<Header>().AddConstructor<FanetHeader>();
    return tid;
}

TypeId
FanetHeader::GetInstanceTypeId(void) const
{
    return GetTypeId();
}

void
FanetHeader::Serialize(Buffer::Iterator start) const
{
    start.WriteU8(type);
    start.WriteHtonU32(seq);
    start.WriteHtonU32(nodeId);

    start.WriteU8(neighbors.size());
    for (auto& n : neighbors)
    {
        start.WriteHtonU32(n.Get());
    }

    // MPR selector list
    start.WriteU8(mprSelectorList.size());
    for (auto& m : mprSelectorList)
        start.WriteHtonU32(m.Get());

    start.WriteHtonU64(timestamp);
}

uint32_t
FanetHeader::Deserialize(Buffer::Iterator start)
{
    uint32_t bytesRead = 0;
    type = start.ReadU8();
    bytesRead += 1;
    seq = start.ReadNtohU32();
    bytesRead += 4;
    nodeId = start.ReadNtohU32();
    bytesRead += 4;
    neighborCount = start.ReadU8();
    bytesRead += 1;

    neighbors.clear();
    neighbors.reserve(neighborCount);
    for (uint8_t i = 0; i < neighborCount; i++)
    {
        neighbors.push_back(Ipv4Address(start.ReadNtohU32()));
        bytesRead += 4;
    }

    uint8_t mprCount = start.ReadU8();
    bytesRead += 1;
    mprSelectorList.clear();
    for (uint8_t i = 0; i < mprCount; i++) {
        mprSelectorList.push_back(Ipv4Address(start.ReadNtohU32()));
        bytesRead += 4;
    }

    timestamp = start.ReadNtohU64();
    bytesRead += 8;
    return bytesRead;
}

uint32_t
FanetHeader::GetSerializedSize(void) const
{
    return 1 + 4 + 4 + 1 + (4 * neighbors.size()) + 1 + (4 * mprSelectorList.size()) + 8;
}

void
FanetHeader::Print(std::ostream& os) const
{
    os << "[FanetHeader type=" << static_cast<uint32_t>(type)
       << " seq=" << seq << " nodeId=" << nodeId << "]";
}

} // namespace ns3
