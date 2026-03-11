#ifndef FANET_HEADER_H
#define FANET_HEADER_H

#include <ns3/header.h>
#include <ns3/ipv4-address.h>
#include <ns3/buffer.h>
#include <vector>

namespace ns3 {

// Packet types exchanged by the FANET protocol
enum FanetPacketType
{
    HELLO = 1, // Neighbor discovery
    TC = 2,    // Topology control
    DATA = 3   // TODO: Data packet not implemented yet
};

// FANET control packet header carried in every HELLO/TC message
struct FanetHeader : public Header
{
    uint8_t type;                       // HELLO, TC
    uint32_t seq;                       // sequence number
    uint32_t nodeId;                    // optional node identifier
    uint8_t neighborCount;              // Number of 1-hopneighbors
    std::vector<Ipv4Address> neighbors; // topology discovery
    std::vector<Ipv4Address> mprSelectorList; // Nodes that chose THIS node as MPR
    uint64_t timestamp; // Time in microseconds

    static TypeId GetTypeId(void);
    virtual TypeId GetInstanceTypeId(void) const override;
    virtual void Serialize(Buffer::Iterator start) const override;
    virtual uint32_t Deserialize(Buffer::Iterator start) override;
    virtual uint32_t GetSerializedSize(void) const override;
    virtual void Print(std::ostream& os) const override;
};

} // namespace ns3

#endif // FANET_HEADER_H
