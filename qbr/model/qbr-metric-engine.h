#ifndef QBR_METRIC_ENGINE_H
#define QBR_METRIC_ENGINE_H

#include "qbr-header.h"
#include "qbr-repositories.h"

#include "ns3/ipv4-address.h"
#include "ns3/nstime.h"

#include <vector>
#include <map>

namespace ns3 {
namespace qbr {

class LinkTuple;
class TopologyTuple;

class MetricEngine
{
public:
    MetricEngine();

    void InitNeighborStats(Ipv4Address neighbor);

    double MeasureSnr(Ipv4Address neighbor) const;

    Time ComputeDelay(Ipv4Address neighbor, Time packetTxTime);

    Time ComputeJitter(Ipv4Address neighbor, Time packetDelay);

    // Called whenever a packet from neighbor is observed
    void RecordPacketReception(Ipv4Address neighbor,
                               double snr,
                               bool controlPacket);

    // Called when a packet transmission attempt occurs
    void RecordTransmission(Ipv4Address neighbor, bool success);

    // Compute metrics for a link
    std::vector<LinkMetric>
    ComputeMetrics(const LinkTuple& link,
                   const TopologySet& topology) const;

private:

    struct LinkStats
    {
        uint64_t txAttempts = 0;
        uint64_t txSuccess = 0;
        uint64_t packetsReceived = 0;

        double snrAvg = 0.0;
        double delayAvg = 0.0;
        double jitterAvg = 0.0;

        Time lastUpdate;
        Time lastRxTime;
    };

    double ComputeETX(const LinkStats& s) const;

public:
    uint16_t ComputeLinkQuality(const LinkStats& s) const;

    uint16_t ComputeTrust(Ipv4Address neighbor,
                          const std::vector<TopologyTuple>& topology) const;

    std::map<Ipv4Address, LinkStats> m_stats;
};

} // namespace qbr
} // namespace ns3

#endif