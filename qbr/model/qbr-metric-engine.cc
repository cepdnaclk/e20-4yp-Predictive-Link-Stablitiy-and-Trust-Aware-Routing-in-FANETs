#include "qbr-metric-engine.h"
#include "qbr-state.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include <algorithm>

namespace ns3 {
namespace qbr {

NS_LOG_COMPONENT_DEFINE("QbrMetricEngine");

MetricEngine::MetricEngine() {}

void
MetricEngine::InitNeighborStats(Ipv4Address neighbor)
{
    // Ensure stats exist for this neighbor
    auto it = m_stats.find(neighbor);
    if (it == m_stats.end()) {
        LinkStats s;
        s.packetsReceived = 0;
        s.txAttempts = 0;
        s.txSuccess = 0;
        s.snrAvg = 0.0;
        s.delayAvg = 0.0;
        s.jitterAvg = 0.0;
        s.lastUpdate = Simulator::Now();
        s.lastRxTime = Seconds(0);
        m_stats[neighbor] = s;
    }
}

double
MetricEngine::MeasureSnr(Ipv4Address neighbor) const
{
    // Placeholder: simple SNR estimate (replace with PHY measurement if available)
    // For example, random variation around a typical 25 dB SNR
    return 20.0 + 5.0 * (std::rand() / static_cast<double>(RAND_MAX));
}

Time
MetricEngine::ComputeDelay(Ipv4Address neighbor, Time packetTxTime)
{
    // Estimate delay: now - stored packetTxTime
    return Simulator::Now() - packetTxTime;
}

Time
MetricEngine::ComputeJitter(Ipv4Address neighbor, Time packetDelay)
{
    LinkStats& s = m_stats[neighbor];

    Time jitter;
    if (s.lastRxTime == Seconds(0)) {
        jitter = Seconds(0);
    } else {
        Time delta = Simulator::Now() - s.lastRxTime;
        jitter = delta - packetDelay; // approximate
    }
    s.lastRxTime = Simulator::Now();

    return jitter;
}

static uint16_t
NormalizeToUint16(double v)
{
    v = std::max(0.0, std::min(1.0, v));
    return static_cast<uint16_t>(v * 65535.0);
}

void
MetricEngine::RecordPacketReception(Ipv4Address neighbor,
                                    double snr,
                                    bool controlPacket)
{
    LinkStats& s = m_stats[neighbor];

    s.packetsReceived++;

    s.snrAvg =
        (s.snrAvg * (s.packetsReceived - 1) + snr) / s.packetsReceived;

    s.lastUpdate = Simulator::Now();
}

void
MetricEngine::RecordTransmission(Ipv4Address neighbor, bool success)
{
    LinkStats& s = m_stats[neighbor];

    s.txAttempts++;

    if (success)
    {
        s.txSuccess++;
    }
}

std::vector<LinkMetric>
MetricEngine::ComputeMetrics(const LinkTuple& link,
                             const TopologySet& topology) const
{
    std::vector<LinkMetric> metrics;

    auto it = m_stats.find(link.neighborIfaceAddr);
    if (it == m_stats.end())
    {
        return metrics;
    }

    const LinkStats& s = it->second;

    LinkMetric lq;
    lq.type = LINK_QUALITY;
    lq.value = ComputeLinkQuality(s);
    metrics.push_back(lq);

    LinkMetric trust;
    trust.type = TRUST;
    trust.value =
        ComputeTrust(link.neighborIfaceAddr, topology);
    metrics.push_back(trust);

    return metrics;
}

uint16_t
MetricEngine::ComputeLinkQuality(const LinkStats& s) const
{
    double etx = ComputeETX(s);

    double snrScore = std::min(1.0, s.snrAvg / 30.0);

    double delayScore =
        1.0 / (1.0 + s.delayAvg / 100.0);

    double jitterScore =
        1.0 / (1.0 + s.jitterAvg / 100.0);

    double score =
        0.4 * (1.0 / etx) +
        0.3 * snrScore +
        0.2 * delayScore +
        0.1 * jitterScore;

    return NormalizeToUint16(score);
}

uint16_t
MetricEngine::ComputeTrust(Ipv4Address neighbor,
                           const TopologySet& topology) const
{
    double opinionSum = 0.0;
    uint32_t count = 0;

    for (const auto& t : topology)
    {
        if (t.destAddr == neighbor)
        {
            opinionSum += (double)t.linkQuality / 65535.0;
            count++;
        }
    }

    double reputation =
        (count > 0) ? opinionSum / count : 0.5;

    auto it = m_stats.find(neighbor);

    double behavior = 0.5;

    if (it != m_stats.end())
    {
        const LinkStats& s = it->second;

        if (s.txAttempts > 0)
        {
            behavior =
                static_cast<double>(s.txSuccess) / s.txAttempts;
        }
    }

    double trust =
        0.6 * behavior +
        0.4 * reputation;

    return NormalizeToUint16(trust);
}

double
MetricEngine::ComputeETX(const MetricEngine::LinkStats& s) const
{
    if (s.txAttempts == 0 || s.packetsReceived == 0)
        return 9999.0;
    double df = static_cast<double>(s.txSuccess) / s.txAttempts;
    double dr = static_cast<double>(s.packetsReceived) / s.txAttempts;
    if (df <= 0.0 || dr <= 0.0)
        return 9999.0;
    return 1.0 / (df * dr);
}

} // namespace qbr
} // namespace ns3