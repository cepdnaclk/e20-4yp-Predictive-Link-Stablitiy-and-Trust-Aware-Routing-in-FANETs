#pragma once
#include "ns3/object.h"
#include "ns3/nstime.h"
#include "ns3/ipv4-address.h"
#include <map>

namespace ns3 {

struct LinkMetrics
{
  // discovery/stability
  Time firstSeen = Seconds(0);
  Time lastSeen  = Seconds(0);
  double stabilitySec = 0.0;

  // PHY estimate (EWMA)
  double snrEwma = 0.0;

  // delivery
  uint32_t txCount = 0;
  uint32_t fwdOkCount = 0;
  double pdrEwma = 0.0;

  // delay/jitter (EWMA)
  double delayEwmaMs = 0.0;
  double jitterEwmaMs = 0.0;
  double lastDelayMs = 0.0;
};

class FanetRlMetrics : public Object
{
public:
  static TypeId GetTypeId();
  void SeenHello(Ipv4Address nbr, Time now);
  void UpdateSnr(Ipv4Address nbr, double snrDb);
  void OnTx(Ipv4Address nextHop);
  void OnForwardResult(Ipv4Address nextHop, bool success, Time delay);

  const LinkMetrics* Get(Ipv4Address nbr) const;
  LinkMetrics* GetMut(Ipv4Address nbr);

private:
  std::map<Ipv4Address, LinkMetrics> m;
  double m_beta = 0.2; // EWMA factor
};

} // namespace ns3
