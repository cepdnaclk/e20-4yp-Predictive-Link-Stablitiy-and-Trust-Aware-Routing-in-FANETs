#pragma once
#include "ns3/object.h"
#include "ns3/ipv4-address.h"
#include <map>

namespace ns3 {

class FanetRlMetrics;

class FanetRlTrust : public Object
{
public:
  static TypeId GetTypeId();
  void SetMetrics(Ptr<FanetRlMetrics> metrics);

  double GetTrust(Ipv4Address nbr) const;
  bool IsMalicious(Ipv4Address nbr) const;

  // call periodically
  void Recompute();

private:
  Ptr<FanetRlMetrics> m_metrics;
  std::map<Ipv4Address, double> m_trust;
  std::map<Ipv4Address, uint32_t> m_badStreak;

  double m_minTrust = 0.35;
  uint32_t m_badK = 3;
};

} // namespace ns3
