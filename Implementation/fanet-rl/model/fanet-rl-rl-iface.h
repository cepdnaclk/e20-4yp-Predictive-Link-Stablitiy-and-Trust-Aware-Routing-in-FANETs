#pragma once
#include "ns3/object.h"
#include "ns3/ipv4-address.h"
#include <vector>

namespace ns3 {

struct FanetRlObs
{
  // flattened observation
  std::vector<float> x;
  // mapping from action index -> neighbor IP
  std::vector<Ipv4Address> actionMap;
};

class FanetRlRlIface : public Object
{
public:
  static TypeId GetTypeId();

  // C++ asks Python: "given obs, return action index"
  virtual int Decide(const FanetRlObs& obs) = 0;

  // C++ notifies Python of reward (and optionally next obs)
  virtual void ReportReward(float r) = 0;
};

} // namespace ns3
