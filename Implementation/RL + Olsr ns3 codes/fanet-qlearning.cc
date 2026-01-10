#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"

#include <fstream>
#include <map>
#include <vector>
#include <tuple>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("FANET_QLEARNING");

/* ===================== Q-LEARNING AGENT ===================== */

class QLearningAgent
{
public:
  QLearningAgent ()
  {
    lr = 0.1;
    discount = 0.9;
    epsilon = 0.1;
    m_rand = CreateObject<UniformRandomVariable> ();
  }

  struct State
  {
    uint32_t snr;
    uint32_t hop;
    uint32_t pdr;
    uint32_t delay;

    bool operator < (State const &o) const
    {
      return std::tie (snr, hop, pdr, delay) <
             std::tie (o.snr, o.hop, o.pdr, o.delay);
    }
  };

  uint32_t SelectAction (State s, const std::vector<uint32_t> &neighbors)
  {
    if (neighbors.empty ())
      return 0;

    if (m_rand->GetValue (0.0, 1.0) < epsilon)
      {
        return neighbors[m_rand->GetInteger (0, neighbors.size () - 1)];
      }

    double maxQ = -1e9;
    uint32_t best = neighbors[0];

    for (auto n : neighbors)
      {
        double q = qtable[{s, n}];
        if (q > maxQ)
          {
            maxQ = q;
            best = n;
          }
      }
    return best;
  }

  void Update (State s, uint32_t action, double reward, State next)
  {
    double maxNext = 0.0;
    for (auto &it : qtable)
      {
        if (it.first.first.snr == next.snr)
          maxNext = std::max (maxNext, it.second);
      }

    qtable[{s, action}] +=
        lr * (reward + discount * maxNext - qtable[{s, action}]);
  }

private:
  double lr, discount, epsilon;
  Ptr<UniformRandomVariable> m_rand;

  using QKey = std::pair<State, uint32_t>;
  std::map<QKey, double> qtable;
};

/* ===================== MAIN ===================== */

int
main (int argc, char *argv[])
{
  Time::SetResolution (Time::NS);
  LogComponentEnable ("FANET_QLEARNING", LOG_LEVEL_INFO);

  NodeContainer nodes;
  nodes.Create (8); // 0=Src, 1-6 UAVs, 7=Dst

  /* ---------------- Mobility ---------------- */

  MobilityHelper mobility;

  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobility.Install (nodes.Get (0));
  mobility.Install (nodes.Get (7));

  mobility.SetMobilityModel (
      "ns3::GaussMarkovMobilityModel",
      "Bounds", BoxValue (Box (0, 500, 0, 500, 0, 200)),
      "TimeStep", TimeValue (Seconds (1)),
      "Alpha", DoubleValue (0.85),
      "MeanVelocity", StringValue ("ns3::UniformRandomVariable[Min=10|Max=20]"),
      "MeanDirection", StringValue ("ns3::UniformRandomVariable[Min=0|Max=6.28]"),
      "MeanPitch", StringValue ("ns3::UniformRandomVariable[Min=-0.3|Max=0.3]"));

  for (uint32_t i = 1; i <= 6; ++i)
    mobility.Install (nodes.Get (i));

  /* ---------------- WiFi ---------------- */

  WifiHelper wifi;
  wifi.SetStandard (WIFI_STANDARD_80211b);

  WifiMacHelper mac;
  mac.SetType ("ns3::AdhocWifiMac");

  YansWifiPhyHelper phy;
  phy.SetChannel (YansWifiChannelHelper::Default ().Create ());
  phy.EnablePcapAll ("fanet-qlearning");

  NetDeviceContainer devices = wifi.Install (phy, mac, nodes);

  /* ---------------- Internet ---------------- */

  InternetStackHelper internet;
  internet.Install (nodes);

  Ipv4AddressHelper ipv4;
  ipv4.SetBase ("10.1.0.0", "255.255.255.0");
  ipv4.Assign (devices);

  /* ---------------- Applications ---------------- */

  uint16_t port = 9000;

  OnOffHelper onoff ("ns3::UdpSocketFactory",
                     InetSocketAddress ("10.1.0.8", port));
  onoff.SetConstantRate (DataRate ("1Mbps"));

  ApplicationContainer srcApp = onoff.Install (nodes.Get (0));
  srcApp.Start (Seconds (1));
  srcApp.Stop (Seconds (100));

  PacketSinkHelper sink ("ns3::UdpSocketFactory",
                          InetSocketAddress (Ipv4Address::GetAny (), port));
  ApplicationContainer sinkApp = sink.Install (nodes.Get (7));
  sinkApp.Start (Seconds (0));
  sinkApp.Stop (Seconds (100));

  /* ---------------- Flow Monitor ---------------- */

  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll ();

  Simulator::Stop (Seconds (100));
  Simulator::Run ();

  /* ---------------- Metrics ---------------- */

  std::ofstream metrics ("fanet-qlearning-metrics.csv");
  metrics << "PDR,Delay,Jitter\n";

  monitor->CheckForLostPackets ();

  for (auto &flow : monitor->GetFlowStats ())
    {
      auto st = flow.second;
      if (st.txPackets == 0 || st.rxPackets == 0)
        continue;

      double pdr = double (st.rxPackets) / st.txPackets;
      double delay = st.delaySum.GetSeconds () / st.rxPackets;
      double jitter = st.jitterSum.GetSeconds () / st.rxPackets;

      metrics << pdr << "," << delay << "," << jitter << "\n";
    }

  metrics.close ();

  Simulator::Destroy ();
  return 0;
}
