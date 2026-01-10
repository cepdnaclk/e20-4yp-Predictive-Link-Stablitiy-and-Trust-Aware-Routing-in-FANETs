#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/olsr-helper.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"

#include <fstream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("FANET_OLSR");

int
main (int argc, char *argv[])
{
  Time::SetResolution (Time::NS);
  LogComponentEnable ("FANET_OLSR", LOG_LEVEL_INFO);

  /* ---------------- Nodes ---------------- */
  NodeContainer nodes;
  nodes.Create (8); // 0=Source, 1–6 UAVs, 7=Destination

  /* ---------------- Mobility ---------------- */
  MobilityHelper mobility;

  // Source & Destination are static
  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobility.Install (nodes.Get (0));
  mobility.Install (nodes.Get (7));

  // UAVs: Gauss-Markov 3D
  mobility.SetMobilityModel (
      "ns3::GaussMarkovMobilityModel",
      "Bounds", BoxValue (Box (0, 500, 0, 500, 0, 200)),
      "TimeStep", TimeValue (Seconds (1.0)),
      "Alpha", DoubleValue (0.85),
      "MeanVelocity",
      StringValue ("ns3::UniformRandomVariable[Min=10|Max=20]"),
      "MeanDirection",
      StringValue ("ns3::UniformRandomVariable[Min=0|Max=6.28]"),
      "MeanPitch",
      StringValue ("ns3::UniformRandomVariable[Min=-0.3|Max=0.3]"));

  for (uint32_t i = 1; i <= 6; ++i)
    mobility.Install (nodes.Get (i));

  /* ---------------- WiFi ---------------- */
  WifiHelper wifi;
  wifi.SetStandard (WIFI_STANDARD_80211b);

  WifiMacHelper mac;
  mac.SetType ("ns3::AdhocWifiMac");

  YansWifiPhyHelper phy;
  phy.SetChannel (YansWifiChannelHelper::Default ().Create ());
  phy.EnablePcapAll ("fanet-olsr");

  NetDeviceContainer devices = wifi.Install (phy, mac, nodes);

  /* ---------------- Internet + OLSR ---------------- */
  OlsrHelper olsr;
  InternetStackHelper internet;
  internet.SetRoutingHelper (olsr);
  internet.Install (nodes);

  Ipv4AddressHelper ipv4;
  ipv4.SetBase ("10.2.0.0", "255.255.255.0");
  ipv4.Assign (devices);

  /* ---------------- Applications ---------------- */
  uint16_t port = 9000;

  // Source: UDP traffic
  OnOffHelper onoff ("ns3::UdpSocketFactory",
                     InetSocketAddress ("10.2.0.8", port));
  onoff.SetConstantRate (DataRate ("1Mbps"));

  ApplicationContainer srcApp = onoff.Install (nodes.Get (0));
  srcApp.Start (Seconds (1.0));
  srcApp.Stop (Seconds (100.0));

  // Destination: Sink
  PacketSinkHelper sink ("ns3::UdpSocketFactory",
                          InetSocketAddress (Ipv4Address::GetAny (), port));
  ApplicationContainer sinkApp = sink.Install (nodes.Get (7));
  sinkApp.Start (Seconds (0.0));
  sinkApp.Stop (Seconds (100.0));

  /* ---------------- Flow Monitor ---------------- */
  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll ();

  Simulator::Stop (Seconds (100.0));
  Simulator::Run ();

  /* ---------------- Metrics ---------------- */
  std::ofstream metrics ("fanet-olsr-metrics.csv");
  metrics << "PDR,Delay,Jitter\n";

  monitor->CheckForLostPackets ();

  for (auto const &flow : monitor->GetFlowStats ())
    {
      const FlowMonitor::FlowStats &st = flow.second;

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
