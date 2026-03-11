#include "ns3/aodv-module.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/olsr-module.h"
#include "ns3/wifi-module.h"
#include "ns3/qbr-module.h"
#include "ns3/netanim-module.h"   // ← NetAnim addition
#include <fstream>

using namespace ns3;

// Global variables for recording
Ptr<FlowMonitor> monitor;
FlowMonitorHelper flowmon;
std::ofstream results;

void RecordMetrics(double simTime) {
    monitor->CheckForLostPackets();
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();

    double tx = 0, rx = 0, delay = 0, bytes = 0;
    for (auto const& [id, stat] : stats) {
        tx    += stat.txPackets;
        rx    += stat.rxPackets;
        delay += stat.delaySum.GetSeconds();
        bytes += stat.rxBytes;
    }

    double pdr = (tx > 0) ? (rx / tx) : 0;
    double thr = (rx > 0) ? (bytes * 8.0 / 1000.0) : 0;

    results << Simulator::Now().GetSeconds() << ","
            << tx << ","
            << rx << ","
            << pdr << ","
            << (rx > 0 ? delay / rx : 0) << ","
            << thr << std::endl;

    if (Simulator::Now().GetSeconds() < simTime) {
        Simulator::Schedule(Seconds(1.0), &RecordMetrics, simTime);
    }
}

int main(int argc, char* argv[]) {
    std::string protocol = "olsr";
    uint32_t    nNodes   = 40;
    double      simTime  = 100.0;

    CommandLine cmd;
    cmd.AddValue("protocol", "Routing protocol: olsr, aodv, or qbr", protocol);
    cmd.AddValue("nNodes",   "Number of nodes",                        nNodes);
    cmd.AddValue("simTime",  "Simulation duration (seconds)",          simTime);
    cmd.Parse(argc, argv);

    // ── Validate protocol ─────────────────────────────────────────────────────
    if (protocol != "olsr" && protocol != "aodv" && protocol != "qbr") {
        NS_FATAL_ERROR("Unknown protocol '" << protocol << "'. Use olsr, aodv, or qbr.");
    }

    NS_LOG_UNCOND("Running simulation: protocol=" << protocol
                  << "  nodes=" << nNodes
                  << "  duration=" << simTime << "s");

    // ── Nodes ─────────────────────────────────────────────────────────────────
    NodeContainer nodes;
    nodes.Create(nNodes);

    // ── WiFi (802.11b ad-hoc) ─────────────────────────────────────────────────
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211b);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode", StringValue("DsssRate11Mbps"));

    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    channel.AddPropagationLoss("ns3::RangePropagationLossModel",
                               "MaxRange", DoubleValue(250.0));

    YansWifiPhyHelper phy;
    phy.SetChannel(channel.Create());

    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");
    NetDeviceContainer devices = wifi.Install(phy, mac, nodes);

    // ── Mobility (300 × 300 m, constant velocity) ─────────────────────────────
    MobilityHelper mobility;
    mobility.SetPositionAllocator("ns3::RandomRectanglePositionAllocator",
                                  "X", StringValue("ns3::UniformRandomVariable[Min=0|Max=300]"),
                                  "Y", StringValue("ns3::UniformRandomVariable[Min=0|Max=300]"));
    mobility.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
    mobility.Install(nodes);

    // ── Routing protocol ──────────────────────────────────────────────────────
    InternetStackHelper internet;

    if (protocol == "olsr") {
        OlsrHelper olsr;
        internet.SetRoutingHelper(olsr);

    } else if (protocol == "aodv") {
        AodvHelper aodv;
        aodv.Set("ActiveRouteTimeout", TimeValue(Seconds(10.0)));
        internet.SetRoutingHelper(aodv);

    } else {  // qbr
        QbrHelper qbr;
        internet.SetRoutingHelper(qbr);
    }

    internet.Install(nodes);

    // ── IP addressing ─────────────────────────────────────────────────────────
    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    // ── Applications ─────────────────────────────────────────────────────────
    uint16_t port      = 9;
    double   appStart  = (protocol == "olsr") ? 20.0 : 5.0;

    // Sink
    PacketSinkHelper sink("ns3::UdpSocketFactory",
                          InetSocketAddress(Ipv4Address::GetAny(), port));
    ApplicationContainer sinkApp = sink.Install(nodes.Get(nNodes - 1));
    sinkApp.Start(Seconds(1.0));
    sinkApp.Stop(Seconds(simTime));

    // Source
    OnOffHelper onoff("ns3::UdpSocketFactory",
                      InetSocketAddress(interfaces.GetAddress(nNodes - 1), port));
    onoff.SetAttribute("DataRate",   StringValue("512Kbps"));
    onoff.SetAttribute("PacketSize", UintegerValue(1024));
    onoff.SetAttribute("OnTime",  StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    ApplicationContainer apps = onoff.Install(nodes.Get(0));
    apps.Start(Seconds(appStart));
    apps.Stop(Seconds(simTime));

    // ── Flow monitor + CSV output ─────────────────────────────────────────────
    monitor = flowmon.InstallAll();

    std::string outFile = "results/csv/" + protocol + "_results.csv";
    results.open(outFile);
    results << "Time,TxPackets,RxPackets,PDR,AvgDelay,Throughput\n";

    Simulator::Schedule(Seconds(1.0), &RecordMetrics, simTime);

    // ── NetAnim ───────────────────────────────────────────────────────────────
    // Output file is named per-protocol so each run gets its own animation file.
    std::string animFile = "results/animations/" + protocol + "_animation.xml";
    AnimationInterface anim(animFile);

    // Label the source and sink so they stand out in the visualiser
    anim.UpdateNodeDescription(nodes.Get(0),           "SRC");
    anim.UpdateNodeDescription(nodes.Get(nNodes - 1),  "SNK");

    // Give source and sink distinct colours (R, G, B)
    anim.UpdateNodeColor(nodes.Get(0),           0,   200, 0);   // green  = source
    anim.UpdateNodeColor(nodes.Get(nNodes - 1),  200, 0,   0);   // red    = sink

    // Keep all other nodes a neutral blue
    for (uint32_t i = 1; i < nNodes - 1; ++i) {
        anim.UpdateNodeColor(nodes.Get(i), 0, 0, 200);
    }

    // Optional: cap the packet metadata NetAnim stores to avoid huge XML files
    anim.SetMaxPktsPerTraceFile(100000);

    // ── Run ───────────────────────────────────────────────────────────────────
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    // ── Final aggregate stats ─────────────────────────────────────────────────
    monitor->CheckForLostPackets();
    auto stats = monitor->GetFlowStats();

    double totalTx = 0, totalRx = 0, totalDelay = 0, totalBytes = 0;
    for (auto const& [id, stat] : stats) {
        totalTx    += stat.txPackets;
        totalRx    += stat.rxPackets;
        totalDelay += stat.delaySum.GetSeconds();
        totalBytes += stat.rxBytes;
    }

    NS_LOG_UNCOND("\n=== Final Results [" << protocol << "] ===");
    NS_LOG_UNCOND("  Total TX packets     : " << totalTx);
    NS_LOG_UNCOND("  Total RX packets     : " << totalRx);
    NS_LOG_UNCOND("  PDR                  : " << (totalTx > 0 ? totalRx / totalTx : 0));
    NS_LOG_UNCOND("  Avg end-to-end delay : "
                  << (totalRx > 0 ? totalDelay / totalRx : 0) << " s");
    NS_LOG_UNCOND("  Throughput           : "
                  << (totalBytes * 8.0 / simTime / 1000.0) << " Kbps");
    NS_LOG_UNCOND("  CSV written to       : " << outFile);
    NS_LOG_UNCOND("  NetAnim XML written  : " << animFile);

    Simulator::Destroy();
    results.close();

    return 0;
}