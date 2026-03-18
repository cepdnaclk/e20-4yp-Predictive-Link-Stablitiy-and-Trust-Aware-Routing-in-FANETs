#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/internet-module.h"
#include "ns3/wifi-module.h"
#include "ns3/qbr-helper.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include "ns3/flow-monitor-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("DroneQbrSimulation");

int main(int argc, char *argv[])
{
    uint32_t numNodes   = 30;
    uint32_t baseIndex  = numNodes - 1;   // Red base node = node 29
    double   simTime    = 120.0;

    // ─── OLSR needs ~20 s to converge on a 30-node chain ───
    double   trafficStart = 25.0;

    CommandLine cmd;
    cmd.Parse(argc, argv);

    NodeContainer nodes;
    nodes.Create(numNodes);

    // ===================== WIFI =====================
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211b);

    YansWifiPhyHelper phy;
    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    phy.SetChannel(channel.Create());

    // TX power kept low enough to require ~2-hop relaying between
    // adjacent chain nodes (spacing 120 m, range ~130 m @ 16 dBm).
    phy.Set("TxPowerStart", DoubleValue(30.0));
    phy.Set("TxPowerEnd",   DoubleValue(30.0));

    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");

    NetDeviceContainer devices = wifi.Install(phy, mac, nodes);

    // ===================== MOBILITY =====================
    MobilityHelper mobility;

    // Straight chain: node 0 … node 28 spread along X axis,
    // base node (29) placed at the far end → every data node
    // must relay through intermediate hops to reach it.
    Ptr<ListPositionAllocator> posAlloc = CreateObject<ListPositionAllocator>();

    double spacing = 30.0;   // distance between chain nodes

    // Drone nodes 0 … 28
    for (uint32_t i = 0; i < numNodes - 1; i++)
    {
        posAlloc->Add(Vector(
            i * spacing,
            500.0 + (rand() % 80),
            80.0  + (rand() % 40)));
    }

    // Base node at the rightmost position
    posAlloc->Add(Vector(
        (numNodes - 1) * spacing,
        500.0,
        80.0));

    mobility.SetPositionAllocator(posAlloc);

    // Gauss-Markov mobility – drones drift slowly; base is mostly static
    mobility.SetMobilityModel("ns3::GaussMarkovMobilityModel",
        "Bounds",         BoxValue(Box(0, numNodes * spacing, 0, 1000, 0, 200)),
        "TimeStep",       TimeValue(Seconds(1.0)),
        "Alpha",          DoubleValue(0.9),
        "MeanVelocity",   StringValue("ns3::UniformRandomVariable[Min=5|Max=15]"),
        "MeanDirection",  StringValue("ns3::UniformRandomVariable[Min=0|Max=6.28]"));

    mobility.Install(nodes);

    // ===================== INTERNET + OLSR =====================
    QbrHelper qbr;
    qbr.Set("HelloInterval", TimeValue(Seconds(1.0)));
    qbr.Set("TcInterval",    TimeValue(Seconds(3.0)));

    InternetStackHelper internet;
    internet.SetRoutingHelper(qbr);
    internet.Install(nodes);

    Ipv4AddressHelper address;
    address.SetBase("10.0.0.0", "255.255.255.0");
    Ipv4InterfaceContainer ifaces = address.Assign(devices);

    // ===================== APPLICATIONS =====================
    uint16_t portUp   = 9;    // drones → base
    uint16_t portDown = 10;   // base   → drones

    // ── 1. Sink on the BASE NODE (receives from all drones) ──
    PacketSinkHelper baseSink("ns3::UdpSocketFactory",
        Address(InetSocketAddress(Ipv4Address::GetAny(), portUp)));
    ApplicationContainer baseSinkApp = baseSink.Install(nodes.Get(baseIndex));
    baseSinkApp.Start(Seconds(0.0));
    baseSinkApp.Stop(Seconds(simTime));

    // ── 2. Sink on EVERY DRONE (receives commands from base) ──
    PacketSinkHelper droneSink("ns3::UdpSocketFactory",
        Address(InetSocketAddress(Ipv4Address::GetAny(), portDown)));
    for (uint32_t i = 0; i < numNodes - 1; i++)
    {
        ApplicationContainer app = droneSink.Install(nodes.Get(i));
        app.Start(Seconds(0.0));
        app.Stop(Seconds(simTime));
    }

    // ── 3. Every drone sends telemetry UP to the base ──
    //       Staggered starts so the channel is not flooded at t=25 s
    for (uint32_t i = 0; i < numNodes - 1; i++)
    {
        UdpClientHelper upClient(
            InetSocketAddress(ifaces.GetAddress(baseIndex), portUp));

        upClient.SetAttribute("MaxPackets", UintegerValue(1000000));
        upClient.SetAttribute("Interval",   TimeValue(Seconds(0.5)));
        upClient.SetAttribute("PacketSize", UintegerValue(512));

        ApplicationContainer app = upClient.Install(nodes.Get(i));
        // Stagger by 0.2 s per node to avoid simultaneous bursts
        app.Start(Seconds(trafficStart + i * 0.2));
        app.Stop(Seconds(simTime - 5.0));
    }

    // ── 4. Base sends commands DOWN to EVERY drone ──
    //       Staggered starts to let OLSR routes stabilise per-node
    for (uint32_t i = 0; i < numNodes - 1; i++)
    {
        UdpClientHelper downClient(
            InetSocketAddress(ifaces.GetAddress(i), portDown));

        downClient.SetAttribute("MaxPackets", UintegerValue(500000));
        downClient.SetAttribute("Interval",   TimeValue(Seconds(1.0)));
        downClient.SetAttribute("PacketSize", UintegerValue(256));

        ApplicationContainer app = downClient.Install(nodes.Get(baseIndex));
        // Slightly later than uplink so OLSR can route back through chain
        app.Start(Seconds(trafficStart + 5.0 + i * 0.2));
        app.Stop(Seconds(simTime - 5.0));
    }

    // ── 5. Relay-heavy cross flows (drone i → drone i+2 via i+1) ──
    //       Forces intermediate nodes to act as OLSR MPRs/relays
    for (uint32_t i = 0; i < numNodes - 5; i += 5)
    {
        uint32_t dest = i + 4;   // separated by 4 hops in chain

        // Also install a sink on the destination for these flows
        // (already installed in step 2 above via portDown; use portUp here)
        UdpClientHelper relayClient(
            InetSocketAddress(ifaces.GetAddress(dest), portUp));

        relayClient.SetAttribute("MaxPackets", UintegerValue(300000));
        relayClient.SetAttribute("Interval",   TimeValue(Seconds(0.8)));
        relayClient.SetAttribute("PacketSize", UintegerValue(400));

        ApplicationContainer app = relayClient.Install(nodes.Get(i));
        app.Start(Seconds(trafficStart + 10.0 + i));
        app.Stop(Seconds(simTime - 5.0));
    }

    // ===================== FLOW MONITOR =====================
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    // ===================== NETANIM =====================
    AnimationInterface anim("drone-qbr.xml");
    anim.SetMaxPktsPerTraceFile(500000);
    anim.EnablePacketMetadata(true);

    // Drone nodes – blue
    for (uint32_t i = 0; i < numNodes - 1; i++)
    {
        anim.UpdateNodeSize(i, 20.0, 20.0);
        anim.UpdateNodeColor(i, 30, 144, 255);
        anim.UpdateNodeDescription(nodes.Get(i), "D" + std::to_string(i));
    }

    // Base node – big red dot
    anim.UpdateNodeSize(baseIndex, 45.0, 45.0);
    anim.UpdateNodeColor(baseIndex, 255, 0, 0);
    anim.UpdateNodeDescription(nodes.Get(baseIndex), "BASE");

    // ===================== LOGGING =====================
    LogComponentEnable("QbrRoutingProtocol", LOG_LEVEL_WARN);

    // ===================== RUN =====================
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    // ===================== RESULTS =====================
    monitor->CheckForLostPackets();

    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());

    auto stats = monitor->GetFlowStats();

    uint64_t totalTx = 0, totalRx = 0;

    std::cout << "\n====== Per-Flow Statistics ======\n";
    for (auto &flow : stats)
    {
        auto t = classifier->FindFlow(flow.first);

        std::cout << "Flow " << flow.first << ": "
                  << t.sourceAddress << ":" << t.sourcePort
                  << " -> "
                  << t.destinationAddress << ":" << t.destinationPort
                  << "\n";
        std::cout << "  Tx Packets : " << flow.second.txPackets << "\n";
        std::cout << "  Rx Packets : " << flow.second.rxPackets << "\n";
        std::cout << "  Lost       : "
                  << (flow.second.txPackets - flow.second.rxPackets) << "\n";

        if (flow.second.rxPackets > 0)
        {
            double avgDelay =
                flow.second.delaySum.GetSeconds() / flow.second.rxPackets;
            double avgJitter =
                (flow.second.rxPackets > 1)
                    ? flow.second.jitterSum.GetSeconds() /
                          (flow.second.rxPackets - 1)
                    : 0.0;
            std::cout << "  Avg Delay  : " << avgDelay  << " s\n";
            std::cout << "  Avg Jitter : " << avgJitter << " s\n";
        }

        std::cout << "  PDR        : "
                  << (flow.second.txPackets > 0
                          ? 100.0 * flow.second.rxPackets /
                                flow.second.txPackets
                          : 0.0)
                  << " %\n";
        std::cout << "----------------------------------\n";

        totalTx += flow.second.txPackets;
        totalRx += flow.second.rxPackets;
    }

    std::cout << "\n====== Global Summary ======\n";
    std::cout << "Total Tx Packets : " << totalTx << "\n";
    std::cout << "Total Rx Packets : " << totalRx << "\n";
    std::cout << "Global PDR       : "
              << (totalTx > 0 ? 100.0 * totalRx / totalTx : 0.0)
              << " %\n\n";

    Simulator::Destroy();
    return 0;
}