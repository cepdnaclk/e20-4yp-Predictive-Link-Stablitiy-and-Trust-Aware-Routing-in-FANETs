#include "protocol/FanetRoutingProtocol.h"
#include <ns3/applications-module.h>
#include <ns3/core-module.h>
#include <ns3/internet-module.h>
#include <ns3/mobility-module.h>
#include <ns3/netanim-module.h>
#include <ns3/wifi-module.h>

using namespace ns3;

int
main(int argc, char* argv[])
{
    uint32_t nNodes = 10;
    double simTime = 30.0;

    LogComponentEnable("FanetCustomRouting", LOG_LEVEL_ALL);
    LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);

    NodeContainer nodes;
    nodes.Create(nNodes);

    MobilityHelper mobility;
    Box areaBounds (0, 300, 0, 300, 0, 100);
    mobility.SetPositionAllocator("ns3::RandomRectanglePositionAllocator",
        "X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=300.0]"),
        "Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=300.0]"));

    mobility.SetMobilityModel("ns3::GaussMarkovMobilityModel",
        "Bounds", BoxValue(areaBounds),
        "TimeStep", TimeValue(Seconds(0.5)),
        "Alpha", DoubleValue(0.85),
        "MeanVelocity", StringValue("ns3::UniformRandomVariable[Min=10.0|Max=30.0]"),
        "MeanDirection", StringValue("ns3::UniformRandomVariable[Min=0|Max=6.28]"),
        "MeanPitch", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=0.0]"));
    mobility.Install(nodes);

    WifiHelper wifi;
    YansWifiPhyHelper phy;
    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    channel.AddPropagationLoss("ns3::FriisPropagationLossModel",
                               "Frequency",
                               DoubleValue(2.4e9),
                               "SystemLoss",
                               DoubleValue(1));
    phy.SetChannel(channel.Create());
    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");
    NetDeviceContainer devices = wifi.Install(phy, mac, nodes);

    FanetRoutingHelper fanetHelper;
    InternetStackHelper internet;
    internet.SetRoutingHelper(fanetHelper);
    internet.Install(nodes);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = ipv4.Assign(devices);

    uint16_t port = 9;
    UdpEchoServerHelper echoServer(port);
    ApplicationContainer serverApps;
    serverApps.Add(echoServer.Install(nodes.Get(1)));
    serverApps.Add(echoServer.Install(nodes.Get(2)));
    serverApps.Start(Seconds(0.4));
    serverApps.Stop(Seconds(5.0));

    for (uint32_t i = 0; i < 3; ++i) {
        UdpEchoClientHelper client(interfaces.GetAddress(nNodes - 1), port);
        client.SetAttribute("MaxPackets", UintegerValue(1000));
        client.SetAttribute("Interval", TimeValue(Seconds(0.2)));
        client.SetAttribute("PacketSize", UintegerValue(512));

        ApplicationContainer clientApp = client.Install(nodes.Get(i));
        clientApp.Start(Seconds(2.0 + i));
        clientApp.Stop(Seconds(simTime));
    }

    AnimationInterface anim("xml/fanet-custom.xml");
    Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper>(&std::cout);

    for (double t = 1.0; t < simTime; t += 5.0) {
        fanetHelper.PrintRoutingTableAllAt(Seconds(t), routingStream);
    }

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();
    return 0;
}
