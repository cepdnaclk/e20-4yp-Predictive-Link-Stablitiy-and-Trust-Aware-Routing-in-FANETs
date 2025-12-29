/*
* Score from RSSI and SNR telemetry data - Exporting to CSV
*/

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include <iostream>
#include <fstream> // Required for CSV output
#include <map>
#include <cmath>
#include <algorithm>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("FanetTrustRouting");

// Global file stream for CSV
std::ofstream g_csvFile;

// 1. Improved Q-learning Agent
class QRoutingAgent {
public:
    std::map<uint32_t, std::map<uint32_t, double>> qTable;
    double alpha = 0.2;
    double gamma = 0.8;

    void UpdateQValue(uint32_t current, uint32_t neighbor, double reward) {
        double oldQ = qTable[current][neighbor];
        double maxNextQ = 0.0;
        if (qTable.count(neighbor)) {
            for (auto const& [target, qVal] : qTable[neighbor]) {
                maxNextQ = std::max(maxNextQ, qVal);
            }
        }
        qTable[current][neighbor] = oldQ + alpha * (reward + (gamma * maxNextQ) - oldQ);
    }
};

QRoutingAgent g_rlAgent;

// 2. Telemetry Sniffer with CSV Export
void MonitorPhyRx(std::string context, 
                  Ptr<const Packet> packet, 
                  uint16_t channelFreqMhz, 
                  WifiTxVector txVector, 
                  MpduInfo aMpdu, 
                  SignalNoiseDbm signalNoise, 
                  uint16_t staId) 
{
    double rssi = signalNoise.signal; 
    double snr = signalNoise.signal - signalNoise.noise;
    double timestamp = Simulator::Now().GetSeconds();

    // Extract Node ID from context string
    std::string sub = context.substr(10); 
    uint32_t nodeId = std::stoi(sub.substr(0, sub.find("/")));

    // Trust/Reward Logic
    double reward = (snr > 20.0) ? 1.0 : -1.0;

    // Update Q-Table
    g_rlAgent.UpdateQValue(nodeId, 0, reward);

    // Write data to CSV file
    if (g_csvFile.is_open()) {
        g_csvFile << timestamp << "," 
                  << nodeId << "," 
                  << rssi << "," 
                  << snr << "," 
                  << reward << "," 
                  << g_rlAgent.qTable[nodeId][0] << "\n";
    }

    NS_LOG_UNCOND("Time: " << timestamp << "s | Node " << nodeId << " | RSSI: " << rssi << "dBm | SNR: " << snr 
                  << "dB | Reward: " << reward);
}

int main (int argc, char *argv[]) {
    LogComponentEnable("FanetTrustRouting", LOG_LEVEL_INFO);

    uint32_t nDrones = 10;
    double simTime = 20.0;
    std::string fileName = "fanet_telemetry_results.csv";

    // Initialize CSV File
    g_csvFile.open(fileName);
    if (g_csvFile.is_open()) {
        g_csvFile << "Timestamp,NodeID,RSSI,SNR,Reward,QValue\n";
    } else {
        NS_FATAL_ERROR("Could not open file for writing: " << fileName);
    }

    NodeContainer uavs;
    uavs.Create(nDrones);

    // WiFi Setup
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211n);
    YansWifiPhyHelper phy;
    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    phy.SetChannel(channel.Create());

    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");
    NetDeviceContainer devices = wifi.Install(phy, mac, uavs);

    // Mobility
    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::GaussMarkovMobilityModel",
        "Bounds", BoxValue(Box(-500, 500, -500, 500, 0, 100)), 
        "TimeStep", TimeValue(Seconds(1.0)),
        "Alpha", DoubleValue(0.85),
        "MeanVelocity", StringValue("ns3::UniformRandomVariable[Min=10.0|Max=20.0]"),
        "MeanDirection", StringValue("ns3::UniformRandomVariable[Min=0|Max=6.28]"),
        "MeanPitch", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=0.0]"));
    mobility.Install(uavs);

    // Stack and IP
    InternetStackHelper stack;
    stack.Install(uavs);
    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    // Sniffer Connection
    Config::Connect("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/MonitorSnifferRx", 
                    MakeCallback(&MonitorPhyRx));

    // Application (Drone 9 to Drone 0)
    uint16_t port = 9;
    OnOffHelper onoff("ns3::UdpSocketFactory", Address(InetSocketAddress(interfaces.GetAddress(0), port)));
    onoff.SetConstantRate(DataRate("500kbps"));

    ApplicationContainer apps = onoff.Install(uavs.Get(nDrones - 1));
    apps.Start(Seconds(1.0));
    apps.Stop(Seconds(simTime));

    AnimationInterface anim("fanet_sim.xml");

    std::cout << "Starting FANET Simulation. Results will be saved to " << fileName << "..." << std::endl;
    
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    // Close the file stream
    if (g_csvFile.is_open()) {
        g_csvFile.close();
    }

    std::cout << "\n--- Simulation Complete ---" << std::endl;
    Simulator::Destroy();
    return 0;
}