#pragma once
#include "ns3/ipv4-routing-protocol.h"
#include "ns3/ipv4.h"
#include "ns3/socket.h"
#include "ns3/timer.h"
#include "ns3/traced-callback.h"
#include "ns3/ipv4-address.h"
#include <map>
#include <set>
#include <vector>

namespace ns3 {

struct NeighborInfo
{
  uint32_t interface = 0;
  Time lastSeen = Seconds(0);
};

struct TopologyEntry
{
  Ipv4Address origin;
  std::vector<Ipv4Address> neighbors;
  Time lastUpdate;
};

struct RouteEntry
{
  Ipv4Address destination;
  Ipv4Address nextHop;
  uint32_t interface = 0;
};

class FanetRlTrust;    // forward decl
class FanetRlMetrics;  // forward decl
class FanetRlRlIface;  // forward decl (Python bridge)

class FanetRlRoutingProtocol : public Ipv4RoutingProtocol
{
public:
  static TypeId GetTypeId();
  FanetRlRoutingProtocol();
  ~FanetRlRoutingProtocol() override;

  // Ipv4RoutingProtocol
  void SetIpv4(Ptr<Ipv4> ipv4) override;
  Ptr<Ipv4Route> RouteOutput(Ptr<Packet> p, const Ipv4Header& header,
                             Ptr<NetDevice> oif, Socket::SocketErrno& sockerr) override;

  bool RouteInput(Ptr<const Packet> p, const Ipv4Header& header, Ptr<const NetDevice> idev,
                  const UnicastForwardCallback& ucb, const MulticastForwardCallback& mcb,
                  const LocalDeliverCallback& lcb, const ErrorCallback& ecb) override;

  void NotifyInterfaceUp(uint32_t interface) override {}
  void NotifyInterfaceDown(uint32_t interface) override {}
  void NotifyAddAddress(uint32_t interface, Ipv4InterfaceAddress address) override {}
  void NotifyRemoveAddress(uint32_t interface, Ipv4InterfaceAddress address) override {}
  void PrintRoutingTable(Ptr<OutputStreamWrapper> stream, Time::Unit unit) const override;

private:
  // sockets + control plane
  void InitializeInterfaces();
  void ReceiveControl(Ptr<Socket> socket);
  void ProcessControl(Ptr<Packet> p, Ipv4Address sender, uint32_t incomingIface);
  void SendHello();
  void SendTc();
  void ExpireNeighbors();
  void UpdateRoutingTable();

  // route helpers
  Ptr<Ipv4Route> Lookup(Ipv4Address dest) const;
  Ipv4Address SelectNextHopRl(Ipv4Address dest);     // RL action selection among safe candidates
  Ipv4Address SelectNextHopFallback(Ipv4Address dest); // metric-based fallback

  // RL reward hooks
  void OnForwarded(Ipv4Address dest, Ipv4Address nextHop, bool success, Time delay);

private:
  Ptr<Ipv4> m_ipv4;
  Ptr<Socket> m_recvSocket;
  std::map<Ptr<Socket>, Ipv4InterfaceAddress> m_sendSockets;

  std::map<Ipv4Address, NeighborInfo>  m_neighborTable;
  std::map<Ipv4Address, TopologyEntry> m_topologyTable;
  std::map<Ipv4Address, RouteEntry>    m_routingTable;
  std::map<Ipv4Address, uint32_t>      m_lastTcSeq;

  uint32_t m_helloSeq = 0;
  uint32_t m_tcSeq = 0;

  // Trust + metrics engines (separate classes)
  Ptr<FanetRlTrust>   m_trust;
  Ptr<FanetRlMetrics> m_metrics;

  // Python bridge
  Ptr<FanetRlRlIface> m_rl;
};

} // namespace ns3
