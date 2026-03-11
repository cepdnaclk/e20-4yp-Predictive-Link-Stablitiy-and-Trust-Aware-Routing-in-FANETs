#ifndef FANET_STATE_H
#define FANET_STATE_H

#include "FanetRepositories.h"
#include <ns3/ipv4-address.h>
#include <ns3/simulator.h>
#include <map>
#include <set>
#include <vector>
#include <cstdint>

namespace ns3 {

/// Manages the state of the FANET protocol including neighbors, topology, routing table, and link metrics
class FanetState
{
  public:
    FanetState();
    virtual ~FanetState();

    // =====================
    // Neighbor Management
    // =====================
    void AddNeighbor(Ipv4Address neighborIp, uint32_t interface);
    void UpdateNeighborLastSeen(Ipv4Address neighborIp);
    void RemoveNeighbor(Ipv4Address neighborIp);
    bool IsNeighbor(Ipv4Address addr) const;
    std::map<Ipv4Address, NeighborInfo>& GetNeighbors();
    const std::map<Ipv4Address, NeighborInfo>& GetNeighbors() const;

    // =====================
    // Topology Management
    // =====================
    void AddTopologyEntry(Ipv4Address origin, const std::vector<Ipv4Address>& neighbors);
    void RemoveTopologyEntry(Ipv4Address origin);
    bool IsTopologyEntry(Ipv4Address origin) const;
    std::map<Ipv4Address, TopologyEntry>& GetTopology();
    const std::map<Ipv4Address, TopologyEntry>& GetTopology() const;

    // =====================
    // Routing Table Management
    // =====================
    void AddRoute(Ipv4Address dest, Ipv4Address nextHop, uint32_t interface);
    void RemoveRoute(Ipv4Address dest);
    void ClearRoutingTable();
    bool HasRoute(Ipv4Address dest) const;
    const RouteEntry* GetRoute(Ipv4Address dest) const;
    std::map<Ipv4Address, RouteEntry>& GetRoutingTable();
    const std::map<Ipv4Address, RouteEntry>& GetRoutingTable() const;

    // =====================
    // Link Metrics Management
    // =====================
    LinkMetric& GetLinkMetric(Ipv4Address neighbor);
    const LinkMetric& GetLinkMetric(Ipv4Address neighbor) const;
    bool HasLinkMetric(Ipv4Address neighbor) const;
    void RemoveLinkMetric(Ipv4Address neighbor);
    std::map<Ipv4Address, LinkMetric>& GetAllLinkMetrics();
    const std::map<Ipv4Address, LinkMetric>& GetAllLinkMetrics() const;

    // =====================
    // Interface Management
    // =====================
    void AddInterface(uint32_t ifIndex, Ipv4Address local);
    std::vector<FanetInterface>& GetInterfaces();
    const std::vector<FanetInterface>& GetInterfaces() const;
    void ClearInterfaces();

    // =====================
    // Two-Hop Neighbors
    // =====================
    void SetTwoHopNeighbors(Ipv4Address neighbor, const std::vector<Ipv4Address>& twoHops);
    std::vector<Ipv4Address> GetTwoHopNeighbors(Ipv4Address neighbor) const;
    std::map<Ipv4Address, std::vector<Ipv4Address>>& GetAllTwoHopNeighbors();

    // =====================
    // MPR Management
    // =====================
    void SetMprSet(const std::set<Ipv4Address>& mprSet);
    std::set<Ipv4Address>& GetMprSet();
    const std::set<Ipv4Address>& GetMprSet() const;

    void AddMprSelector(Ipv4Address mprSelector);
    void RemoveMprSelector(Ipv4Address mprSelector);
    std::set<Ipv4Address>& GetMprSelectors();
    const std::set<Ipv4Address>& GetMprSelectors() const;

    // =====================
    // Sequence Number Management
    // =====================
    uint32_t GetNextHelloSeq();
    uint32_t GetNextTcSeq();
    uint32_t GetLastTcSeq(Ipv4Address origin) const;
    void SetLastTcSeq(Ipv4Address origin, uint32_t seq);

    // =====================
    // Q-Learning State
    // =====================
    double GetQValue(Ipv4Address dest, Ipv4Address action);
    void SetQValue(Ipv4Address dest, Ipv4Address action, double value);
    std::map<Ipv4Address, std::map<Ipv4Address, double>>& GetQTable();

  private:
    // Core state data
    std::map<Ipv4Address, NeighborInfo> m_neighborTable;
    std::map<Ipv4Address, TopologyEntry> m_topologyTable;
    std::map<Ipv4Address, RouteEntry> m_routingTable;
    std::map<Ipv4Address, LinkMetric> m_linkMetrics;
    std::vector<FanetInterface> m_interfaces;
    std::map<Ipv4Address, std::vector<Ipv4Address>> m_twoHopNeighbors;
    std::set<Ipv4Address> m_mprSet;
    std::set<Ipv4Address> m_mprSelectors;
    std::map<Ipv4Address, uint32_t> m_lastTcSeq;
    std::map<Ipv4Address, std::map<Ipv4Address, double>> m_qTable;

    uint32_t m_helloSeq;
    uint32_t m_tcSeq;
};

} // namespace ns3

#endif // FANET_STATE_H
