#ifndef QBR_ROUTING_TABLE_H
#define QBR_ROUTING_TABLE_H

/**
 * @file qbr-routing-table.h
 * @brief Owns the QBR routing table data and all entry-level operations.
 *
 * Any translation unit that only needs to query or modify routes should
 * include only this header — it has no dependency on the send/recv pipeline
 * or on tuple management.
 *
 * Members migrated from RoutingProtocol (qbr-message-handler.h):
 *   Data:    m_table, m_hnaRoutingTable, m_routingTableAssociation
 *   Methods: Clear, GetSize, AddEntry (×2), RemoveEntry, Lookup,
 *            FindSendEntry, GetRoutingTableEntries, SetRoutingTableAssociation,
 *            GetRoutingTableAssociation, PrintRoutingTable (query helper),
 *            RoutingTableComputation
 */

#include "qbr-header.h"
#include "qbr-state.h"

#include "ns3/ipv4-address.h"
#include "ns3/ipv4-static-routing.h"
#include "ns3/ipv4.h"
#include "ns3/output-stream-wrapper.h"

#include <map>
#include <vector>

namespace ns3
{
namespace qbr
{

/// @ingroup qbr
/// A single entry in the QBR routing table.
struct RoutingTableEntry
{
    Ipv4Address destAddr; //!< Address of the destination node.
    Ipv4Address nextAddr; //!< Address of the next hop.
    uint32_t    interface; //!< Interface index.
    uint32_t    distance;  //!< Distance in hops to the destination.

    RoutingTableEntry()
        : destAddr(),
          nextAddr(),
          interface(0),
          distance(0)
    {
    }
};

/**
 * @ingroup qbr
 * @brief Encapsulates the QBR routing table and all entry-level operations.
 *
 * RoutingProtocol inherits (or composes) this class. Keeping these members
 * together means route-lookup code never has to pull in the full protocol
 * header with its socket and timer dependencies.
 */
class RoutingTable
{
  public:
    // ------------------------------------------------------------------ //
    //  Construction / lifecycle
    // ------------------------------------------------------------------ //
    RoutingTable()  = default;
    ~RoutingTable() = default;

    // ------------------------------------------------------------------ //
    //  Wiring helpers — called by RoutingProtocol
    // ------------------------------------------------------------------ //

    /**
     * @brief Provides the Ipv4 object needed by the interface-address overload of AddEntry.
     * @param ipv4 The Ipv4 object of this node.
     */
    void SetIpv4(Ptr<Ipv4> ipv4) { m_ipv4 = ipv4; }

    /**
     * @brief Provides the HNA routing table so GetRoutingTableAssociation() can return it.
     * @param hna The Ipv4StaticRouting table used for HNA routes.
     */
    void SetHnaRoutingTable(Ptr<Ipv4StaticRouting> hna) { m_hnaRoutingTable = hna; }

    /**
     * @brief Returns the HNA routing table (non-const) for direct mutation
     *        during RoutingTableComputation (clear-and-rebuild pattern).
     * @return A smart pointer to the HNA Ipv4StaticRouting table.
     */
    Ptr<Ipv4StaticRouting> GetHnaRoutingTable() { return m_hnaRoutingTable; }

    /**
     * @brief Returns the HNA routing table (const) for read-only access
     *        (e.g. RouteOutput fallback, PrintRoutingTable).
     * @return A const smart pointer to the HNA Ipv4StaticRouting table.
     */
    Ptr<const Ipv4StaticRouting> GetHnaRoutingTableConst() const { return m_hnaRoutingTable; }

    /**
     * @brief Stores the user-supplied Ipv4StaticRouting association table and
     *        returns the old one (may be null) so the caller can remove stale
     *        HNA entries before adding new ones.
     *
     * @param routingTable The new association table.
     * @return The previously stored association table (or null).
     */
    Ptr<Ipv4StaticRouting> SwapRoutingTableAssociation(Ptr<Ipv4StaticRouting> routingTable)
    {
        Ptr<Ipv4StaticRouting> old = m_routingTableAssociation;
        m_routingTableAssociation  = routingTable;
        return old;
    }

    /**
     * @brief Returns the current routing-table association (const).
     * @return A const pointer to the association table, or null.
     */
    Ptr<const Ipv4StaticRouting> GetRoutingTableAssociationRaw() const
    {
        return m_routingTableAssociation;
    }

    /**
     * @brief Nulls out both internal Ipv4StaticRouting pointers.
     *
     * Called from RoutingProtocol::DoDispose() to break reference cycles.
     */
    void DisposeStaticRoutes()
    {
        m_hnaRoutingTable         = nullptr;
        m_routingTableAssociation = nullptr;
    }

    /**
     * @brief Returns a const reference to the raw routing map.
     *
     * Intended for use by RoutingProtocol when iterating the table for
     * logging (Dump, RouteInput debug output) without copying all entries.
     *
     * @return Const reference to the internal destination → entry map.
     */
    const std::map<Ipv4Address, RoutingTableEntry>& GetTableRef() const { return m_table; }

    // ------------------------------------------------------------------ //
    //  Association with an Ipv4StaticRouting table (HNA)
    // ------------------------------------------------------------------ //

    /**
     * @brief Associates an Ipv4StaticRouting instance for HNA advertisements.
     *
     * Entries from the associated table that use non-QBR outgoing interfaces
     * are injected into the local HNA association list.  Calling this method
     * again replaces the previous association.
     *
     * @param routingTable The Ipv4StaticRouting table to associate.
     */
    void SetRoutingTableAssociation(Ptr<Ipv4StaticRouting> routingTable);

    /**
     * @brief Returns the currently associated HNA routing table.
     * @return A const smart pointer to the associated Ipv4StaticRouting table,
     *         or null if none has been set.
     */
    Ptr<const Ipv4StaticRouting> GetRoutingTableAssociation() const;

    // ------------------------------------------------------------------ //
    //  Table-level operations
    // ------------------------------------------------------------------ //

    /**
     * @brief Clears the routing table, releasing all entries.
     */
    void Clear();

    /**
     * @brief Returns the number of entries currently in the routing table.
     * @return Routing table size.
     */
    uint32_t GetSize() const
    {
        return m_table.size();
    }

    /**
     * @brief Returns a snapshot of all routing table entries.
     * @return Vector of RoutingTableEntry.
     */
    std::vector<RoutingTableEntry> GetEntries() const;

    // ------------------------------------------------------------------ //
    //  Entry-level operations
    // ------------------------------------------------------------------ //

    /**
     * @brief Adds (or replaces) an entry identified by interface index.
     *
     * If an entry for @p dest already exists it is deleted first.
     *
     * @param dest      Destination address.
     * @param next      Next-hop address.
     * @param interface Interface index of the outgoing interface.
     * @param distance  Hop distance to the destination.
     */
    void AddEntry(const Ipv4Address& dest,
                  const Ipv4Address& next,
                  uint32_t           interface,
                  uint32_t           distance);

    /**
     * @brief Adds (or throws on collision) an entry identified by interface address.
     *
     * If an entry for @p dest already exists an error is raised.
     *
     * @param dest             Destination address.
     * @param next             Next-hop address.
     * @param interfaceAddress IPv4 address of the outgoing interface.
     * @param distance         Hop distance to the destination.
     */
    void AddEntry(const Ipv4Address& dest,
                  const Ipv4Address& next,
                  const Ipv4Address& interfaceAddress,
                  uint32_t           distance);

    /**
     * @brief Removes the entry for the given destination.
     * @param dest Destination address whose entry should be removed.
     */
    void RemoveEntry(const Ipv4Address& dest);

    /**
     * @brief Looks up the entry for a given destination address.
     *
     * @param[in]  dest     Destination address to look up.
     * @param[out] outEntry Populated with the matching entry when found.
     * @return true if an entry was found, false otherwise.
     */
    bool Lookup(const Ipv4Address& dest, RoutingTableEntry& outEntry) const;

    /**
     * @brief Resolves the next-hop neighbor entry for forwarding a packet.
     *
     * Given a routing entry whose next-hop may itself not be a direct
     * neighbor, this method walks the table recursively until it finds a
     * neighbor entry that can be used for actual packet transmission.
     *
     * Example: table = [A→B, B→C, C→C].  FindSendEntry([A→B]) returns
     * [C→C] because C is the directly reachable neighbor.
     *
     * @param[in]  entry    The routing entry for the intended destination.
     * @param[out] outEntry The resolved neighbor routing entry.
     * @return true if a suitable entry was found, false otherwise.
     */
    bool FindSendEntry(const RoutingTableEntry& entry,
                       RoutingTableEntry&        outEntry) const;

    /**
     * @brief Prints the routing table to the given output stream.
     * @param stream The output stream wrapper.
     * @param unit   Time unit to use for expiry fields (default: seconds).
     */
    void Print(Ptr<OutputStreamWrapper> stream,
               Time::Unit               unit = Time::S) const;

  private:
    // ------------------------------------------------------------------ //
    //  Data members
    // ------------------------------------------------------------------ //

    /// The main routing table: destination address → entry.
    std::map<Ipv4Address, RoutingTableEntry> m_table;

    /// Routing table used exclusively for HNA (Host and Network Association) routes.
    Ptr<Ipv4StaticRouting> m_hnaRoutingTable;

    /// Static routing table whose non-QBR routes are advertised via HNA messages.
    Ptr<Ipv4StaticRouting> m_routingTableAssociation;

    /// Ipv4 object — needed by the interface-address overload of AddEntry.
    Ptr<Ipv4> m_ipv4;
};

} // namespace qbr
} // namespace ns3

#endif /* QBR_ROUTING_TABLE_H */