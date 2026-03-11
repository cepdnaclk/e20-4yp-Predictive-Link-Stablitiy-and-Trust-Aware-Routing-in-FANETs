#ifndef QBR_Q_TABLE_H
#define QBR_Q_TABLE_H

/**
 * @file qbr-q-table.h
 * @brief Tabular Quantile-Regression Q-table used for QR-DQN routing decisions.
 *
 * This module stores the distributional Q-values for state–action pairs
 * using a fixed number of quantiles. It is designed for resource-constrained
 * nodes where neural-network inference is not feasible.
 *
 * State  : destination node address
 * Action : next-hop neighbor address
 * Value  : fixed-size vector of quantile estimates
 */

#include "qbr-repositories.h"
#include "ns3/ipv4-address.h"
#include "ns3/output-stream-wrapper.h"

#include <map>
#include <vector>
#include <array>
#include <set>

namespace ns3
{
namespace qbr
{

/// Number of quantiles used by QR-DQN
static const uint32_t QBR_NUM_QUANTILES = 16;

/**
 * @ingroup qbr
 * @brief Distributional value of a state–action pair.
 */
struct QuantileValue
{
    std::array<double, QBR_NUM_QUANTILES> quantiles;

    QuantileValue()
    {
        quantiles.fill(0.0);
    }
};

/**
 * @ingroup qbr
 * @brief Entry representing a state–action pair in the Q-table.
 */
struct QTableEntry
{
    Ipv4Address state;   //!< Destination (state)
    Ipv4Address action;  //!< Next hop (action)

    QuantileValue value; //!< Quantile distribution

    QTableEntry()
        : state(),
          action(),
          value()
    {
    }
};


/**
 * @ingroup qbr
 * @brief Encapsulates a tabular QR-DQN Q-table.
 *
 * Data layout:
 *
 *   State (destination)
 *        ↓
 *   Action (next hop)
 *        ↓
 *   Quantile distribution
 *
 * The table is implemented as:
 *
 *   map<State, map<Action, QuantileValue>>
 *
 * which allows fast lookup of actions for a given destination.
 */
class QTable
{
  public:

    // --------------------------------------------------------------- //
    // Construction / lifecycle
    // --------------------------------------------------------------- //

    QTable()  = default;
    ~QTable() = default;


    // --------------------------------------------------------------- //
    // Table-level operations
    // --------------------------------------------------------------- //

    /**
     * @brief Clears the entire Q-table.
     */
    void Clear();

    /**
     * @brief Returns the number of stored state entries.
     */
    uint32_t GetStateCount() const;

    /**
     * @brief Returns number of actions stored for a state.
     */
    uint32_t GetActionCount(const Ipv4Address& state) const;

    /**
     * @brief Removes all Q-table actions (columns) whose address is NOT in
     *        @p liveNeighbors.  Called after every topology change so that
     *        stale neighbors can never be selected as a forwarding action.
     *
     * @param liveNeighbors  The current set of reachable symmetric neighbors.
     */
    void RemoveActionsNotIn(const std::set<Ipv4Address>& liveNeighbors);

    // --------------------------------------------------------------- //
    // Entry operations
    // --------------------------------------------------------------- //

    /**
     * @brief Adds or replaces a state–action entry.
     */
    void SetEntry(const Ipv4Address& state,
                  const Ipv4Address& action,
                  const QuantileValue& value);

    /**
     * @brief Retrieves the quantile value for a state–action pair.
     */
    bool GetEntry(const Ipv4Address& state,
                  const Ipv4Address& action,
                  QuantileValue& outValue) const;

    /**
     * @brief Removes a specific state–action entry.
     */
    void RemoveEntry(const Ipv4Address& state,
                     const Ipv4Address& action);


    // --------------------------------------------------------------- //
    // RL helper functions
    // --------------------------------------------------------------- //

    /**
     * @brief Returns the expected Q-value of a state–action pair.
     *
     * Computed as the mean of the quantile distribution.
     */
    double GetExpectedValue(const Ipv4Address& state,
                            const Ipv4Address& action) const;

    /**
     * @brief Returns the best action for a state.
     *
     * Uses expected value of the quantile distribution.
     */
    bool GetBestAction(const Ipv4Address& state,
                       Ipv4Address& bestAction) const;


    /**
     * @brief Returns all available actions for a state.
     */
    std::vector<Ipv4Address> GetActions(const Ipv4Address& state) const;


    // --------------------------------------------------------------- //
    // QR-DQN update operations
    // --------------------------------------------------------------- //

    /**
     * @brief Updates quantiles using a TD target.
     *
     * This function performs a simplified tabular QR-DQN update.
     */
    void UpdateQuantiles(const Ipv4Address& state,
                         const Ipv4Address& action,
                         const std::array<double, QBR_NUM_QUANTILES>& target,
                         double learningRate);


    // --------------------------------------------------------------- //
    // Debug helpers
    // --------------------------------------------------------------- //

    /**
     * @brief Prints the Q-table contents.
     */
    void Print(Ptr<OutputStreamWrapper> stream) const;

    double GetLinkMetricReward(const LinkTuple& link);

    /**
     * @brief Returns internal table reference for iteration.
     */
    const std::map<Ipv4Address,
                   std::map<Ipv4Address, QuantileValue>>& GetTableRef() const
    {
        return m_table;
    }


  private:

    // --------------------------------------------------------------- //
    // Data members
    // --------------------------------------------------------------- //

    /**
     * @brief Core Q-table structure.
     *
     * state -> action -> quantile distribution
     */
    std::map<Ipv4Address,
             std::map<Ipv4Address, QuantileValue>> m_table;
};

} // namespace qbr
} // namespace ns3

#endif /* QBR_Q_TABLE_H */