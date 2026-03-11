///
/// @file qbr-q-table.cc
/// @brief Implementation of QTable — owns the tabular QR-DQN state–action
///        quantile values and all related operations.
///
/// Methods implemented:
///   Clear, GetStateCount, GetActionCount,
///   SetEntry, GetEntry, RemoveEntry,
///   GetExpectedValue, GetBestAction, GetActions,
///   UpdateQuantiles, Print
///

#include "qbr-q-table.h"
#include "qbr-repositories.h"

#include "ns3/assert.h"
#include "ns3/log.h"

#include <iomanip>
#include <sstream>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QbrQTable");

namespace qbr
{

// -----------------------------------------------------------------------
// Table-level operations
// -----------------------------------------------------------------------

void
QTable::Clear()
{
    NS_LOG_FUNCTION_NOARGS();
    m_table.clear();
}

uint32_t
QTable::GetStateCount() const
{
    return m_table.size();
}

uint32_t
QTable::GetActionCount(const Ipv4Address& state) const
{
    auto it = m_table.find(state);
    if (it == m_table.end())
    {
        return 0;
    }
    return it->second.size();
}

// -----------------------------------------------------------------------
// Entry operations
// -----------------------------------------------------------------------

void
QTable::SetEntry(const Ipv4Address& state,
                 const Ipv4Address& action,
                 const QuantileValue& value)
{
    NS_LOG_FUNCTION(state << action);
    m_table[state][action] = value;
}

bool
QTable::GetEntry(const Ipv4Address& state,
                 const Ipv4Address& action,
                 QuantileValue& outValue) const
{
    auto s = m_table.find(state);
    if (s == m_table.end())
    {
        return false;
    }

    auto a = s->second.find(action);
    if (a == s->second.end())
    {
        return false;
    }

    outValue = a->second;
    return true;
}

void
QTable::RemoveEntry(const Ipv4Address& state,
                    const Ipv4Address& action)
{
    NS_LOG_FUNCTION(state << action);

    auto s = m_table.find(state);
    if (s == m_table.end())
    {
        return;
    }

    s->second.erase(action);

    if (s->second.empty())
    {
        m_table.erase(s);
    }
}

// -----------------------------------------------------------------------
// RL helper functions
// -----------------------------------------------------------------------

double
QTable::GetExpectedValue(const Ipv4Address& state,
                         const Ipv4Address& action) const
{
    auto s = m_table.find(state);
    if (s == m_table.end())
    {
        return 0.0;
    }

    auto a = s->second.find(action);
    if (a == s->second.end())
    {
        return 0.0;
    }

    const auto& q = a->second.quantiles;

    double sum = 0.0;
    for (uint32_t i = 0; i < QBR_NUM_QUANTILES; ++i)
    {
        sum += q[i];
    }

    return sum / QBR_NUM_QUANTILES;
}

bool
QTable::GetBestAction(const Ipv4Address& state,
                      Ipv4Address& bestAction) const
{
    auto s = m_table.find(state);
    if (s == m_table.end())
    {
        return false;
    }

    double bestValue = -std::numeric_limits<double>::infinity();
    bool found = false;

    for (const auto& kv : s->second)
    {
        double value = 0.0;
        const auto& q = kv.second.quantiles;

        for (uint32_t i = 0; i < QBR_NUM_QUANTILES; ++i)
        {
            value += q[i];
        }

        value /= QBR_NUM_QUANTILES;

        if (!found || value > bestValue)
        {
            bestValue = value;
            bestAction = kv.first;
            found = true;
        }
    }

    return found;
}

std::vector<Ipv4Address>
QTable::GetActions(const Ipv4Address& state) const
{
    std::vector<Ipv4Address> actions;

    auto s = m_table.find(state);
    if (s == m_table.end())
    {
        return actions;
    }

    actions.reserve(s->second.size());

    for (const auto& kv : s->second)
    {
        actions.push_back(kv.first);
    }

    return actions;
}

void
QTable::RemoveActionsNotIn(const std::set<Ipv4Address>& liveNeighbors)
{
    // Iterate over every (state → action-map) pair in the table.
    // For each action-map, erase entries whose action address is not in
    // liveNeighbors.
    for (auto& [state, actionMap] : m_table)
    {
        for (auto it = actionMap.begin(); it != actionMap.end();)
        {
            if (liveNeighbors.count(it->first) == 0)
            {
                it = actionMap.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }
}

// -----------------------------------------------------------------------
// QR-DQN update
// -----------------------------------------------------------------------

void
QTable::UpdateQuantiles(const Ipv4Address& state,
                        const Ipv4Address& action,
                        const std::array<double, QBR_NUM_QUANTILES>& target,
                        double learningRate)
{
    NS_LOG_FUNCTION(state << action << learningRate);

    auto s = m_table.find(state);
    if (s == m_table.end())
    {
        return;
    }

    auto a = s->second.find(action);
    if (a == s->second.end())
    {
        return;
    }

    auto& quantiles = a->second.quantiles;

    for (uint32_t i = 0; i < QBR_NUM_QUANTILES; ++i)
    {
        double tdError = target[i] - quantiles[i];
        quantiles[i] += learningRate * tdError;
    }
}

// -----------------------------------------------------------------------
// Printing
// -----------------------------------------------------------------------

void
QTable::Print(Ptr<OutputStreamWrapper> stream) const
{
    std::ostream* os = stream->GetStream();

    std::ios savedState(nullptr);
    savedState.copyfmt(*os);

    *os << std::resetiosflags(std::ios::adjustfield)
        << std::setiosflags(std::ios::left);

    *os << std::setw(16) << "State"
        << std::setw(16) << "Action"
        << "ExpectedQ"
        << std::endl;

    for (const auto& statePair : m_table)
    {
        for (const auto& actionPair : statePair.second)
        {
            std::ostringstream state;
            std::ostringstream action;

            state << statePair.first;
            action << actionPair.first;

            const auto& q = actionPair.second.quantiles;

            double mean = 0.0;
            for (uint32_t i = 0; i < QBR_NUM_QUANTILES; ++i)
            {
                mean += q[i];
            }

            mean /= QBR_NUM_QUANTILES;

            *os << std::setw(16) << state.str()
                << std::setw(16) << action.str()
                << mean
                << std::endl;
        }
    }

    *os << std::endl;

    (*os).copyfmt(savedState);
}

double 
QTable::GetLinkMetricReward(const LinkTuple& link)
{
    double reward = 0.0;

    for (const auto& metric : link.metrics)
    {
        switch (metric.type)
        {
            case TRUST:           // example: type 0
                reward += metric.value / 255.0;  // normalize 0-255 -> 0-1
                break;
            case LINK_QUALITY:    // example: type 1
                reward += metric.value / 255.0;
                break;
            default:
                break; // ignore unknown types
        }
    }

    // Average if multiple metrics
    if (!link.metrics.empty())
    {
        reward /= static_cast<double>(link.metrics.size());
    }

    return reward;
}

} // namespace qbr
} // namespace ns3