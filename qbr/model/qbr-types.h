#ifndef QBR_TYPES_H
#define QBR_TYPES_H

#include <cstdint>
#include <iostream>

namespace ns3
{
namespace qbr
{

/**
 * Link metric type
 */
enum MetricType
{
    TRUST = 1,
    LINK_QUALITY = 2,
};

/**
 * Link Metric Structure
 */
struct LinkMetric
{
    uint8_t type;   // MetricType enum (TRUST = 1, LINK_QUALITY = 2)
    uint16_t value; // metric value
};

/**
 * @ingroup qbr
 *
 * Willingness for forwarding packets from other nodes.
 * The standard defines the following set of values.
 * Values 0 - 7 are allowed by the standard, but this is not enforced in the code.
 *
 * See \RFC{3626} section 18.8
 */
enum Willingness : uint8_t
{
    NEVER = 0,
    LOW = 1,
    DEFAULT = 3, // medium
    HIGH = 6,
    ALWAYS = 7,
};

/**
 * Stream insertion operator for QBR willingness.
 *
 * @param os Output stream.
 * @param willingness Willingness.
 * @return A reference to the output stream.
 */
inline std::ostream&
operator<<(std::ostream& os, Willingness willingness)
{
    switch (willingness)
    {
    case Willingness::NEVER:
        return (os << "NEVER");
    case Willingness::LOW:
        return (os << "LOW");
    case Willingness::DEFAULT:
        return (os << "DEFAULT");
    case Willingness::HIGH:
        return (os << "HIGH");
    case Willingness::ALWAYS:
        return (os << "ALWAYS");
    default:
        return (os << static_cast<uint32_t>(willingness));
    }
    return os;
}

} // namespace qbr
} // namespace ns3

#endif /* QBR_TYPES_H */