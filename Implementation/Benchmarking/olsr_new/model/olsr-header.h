/*
 * Copyright (c) 2007 INESC Porto
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Gustavo J. A. M. Carneiro  <gjc@inescporto.pt>
 */

#ifndef OLSR_HEADER_H
#define OLSR_HEADER_H

#include "olsr-repositories.h"

#include "ns3/header.h"
#include "ns3/ipv4-address.h"
#include "ns3/nstime.h"
#include "ns3/vector.h"

#include <stdint.h>
#include <vector>

namespace ns3
{
namespace olsr
{

double EmfToSeconds(uint8_t emf);
uint8_t SecondsToEmf(double seconds);

/**
 * \ingroup olsr
 *
 * The basic layout of any packet in OLSR is as follows (omitting IP and
 * UDP headers):
  \verbatim
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Packet Length         |    Packet Sequence Number     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Message Type |     Vtime     |         Message Size          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Originator Address                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time To Live |   Hop Count   |    Message Sequence Number    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   :                            MESSAGE                            :
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Message Type |     Vtime     |         Message Size          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Originator Address                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time To Live |   Hop Count   |    Message Sequence Number    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   :                            MESSAGE                            :
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   :                                                               :
            (etc.)
  \endverbatim
  *
  * This header only holds the common part of a message group, i.e.,
  * the first 4 bytes.
  */
class PacketHeader : public Header
{
  public:
    PacketHeader();
    ~PacketHeader() override;

    /**
     * Set the packet total length.
     * \param length The packet length.
     */
    void SetPacketLength(uint16_t length)
    {
        m_packetLength = length;
    }

    /**
     * Get the packet total length.
     * \return The packet length.
     */
    uint16_t GetPacketLength() const
    {
        return m_packetLength;
    }

    /**
     * Set the packet sequence number.
     * \param seqnum The packet sequence number.
     */
    void SetPacketSequenceNumber(uint16_t seqnum)
    {
        m_packetSequenceNumber = seqnum;
    }

    /**
     * Get the packet sequence number.
     * \returns The packet sequence number.
     */
    uint16_t GetPacketSequenceNumber() const
    {
        return m_packetSequenceNumber;
    }

  private:
    uint16_t m_packetLength;         //!< The packet length.
    uint16_t m_packetSequenceNumber; //!< The packet sequence number.

  public:
    /**
     * \brief Get the type ID.
     * \return The object TypeId.
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    void Print(std::ostream& os) const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;
};

/**
 * \ingroup olsr
 *
 * This header can store HELP, TC, MID and HNA messages.
 * The header size is variable, and depends on the
 * actual message type.
 *
  \verbatim
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Message Type |     Vtime     |         Message Size          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Originator Address                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time To Live |   Hop Count   |    Message Sequence Number    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   :                            MESSAGE                            :
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  \endverbatim
 */
class MessageHeader : public Header
{
  public:
    /**
     * Message type
     */
    enum MessageType
    {
        HELLO_MESSAGE = 1,
        TC_MESSAGE = 2,
        MID_MESSAGE = 3,
        HNA_MESSAGE = 4,
    };

    MessageHeader();
    ~MessageHeader() override;

    /**
     * Set the message type.
     * \param messageType The message type.
     */
    void SetMessageType(MessageType messageType)
    {
        m_messageType = messageType;
    }

    /**
     * Get the message type.
     * \return The message type.
     */
    MessageType GetMessageType() const
    {
        return m_messageType;
    }

    /**
     * Set the validity time.
     * \param time The validity time.
     */
    void SetVTime(Time time)
    {
        m_vTime = SecondsToEmf(time.GetSeconds());
    }

    /**
     * Get the validity time.
     * \return The validity time.
     */
    Time GetVTime() const
    {
        return Seconds(EmfToSeconds(m_vTime));
    }

    /**
     * Set the originator address.
     * \param originatorAddress The originator address.
     */
    void SetOriginatorAddress(Ipv4Address originatorAddress)
    {
        m_originatorAddress = originatorAddress;
    }

    /**
     * Get the originator address.
     * \return The originator address.
     */
    Ipv4Address GetOriginatorAddress() const
    {
        return m_originatorAddress;
    }

    /**
     * Set the time to live.
     * \param timeToLive The time to live.
     */
    void SetTimeToLive(uint8_t timeToLive)
    {
        m_timeToLive = timeToLive;
    }

    /**
     * Get the time to live.
     * \return The time to live.
     */
    uint8_t GetTimeToLive() const
    {
        return m_timeToLive;
    }

    /**
     * Set the hop count.
     * \param hopCount The hop count.
     */
    void SetHopCount(uint8_t hopCount)
    {
        m_hopCount = hopCount;
    }

    /**
     * Get the hop count.
     * \return The hop count.
     */
    uint8_t GetHopCount() const
    {
        return m_hopCount;
    }

    /**
     * Set the message sequence number.
     * \param messageSequenceNumber The message sequence number.
     */
    void SetMessageSequenceNumber(uint16_t messageSequenceNumber)
    {
        m_messageSequenceNumber = messageSequenceNumber;
    }

    /**
     * Get the message sequence number.
     * \return The message sequence number.
     */
    uint16_t GetMessageSequenceNumber() const
    {
        return m_messageSequenceNumber;
    }

  private:
    MessageType m_messageType;        //!< The message type
    uint8_t m_vTime;                  //!< The validity time.
    Ipv4Address m_originatorAddress;  //!< The originator address.
    uint8_t m_timeToLive;             //!< The time to live.
    uint8_t m_hopCount;               //!< The hop count.
    uint16_t m_messageSequenceNumber; //!< The message sequence number.
    uint16_t m_messageSize;           //!< The message size.

  public:
    /**
     * \brief Get the type ID.
     * \return The object TypeId.
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    void Print(std::ostream& os) const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;

    /**
     * \ingroup olsr
     * MID Message Format
     *
    \verbatim
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                    OLSR Interface Address                     |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                    OLSR Interface Address                     |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                              ...                              |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    \endverbatim
    */
    struct Mid
    {
        std::vector<Ipv4Address> interfaceAddresses; //!< Interface Address container.
        /**
         * This method is used to print the content of a MID message.
         * \param os output stream
         */
        void Print(std::ostream& os) const;
        /**
         * Returns the expected size of the header.
         * \returns the expected size of the header.
         */
        uint32_t GetSerializedSize() const;
        /**
         * This method is used by Packet::AddHeader to
         * store a header into the byte buffer of a packet.
         *
         * \param start an iterator which points to where the header should
         *        be written.
         */
        void Serialize(Buffer::Iterator start) const;
        /**
         * This method is used by Packet::RemoveHeader to
         * re-create a header from the byte buffer of a packet.
         *
         * \param start an iterator which points to where the header should
         *        read from.
         * \param messageSize the message size.
         * \returns the number of bytes read.
         */
        uint32_t Deserialize(Buffer::Iterator start, uint32_t messageSize);
    };

    /**
     * \ingroup olsr
     * HELLO Message Format
     *
    \verbatim
      0               1               2               3    
      0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7

     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |          Altitude             |    Htime       |  Willingness |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                            Latitude                           |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                            Longitude                          |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Link Code   |   Reserved    |       Link Message Size       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                  Neighbor Interface Address                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  φ(η′)        |    ρ(η′)      |      vi,j′ℓ(rel. speed)       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                  Neighbor Interface Address                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  φ(η′′)       |    ρ(η′′)     |      vi,j′′ℓ(rel. speed)      |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     :                             .  .  .                           :
     :                                                               :
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Link Code   |   Reserved    |       Link Message Size       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                  Neighbor Interface Address                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                  Neighbor Interface Address                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     :                                                               :
       (etc.)
    \endverbatim
    */
    struct Hello
    {
        /**
         * Link message item
         */
        uint8_t hTime; //!< HELLO emission interval (coded)

        // --- P-OLSR FIELDS ---
        float latitude;  // 4 bytes 
        float longitude; // 4 bytes 
        uint16_t altitude; // 2 bytes
        
        // Velocity Vector (Required for your GetSpeedWeight logic)
        float velX;
        float velY;
        float velZ;
        
        // Flag to tell the system this data is valid
        bool hasMobilityData = false; 

        // --- Helper Methods called by olsr-routing-protocol.cc ---
        
        void SetPosition(Vector pos) {
            latitude = pos.x;
            longitude = pos.y;
            altitude = static_cast<uint16_t>(pos.z);
            hasMobilityData = true;
        }

        Vector GetPosition() const {
            return Vector(latitude, longitude, altitude);
        }

        void SetVelocity(Vector vel) {
            velX = vel.x;
            velY = vel.y;
            velZ = vel.z;
            hasMobilityData = true;
        }

        Vector GetVelocity() const {
            return Vector(velX, velY, velZ);
        }
        // -----------------------

        struct LinkMessage
        {
            uint8_t linkCode;
            uint8_t reserved;
            uint16_t messageSize;
            
            struct Neighbor
            {
                Ipv4Address address;
                // P-OLSR fields for link quality 
                uint8_t lq; // Link Quality (phi)
                uint8_t nlq; // Neighbor Link Quality (rho)
                uint16_t weight; // 2 bytes for averaged relative speed 
            };
            std::vector<Neighbor> neighbors;    
        };
        std::vector<LinkMessage> linkMessages;

        

        /**
         * Set the HELLO emission interval.
         * \param time The HELLO emission interval.
         */
        void SetHTime(Time time)
        {
            this->hTime = SecondsToEmf(time.GetSeconds());
        }

        /**
         * Get the HELLO emission interval.
         * \return The HELLO emission interval.
         */
        Time GetHTime() const
        {
            return Seconds(EmfToSeconds(this->hTime));
        }

        Willingness willingness; //!< The willingness of a node to carry and forward traffic for
                                 //!< other nodes.
         //!< Link messages container.

        /**
         * This method is used to print the content of a Hello message.
         * \param os output stream
         */
        void Print(std::ostream& os) const;
        /**
         * Returns the expected size of the header.
         * \returns the expected size of the header.
         */
        uint32_t GetSerializedSize() const;
        /**
         * This method is used by Packet::AddHeader to
         * store a header into the byte buffer of a packet.
         *
         * \param start an iterator which points to where the header should
         *        be written.
         */
        void Serialize(Buffer::Iterator start) const;
        /**
         * This method is used by Packet::RemoveHeader to
         * re-create a header from the byte buffer of a packet.
         *
         * \param start an iterator which points to where the header should
         *        read from.
         * \param messageSize the message size.
         * \returns the number of bytes read.
         */
        uint32_t Deserialize(Buffer::Iterator start, uint32_t messageSize);
    };

    /**
     * \ingroup olsr
     * TC Message Format
     *
     \verbatim
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |              ANSN             |           Reserved            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |               Advertised Neighbor Main Address                |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |               Advertised Neighbor Main Address                |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                              ...                              |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     \endverbatim
     */
    struct Tc
    {
        uint16_t ansn;                              //!< Advertised Neighbor Sequence Number.
        uint16_t reserved;

        struct Neighbor
        {
            Ipv4Address address;
            // Added relative speed in TC messages [cite: 126]
            uint16_t reserved;    // Padding
            uint16_t weight;      // P-OLSR Weight or Relative Speed
        };
        std::vector<Neighbor> neighbors; //!< Neighbor list including weights

        /**
         * This method is used to print the content of a Tc message.
         * \param os output stream
         */
        void Print(std::ostream& os) const;
        /**
         * Returns the expected size of the header.
         * \returns the expected size of the header.
         */
        uint32_t GetSerializedSize() const;
        /**
         * This method is used by Packet::AddHeader to
         * store a header into the byte buffer of a packet.
         *
         * \param start an iterator which points to where the header should
         *        be written.
         */
        void Serialize(Buffer::Iterator start) const;
        /**
         * This method is used by Packet::RemoveHeader to
         * re-create a header from the byte buffer of a packet.
         *
         * \param start an iterator which points to where the header should
         *        read from.
         * \param messageSize the message size.
         * \returns the number of bytes read.
         */
        uint32_t Deserialize(Buffer::Iterator start, uint32_t messageSize);
    };

    /**
     * \ingroup olsr
     * HNA (Host Network Association) Message Format
     *
     \verbatim
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Network Address                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                             Netmask                           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Network Address                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                             Netmask                           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                              ...                              |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     \endverbatim
     */
    struct Hna
    {
        /**
         * Association item structure.
         */
        struct Association
        {
            Ipv4Address address; //!< IPv4 Address.
            Ipv4Mask mask;       //!< IPv4 netmask.
        };

        std::vector<Association> associations; //!< Association container.

        /**
         * This method is used to print the content of a Hna message.
         * \param os output stream
         */
        void Print(std::ostream& os) const;
        /**
         * Returns the expected size of the header.
         * \returns the expected size of the header.
         */
        uint32_t GetSerializedSize() const;
        /**
         * This method is used by Packet::AddHeader to
         * store a header into the byte buffer of a packet.
         *
         * \param start an iterator which points to where the header should
         *        be written.
         */
        void Serialize(Buffer::Iterator start) const;
        /**
         * This method is used by Packet::RemoveHeader to
         * re-create a header from the byte buffer of a packet.
         *
         * \param start an iterator which points to where the header should
         *        read from.
         * \param messageSize the message size.
         * \returns the number of bytes read.
         */
        uint32_t Deserialize(Buffer::Iterator start, uint32_t messageSize);
    };

  private:
    /**
     * Structure holding the message content.
     */
    struct
    {
        Mid mid;     //!< MID message (optional).
        Hello hello; //!< HELLO message (optional).
        Tc tc;       //!< TC message (optional).
        Hna hna;     //!< HNA message (optional).
    } m_message;     //!< The actual message being carried.

  public:
    /**
     * Set the message type to MID and return the message content.
     * \returns The MID message.
     */
    Mid& GetMid()
    {
        if (m_messageType == 0)
        {
            m_messageType = MID_MESSAGE;
        }
        else
        {
            NS_ASSERT(m_messageType == MID_MESSAGE);
        }
        return m_message.mid;
    }

    /**
     * Set the message type to HELLO and return the message content.
     * \returns The HELLO message.
     */
    Hello& GetHello()
    {
        if (m_messageType == 0)
        {
            m_messageType = HELLO_MESSAGE;
        }
        else
        {
            NS_ASSERT(m_messageType == HELLO_MESSAGE);
        }
        return m_message.hello;
    }

    /**
     * Set the message type to TC and return the message content.
     * \returns The TC message.
     */
    Tc& GetTc()
    {
        if (m_messageType == 0)
        {
            m_messageType = TC_MESSAGE;
        }
        else
        {
            NS_ASSERT(m_messageType == TC_MESSAGE);
        }
        return m_message.tc;
    }

    /**
     * Set the message type to HNA and return the message content.
     * \returns The HNA message.
     */
    Hna& GetHna()
    {
        if (m_messageType == 0)
        {
            m_messageType = HNA_MESSAGE;
        }
        else
        {
            NS_ASSERT(m_messageType == HNA_MESSAGE);
        }
        return m_message.hna;
    }

    /**
     * Get the MID message.
     * \returns The MID message.
     */
    const Mid& GetMid() const
    {
        NS_ASSERT(m_messageType == MID_MESSAGE);
        return m_message.mid;
    }

    /**
     * Get the HELLO message.
     * \returns The HELLO message.
     */
    const Hello& GetHello() const
    {
        NS_ASSERT(m_messageType == HELLO_MESSAGE);
        return m_message.hello;
    }

    /**
     * Get the TC message.
     * \returns The TC message.
     */
    const Tc& GetTc() const
    {
        NS_ASSERT(m_messageType == TC_MESSAGE);
        return m_message.tc;
    }

    /**
     * Get the HNA message.
     * \returns The HNA message.
     */
    const Hna& GetHna() const
    {
        NS_ASSERT(m_messageType == HNA_MESSAGE);
        return m_message.hna;
    }
};

inline std::ostream&
operator<<(std::ostream& os, const PacketHeader& packet)
{
    packet.Print(os);
    return os;
}

inline std::ostream&
operator<<(std::ostream& os, const MessageHeader& message)
{
    message.Print(os);
    return os;
}

typedef std::vector<MessageHeader> MessageList;

inline std::ostream&
operator<<(std::ostream& os, const MessageList& messages)
{
    os << "[";
    for (auto messageIter = messages.begin(); messageIter != messages.end(); messageIter++)
    {
        messageIter->Print(os);
        if (messageIter + 1 != messages.end())
        {
            os << ", ";
        }
    }
    os << "]";
    return os;
}

} // namespace olsr
} // namespace ns3

#endif /* OLSR_HEADER_H */
