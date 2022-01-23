#include <cstring>
#include "Packet.h"

/// <summary>
/// Конструктор для формирования объекта класса из бинарных данных
/// вызывает соответсвующие конструкторы подзаголовков (заголовков протоколов)
/// и формата времени.
/// </summary>
/// <param name="byteHeader"></param>
/// <param name="byteData"></param>
Packet::Packet(char* byteHeader, char* byteData) : receiveTime_(byteHeader),
ethernet_(byteData),
ip4_(byteData + IP_HEADER_OFSET),
udp_(byteData + IP_HEADER_OFSET + ip4_.headerLength)

{
    std::memcpy(&capturedLength_, byteHeader + CAPTURED_LENGTH_OFSET, sizeof(std::uint32_t)); // Чтение захваченной 4 байтной длины пакета из позиции, смещенной относительно начала заголовка на
    std::memcpy(&originalLength_, byteHeader + ORIGINAL_LENGTH_OFSET, sizeof(std::uint32_t)); //CAPTURED_LENGTH_OFSET и ORIGINAL_LENGTH_OFSET байт соответсвенно.
}

std::string Packet::toString() const noexcept
{

    std::string result = "\n========== PACKET HEADER ==========\n\n" +
        receiveTime_.toString() + '\n' +
        "Captured length (bites) : " + std::to_string(capturedLength_) + '\n' +
        "Original length (bites) : " + std::to_string(originalLength_) + '\n' +
        ethernet_.toString() + '\n' +
        ip4_.toString() + '\n' +
        udp_.toString() +
        "\n\n==============================\n";
    return result;
}

inline Packet& Packet::setCapturedLength(std::uint32_t length) noexcept
{
    capturedLength_ = length;
    return *this;
}

inline const Packet& Packet::setOriginalLength(std::uint32_t length) noexcept
{
    originalLength_ = length;
    return *this;
}

inline const Packet& Packet::setTimeStamp(timeStamp time) noexcept
{
    receiveTime_ = time;
    return *this;
}

inline const Packet& Packet::setEthernetHeader(ethernet_header eth_head) noexcept
{
    ethernet_ = eth_head;
    return *this;
}

inline const Packet& Packet::setIPv4Header(IPv4_header ip) noexcept
{
    ip4_ = ip;
    return *this;
}

inline const Packet& Packet::setUDPHeader(udp_header udp) noexcept
{
    udp_ = udp;
    return *this;
}
