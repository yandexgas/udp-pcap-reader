#pragma once
#include <iostream>
#include "Headers.h"
#include <string>
#include <cstring>
#include <optional>

/// <summary>
/// Класс описывающий пакет, считанный из .pcap файла
/// Статические константы - для хранения смещения определённых частей заголовка пакета относительно начала заголовка.
///
/// Поля класса - Время получения пакета,
///				  Захваченная длина пакета,
///				  Полная длина пакета
/// (подробнее о структуре заголовка можно почитать в интеренете ".pcap file format")
///
///				  Объект заголовка ethernet;
///				  Объект IPv4 заголовка,
///				  Объект UDP заголовка.
/// </summary>
class Packet {
private:

    static const std::uint8_t CAPTURED_LENGTH_OFSET = 8;
    static const std::uint8_t ORIGINAL_LENGTH_OFSET = 12;
    static const std::uint8_t IP_HEADER_OFSET = 14;

private:

    timeStamp receiveTime_;
    std::uint32_t capturedLength_ = 0;
    std::uint32_t originalLength_ = 0;
    ethernet_header ethernet_;
    IPv4_header ip4_;
    udp_header udp_;

public:

    Packet() {}
    Packet(char* byteHeader, char* byteData);
    std::string toString() const noexcept;
    friend std::ostream& operator <<(std::ostream& os, Packet& pack) { os << pack.toString(); return os; }
    inline const uint32_t getCapturedLength() const noexcept { return capturedLength_; }
    inline const uint32_t getOriginalLength() const noexcept { return originalLength_; }
    inline const timeStamp& getTimeStamp() const noexcept { return receiveTime_; }
    inline const ethernet_header& getEthernetHeader() const noexcept { return ethernet_; }
    inline const IPv4_header& getIPv4Header() const noexcept { return ip4_; }
    inline const udp_header& getUDPHeader() const noexcept { return udp_; }

    inline Packet& setCapturedLength(std::uint32_t length)  noexcept;
    inline const  Packet& setOriginalLength(std::uint32_t length)  noexcept;
    inline const  Packet& setTimeStamp(timeStamp time)  noexcept;
    inline const  Packet& setEthernetHeader(ethernet_header eth_head)  noexcept;
    inline const  Packet& setIPv4Header(IPv4_header ip) noexcept;
    inline const  Packet& setUDPHeader(udp_header udp)  noexcept;

    bool operator == (Packet& pack) {
        return std::memcmp(this, &pack, sizeof(Packet)) == 0;
    }
    bool operator != (Packet& pack) {
        return std::memcmp(this, &pack, sizeof(Packet)) != 0;
    }
};

