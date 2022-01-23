#pragma once
#include <iostream>
#include <fstream>
#include <optional>
#include <memory>
#include "Packet.h"

// Класс для чтения информации о пакетах из .pcap файлов
// Определяет статические константы: разрешенных значений магического числа,
// Смещение зарезервированной части заголовка .pcap файла,
// размер буфера для чтения из файла (размер кратен размеру класстеров большинства жестких дисков и является достаточно большим,
// чтобы как можно реже "под капотом" совершались системные вызовы чтенияя с диска, но и не смертельно забивалась оперативная память.
//
// Поля класса - основные поля заголовков pcap файла,
// Поток чтения из файла, буфер, для эттоо потока, число прочитанных пакетов, флаг корректности, которые устанавливается в false
// если структура файла некорретна, или программа не поддерживает что/то, что есть в файле, например другие типы протоколов, а так
// же false, если нет исходного файла с именем, поданным в конструктор класса.
//
//
class File_pcap_reader
{
private:

    static const std::uint32_t MAGIC_NUMBER_1 = 0xA1B2C3D4;
    static const std::uint32_t MAGIC_NUMBER_2 = 0xA1B23C4D;
    static const std::uint8_t RESERVED_SKIP = 8;
    static const std::uint32_t BUFFER_SIZE = 0x80000;

private:

    std::uint32_t magicNumber_ = 0;
    std::uint16_t majorVersion_ = 0;
    std::uint16_t minorVersion_ = 0;
    std::uint32_t dataLenthLimit_ = 0;
    std::uint32_t linkType_ = 0;
    std::ifstream dumpFile_;
    std::unique_ptr<char[]> input_buffer = std::make_unique<char[]>(BUFFER_SIZE);
    std::uint32_t readed_count_ = 0;
    bool correct_flag_ = true;

public:

    File_pcap_reader(std::string filePath);
    std::optional<Packet> getNextPacket();
    inline bool eof() const noexcept { return dumpFile_.eof(); }
    inline bool correct() const noexcept { return correct_flag_; }
    operator bool() const noexcept { return correct(); }
    inline std::uint32_t getLastPacketNumber() const noexcept { return readed_count_; }
    std::string getHeaderInfoAsString() const noexcept;
    inline std::uint32_t getMagicNumber() const noexcept { return magicNumber_; }
    inline std::uint16_t getMajorVersion() const noexcept { return majorVersion_; }
    inline std::uint16_t getMinorVersion() const noexcept { return minorVersion_; }
    inline std::uint32_t getDataLenthLimit() const noexcept { return dataLenthLimit_; }
    inline std::uint32_t getLinkType() const noexcept { return linkType_; }
    inline void close() { dumpFile_.close(); }
    ~File_pcap_reader() { dumpFile_.close(); }

};

