#include "File_pcap.h"
#include <memory>
#include <sstream>
#include <cstring>

/// <summary>
/// ����������� ������. ��������� ������ � ������, ��� �������� ���� �������� � ������������.
/// � ������ ���� ��������� �� ����� �������� � ����� ������ ��� ��� �� ����������, ���� ������������ ������������ = false.
/// � ���� ������ �������������� �������� ������ �� ��������� ����� � ������������ � ��������� .pcap ���������.
/// (��������� � ������� ��������� ����� �������� � ��������� ".pcap file format")
/// </summary>
/// <param name="filePath"></param>
File_pcap_reader::File_pcap_reader(std::string filePath)
{
    try {
        //�������� ����� � ��������� ������ ��� ������ �� ���� (��� ���������� ���������� ��������� �������).
        dumpFile_.open(filePath, std::ios_base::in | std::ios_base::binary);
        dumpFile_.rdbuf()->pubsetbuf(input_buffer.get(), BUFFER_SIZE);

        if (dumpFile_.is_open()) {
            dumpFile_.read((char*)&magicNumber_, sizeof magicNumber_);
            dumpFile_.read((char*)&majorVersion_, sizeof majorVersion_);
            dumpFile_.read((char*)&minorVersion_, sizeof minorVersion_);
            dumpFile_.seekg(RESERVED_SKIP, std::ios_base::cur);
            dumpFile_.read((char*)&dataLenthLimit_, sizeof dataLenthLimit_);
            dumpFile_.read((char*)&linkType_, sizeof linkType_);

            if (magicNumber_ != MAGIC_NUMBER_1 && magicNumber_ != MAGIC_NUMBER_2) {
                correct_flag_ = false;
                std::cerr << "Incorrect magic number. Wrong file format." << std::endl;
            }

            if (linkType_ != 1) {
                correct_flag_ = false;
                std::cerr << "It's working only with Ethernet." << std::endl;
            }

            if (majorVersion_ != 2 || minorVersion_ > 4) {
                correct_flag_ = false;
                std::cerr << "Unsupported format version." << std::endl;
            }
        }
        else {
            correct_flag_ = false;
        }
    }
    catch (std::iostream::failure e) {
        correct_flag_ = false;
        std::cerr << e.what() << std::endl;
    }
}

/// <summary>
/// �������, ������������ ������ ���������� ������ �� �����.
/// </summary>
/// <returns> ���������� ������ ������ Packet, ���� ����� ���� ��������, � std::nullopt � ������ ��������� �������� ��� ����� �����.</returns>
std::optional<Packet> File_pcap_reader::getNextPacket()
{
    try {
        if (correct_flag_) {
            char packet_header_binary[16];
            dumpFile_.read(packet_header_binary, sizeof packet_header_binary); // �������� ��������� ������ ������������� ������, ����� ������ ������ �������� ����� ������.
            std::uint32_t data_length;
            if (!dumpFile_.eof())
            {
                readed_count_++;
                std::memcpy(&data_length, packet_header_binary + 8, sizeof data_length); // �������������� �������� ������ ������ � ����������� ������� � ����� ������.
                auto data = std::make_unique<char[]>(data_length);
                dumpFile_.read(data.get(), data_length); // ������ �������� ����� ������
                return Packet(packet_header_binary, data.get());
            }
            else return std::nullopt;
        }
        else return std::nullopt;
    }
    catch (std::exception e) {
        std::cerr << e.what() << std::endl
            << "Error while reading packet with number" << readed_count_ << std::endl;
        return std::nullopt;
    }
}

/// <summary>
/// ������� ���������� ��������� ������������� �������� ���������� � ��������� .pcap �����.
/// </summary>
/// <returns></returns>
std::string File_pcap_reader::getHeaderInfoAsString() const noexcept
{
    std::string hex_magic_number;
    std::string hex_link_type;
    std::stringstream res_stream;
    res_stream << std::hex << magicNumber_ << std::endl << linkType_ << std::endl; // ������������� ����������� ����� � 16-� ����.
    res_stream >> hex_magic_number >> hex_link_type;
    std::string result = "\n========= PCAP FILE HEADER =========\n\n";
    result += "Magic number : " + hex_magic_number + '\n' +
        "Version : " + std::to_string(majorVersion_) + '.' + std::to_string(minorVersion_) + '\n' +
        "Data length limit : " + std::to_string(dataLenthLimit_) + '\n' +
        "Ethernet. Link type : " + hex_link_type +
        "\n===================================\n";

    return result;
}
