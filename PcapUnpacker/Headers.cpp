#include "Headers.h"


/// <summary>
/// ‘ункци€ возвращающа€ little - endian  представление двухбайтового числа из его big-endian представлени€.
/// Ќеобходима, т.к часть данных (в основном двухбайтовых) записана в .pcap файл в формате little - endian.
/// </summary>
/// <param name="i"></param>
inline void swap_endian(std::uint16_t& i) { i= (i << 8) | (i >> 8); } // дл€ двухбайтного числа просто старший и младший байты мен€ютс€ местами.


ethernet_header::ethernet_header(char* byteArray)
{
	std::memcpy(destination_host, byteArray, sizeof destination_host);
	std::memcpy(source_host, byteArray + SOURCE_HOST_HEADER_OFSET, sizeof source_host);
	std::memcpy(&protocol_type, byteArray + PROTOCOL_TYPE_HEADER_OFSET, sizeof protocol_type);
	if (protocol_type != 8)
		throw ("Only IPv4 supported. Can't read this packet.");
}

std::string ethernet_header::toString() const noexcept
{
	std::string src_host = std::to_string(source_host[0]) + '.' +
						   std::to_string(source_host[1]) + '.' +
						   std::to_string(source_host[2]) + '.' +
						   std::to_string(source_host[3]) + '.' +
						   std::to_string(source_host[4]) + '.' +
						   std::to_string(source_host[5]);
							
	std::string dst_host = std::to_string(destination_host[0]) + '.' +
						   std::to_string(destination_host[1]) + '.' +
						   std::to_string(destination_host[2]) + '.' +
						   std::to_string(destination_host[3]) + '.' +
						   std::to_string(destination_host[4]) + '.' +
						   std::to_string(destination_host[5]);

	std::string result = "";
	result = result + "\n========== EHERNET HEADER =========\n" +
			 "Source host : " + src_host + '\n' +
			 "Destination host : " + dst_host + '\n' +
			 "Protocol type code : " + std::to_string(protocol_type);

	return result;
}

IPv4_header::IPv4_header(char* byteArray)
							
{

	std::uint8_t first_byte; // первый байт заголовка в первых 4-х битах которого хранитс€ верси€ протокола, а во вторых 4-х - длина заголовка.
	constexpr std::uint8_t top4_bits_mask = 0b11110000; // ћаски дл€ получени€ доступа к нужным битам заголовка.
	constexpr std::uint8_t low4_bits_mask = 0b00001111;
	std::memcpy(&first_byte, byteArray, 1);
	version = (first_byte & top4_bits_mask) >> 4;
	headerLength = (first_byte & low4_bits_mask) * 4; // –азмер заголовка в .pcap файле представлен в количестве двоичных слов (1 слово = 4 байта), а нам нужно в байтах

	std::uint8_t second_byte; // ƒалее подобные операции аналогичны.
	constexpr std::uint8_t top6_bits_mask = 0b11111100;
	constexpr std::uint8_t low2_bits_mask = 0b00000011;
	std::memcpy(&second_byte, byteArray + DSCP_ECN_HEADER_OFSET, 1);
	DSCP = (second_byte & top6_bits_mask) >> 6;
	ECN = second_byte & low2_bits_mask;

	std::memcpy(&packetSize, byteArray + PACKET_SIZE_HEADER_OFSET, sizeof packetSize);
	swap_endian(packetSize);
	std::memcpy(&id, byteArray +ID_HEADER_OFSET, sizeof id);
	swap_endian(id);

	std::uint8_t sixth_bite;
	constexpr std::uint8_t top3_bits_mask = 0b11100000;
	constexpr std::uint8_t low5_bits_mask = 0b00011111;
	std::memcpy(&sixth_bite, byteArray + FLAGS_FRAGMENT_HEADER_OFSET, 1);
	flags = (sixth_bite & top3_bits_mask) >> 5;
	fragment_ofset = sixth_bite & low5_bits_mask;

	std::memcpy(&time_to_life, byteArray + LIFETIME_HEADER_OFSET, sizeof time_to_life);
	std::memcpy(&protocol_type, byteArray + PROTOCOL_TYPE_HEADER_OFSET, sizeof protocol_type);
	if (protocol_type != 17)
		throw ("Only UDP supported. Can't read this packet.");

	std::memcpy(&checkSum, byteArray + CHECKSUM_HEADER_OFSET, sizeof checkSum);
	swap_endian(checkSum);
	std::memcpy(&source_IP_address, byteArray + SOURCE_IP_HEADER_OFSET, sizeof source_IP_address);
	std::memcpy(&destination_IP_address, byteArray + DESTINATION_IP_HEADER_OFSET, sizeof destination_IP_address);

}

std::string IPv4_header::toString() const noexcept
{
	std::string src_ip = std::to_string(source_IP_address[0]) + '.' +
						   std::to_string(source_IP_address[1]) + '.' +
						   std::to_string(source_IP_address[2]) + '.' +
						   std::to_string(source_IP_address[3]);
							
	std::string dst_ip = std::to_string(destination_IP_address[0]) + '.' +
						   std::to_string(destination_IP_address[1]) + '.' +
						   std::to_string(destination_IP_address[2]) + '.' +
						   std::to_string(destination_IP_address[3]);

	std::string result = "\n========== IPv4  HEADER =========\n\n";
	result +=
			 "IP version : " + std::to_string(version) + '\n' +
			 "Header length : " + std::to_string(headerLength) + '\n' +
			 "Differentiated Services Code Point : " + std::to_string(DSCP) + '\n' +
			 "Explicit Congestion Notification : " + std::to_string(ECN) + '\n' +
			 "Packet size : " + std::to_string(packetSize) + '\n' +
			 "id : " + std::to_string(id) + '\n' +
			 "Reserved flag : " + std::to_string((flags & 0b00000100) != 0) +
			 "		Not fragment flag : " + std::to_string((flags & 0b0000010) != 0) +
			 "		Fragment flag : " + std::to_string(flags & 0b00000001) + '\n' +
			 "Fragment ofset : " + std::to_string(fragment_ofset) + '\n' +
			 "Time to life : " + std::to_string(time_to_life) + '\n' +
			 "Protocol type code : " + std::to_string(protocol_type) + '\n' +
			 "Check sum : " + std::to_string(checkSum) + '\n' +
			 "Source ip : " + src_ip + '\n' +
			 "Destination ip : " + dst_ip;

	return result;
}

udp_header::udp_header(char* byteArray)
{
	std::memcpy(&source_port, byteArray, sizeof source_port);
	swap_endian(source_port);

	std::memcpy(&destination_port, byteArray + DESTINATION_PORT_HEADER_OFSET, sizeof destination_port);
	swap_endian(destination_port);

	std::memcpy(&datagram_length, byteArray + DATA_LENGTH_HEADER_OFSET, sizeof datagram_length);
	swap_endian(datagram_length);

	std::memcpy(&checkSum, byteArray + CHECKSUM_HEADER_OFSET, sizeof checkSum);
	swap_endian(checkSum);
}

std::string udp_header::toString() const noexcept
{
	std::string result = "";
	result = result + "\n========== UDP   HEADER =========\n\n" +
			 "Source port : " + std::to_string(source_port) + '\n' +
			 "Destination port : " + std::to_string(destination_port) + '\n' +
			 "Datagram length : " + std::to_string(datagram_length) + '\n' +
			 "Check sum : " + std::to_string(checkSum);

	return result;
}

timeStamp::timeStamp(char* byteArray)
{
	std::memcpy(&seconds, byteArray, sizeof seconds);
	std::memcpy(&micro_or_nano_seconds, byteArray + AFTERPOINT_TIME_OFSET, sizeof micro_or_nano_seconds);
}

std::string timeStamp::toString() const noexcept
{
	std::string result = "Time : " + std::to_string(seconds) + '.' + std::to_string(micro_or_nano_seconds) + '\n';
	return result;
}
