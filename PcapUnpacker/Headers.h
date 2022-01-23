
// Файл описывает структуры основных протоколов, которые используются в программе
// ethrnet, ip4, udp , а так же структуру с форматом времени прихода пакета.




#pragma once
#include <iostream>
#include <string>


	struct ethernet_header
	{	
	private:

		static const std::uint8_t SOURCE_HOST_HEADER_OFSET = 6;
		static const std::uint8_t PROTOCOL_TYPE_HEADER_OFSET = 12;

	public:

		std::uint8_t destination_host[6] = {};
		std::uint8_t source_host[6] = {};
		std::uint16_t protocol_type = 0;

		ethernet_header(char* byteArray);
		ethernet_header() {};
		std::string toString() const noexcept;
	};

	struct IPv4_header
	{	
	private:

		static const std::uint8_t DSCP_ECN_HEADER_OFSET = 1;
		static const std::uint8_t PACKET_SIZE_HEADER_OFSET = 2;
		static const std::uint8_t ID_HEADER_OFSET = 4;
		static const std::uint8_t FLAGS_FRAGMENT_HEADER_OFSET = 6;
		static const std::uint8_t LIFETIME_HEADER_OFSET = 8;
		static const std::uint8_t PROTOCOL_TYPE_HEADER_OFSET = 9;
		static const std::uint8_t CHECKSUM_HEADER_OFSET = 10;
		static const std::uint8_t SOURCE_IP_HEADER_OFSET = 12;
		static const std::uint8_t DESTINATION_IP_HEADER_OFSET = 16;

	public:

		std::uint8_t version = 0;
		std::uint8_t headerLength =0;
		std::uint8_t DSCP = 0;
		std::uint8_t ECN = 0;
		std::uint16_t packetSize = 0;
		std::uint16_t id = 0;
		std::uint8_t flags = 0;
		std::uint8_t fragment_ofset = 0;
		std::uint8_t time_to_life = 0;
		std::uint8_t protocol_type =0;
		std::uint16_t checkSum = 0;
		std::uint8_t source_IP_address[4] = {};
		std::uint8_t destination_IP_address[4] = {};

		IPv4_header(char* byteArray);
		IPv4_header (){}
		std::string toString() const noexcept;
	};

	struct udp_header
	{
	private:

		static const std::uint8_t DESTINATION_PORT_HEADER_OFSET = 2;
		static const std::uint8_t DATA_LENGTH_HEADER_OFSET = 4;
		static const std::uint8_t CHECKSUM_HEADER_OFSET = 6;

	public:

		std::uint16_t source_port = 0;
		std::uint16_t destination_port = 0;
		std::uint16_t datagram_length = 0;
		std::uint16_t checkSum = 0 ;

		udp_header(char* byteArray);
		udp_header() {}
		std::string toString() const noexcept;
	};

	struct timeStamp
	{
	private:

		static const std::uint8_t AFTERPOINT_TIME_OFSET = 4;

	public:

		std::uint32_t seconds = 0;
		std::uint32_t micro_or_nano_seconds = 0;

		timeStamp(char* byteArray);
		timeStamp() {}
		std::string toString() const noexcept;

	};
