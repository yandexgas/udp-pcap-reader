OBJS	= PcapUnpacker.o File_pcap.o Packet.o Headers.o
SOURCE	= PcapUnpacker.cpp File_pcap.cpp Packet.cpp Headers.cpp
HEADER	= File_pcap.h Packet.h Headers.h
OUT	= pp
CC	 = g++
FLAGS	 = -g -c -Wall
LFLAGS	 = 

all: $(OBJS)
	$(CC) -g $(OBJS) -o $(OUT) $(LFLAGS)

PcapUnpacker.o: PcapUnpacker.cpp
	$(CC) $(FLAGS) PcapUnpacker.cpp -std=c++17

File_pcap.o: File_pcap.cpp
	$(CC) $(FLAGS) File_pcap.cpp -std=c++17

Packet.o: Packet.cpp
	$(CC) $(FLAGS) Packet.cpp -std=c++17

Headers.o: Headers.cpp
	$(CC) $(FLAGS) Headers.cpp -std=c++17


clean:
	rm -f $(OBJS) $(OUT)