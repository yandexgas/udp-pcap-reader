

// Именя файлов, с которыми будет работать программа хранятся в массиве SOURCE_FILES
// Чтобы программа работала корректно, необходимо, чтобы файлы с соответствующими именами находились
// в одной директории с исполняемым файлом

#include <iostream>
#include <fstream>
#include <algorithm>
#include <vector>
#include <memory>
#include "File_pcap.h"

/// <summary>
/// Функция распаковывает .pcap файл сохраняя основуню информацию о всех пакетах в другой файл и в оперативную память
/// в виде вектора. А так же выводит информацию об общем числе пакетов. (Будет выведено 0, если файл с такми именем не существует).
/// </summary>
/// <param name="Имя .pcap файла"></param>
/// <param name="Имя фала для сохранения данных пакетов"></param>
/// <returns> Вектор пакетов</returns>
std::vector<Packet> getPacketVector(const char*, const char*);

/// <summary>
/// Функция проверяет правильность данных, записанных в пользовательском бинарном файле. (Проверка соответствия
/// данным в оперативной памяти). Выводит в консоль результат проверки.
/// </summary>
/// <param name="Вектор пакетов с которыми будет проводиться сравнение"></param>
/// <param name="Имя файла с бинарными данными"></param>
/// <returns>Возвращает true, если проверка пройдена, иначе - false </returns>
bool checkMyFile(std::vector<Packet>&, const char*);

/// <summary>
/// Диалоговая функция для вывода содержимого заголовков пакетов на экран.
/// При нажатии на enter выводит информацию о следующих 15 пакетах в консоль, при вооде
/// конца файла завершает работу.
/// </summary>
/// <param name="Вектор пакетов для вывода на экран"></param>
void showPacketsData(std::vector<Packet>&);



const char* SOURCE_FILES[] = {      "Corvil-13052-1636559040000000000-1636560600000000000.pcap",
                                    "Corvil-13052-1636577340000000000-1636577700000000000.pcap",
                                    "Corvil-13052-1636594740000000000-1636595400000000000.pcap",
                                    "Corvil-13052-1636603140000000000-1636603500000000000.pcap",
                                    "Corvil-13052-1636613940000000000-1636614300000000000.pcap",
                                    "Corvil-13052-1636628340000000000-1636628700000000000.pcap",
                                    "Corvil-13052-1636645440000000000-1636647000000000000.pcap" };

const char* MYCLASS_FILES[] = { "file1", "file2", "file3", "file4" , "file5" , "file6" ,"file7" };



int main()
{
    for (size_t i = 0; i < 6; i++) {
        auto packets_data = getPacketVector(SOURCE_FILES[i], MYCLASS_FILES[i]);
        checkMyFile(packets_data, MYCLASS_FILES[i]);
        showPacketsData(packets_data);
    }

}

std::vector<Packet> getPacketVector(const char* sourceFileName, const char* my_class_filename)
{
    std::cout << "Processing file : " << sourceFileName << " ......" << std::endl;

    // Создание буфера для записи в пользовательский файл. Значение размера буфера кратно размеру класстера большинства жестких дисков.
    // Это позволяет ускорить операции записи в  файл
    auto buf = std::make_unique<char[]>(0x80000);
    std::ofstream my_file(my_class_filename, std::ios_base::out | std::ios_base::binary);
    my_file.rdbuf()->pubsetbuf(buf.get(), 0x80000);

    File_pcap_reader pcap(sourceFileName);
    std::vector<Packet> vector_for_read_write_check;
    if (pcap) {
        std::cout << pcap.getHeaderInfoAsString() << std::endl;
        while (!pcap.eof())
        {
            auto pack = pcap.getNextPacket();
            if (pack) {
                my_file.write((char*)&pack.value(), sizeof(Packet));
                vector_for_read_write_check.emplace_back(pack.value());
            }
        }
    }
    my_file.close();
    std::cout << "Total packets number : " << vector_for_read_write_check.size() << std::endl;
    return vector_for_read_write_check;
}

bool checkMyFile(std::vector<Packet>& original_data, const char* filename)
{
    // Создание буфера для чтения из пользовательского файл. Значение размера буфера кратно размеру класстера большинства жестких дисков.
    // Это позволяет ускорить операции чтения из файла.
    auto buf = std::make_unique<char[]>(0x80000);
    std::ifstream my_file(filename, std::ios_base::in | std::ios_base::binary);
    my_file.rdbuf()->pubsetbuf(buf.get(), 0x80000);

    for (auto i : original_data) {
        Packet test_pack;
        my_file.read((char*)&test_pack, sizeof(Packet));
        if (test_pack != i) {
            std::cout << "Source file not equal with data in memory." << std::endl;
            my_file.close();
            return false;
        }
    }
    my_file.close();
    std::cout << "File was writed and readed correctly." << std::endl;
    return true;
}

void showPacketsData(std::vector<Packet>& original_data) {
    std::cout << "Input EOF if you don't want to see packet data, else input enter, to see next 15 packets." << std::endl;
    auto current_packete = original_data.cbegin();
    char buf[16];
    std::cin.getline(buf, 16);
    while (current_packete != original_data.cend() && !std::cin.eof())
    {
        std::for_each(current_packete, current_packete + 14, [](Packet p) {std::cout << p << std::endl; });
        current_packete += 14;
        std::cin.getline(buf, 16);
    }
    std::cin.clear();
}
