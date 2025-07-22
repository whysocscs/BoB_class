#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>

using namespace std;

int main() {
    ifstream file("gpt_128.dd", ios::binary);
    if (!file) {
        cerr << "디스크 이미지를 열 수 없습니다." << endl;
        return 1;
    }

    const size_t sector_size = 512;
    const size_t gpt_entry_start_lba = 2;
    const size_t entry_size = 128;
    const size_t max_entries = 128;

    vector<unsigned char> buffer(entry_size);
    size_t entry_base_offset = gpt_entry_start_lba * sector_size;

    for (int i = 0; i < max_entries; ++i) {
        size_t entry_offset = entry_base_offset + i * entry_size;
        size_t real_sector = entry_offset / sector_size;

        file.seekg(entry_offset, ios::beg);
        file.read(reinterpret_cast<char*>(buffer.data()), entry_size);

        bool is_empty = true;
        for (int j = 0; j < 16; ++j) {
            if (buffer[j] != 0) {
                is_empty = false;
                break;
            }
        }
        if (is_empty) continue;

        for (int j = 0; j < 16; ++j) {
            cout << hex << setw(2) << setfill('0') << uppercase
                << static_cast<int>(buffer[j]);
        }

        uint64_t start_lba = *reinterpret_cast<uint64_t*>(&buffer[32]);
        uint64_t end_lba = *reinterpret_cast<uint64_t*>(&buffer[40]);
        uint64_t size = end_lba - start_lba + 1;

        cout << " " << dec <<  start_lba << " " << size << endl;
    }

    return 0;
}
