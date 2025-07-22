#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>

using namespace std;

int main(int argc, char * argv[]) {
	string filename = "mbr_128.dd";
	size_t sector_size = 16, boundary = 0, current_point = 0;
	unsigned int real_size = 0;
	ifstream file(filename, std::ios::binary);

	file.seekg(448, ios::beg);
	vector<unsigned char> buffer(sector_size);
	while (file.read(reinterpret_cast<char*>(buffer.data()), sector_size)) {
		unsigned int value = (buffer[8] << 16) | (buffer[7] << 8) | buffer[6];
		real_size = (buffer[13] << 24) | (buffer[12] << 16) | (buffer[11] << 8) | buffer[10];
		if (buffer[2] == 0x7) 
			if (boundary == 0) 
				cout <<  value << " " << dec << real_size << endl;
			else 
				cout << (current_point / 512 + value) << " " << dec << real_size << endl;

			
		else if (buffer[2] == 0x05) {
			if (boundary == 0) {
				file.seekg(value*512 + 448 , ios::beg);
				boundary = value * 512;
				current_point = value * 512;
			}
			else {
				current_point = value * 512 + boundary;	
				file.seekg(value * 512 + boundary + 448, ios::beg);
			}
		}
		else if (buffer[2] == 0x00) {
			exit(0);
		}
		

	}

}