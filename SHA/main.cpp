/*!
	Author: asal
	Date: 18/12/2017
	
	Implementation of the SHA-256 cryptographic hash algorithm based on the pseudocode found in the corresponding Wikipedia article:
	https://en.wikipedia.org/wiki/SHA-2

	The implementation is a mix of C (malloc) and C++ (std::vector) elements (just for fun).
 */

#include <iostream>
#include <string>
#include <vector>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <sstream>

size_t rotateRight(const size_t& x, const size_t& n)
{
	size_t y = x >> n;
	size_t z = x << (32 - n);
	size_t g = y | z;
	return g;
}

int main(int argc, char** argv)
{
	const int chunkSize = 64;
	std::string input(argv[1]);
	std::cout << "Input: " << input << std::endl;

	size_t h0 = 0x6a09e667;
	size_t h1 = 0xbb67ae85;
	size_t h2 = 0x3c6ef372;
	size_t h3 = 0xa54ff53a;
	size_t h4 = 0x510e527f;
	size_t h5 = 0x9b05688c;
	size_t h6 = 0x1f83d9ab;
	size_t h7 = 0x5be0cd19;

	size_t k[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
					0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
					0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
					0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
					0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
					0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
					0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
					0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

	size_t initialInputLen = input.length();
	size_t numOfChunks = -1;

	// padding with '0'
	if (initialInputLen <= chunkSize)
	{
		for (size_t i = initialInputLen; i < chunkSize; ++i)
			input.push_back('0');
		numOfChunks = 1;
	}
	else
	{
		if (initialInputLen % chunkSize != 0)
		{
			numOfChunks = (initialInputLen / chunkSize) + 1;
			for (size_t i = initialInputLen; i < (numOfChunks * chunkSize); ++i)
				input.push_back('0');

		}
		else
			numOfChunks = initialInputLen / chunkSize;
	}
	size_t newInputLen = input.length();

	unsigned char * input_c_arr = (unsigned char*)malloc(newInputLen * sizeof(unsigned char));
	for (size_t i = 0; i < newInputLen; ++i)
		input_c_arr[i] = input[i];

	std::vector<unsigned char*> chunks;
	for (size_t i = 0; i < numOfChunks; ++i)
	{
		unsigned char* c = (unsigned char*)malloc(64 * sizeof(unsigned char));
		size_t chunk_start = i * chunkSize;
		size_t chunk_end = chunk_start + chunkSize;
		size_t c_index = 0;
		for (size_t j = chunk_start; j < chunk_end; ++j)
		{
			c[c_index] = input_c_arr[j];
			c_index++;
		}
		chunks.push_back(c);
	}
	// free memory
	free(input_c_arr);

	for (size_t i = 0; i < chunks.size(); ++i)
	{
		size_t w[chunkSize];
		for (size_t j = 0; j < chunkSize; ++j)
			w[j] = 0;

		// copy chunk into first 16 words w[0..15] of the message schedule array
		size_t w_index = 0;
		for (size_t j = 0; j < chunkSize; j+=4)
		{
			w[w_index] = (unsigned int) (chunks[i][j] << 24 | chunks[i][j + 1] << 16 | chunks[i][j + 2] << 8 | chunks[i][j + 3]);
			w_index++;
		}

		for (size_t j = 16; j < chunkSize; ++j)
		{
			size_t s0 = (rotateRight(w[j - 15], 7)) ^ (rotateRight(w[j - 15], 18)) ^ (w[j - 15] >> 3);
			size_t s1 = (rotateRight(w[j - 2], 17)) ^ (rotateRight(w[j - 2], 19)) ^ (w[j - 2] >> 10);
			w[j] = w[j - 16] + s0 + w[j - 7] + s1;
		}

		size_t a = h0;
		size_t b = h1;
		size_t c = h2;
		size_t d = h3;
		size_t e = h4;
		size_t f = h5;
		size_t g = h6;
		size_t h = h7;

		size_t S1, ch, temp1, S0, maj, temp2;
		for (size_t i = 0; i < chunkSize; ++i)
		{
			S1 = (rotateRight(e, 6)) ^ (rotateRight(e, 11)) ^ (rotateRight(e, 25));
			ch = (e & f) ^ ((~e) & g);
			temp1 = h + S1 + ch + k[i] + w[i];
			S0 = (rotateRight(a, 2)) ^ (rotateRight(a, 13)) ^ (rotateRight(a, 22));
			maj = (a & b) ^ (a & c) ^ (b & c);
			temp2 = S0 + maj;

			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}

		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
		h5 += f;
		h6 += g;
		h7 += h;

	}
	
	// Free memory
	for (size_t i = 0; i < chunks.size(); ++i)
		free(chunks[i]);

	std::stringstream ss;
	ss << h0;
	ss << h1;
	ss << h2;
	ss << h3;
	ss << h4;
	ss << h5;
	ss << h6;
	ss << h7;
	
	std::cout << "Hash: " << std::hex << ss.str() << std::endl;
	return 0;
}