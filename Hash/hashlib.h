#ifndef HASH_HASHLIB_H_
#define HASH_HASHLIB_H_

#include <string>
#include <sstream>

//Bitwise left circular shift
template<typename T1, typename T2>
constexpr auto LEFTROTATE(T1 x, T2  c) { return (((x) << (c)) | ((x) >> (32 - (c)))); }

//Bitwise right circular shift
template<typename T1, typename T2>
constexpr auto RIGHTROTATE(T1 x, T2  c) { return (((x) >> (c)) | ((x) << (32 - (c)))); }

std::string preprocessMsg(std::string message)
{
	uint64_t MessageSize = message.size();
	uint64_t new_len;

	//Endended message length calculation
	for (new_len = MessageSize * 8; new_len % 512 != 448; new_len++);
	{
		new_len /= 8;
	}

	//append zeroes to end
	message.resize(new_len, '\0');

	//append '1' bit to end
	message[MessageSize] = 0x80;

	//append message size to end
	std::string appendMsgSize;
	for (int k = 0; k < 8; k++)
	{
		appendMsgSize += (uint8_t)((8 * MessageSize) >> (8 * k));
	}

	for (int i = 7; i >= 0; --i)
	{
		message += appendMsgSize[i];
	}
	return message;
}

std::string SHA1(std::string message)
{
	//Preprocessing
	message = preprocessMsg(message);

	//h0-h4 var initialization
	uint32_t h0 = 0x67452301;
	uint32_t h1 = 0xEFCDAB89;
	uint32_t h2 = 0x98BADCFE;
	uint32_t h3 = 0x10325476;
	uint32_t h4 = 0xC3D2E1F0;

	//Divide into blocks
	for (int i = 0; i < message.size(); i += 64)
	{
		//16 32-bit words are extended to 80 32-bit words
		// 0-15 words dont change
		uint32_t w[80];
		for (int j = 0; j < 16; j++)
		{
			uint32_t temp = 0;
			for (int k = 0; k < 4; k++)
			{
				if ((i + (4 * j) + k) <= message.size())
				{
					temp += ((unsigned char)(message[i + (4 * j) + k])) << (24 - 8 * k);
				}
				else break;
			}
			w[j] = temp;
		}
		//16-79 words are extended and left cycle shifted
		for (int j = 16; j < 80; j++)
		{
			w[j] = LEFTROTATE((w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16]), 1);
		}

		//ABCD vector initialization
		uint32_t a = h0;
		uint32_t b = h1;
		uint32_t c = h2;
		uint32_t d = h3;
		uint32_t e = h4;

		//Main loop
		for (int j = 0; j < 80; j++)
		{
			uint32_t f, k, temp;
			if (j <= 19)
			{
				f = (b & c) | ((~b) & d);
				k = 0x5A827999;
			}
			else if ((j >= 20) && (j <= 39))
			{
				f = b ^ c ^ d;
				k = 0x6ED9EBA1;
			}
			else if ((j >= 40) && (j <= 59))
			{
				f = (b & c) | (b & d) | (c & d);
				k = 0x8F1BBCDC;
			}
			else if ((j >= 60) && (j <= 79))
			{
				f = b ^ c ^ d;
				k = 0xCA62C1D6;
			}

			temp = LEFTROTATE(a, 5) + f + e + k + w[j];
			e = d;
			d = c;
			c = LEFTROTATE(b, 30);
			b = a;
			a = temp;
		}
		//Add hash value to result
		h0 = h0 + a;
		h1 = h1 + b;
		h2 = h2 + c;
		h3 = h3 + d;
		h4 = h4 + e;
	}

	//Construct results into HEX digest
	std::stringstream Append;
	std::string HexResult;

	Append << std::uppercase << std::hex << h0 << h1 << h2 << h3 << h4;
	HexResult = Append.str();
	
	return HexResult;
}

std::string MD5(std::string message)
{
	//Preprocessing
	message = preprocessMsg(message);

	//h0-h3 var initialization
	uint32_t h0 = 0x67452301;
	uint32_t h1 = 0xEFCDAB89;
	uint32_t h2 = 0x98BADCFE;
	uint32_t h3 = 0x10325476;


	uint32_t K[64] = 
	{	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,0xf57c0faf,0x4787c62a, 
		0xa8304613, 0xfd469501,0x698098d8, 0x8b44f7af, 0xffff5bb1,0x895cd7be,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,0xf61e2562,0xc040b340, 
		0x265e5a51, 0xe9b6c7aa,0xd62f105d, 0x02441453, 0xd8a1e681,0xe7d3fbc8, 
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,0xa9e3e905,0xfcefa3f8, 
		0x676f02d9, 0x8d2a4c8a,0xfffa3942, 0x8771f681, 0x6d9d6122,0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,0x289b7ec6,0xeaa127fa,
		0xd4ef3085, 0x04881d05,0xd9d4d039, 0xe6db99e5, 0x1fa27cf8,0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,0x655b59c3,0x8f0ccc92,
		0xffeff47d, 0x85845dd1,0x6fa87e4f, 0xfe2ce6e0, 0xa3014314,0x4e0811a,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 
	};

	uint32_t s[64] = 
	{	7, 12, 17, 22,		7, 12, 17, 22,		7, 12, 17, 22,		7, 12, 17, 22,
		5,  9, 14, 20,		5,  9, 14, 20,		5,  9, 14, 20,		5,  9, 14, 20,
		4, 11, 16, 23,		4, 11, 16, 23,		4, 11, 16, 23,		4, 11, 16, 23,
		6, 10, 15, 21,		6, 10, 15, 21,		6, 10, 15, 21,		6, 10, 15, 21 
	};

	//Divide into blocks
	for (int i = 0; i < message.size(); i += 64)
	{
		//Divide into 16 32bit words 
		uint32_t w[16];
		for (int j = 0; j < 16; j++)
		{
			uint32_t temp = 0;
			for (int k = 0; k < 4; k++)
			{
				if ((i + (4 * j) + k) <= message.size())
				{
					temp += ((unsigned char)(message[i + (4 * j) + k])) << (24 - 8 * k);
				}
				else break;
			}
			w[j] = temp;
		}

		//ABCD vector initialization
		uint32_t a = h0;
		uint32_t b = h1;
		uint32_t c = h2;
		uint32_t d = h3;

		//Main loop
		for (int j = 0; j < 64; j++)
		{
			uint32_t f, g;
			if (j <= 15)
			{
				f = (b&c) | ((~b)&d);
				g = j;
			}
			else if ((j >= 16) && (j <= 31))
			{
				f = (d&b) | ((~d)&c);
				g = (5 * j + 1) % 16;
			}
			else if ((j >= 32) && (j <= 47))
			{
				f = b ^ c^d;
				g = (3 * j + 5) % 16;
			}
			else if ((j >= 48) && (j <= 63))
			{
				f = c ^ (b | (~d));
				g = (7 * j) % 16;
			}

			f = f + a + w[g] + K[j];
			a = d;
			d = c;
			c = b;
			b = b + LEFTROTATE(f, s[j]);
		}
		//Add hash value to result
		h1 = h1 + b;
		h2 = h2 + c;
		h3 = h3 + d;
	}

	//Construct results into HEX digest
	std::stringstream Append;
	std::string HexResult;

	Append << std::uppercase << std::hex << h0 << h1 << h2 << h3;
	HexResult = Append.str();

	return HexResult;
}

std::string RIPEMD160(std::string message)
{
	//Preprocessing
	message = preprocessMsg(message);


	//h0-h4 var initialization
	uint32_t h0 = 0x67452301;
	uint32_t h1 = 0xEFCDAB89;
	uint32_t h2 = 0x98BADCFE;
	uint32_t h3 = 0x10325476;
	uint32_t h4 = 0xC3D2E1F0;

	uint32_t r[80] =
	{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
		3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
		1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
		4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
	};

	uint32_t r_[80] =
	{
		5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
		6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
		15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
		8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
		12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
	};
	
	uint32_t s[80] =
	{
		11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
		7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
		11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
		11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
		9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
	};

	uint32_t s_[80] =
	{
		8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
		9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
		9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
		15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
		8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
	};

	//Divide into blocks
	for (int i = 0; i < message.size(); i += 64)
	{
		uint32_t t, t_;
		//Divide into 16 32-bit words
		uint32_t w[16];
		for (int j = 0; j < 16; j++)
		{
			uint32_t temp = 0;
			for (int k = 0; k < 4; k++)
			{
				if ((i + (4 * j) + k) <= message.size())
				{
					temp += ((unsigned char)(message[i + (4 * j) + k])) << (24 - 8 * k);
				}
				else break;
			}
			w[j] = temp;
		}


		//ABCDE vector initialization
		uint32_t a = h0;
		uint32_t b = h1;
		uint32_t c = h2;
		uint32_t d = h3;
		uint32_t e = h4;

		uint32_t a_ = h0;
		uint32_t b_ = h1;
		uint32_t c_ = h2;
		uint32_t d_ = h3;
		uint32_t e_ = h4;

		//Main loop
		for (int j = 0; j < 80; j++)
		{
			uint32_t f,f_,k,k_;
			if (j <= 15)
			{
				f = b ^ c ^ d;
				f_ = b ^ (c | (~d));
				k = 0x00000000;
				k_ = 0x50A28BE6;
			}
			else if ((j >= 16) && (j <= 31))
			{
				f = (b&c)|((~b)&d);
				f_ = (b & d) | (c & (~d));
				k = 0x5A827999;
				k_ = 0x5C4DD124;
			}
			else if ((j >= 32) && (j <= 47))
			{
				f = (b | (~c)) ^ d;
				f_ = (b | (~c)) ^ d;
				k = 0x8F1BBCDC;
				k_ = 0x6D703EF3;
			}
			else if ((j >= 48) && (j <= 63))
			{
				f = (b & d) | (c & (~d));
				f_ = (b&c) | ((~b)&d);
				k = 0xCA62C1D6;
				k_= 0x7A6D76E9;
			}
			else if ((j >= 64) && (j <= 79))
			{
				f = b ^ (c | (~d));
				f_ = b ^ c ^ d;
				k = 0xA953FD4E;
				k_ = 0x00000000;
			}

			t = LEFTROTATE((a + f  + w[r[j]] + k),s[j])+e;
			a = e;
			e = d;
			d = LEFTROTATE(c, 10);
			c = b;
			b = t;

			t_ = LEFTROTATE((a_ + f_ + w[r_[j]] + k_), s_[j]) + e_;
			a_ = e_;
			e_ = d_;
			d_ = LEFTROTATE(c_, 10);
			c_ = b_;
			b_ = t_;
		}
		//Add hash value to result
		t = h1 + c + d_;
		h1 = h2 + d + e_; 
		h2 = h3 + e + a_;
		h3 = h4 + a + b_;
		h4 = h0 + b + c_; 
		h0 = t;
	}

	//Construct results into HEX digest
	std::stringstream Append;
	std::string HexResult;

	Append << std::uppercase << std::hex << h0 << h1 << h2 << h3 << h4;
	HexResult = Append.str();

	return HexResult;
}

std::string SHA256(std::string message)
{
	//Preprocessing
	message = preprocessMsg(message);

	//h0-h7 var initialization
	uint32_t h0 = 0x6A09E667;
	uint32_t h1 = 0xBB67AE85;
	uint32_t h2 = 0x3C6EF372;
	uint32_t h3 = 0xA54FF53A;
	uint32_t h4 = 0x510E527F;
	uint32_t h5 = 0x9B05688C;
	uint32_t h6 = 0x1F83D9AB;
	uint32_t h7 = 0x5BE0CD19;
	
	uint32_t k[64] =
	{
		0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
		0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
		0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
		0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
		0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
		0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
		0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
		0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
	};

	//Divide into blocks
	for (int i = 0; i < message.size(); i += 64)
	{
		//16 32-bit words are extended to 80 32-bit words
		// 0-15 words dont change
		uint32_t w[64];
		for (int j = 0; j < 16; j++)
		{
			uint32_t temp = 0;
			for (int k = 0; k < 4; k++)
			{
				if ((i + (4 * j) + k) <= message.size())
				{
					temp += ((unsigned char)(message[i + (4 * j) + k])) << (24 - 8 * k);
				}
				else break;
			}
			w[j] = temp;
		}
		//16-79 words are extended and right cycle shifted
		uint32_t s0, s1;
		for (int j = 16; j < 64; j++)
		{
			s0 = RIGHTROTATE(w[j - 15], 7) ^ RIGHTROTATE(w[j - 15],18) ^ (w[j - 15] >> 3);
			s1 = RIGHTROTATE(w[j - 2], 17) ^ RIGHTROTATE(w[j - 2], 19) ^ (w[j - 2] >> 10);
			w[j] = w[j - 16] + s0 + w[j - 7] + s1;
		}
			
		//ABCDEFGH vector initialization
		uint32_t a = h0;
		uint32_t b = h1;
		uint32_t c = h2;
		uint32_t d = h3;
		uint32_t e = h4;
		uint32_t f = h5;
		uint32_t g = h6;
		uint32_t h = h7;

		//Main loop
		for (int j = 0; j < 64; j++)
		{
			uint32_t sum0, sum1, Ma, Ch, t1, t2;
			sum0 = RIGHTROTATE(a, 2) ^ RIGHTROTATE(a, 13) ^ RIGHTROTATE(a, 22);
			Ma = (a & b) ^ (a & c) ^ (b & c);
			t2 = sum0 + Ma;
			sum1 = RIGHTROTATE(e, 6) xor RIGHTROTATE(e, 11) xor RIGHTROTATE(e, 25);
			Ch = (e & f) xor ((~e) & g);
			t1 = h + sum1 + Ch + k[j] + w[j];

			h = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}
		//Add hash value to result
		h0 = h0 + a;
		h1 = h1 + b;
		h2 = h2 + c;
		h3 = h3 + d;
		h4 = h4 + e;
		h5 = h5 + f;
		h6 = h6 + g;
		h7 = h7 + h;
	}

	//Construct results into HEX digest
	std::stringstream Append;
	std::string HexResult;

	Append << std::uppercase << std::hex << h0 << h1 << h2 << h3 << h4 << h5 << h6 << h7;
	HexResult = Append.str();

	return HexResult;
}

std::string SHA224(std::string message)
{
	//Preprocessing
	message = preprocessMsg(message);
					
	//h0-h7 var initialization
	uint32_t h0 = 0xc1059ed8;
	uint32_t h1 = 0x367cd507;
	uint32_t h2 = 0x3070dd17;
	uint32_t h3 = 0xf70e5939;
	uint32_t h4 = 0xffc00b31;
	uint32_t h5 = 0x68581511;
	uint32_t h6 = 0x64f98fa7;
	uint32_t h7 = 0xbefa4fa4;

	uint32_t k[64] =
	{
		0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
		0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
		0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
		0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
		0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
		0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
		0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
		0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
	};

	//Divide into blocks
	for (int i = 0; i < message.size(); i += 64)
	{
		//16 32-bit words are extended to 80 32-bit words
		// 0-15 words dont change
		uint32_t w[64];
		for (int j = 0; j < 16; j++)
		{
			uint32_t temp = 0;
			for (int k = 0; k < 4; k++)
			{
				if ((i + (4 * j) + k) <= message.size())
				{
					temp += ((unsigned char)(message[i + (4 * j) + k])) << (24 - 8 * k);
				}
				else break;
			}
			w[j] = temp;
		}
		//16-79 words are extended and right cycle shifted
		uint32_t s0, s1;
		for (int j = 16; j < 64; j++)
		{
			s0 = RIGHTROTATE(w[j - 15], 7) ^ RIGHTROTATE(w[j - 15], 18) ^ (w[j - 15] >> 3);
			s1 = RIGHTROTATE(w[j - 2], 17) ^ RIGHTROTATE(w[j - 2], 19) ^ (w[j - 2] >> 10);
			w[j] = w[j - 16] + s0 + w[j - 7] + s1;
		}

		//ABCDEFGH vector initialization
		uint32_t a = h0;
		uint32_t b = h1;
		uint32_t c = h2;
		uint32_t d = h3;
		uint32_t e = h4;
		uint32_t f = h5;
		uint32_t g = h6;
		uint32_t h = h7;

		//Main loop
		for (int j = 0; j < 64; j++)
		{
			uint32_t sum0, sum1, Ma, Ch, t1, t2;
			sum0 = RIGHTROTATE(a, 2) ^ RIGHTROTATE(a, 13) ^ RIGHTROTATE(a, 22);
			Ma = (a & b) ^ (a & c) ^ (b & c);
			t2 = sum0 + Ma;
			sum1 = RIGHTROTATE(e, 6) xor RIGHTROTATE(e, 11) xor RIGHTROTATE(e, 25);
			Ch = (e & f) xor ((~e) & g);
			t1 = h + sum1 + Ch + k[j] + w[j];

			h = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}
		//Add hash value to result
		h0 = h0 + a;
		h1 = h1 + b;
		h2 = h2 + c;
		h3 = h3 + d;
		h4 = h4 + e;
		h5 = h5 + f;
		h6 = h6 + g;
		h7 = h7 + h;
	}

	//Construct results into HEX digest
	std::stringstream Append;
	std::string HexResult;

	Append << std::uppercase << std::hex << h0 << h1 << h2 << h3 << h4 << h5 << h6;
	HexResult = Append.str();

	return HexResult;
}

std::string SHA512(std::string message)
{
	//Preprocessing
	{
		uint64_t MessageSize = message.size();
		uint64_t new_len;

		//Endended message length calculation
		for (new_len = MessageSize * 8; new_len % 1024 != 960; new_len++);
		{
			new_len /= 8;
		}

		//append zeroes to end
		message.resize(new_len, '\0');

		//append '1' bit to end
		message[MessageSize] = 0x80;

		//append message size to end
		{
			std::string temp;
			for (int k = 0; k < 8; k++)
			{
				temp += (uint8_t)((8 * MessageSize) >> (8 * k));
			}

			for (int i = 7; i >= 0; --i)
			{
				message += temp[i];
			}
		}
	}

	//h0-h7 var initialization
	uint64_t h0 = 0x6a09e667f3bcc908;
	uint64_t h1 = 0xbb67ae8584caa73b;
	uint64_t h2 = 0x3c6ef372fe94f82b;
	uint64_t h3 = 0xa54ff53a5f1d36f1;
	uint64_t h4 = 0x510e527fade682d1;
	uint64_t h5 = 0x9b05688c2b3e6c1f;
	uint64_t h6 = 0x1f83d9abfb41bd6b;
	uint64_t h7 = 0x5be0cd19137e2179;

	uint64_t k[80] =
	{
		0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
		0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
		0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
		0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
		0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
		0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
		0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
		0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
		0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
		0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
		0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
		0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
		0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
		0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
		0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
	};

	//Divide into blocks
	for (int i = 0; i < message.size(); i += 128)
	{
		//16 32-bit words are extended to 80 32-bit words
		// 0-15 words dont change
		uint64_t w[80];
		for (int j = 0; j < 16; j++)
		{
			uint64_t temp = 0;
			for (int k = 0; k < 8; k++)
			{
				if ((i + (8 * j) + k) <= message.size())
				{
					temp += ((unsigned char)(message[i + (8 * j) + k])) << (56 - 8 * k);
				}
				else break;
			}
			w[j] = temp;
		}
		//16-79 words are extended and right cycle shifted
		uint64_t s0, s1;
		for (int j = 16; j < 80; j++)
		{
			s0 = RIGHTROTATE(w[j - 15], 1) ^ RIGHTROTATE(w[j - 15], 8) ^ (w[j - 15]>> 7);
			s1 = RIGHTROTATE(w[j - 2], 19) ^ RIGHTROTATE(w[j - 2], 61) ^ (w[j - 2]>> 6);
			w[j] = w[j - 16] + s0 + w[j - 7] + s1;
		}

		//ABCDEFGH vector initialization
		uint64_t a = h0;
		uint64_t b = h1;
		uint64_t c = h2;
		uint64_t d = h3;
		uint64_t e = h4;
		uint64_t f = h5;
		uint64_t g = h6;
		uint64_t h = h7;

		//Main loop
		for (int j = 0; j < 80; j++)
		{
			uint64_t sum0, sum1, Ma, Ch, t1, t2;
			sum0 = RIGHTROTATE(a, 28) ^ RIGHTROTATE(a, 34) ^ RIGHTROTATE(a, 39);
			Ma = (a & b) ^ (a & c) ^ (b & c);
			t2 = sum0 + Ma;
			sum1 = RIGHTROTATE(e, 14) ^ RIGHTROTATE(e, 18) ^ RIGHTROTATE(e, 41);
			Ch = (e & f) ^ ((~e) & g);
			t1 = h + sum1 + Ch + k[j] + w[j];

			h = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}
		//Add hash value to result
		h0 = h0 + a;
		h1 = h1 + b;
		h2 = h2 + c;
		h3 = h3 + d;
		h4 = h4 + e;
		h5 = h5 + f;
		h6 = h6 + g;
		h7 = h7 + h;
	}

	//Construct results into HEX digest
	std::stringstream Append;
	std::string HexResult;

	Append << std::uppercase << std::hex << h0 << h1 << h2 << h3 << h4 << h5 << h6 << h7;
	HexResult = Append.str();

	return HexResult;
}

#endif  // HASH_HASHLIB_H_