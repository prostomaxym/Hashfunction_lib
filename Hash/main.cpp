#include <iostream>
#include "hashlib.h"

int main()
{
	std::cout << "SHA1 Hash examples:" << std::endl;
	std::cout << SHA1("The quick brown fox jumps over the lazy dog") << std::endl;
	std::cout << SHA1("") << std::endl;
	std::cout << std::endl;

	std::cout << "MD5 Hash examples:" << std::endl;
	std::cout << MD5("The quick brown fox jumps over the lazy dog") << std::endl;
	std::cout << MD5("") << std::endl;
	std::cout << std::endl;

	std::cout << "RIPEMD160 Hash examples:" << std::endl;
	std::cout << RIPEMD160("The quick brown fox jumps over the lazy dog") << std::endl;
	std::cout << RIPEMD160("") << std::endl;
	std::cout << std::endl;

	std::cout << "SHA256 Hash examples:" << std::endl;
	std::cout << SHA256("The quick brown fox jumps over the lazy dog") << std::endl;
	std::cout << SHA256("") << std::endl;
	std::cout << std::endl;

	std::cout << "SHA224 Hash examples:" << std::endl;
	std::cout << SHA224("The quick brown fox jumps over the lazy dog") << std::endl;
	std::cout << SHA224("") << std::endl;
	std::cout << std::endl;

	std::cout << "SHA512 Hash examples:" << std::endl;
	std::cout << SHA512("The quick brown fox jumps over the lazy dog") << std::endl;
	std::cout << SHA512("") << std::endl;
	std::cout << std::endl;

	return 0;
}

