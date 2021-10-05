#ifndef HASH_HASHLIB_H_
#define HASH_HASHLIB_H_

#include <string>
#include <sstream>

//Bitwise left circular shift
template<typename T1, typename T2> constexpr auto LEFTROTATE(T1 x, T2  c);

//Bitwise right circular shift
template<typename T1, typename T2> constexpr auto RIGHTROTATE(T1 x, T2  c);

std::string preprocessMsg(std::string message);
std::string MD5(std::string message);
std::string RIPEMD160(std::string message);
std::string SHA1(std::string message);
std::string SHA224(std::string message);
std::string SHA256(std::string message);
std::string SHA512(std::string message);
#endif  // HASH_HASHLIB_H_