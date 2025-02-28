#include <iostream>
#include <string>
#include <openssl/md5.h>
#include <sstream>
#include <iomanip>

std::string calculateMD5(const std::string& input) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)input.c_str(), input.length(), (unsigned char*)&digest);

    std::stringstream ss;
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }

    return ss.str();
}

int main() {
    std::string input;
    std::cout << "Enter a string to calculate its MD5 hash: ";
    std::getline(std::cin, input);

    std::string md5Hash = calculateMD5(input);
    std::cout << "MD5 Hash: " << md5Hash << std::endl;

    std::string targetHash = "7b8d01c3730fe01eafbae3f80c66e4bc";

    if (md5Hash == targetHash) {
        std::cout << "The MD5 hash matches the target hash." << std::endl;
    } else {
        std::cout << "The MD5 hash does not match the target hash." << std::endl;
    }

    return 0;
}
