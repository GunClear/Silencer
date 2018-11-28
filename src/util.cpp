#include "util.h"

using namespace libsnark;

// Convert bytes into boolean vector. (MSB to LSB)
std::vector<bool> gunero::convertBytesVectorToBitVector(const std::vector<unsigned char>& bytes, size_t bits) {
    std::vector<bool> ret;
    ret.resize(bits);

    if (bits <= 8)
    {
        unsigned char c = bytes.at(0);
        for (size_t j = 0; j < bits; j++) {
            ret.at(j) = (c >> (bits-1-j)) & 1;
        }
    }
    else
    {
        // unsigned char c;
        // for (size_t i = 0; i < bytes.size(); i++) {
        //     c = bytes.at(i);
        //     for (size_t j = 0; j < 8; j++) {
        //         ret.at((i*8)+j) = (c >> (7-j)) & 1;
        //     }
        // }
        throw std::runtime_error("cannot compress bit vector when given number of bits > 8");
    }

    return ret;
}
std::vector<unsigned char> gunero::convertIntToVectorLE(const uint8_t val_int) {
    std::vector<unsigned char> bytes;
    bytes.push_back(val_int);

    return bytes;
}
std::vector<bool> gunero::uint8_to_bool_vector(uint8_t input, size_t bits) {
    auto num_bv = convertIntToVectorLE(input);

    return convertBytesVectorToBitVector(num_bv, bits);
}

// Convert bytes into boolean vector. (MSB to LSB)
std::vector<bool> gunero::convertBytesVectorToVector(const std::vector<unsigned char>& bytes) {
    std::vector<bool> ret;
    ret.resize(bytes.size() * 8);

    unsigned char c;
    for (size_t i = 0; i < bytes.size(); i++) {
        c = bytes.at(i);
        for (size_t j = 0; j < 8; j++) {
            ret.at((i*8)+j) = (c >> (7-j)) & 1;
        }
    }

    return ret;
}

template<typename T>
std::vector<bool> gunero::to_bool_vector(T input) {
    std::vector<unsigned char> input_v(input.begin(), input.end());

    return convertBytesVectorToVector(input_v);
}

// Convert boolean vector into bytes . (LSB to MSB)
std::vector<unsigned char> gunero::convertVectorToBytesVector(const std::vector<bool>& bits) {
    assert((bits.size() % 8) == 0);

    std::vector<unsigned char> ret;
    ret.resize(bits.size() / 8);

    unsigned char c;
    //i is byte, j is bit
    for (size_t i = 0; i < (bits.size() / 8); i++) {
        // c = bytes.at(i);
        // for (size_t j = 0; j < 8; j++) {
        //     ret.at((i*8)+j) = (c >> (7-j)) & 1;
        // }
        for (size_t j = 0; j < 8; j++) {
            c = bits.at((i*8)+j) ? 1 : 0;
            ret.at(i) |= (c << (7-j));
        }
    }

    return ret;
}

uint160 gunero::bool_vector_left_to_uint160(std::vector<bool> input) {
    if (input.size() > 160)
    {
        std::vector<unsigned char> input_vlong = convertVectorToBytesVector(input);
        input_vlong.erase(input_vlong.begin() + (160 / 8), input_vlong.end());

        return uint160(input_vlong);
    }
    else
    {
        std::vector<unsigned char> input_v = convertVectorToBytesVector(input);

        return uint160(input_v);
    }
}

uint256 gunero::bool_vector_to_uint256(std::vector<bool> input) {
    assert(input.size() == 256);

    std::vector<unsigned char> input_v = convertVectorToBytesVector(input);

    return uint256(input_v);
}

uint256 gunero::uint8_to_uint256(uint8_t input) {
    uint256 ret;

    std::generate(ret.begin() + 31, ret.end(), [&]() { return input; });

    return ret;
}

uint160 gunero::uint8_to_uint160(uint8_t input) {
    uint160 ret;

    std::generate(ret.begin() + 19, ret.end(), [&]() { return input; });

    return ret;
}

std::vector<bool> gunero::uint160_to_bool_vector_256_rpad(uint160 input) {
    std::vector<bool> input160 = to_bool_vector(input);

    std::vector<bool> blob(256 - 160);
    input160.insert(input160.end(), blob.begin(), blob.end());

    return input160;
}

std::vector<bool> gunero::uint252_to_bool_vector_256(uint252 input) {
    return to_bool_vector(input);
}

std::vector<bool> gunero::uint256_to_bool_vector(uint256 input) {
    return to_bool_vector(input);
}

void gunero::insert_uint256(std::vector<bool>& into, uint256 from) {
    std::vector<bool> blob = uint256_to_bool_vector(from);
    into.insert(into.end(), blob.begin(), blob.end());
}

void gunero::insert_uint_bits(std::vector<bool>& into, uint8_t from, size_t bits) {
    std::vector<bool> blob = uint8_to_bool_vector(from, bits);
    into.insert(into.end(), blob.begin(), blob.end());
}

std::vector<bool> gunero::trailing252(std::vector<bool> input) {
    if (input.size() != 256) {
        throw std::length_error("trailing252 input invalid length");
    }

    return std::vector<bool>(input.begin() + 4, input.end());
}

std::vector<bool> gunero::uint252_to_bool_vector(uint252 input) {
    return trailing252(to_bool_vector(input));
}

bool gunero::operator==(const r1cs_primary_input<FieldType> &left, const r1cs_primary_input<FieldType> &right)
{
    if (left.size() != right.size())
    {
        printf("sizes: %lu -vs- %lu\n", left.size(), right.size());
        return false;
    }

    for (size_t i=0; i<left.size();i++) {
        if (!(left.at(i) == right.at(i)))
        {
            return false;
        }
    }

    return true;
}

int gunero::div_ceil(int numerator, int denominator)
{
    std::div_t res = std::div(numerator, denominator);
    return res.rem ? (res.quot + 1) : res.quot;
}

std::string gunero::strprintf(const char *fromat, ...)
{
    std::string s;
    s.resize(128); // best guess
    char *buff = const_cast<char *>(s.data());

    va_list arglist;
    va_start(arglist, fromat);
    auto len = vsnprintf(buff, 128, fromat, arglist);
    va_end(arglist);

    if (len > 127)
    {
        va_start(arglist, fromat);
        s.resize(len + 1); // leave room for null terminator
        buff = const_cast<char *>(s.data());
        len = vsnprintf(buff, len+1, fromat, arglist);
        va_end(arglist);
    }
    s.resize(len);
    return s; // move semantics FTW
}

void
gunero::randombytes_buf(void * const buf, const size_t size)
{
    unsigned char *p = (unsigned char *) buf;
    size_t         i;

    for (i = (size_t) 0U; i < size; i++) {
        p[i] = (unsigned char)(std::rand() % 256);
    }
}

uint256 gunero::random_uint256()
{
    uint256 ret;
    randombytes_buf(ret.begin(), 32);

    return ret;
}

uint252 gunero::random_uint252()
{
    uint256 rand = random_uint256();
    (*rand.begin()) &= 0x0F;

    return uint252(rand);
}

uint160 gunero::random_uint160()
{
    uint160 ret;
    gunero::randombytes_buf(ret.begin(), 20);

    return ret;
}
