#ifndef GUNERO_UTIL_H_
#define GUNERO_UTIL_H_

#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/uscs_ppzksnark/uscs_ppzksnark.hpp>
#include <libff/algebra/fields/field_utils.hpp>
#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/edwards/edwards_pp.hpp>
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp>
#include <libff/common/utils.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>

#include "uint256.h"
#include "uint252.h"
#include "serialize.h"

using namespace libsnark;

template <unsigned int BITS>
std::string base_blob<BITS>::GetHex() const
{
    char psz[sizeof(data) * 2 + 1];
    for (unsigned int i = 0; i < sizeof(data); i++)
        sprintf(psz + i * 2, "%02x", data[sizeof(data) - i - 1]);
    return std::string(psz, psz + sizeof(data) * 2);
}

namespace gunero {

typedef libff::alt_bn128_pp BaseType;
typedef libff::Fr<BaseType> FieldType;

bool operator==(const r1cs_primary_input<FieldType> &left, const r1cs_primary_input<FieldType> &right);

// Convert bytes into boolean vector. (MSB to LSB)
std::vector<bool> convertBytesVectorToBitVector(const std::vector<unsigned char>& bytes, size_t bits) {
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
std::vector<unsigned char> convertIntToVectorLE(const uint8_t val_int) {
    std::vector<unsigned char> bytes;

    // for(size_t i = 0; i < 1; i++) {
    //     bytes.push_back(val_int >> (i * 8));
    // }
    bytes.push_back(val_int);

    return bytes;
}
std::vector<bool> uint8_to_bool_vector(uint8_t input, size_t bits) {
    auto num_bv = convertIntToVectorLE(input);

    return convertBytesVectorToBitVector(num_bv, bits);
}

// Convert bytes into boolean vector. (MSB to LSB)
std::vector<bool> convertBytesVectorToVector(const std::vector<unsigned char>& bytes) {
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
std::vector<bool> to_bool_vector(T input) {
    std::vector<unsigned char> input_v(input.begin(), input.end());

    return convertBytesVectorToVector(input_v);
}

// Convert boolean vector into bytes . (LSB to MSB)
std::vector<unsigned char> convertVectorToBytesVector(const std::vector<bool>& bits) {
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

uint160 bool_vector_left_to_uint160(std::vector<bool> input) {
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

uint256 bool_vector_to_uint256(std::vector<bool> input) {
    //std::vector<unsigned char> input_v(input.begin(), input.end());

    //return convertVectorToBytesVector(input_v);

    assert(input.size() == 256);

    std::vector<unsigned char> input_v = convertVectorToBytesVector(input);

    return uint256(input_v);
}

uint256 uint8_to_uint256(uint8_t input) {
    uint256 ret;

    std::generate(ret.begin() + 31, ret.end(), [&]() { return input; });

    return ret;
}

uint160 uint8_to_uint160(uint8_t input) {
    uint160 ret;

    std::generate(ret.begin() + 19, ret.end(), [&]() { return input; });

    return ret;
}

// uint252 uint8_to_uint252(uint8_t input) {
//     uint252 ret;

//     std::generate(ret.begin() + 31, ret.end(), [&]() { return input; });

//     return ret;
// }

std::vector<bool> uint160_to_bool_vector_256_rpad(uint160 input) {
    std::vector<bool> input160 = to_bool_vector(input);

    std::vector<bool> blob(256 - 160);
    input160.insert(input160.end(), blob.begin(), blob.end());

    return input160;
}

std::vector<bool> uint252_to_bool_vector_256(uint252 input) {
    return to_bool_vector(input);
}

std::vector<bool> uint256_to_bool_vector(uint256 input) {
    return to_bool_vector(input);
}

void insert_uint256(std::vector<bool>& into, uint256 from) {
    std::vector<bool> blob = uint256_to_bool_vector(from);
    into.insert(into.end(), blob.begin(), blob.end());
}

void insert_uint_bits(std::vector<bool>& into, uint8_t from, size_t bits) {
    std::vector<bool> blob = uint8_to_bool_vector(from, bits);
    into.insert(into.end(), blob.begin(), blob.end());
}

std::vector<bool> trailing252(std::vector<bool> input) {
    if (input.size() != 256) {
        throw std::length_error("trailing252 input invalid length");
    }

    return std::vector<bool>(input.begin() + 4, input.end());
}

std::vector<bool> uint252_to_bool_vector(uint252 input) {
    return trailing252(to_bool_vector(input));
}

bool operator==(const r1cs_primary_input<FieldType> &left, const r1cs_primary_input<FieldType> &right)
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

int div_ceil(int numerator, int denominator)
{
    std::div_t res = std::div(numerator, denominator);
    return res.rem ? (res.quot + 1) : res.quot;
}

template <unsigned int BITS>
base_blob<BITS>::base_blob(const std::vector<unsigned char>& vch)
{
    assert(vch.size() == sizeof(data));
    memcpy(data, &vch[0], sizeof(data));
}

std::string strprintf(const char *fromat, ...)
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

template<typename T>
void saveToFile(const std::string path, T& obj) {
    std::stringstream ss;
    ss << obj;
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename T>
void loadFromFile(const std::string path, T& objIn) {
    std::stringstream ss;
    std::ifstream fh(path, std::ios::binary);

    if(!fh.is_open()) {
        throw std::runtime_error(strprintf("could not load param file at %s", path));
    }

    ss << fh.rdbuf();
    fh.close();

    ss.rdbuf()->pubseekpos(0, std::ios_base::in);

    T obj;
    ss >> obj;

    objIn = std::move(obj);
}

void
randombytes_buf(void * const buf, const size_t size)
{
    unsigned char *p = (unsigned char *) buf;
    size_t         i;

    for (i = (size_t) 0U; i < size; i++) {
        p[i] = (unsigned char)(std::rand() % 256);
    }
}

uint256 random_uint256()
{
    uint256 ret;
    randombytes_buf(ret.begin(), 32);

    return ret;
}

uint252 random_uint252()
{
    uint256 rand = random_uint256();
    (*rand.begin()) &= 0x0F;

    return uint252(rand);
}

uint160 random_uint160()
{
    uint160 ret;
    randombytes_buf(ret.begin(), 20);

    return ret;
}

} // end namespace `gunero`

#endif /* GUNERO_UTIL_H_ */