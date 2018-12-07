#ifndef GUNERO_UTIL_H_
#define GUNERO_UTIL_H_

#include <fstream>

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
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>

#include "uint256.h"
#include "uint252.h"
#include "serialize.h"

using namespace libsnark;

namespace gunero {

typedef libff::alt_bn128_pp BaseType;
typedef libff::Fr<BaseType> FieldType;

bool operator==(const r1cs_primary_input<FieldType> &left, const r1cs_primary_input<FieldType> &right);

// Convert bytes into boolean vector. (MSB to LSB)
std::vector<bool> convertBytesVectorToBitVector(const std::vector<unsigned char>& bytes, size_t bits);
std::vector<unsigned char> convertIntToVectorLE(const uint8_t val_int);
std::vector<bool> uint8_to_bool_vector(uint8_t input, size_t bits);

// Convert bytes into boolean vector. (MSB to LSB)
std::vector<bool> convertBytesVectorToVector(const std::vector<unsigned char>& bytes);

template<typename T>
std::vector<bool> to_bool_vector(T input);

// Convert boolean vector into bytes . (LSB to MSB)
std::vector<unsigned char> convertVectorToBytesVector(const std::vector<bool>& bits);

uint160 bool_vector_left_to_uint160(std::vector<bool> input);

uint256 bool_vector_to_uint256(std::vector<bool> input);

uint256 uint8_to_uint256(uint8_t input);

uint160 uint8_to_uint160(uint8_t input);

std::vector<bool> uint160_to_bool_vector_256_rpad(uint160 input);

std::vector<bool> uint252_to_bool_vector_256(uint252 input);

std::vector<bool> uint256_to_bool_vector(uint256 input);

void insert_uint256(std::vector<bool>& into, uint256 from);

void insert_uint_bits(std::vector<bool>& into, uint8_t from, size_t bits);

std::vector<bool> trailing252(std::vector<bool> input);

std::vector<bool> uint252_to_bool_vector(uint252 input);

int div_ceil(int numerator, int denominator);

std::string strprintf(const char *fromat, ...);

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
randombytes_buf(void * const buf, const size_t size);

uint256 random_uint256();

uint252 random_uint252();

uint160 random_uint160();

} // end namespace `gunero`

#endif /* GUNERO_UTIL_H_ */