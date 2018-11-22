#include <fstream>
#include <mutex>

//#include <libff/common/default_types/ec_pp.hpp> 
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

#ifndef ALT_BN128
#define ALT_BN128
#endif

#ifdef ALT_BN128
// #include <libff/algebra/curves/alt_bn128/alt_bn128_init.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#endif
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
#include "keccak_gadget.hpp"
#include "GuneroProof.hpp"
#include "GuneroMembershipCircuit.hpp"
#include "GuneroTransactionReceiveCircuit.hpp"

typedef libff::alt_bn128_pp BaseType;
typedef libff::Fr<BaseType> FieldType;

using namespace libsnark;
using namespace gunero;

bool operator==(const r1cs_primary_input<FieldType> &left, const r1cs_primary_input<FieldType> &right);

template <unsigned int BITS>
std::string base_blob<BITS>::GetHex() const
{
    char psz[sizeof(data) * 2 + 1];
    for (unsigned int i = 0; i < sizeof(data); i++)
        sprintf(psz + i * 2, "%02x", data[sizeof(data) - i - 1]);
    return std::string(psz, psz + sizeof(data) * 2);
}

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

std::vector<bool> trailing160(std::vector<bool> input) {
    if (input.size() != 256) {
        throw std::length_error("trailing160 input invalid length");
    }

    return std::vector<bool>(input.begin() + 96, input.end());
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

template<typename FieldT>
pb_variable_array<FieldT> gen256zeroes(pb_variable<FieldT>& ZERO) {
    pb_variable_array<FieldT> ret;
    while (ret.size() < 256) {
        ret.emplace_back(ZERO);
    }

    return ret;
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

int main ()
{
    std::srand(std::time(NULL));

    libff::start_profiling();

#ifdef ALT_BN128
    //alt_bn128_pp
    libff::init_alt_bn128_params();
#endif

#define MERKLE_TREE_DEPTH 3
    bool EXECUTE_MEMBERSHIP = false;
    bool EXECUTE_TRANSACTION = false;

    //Test SHA256
    // {
    //     const libff::bit_vector left_bv = libff::int_list_to_bits({0x426bc2d8, 0x4dc86782, 0x81e8957a, 0x409ec148, 0xe6cffbe8, 0xafe6ba4f, 0x9c6f1978, 0xdd7af7e9}, 32);
    //     const libff::bit_vector right_bv = libff::int_list_to_bits({0x038cce42, 0xabd366b8, 0x3ede7e00, 0x9130de53, 0x72cdf73d, 0xee825114, 0x8cb48d1b, 0x9af68ad0}, 32);
    //     const libff::bit_vector hash_bv = libff::int_list_to_bits({0xeffd0b7f, 0x1ccba116, 0x2ee816f7, 0x31c62b48, 0x59305141, 0x990e5c0a, 0xce40d33d, 0x0b1167d1}, 32);

    //     libff::bit_vector block;
    //     block.insert(block.end(), left_bv.begin(), left_bv.end());
    //     block.insert(block.end(), right_bv.begin(), right_bv.end());
    //     libff::bit_vector hash_bv_calc = sha256_two_to_one_hash_gadget<FieldT>::get_hash(block);

    //     assert(hash_bv_calc == hash_bv);
    // }

    ///// MEMBERSHIP PROOF /////
    // Public Parameters:
    // Authorization Root Hash (W)
    // Account Status (N_account)
    // Account View Hash (V_account)

    // Private Parameters:
    // Account Secret Key (s_account)
    // alt: Proof Secret Key (s_proof)
    // alt: Account (A_account)
    // Authorization Merkle Path (M_account[160])
    // Account View Randomizer (r_account)

    //1) Obtain A_account from s_account through EDCSA (secp256k1) operations
    //1 alt) Obtain P_proof from s_proof through PRF operations
    //2) Validate W == calc_root(A_account, N_account, M_account[160]) (User is authorized)
    //2 alt) Validate W == calc_root(A_account, keccak256(P_proof,N_account), M_account[160]) (User is authorized)
    //3) Validate V_account == keccak256(A_account, keccak256(W,r_account) (View Hash is consistent)

    //Public Input variables
    uint256 W;//set
    uint8_t N_account = 1;//1 = authorized
    uint256 V_account;//set

    //Private Input variables
    uint252 s_proof = uint252(uint8_to_uint256(1));//alt
    uint256 r_account;//set

    //Storage variables
    std::vector<gunero_merkle_authentication_node> M_account;
    uint160 A_account;

    //Make test
    {
        libff::bit_vector N_account_lsb(uint256_to_bool_vector(uint8_to_uint256(N_account)));

        uint256 PRF_addr_a_pk_one_calc;
        uint256 leaf_calc;
        {
            libff::bit_vector PRF_addr_a_pk_one_lsb_calc;
            {
                libff::bit_vector one_lsb(252);
                one_lsb.at(251) = true;

                libff::bit_vector zero_lsb(256);

                //1 1 0 0 + a_sk(252) + 0(256)
                libff::bit_vector block(4);
                block.at(0) = true;
                block.at(1) = true;
                block.insert(block.end(), one_lsb.begin(), one_lsb.end());
                block.insert(block.end(), zero_lsb.begin(), zero_lsb.end());

                PRF_addr_a_pk_one_lsb_calc = sha256_two_to_one_hash_gadget<FieldType>::get_hash(block);

                PRF_addr_a_pk_one_calc = bool_vector_to_uint256(PRF_addr_a_pk_one_lsb_calc);
            }
            {
                //leaf = hash(P_proof,N_account)
                libff::bit_vector block;
                block.insert(block.end(), PRF_addr_a_pk_one_lsb_calc.begin(), PRF_addr_a_pk_one_lsb_calc.end());
                block.insert(block.end(), N_account_lsb.begin(), N_account_lsb.end());

                libff::bit_vector leaf_lsb_calc = sha256_two_to_one_hash_gadget<FieldType>::get_hash(block);

                leaf_calc = bool_vector_to_uint256(leaf_lsb_calc);
            }
        }

        libff::bit_vector r_account_lsb(uint256_to_bool_vector(r_account));
        libff::bit_vector P_proof;//alt
        libff::bit_vector leaf;//alt
        libff::bit_vector W_lsb;
        libff::bit_vector view_hash_1_lsb;//alt
        libff::bit_vector A_account_padded_lsb;
        libff::bit_vector V_account_lsb;

        GuneroMembershipCircuit<FieldType, BaseType, sha256_two_to_one_hash_gadget<FieldType>, MERKLE_TREE_DEPTH>::makeTestVariables(
            s_proof,
            N_account_lsb,
            r_account_lsb,
            P_proof,
            leaf,
            M_account,
            A_account_padded_lsb,
            W_lsb,
            view_hash_1_lsb,
            V_account_lsb
            );

        uint256 P_proof_msb = bool_vector_to_uint256(P_proof);

        assert(P_proof_msb == PRF_addr_a_pk_one_calc);

        uint256 leaf_msb = bool_vector_to_uint256(leaf);

        assert(leaf_msb == leaf_calc);

        r_account = bool_vector_to_uint256(r_account_lsb);

        A_account = bool_vector_left_to_uint160(A_account_padded_lsb);

        W = bool_vector_to_uint256(W_lsb);

        V_account = bool_vector_to_uint256(V_account_lsb);
    }

    if (EXECUTE_MEMBERSHIP)
    {
        std::string r1csPath = "/home/sean/Silencer/build/src/r1cs.bin";
        std::string pkPath = "/home/sean/Silencer/build/src/pk.bin";
        std::string vkPath = "/home/sean/Silencer/build/src/vk.bin";

        std::string proofPath = "/home/sean/Silencer/build/src/proof.bin";

        //Generate Membership
        {
            /* generate circuit */
            libff::print_header("Gunero Generator");

            GuneroMembershipCircuit<FieldType, BaseType, sha256_two_to_one_hash_gadget<FieldType>, MERKLE_TREE_DEPTH> gmc;

            gmc.generate(r1csPath, pkPath, vkPath);
        }

        //Prove Membership
        {
            r1cs_ppzksnark_proving_key<BaseType> pk;
            loadFromFile(pkPath, pk);

            r1cs_ppzksnark_verification_key<BaseType> vk;
            loadFromFile(vkPath, vk);

            GuneroMembershipCircuit<FieldType, BaseType, sha256_two_to_one_hash_gadget<FieldType>, MERKLE_TREE_DEPTH> gmc;

            GuneroProof proof;
            bool proven = gmc.prove(
                W,
                N_account,
                V_account,
                s_proof,
                M_account,
                A_account,
                r_account,
                pk,
                vk,
                proof);

            assert(proven);

            saveToFile(proofPath, proof);
        }

        //Verify Membership
        {
            r1cs_ppzksnark_verification_key<BaseType> vk;
            loadFromFile(vkPath, vk);

            r1cs_ppzksnark_processed_verification_key<BaseType> vk_precomp = r1cs_ppzksnark_verifier_process_vk<BaseType>(vk);

            GuneroProof proof;
            loadFromFile(proofPath, proof);

            GuneroMembershipCircuit<FieldType, BaseType, sha256_two_to_one_hash_gadget<FieldType>, MERKLE_TREE_DEPTH> gmc;

            bool verified = gmc.verify(
                W,
                N_account,
                V_account,
                proof,
                vk,
                vk_precomp);

            assert(verified);

            printf("verified: ");
            if (verified)
            {
                printf("true");
            }
            else
            {
                printf("false");
            }
            printf("\n");
        }
    }


    ///// TRANSACTION RECEIVE PROOF /////
    // Public Parameters:
    // Authorization Root Hash (W)
    // Token UID (T)
    // Sender Account View Hash (V_S)
    // Receiver Account View Hash (V_R)
    // Current Transaction Hash (L)

    // Private Parameters:
    // Receiver Private Key (s_R)
    // Receiver Account View Randomizer (r_R)
    // Sender Account Address (A_S)
    // Sender Account View Randomizer (r_S)
    // Firearm Serial Number (F)
    // Firearm View Randomizer (j)

    //1) Obtain A_R from s_R through EDCSA operations
    //2) Validate V_S == hash(A_S + W + r_S) (View Hash is consistent for Sender)
    //3) Validate V_R == hash(A_R + W + r_R) (View Hash is consistent for Receiver)
    //4) Validate T == hash(F + j) (Both parties know the serial number)
    //5) Validate L == hash(A_S + s_R + T + W) (The send proof is consistent, not forged)

    //Public Input variables
    // uint256 W = W;
    uint256 T;//set = hash(F, j)
    uint256 V_S;//set = hash(A_S, hash(W, r_S))
    uint256 V_R = V_account;
    uint256 L;//set = hash(A_S, hash(s_R, hash(T, W)))

    //Private Input variables
    uint252 s_R = s_proof;
    uint256 r_R = r_account;
    uint160 A_S;//= 0
    uint256 r_S = uint8_to_uint256(2);
    uint256 F = uint8_to_uint256(3);
    uint256 j = uint8_to_uint256(4);

    //Make test
    {
        {//T = hash(F, j)
            libff::bit_vector F_lsb = uint256_to_bool_vector(F);
            libff::bit_vector j_lsb = uint256_to_bool_vector(j);

            libff::bit_vector block;
            block.insert(block.end(), F_lsb.begin(), F_lsb.end());
            block.insert(block.end(), j_lsb.begin(), j_lsb.end());

            libff::bit_vector T_lsb = sha256_two_to_one_hash_gadget<FieldType>::get_hash(block);

            T = bool_vector_to_uint256(T_lsb);
        }
        {//V_S = hash(A_S, hash(W, r_S))
            libff::bit_vector W_lsb = uint256_to_bool_vector(W);
            libff::bit_vector r_S_lsb = uint256_to_bool_vector(r_S);

            libff::bit_vector block_1;
            block_1.insert(block_1.end(), W_lsb.begin(), W_lsb.end());
            block_1.insert(block_1.end(), r_S_lsb.begin(), r_S_lsb.end());

            libff::bit_vector hash_1 = sha256_two_to_one_hash_gadget<FieldType>::get_hash(block_1);

            libff::bit_vector A_S_lsb = uint160_to_bool_vector_256_rpad(A_S);

            libff::bit_vector block_2;
            block_2.insert(block_2.end(), A_S_lsb.begin(), A_S_lsb.end());
            block_2.insert(block_2.end(), hash_1.begin(), hash_1.end());

            libff::bit_vector V_S_lsb = sha256_two_to_one_hash_gadget<FieldType>::get_hash(block_2);

            V_S = bool_vector_to_uint256(V_S_lsb);
        }
        {//L = hash(A_S, hash(s_R, hash(T, W)))
            libff::bit_vector T_lsb = uint256_to_bool_vector(T);
            libff::bit_vector W_lsb = uint256_to_bool_vector(W);

            libff::bit_vector block_1;
            block_1.insert(block_1.end(), T_lsb.begin(), T_lsb.end());
            block_1.insert(block_1.end(), W_lsb.begin(), W_lsb.end());

            libff::bit_vector hash_1 = sha256_two_to_one_hash_gadget<FieldType>::get_hash(block_1);

            libff::bit_vector s_R_lsb = uint252_to_bool_vector_256(s_R);

            libff::bit_vector block_2;
            block_2.insert(block_2.end(), s_R_lsb.begin(), s_R_lsb.end());
            block_2.insert(block_2.end(), hash_1.begin(), hash_1.end());

            libff::bit_vector hash_2 = sha256_two_to_one_hash_gadget<FieldType>::get_hash(block_2);

            libff::bit_vector A_S_lsb = uint160_to_bool_vector_256_rpad(A_S);

            libff::bit_vector block_3;
            block_3.insert(block_3.end(), A_S_lsb.begin(), A_S_lsb.end());
            block_3.insert(block_3.end(), hash_2.begin(), hash_2.end());

            libff::bit_vector L_lsb = sha256_two_to_one_hash_gadget<FieldType>::get_hash(block_3);

            L = bool_vector_to_uint256(L_lsb);
        }
    }

    if (EXECUTE_TRANSACTION)
    {
        std::string GTRr1csPath = "/home/sean/Silencer/build/src/GTR.r1cs.bin";
        std::string GTRpkPath = "/home/sean/Silencer/build/src/GTR.pk.bin";
        std::string GTRvkPath = "/home/sean/Silencer/build/src/GTR.vk.bin";

        std::string GTRproofPath = "/home/sean/Silencer/build/src/GTR.proof.bin";

        //Generate Transaction Receive
        {
            /* generate circuit */
            libff::print_header("Gunero Generator");

            GuneroTransactionReceiveCircuit<FieldType, BaseType, sha256_two_to_one_hash_gadget<FieldType>> gtrc;

            gtrc.generate(GTRr1csPath, GTRpkPath, GTRvkPath);
        }

        //Prove Transaction Receive
        {
            r1cs_ppzksnark_proving_key<BaseType> pk;
            loadFromFile(GTRpkPath, pk);

            r1cs_ppzksnark_verification_key<BaseType> vk;
            loadFromFile(GTRvkPath, vk);

            GuneroTransactionReceiveCircuit<FieldType, BaseType, sha256_two_to_one_hash_gadget<FieldType>> gtrc;

            GuneroProof proof;
            bool proven = gtrc.prove(
                W,
                T,
                V_S,
                V_R,
                L,
                s_R,
                r_R,
                A_S,
                r_S,
                F,
                j,
                pk,
                vk,
                proof);

            assert(proven);

            saveToFile(GTRproofPath, proof);
        }

        //Verify Transaction Receive
        {
            r1cs_ppzksnark_verification_key<BaseType> vk;
            loadFromFile(GTRvkPath, vk);

            r1cs_ppzksnark_processed_verification_key<BaseType> vk_precomp = r1cs_ppzksnark_verifier_process_vk<BaseType>(vk);

            GuneroProof proof;
            loadFromFile(GTRproofPath, proof);

            GuneroTransactionReceiveCircuit<FieldType, BaseType, sha256_two_to_one_hash_gadget<FieldType>> gtrc;

            bool verified = gtrc.verify(
                W,
                T,
                V_S,
                V_R,
                L,
                proof,
                vk,
                vk_precomp);

            assert(verified);

            printf("verified: ");
            if (verified)
            {
                printf("true");
            }
            else
            {
                printf("false");
            }
            printf("\n");
        }
    }

    return 0;
}
