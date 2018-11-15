#include <fstream>

// inline void assert_except(bool condition) {
//     if (!condition) {
//         throw std::runtime_error("Assertion failed.");
//     }
// }

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

// #ifndef CURVE_BN128
// #define CURVE_BN128
// #endif
#ifndef ALT_BN128
#define ALT_BN128
#endif

#ifdef CURVE_BN128
#include <libff/algebra/curves/bn128/bn128_pp.hpp>
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

#include <zcash/util.h>
#include <zcash/Note.hpp>
#include <zcash/IncrementalMerkleTree.hpp>

#include "sparse_merkle_tree_check_read_gadget.hpp"
#include "sparse_merkle_tree_check_update_gadget.hpp"

#include "serialize.h"
#include "crypto/sha256.h"
#include "GuneroMerkleTree.hpp"

#ifdef CURVE_BN128
    // //bn128_pp
    // typedef libff::Fr<libff::bn128_pp> FieldT;
    // typedef libff::bn128_pp BaseT;
#endif

#ifdef ALT_BN128
    //alt_bn128_pp
    typedef libff::Fr<libff::alt_bn128_pp> FieldT;
    typedef libff::alt_bn128_pp BaseT;
#endif

#ifdef CURVE_BN128
// typedef libff::bn128_pp::G1_type curve_G1;
// typedef libff::bn128_pp::G2_type curve_G2;
// typedef libff::bn128_pp::GT_type curve_GT;
// typedef libff::bn128_pp::Fp_type curve_Fr;
// typedef libff::bn128_pp::Fq_type curve_Fq;
// typedef libff::bn128_pp::Fqe_type curve_Fq2;
#endif

#ifdef ALT_BN128
typedef libff::alt_bn128_pp::G1_type curve_G1;
typedef libff::alt_bn128_pp::G2_type curve_G2;
typedef libff::alt_bn128_pp::GT_type curve_GT;
typedef libff::alt_bn128_pp::Fp_type curve_Fr;
typedef libff::alt_bn128_pp::Fq_type curve_Fq;
typedef libff::alt_bn128_pp::Fqe_type curve_Fq2;
#endif

using namespace libsnark;
using namespace libzcash;
using namespace gunero;

std::ostream& operator<<(std::ostream &out, const libff::bit_vector &a);
std::istream& operator>>(std::istream &in, libff::bit_vector &a);
std::ostream& operator<<(std::ostream &out, const std::vector<libff::bit_vector> &a);
std::istream& operator>>(std::istream &in, std::vector<libff::bit_vector> &a);

bool operator==(const r1cs_primary_input<FieldT> &left, const r1cs_primary_input<FieldT> &right);

uint256 random_uint256();
uint252 random_uint252();
uint160 random_uint160();

#define NOTEENCRYPTION_AUTH_BYTES 16

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

uint256 bool_vector_to_uint256(std::vector<bool> input) {
    //std::vector<unsigned char> input_v(input.begin(), input.end());

    //return convertVectorToBytesVector(input_v);

    std::vector<unsigned char> input_v = convertVectorToBytesVector(input);

    return uint256(input_v);
}

std::vector<bool> uint256_to_bool_vector(uint256 input) {
    return to_bool_vector(input);
}

void insert_uint256(std::vector<bool>& into, uint256 from) {
    std::vector<bool> blob = uint256_to_bool_vector(from);
    into.insert(into.end(), blob.begin(), blob.end());
}

//bool operator==(const FieldT &left, const FieldT &right);
bool operator==(const r1cs_primary_input<FieldT> &left, const r1cs_primary_input<FieldT> &right)
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

// template<size_t MLEN>
// class NoteEncryption {
// protected:
//     enum { CLEN=MLEN+NOTEENCRYPTION_AUTH_BYTES };
//     uint256 epk;
//     uint256 esk;
//     unsigned char nonce;
//     uint256 hSig;

// public:
//     typedef boost::array<unsigned char, CLEN> Ciphertext;
//     typedef boost::array<unsigned char, MLEN> Plaintext;

//     NoteEncryption(uint256 hSig);

//     // Gets the ephemeral public key
//     uint256 get_epk() {
//         return epk;
//     }

//     // Encrypts `message` with `pk_enc` and returns the ciphertext.
//     // This is only called ZC_NUM_JS_OUTPUTS times for a given instantiation; 
//     // but can be called 255 times before the nonce-space runs out.
//     Ciphertext encrypt(const uint256 &pk_enc,
//                        const Plaintext &message
//                       );

//     // Creates a NoteEncryption private key
//     static uint256 generate_privkey(const uint252 &a_sk);

//     // Creates a NoteEncryption public key from a private key
//     static uint256 generate_pubkey(const uint256 &sk_enc);
// };

// template<size_t MLEN>
// class NoteDecryption {
// protected:
//     enum { CLEN=MLEN+NOTEENCRYPTION_AUTH_BYTES };
//     uint256 sk_enc;
//     uint256 pk_enc;

// public:
//     typedef boost::array<unsigned char, CLEN> Ciphertext;
//     typedef boost::array<unsigned char, MLEN> Plaintext;

//     NoteDecryption() { }
//     NoteDecryption(uint256 sk_enc);

//     Plaintext decrypt(const Ciphertext &ciphertext,
//                       const uint256 &epk,
//                       const uint256 &hSig,
//                       unsigned char nonce
//                      ) const;

//     friend inline bool operator==(const NoteDecryption& a, const NoteDecryption& b) {
//         return a.sk_enc == b.sk_enc && a.pk_enc == b.pk_enc;
//     }
//     friend inline bool operator<(const NoteDecryption& a, const NoteDecryption& b) {
//         return (a.sk_enc < b.sk_enc ||
//                 (a.sk_enc == b.sk_enc && a.pk_enc < b.pk_enc));
//     }
// };

#define ZC_NOTEPLAINTEXT_LEADING 1
#define ZC_V_SIZE 8
#define ZC_RHO_SIZE 32
#define ZC_R_SIZE 32
#define ZC_MEMO_SIZE 512
#define ZC_NOTEPLAINTEXT_SIZE (ZC_NOTEPLAINTEXT_LEADING + ZC_V_SIZE + ZC_RHO_SIZE + ZC_R_SIZE + ZC_MEMO_SIZE)

// typedef NoteEncryption<ZC_NOTEPLAINTEXT_SIZE> ZCNoteEncryption;
// typedef NoteDecryption<ZC_NOTEPLAINTEXT_SIZE> ZCNoteDecryption;

// Convert boolean vector (big endian) to integer
uint64_t convertVectorToInt(const std::vector<bool>& v) {
    if (v.size() > 64) {
        throw std::length_error ("boolean vector can't be larger than 64 bits");
    }

    uint64_t result = 0;
    for (size_t i=0; i<v.size();i++) {
        if (v.at(i)) {
            result |= (uint64_t)1 << ((v.size() - 1) - i);
        }
    }

    return result;
}

template<typename FieldT>
linear_combination<FieldT> packed_addition_direct(pb_variable_array<FieldT> input) {
    return pb_packing_sum<FieldT>(pb_variable_array<FieldT>(
        input.rbegin(), input.rend()
    ));
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

template<typename FieldT, typename HashT, size_t tree_depth>
class gunero_merkle_tree_gadget : gadget<FieldT> {
private:
    pb_variable_array<FieldT> positions;
    std::shared_ptr<merkle_authentication_path_variable<FieldT, HashT>> authvars;
    std::shared_ptr<merkle_tree_check_read_gadget<FieldT, HashT>> auth;

public:
    gunero_merkle_tree_gadget(
        protoboard<FieldT>& pb,
        digest_variable<FieldT>& leaf,
        digest_variable<FieldT>& root,
        const pb_variable<FieldT>& enforce,
        const std::string &annotation_prefix
    ) : gadget<FieldT>(pb, annotation_prefix) {
        positions.allocate(pb, tree_depth);
        authvars.reset(new merkle_authentication_path_variable<FieldT, HashT>(
            pb, tree_depth, "auth"
        ));
        auth.reset(new merkle_tree_check_read_gadget<FieldT, HashT>(
            pb,
            tree_depth,
            positions,
            leaf,
            root,
            *authvars,
            enforce,
            "path"
        ));
    }

    void generate_r1cs_constraints() {
        for (size_t i = 0; i < tree_depth; i++) {
            // TODO: This might not be necessary, and doesn't
            // appear to be done in libsnark's tests, but there
            // is no documentation, so let's do it anyway to
            // be safe.
            generate_boolean_r1cs_constraint<FieldT>(
                this->pb,
                positions[i],
                "boolean_positions"
            );
        }

        authvars->generate_r1cs_constraints();
        auth->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(const GuneroMerklePath& path) {
        // TODO: Change libsnark so that it doesn't require this goofy
        // number thing in its API.
        size_t path_index = convertVectorToInt(path.index);

        positions.fill_with_bits_of_ulong(this->pb, path_index);

        authvars->generate_r1cs_witness(path_index, path.authentication_path);
        auth->generate_r1cs_witness();
    }
};

template<typename FieldT, typename BaseT, typename HashT, size_t tree_depth>
class guneromembership_gadget : public gadget<FieldT> {
public:
    // Verifier inputs
    // pb_variable_array<FieldT> zk_packed_inputs;
    // pb_variable_array<FieldT> zk_unpacked_inputs;
    // std::shared_ptr<multipacking_gadget<FieldT>> unpacker;

    std::shared_ptr<digest_variable<FieldT>> zk_merkle_root;

    // Aux inputs
    // pb_variable<FieldT> ZERO;
    std::shared_ptr<digest_variable<FieldT>> leaf_digest;
    std::shared_ptr<gunero_merkle_tree_gadget<FieldT, HashT, tree_depth>> witness_input;
    pb_variable_array<FieldT> status_uint2;

    guneromembership_gadget(protoboard<FieldT>& pb)
        : gadget<FieldT>(pb, "guneromembership_gadget")
    {
        // Verifier inputs
        {
            // // The verification inputs are all bit-strings of various
            // // lengths (256-bit digests and 64-bit integers) and so we
            // // pack them into as few field elements as possible. (The
            // // more verification inputs you have, the more expensive
            // // verification is.)
            // zk_packed_inputs.allocate(pb, verifying_field_element_size());
            // pb.set_input_sizes(verifying_field_element_size());

            // alloc_uint256(zk_unpacked_inputs, zk_merkle_root);

            // assert(zk_unpacked_inputs.size() == verifying_input_bit_size());

            // // This gadget will ensure that all of the inputs we provide are
            // // boolean constrained.
            // unpacker.reset(new multipacking_gadget<FieldT>(
            //     pb,
            //     zk_unpacked_inputs,
            //     zk_packed_inputs,
            //     FieldT::capacity(),
            //     "unpacker"
            // ));

            zk_merkle_root.reset(new digest_variable<FieldT>(pb, 256, "root"));

            pb.set_input_sizes(verifying_field_element_size());
        }

        // // We need a constant "zero" variable in some contexts. In theory
        // // it should never be necessary, but libsnark does not synthesize
        // // optimal circuits.
        // // 
        // // The first variable of our constraint system is constrained
        // // to be one automatically for us, and is known as `ONE`.
        // ZERO.allocate(pb);

        leaf_digest.reset(new digest_variable<FieldT>(pb, 256, "leaf"));

        status_uint2.allocate(pb, 2);

        witness_input.reset(new gunero_merkle_tree_gadget<FieldT, HashT, tree_depth>(
            pb,
            *leaf_digest,
            *zk_merkle_root,
            ONE,
            "witness_input"));
    }

    ~guneromembership_gadget()
    {

    }

    static size_t verifying_input_bit_size() {
        size_t acc = 0;

        acc += HashT::get_digest_len(); // the merkle root (anchor) => libff::bit_vector root(digest_len);

        return acc;
    }

    static size_t verifying_field_element_size() {
        return div_ceil(verifying_input_bit_size(), FieldT::capacity());
    }

    // void load_r1cs_constraints()
    // {
    //     libff::print_header("Gunero load constraints");

    //     // path_var.generate_r1cs_constraints();
    //     merkle_tree->generate_r1cs_constraints();

    //     // const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    //     // r1cs_constraint_system<FieldT> constraint_system;
    //     // loadFromFile(r1csPath, mpb.constraint_system);

    //     printf("\n"); libff::print_indent(); libff::print_mem("after load"); libff::print_time("after load");

    //     // r1cs_ppzksnark_keypair<BaseT> keypair = r1cs_ppzksnark_generator<BaseT>(constraint_system);

    //     // saveToFile(pkPath, keypair.pk);
    //     // saveToFile(vkPath, keypair.vk);

    //     // printf("\n"); libff::print_indent(); libff::print_mem("after constraints"); libff::print_time("after constraints");
    // }

    void generate_r1cs_constraints(
        const std::string& r1csPath,
        // const std::string& pkPath,
        r1cs_ppzksnark_proving_key<BaseT>& pk,
        // const std::string& vkPath
        r1cs_ppzksnark_verification_key<BaseT>& vk
        )
    {
        libff::print_header("Gunero constraints");

        // // The true passed here ensures all the inputs
        // // are boolean constrained.
        // unpacker->generate_r1cs_constraints(true);

        zk_merkle_root->generate_r1cs_constraints();

        // // Constrain `ZERO`
        // generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero(), "ZERO");

        // Constrain bitness of leaf_digest
        leaf_digest->generate_r1cs_constraints();

        // Constrain bitness of merkle_tree
        witness_input->generate_r1cs_constraints();

        // // Perform the critical check
        // {
        //     // linear_combination<FieldT> left_side = packed_addition(zk_vpub_old);
        //     // left_side = left_side + packed_addition(zk_input_notes[i]->value);

        //     // linear_combination<FieldT> right_side = packed_addition(zk_vpub_new);
        //     // right_side = right_side + packed_addition(zk_output_notes[i]->value);

        //     // Ensure that both sides are equal
        //     this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
        //         1,
        //         zk_merkle_root,
        //         merkle_tree[CARP]
        //     ));
        // }

        // {
        //     pb_linear_combination<FieldT> lc_0(status_uint2[0]);

        //     generate_r1cs_equals_const_constraint<FieldT>(
        //         this->pb,
        //         lc_0,
        //         0,
        //         "");

        //     pb_linear_combination<FieldT> lc_1(status_uint2[1]);

        //     generate_r1cs_equals_const_constraint<FieldT>(
        //         this->pb,
        //         lc_1,
        //         1,
        //         "");
        // }

        // Ensure that status is a 2-bit integer.
        for (size_t i = 0; i < 2; i++) {
            generate_boolean_r1cs_constraint<FieldT>(
                this->pb,
                status_uint2[i],
                ""
            );
        }

        {
            // Ensure that reality is true
            linear_combination<FieldT> left_side = packed_addition_direct(status_uint2);

            linear_combination<FieldT> right_side = packed_addition_direct(status_uint2);

            // Ensure that both sides are equal
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                1,
                left_side,
                right_side
            ));
            }

        {
            const r1cs_constraint_system<FieldT> constraint_system = this->pb.get_constraint_system();

            if (r1csPath.length() > 0)
            {
                saveToFile(r1csPath, constraint_system);
            }

            printf("\n"); libff::print_indent(); libff::print_mem("after generator"); libff::print_time("after generator");

            r1cs_ppzksnark_keypair<BaseT> keypair = r1cs_ppzksnark_generator<BaseT>(constraint_system);

            // if (pkPath.length() > 0)
            // {
            //     saveToFile(pkPath, keypair.pk);
            // }
            pk = keypair.pk;
            // if (vkPath.length() > 0)
            // {
            //     saveToFile(vkPath, keypair.vk);
            // }
            vk = keypair.vk;
        }

        printf("\n"); libff::print_indent(); libff::print_mem("after constraints"); libff::print_time("after constraints");
    }

    static r1cs_primary_input<FieldT> witness_map(
        const uint256& rt
    ) {
        std::vector<bool> verify_inputs;

        insert_uint256(verify_inputs, rt);
        
        assert(verify_inputs.size() == verifying_input_bit_size());
        auto verify_field_elements = libff::pack_bit_vector_into_field_element_vector<FieldT>(verify_inputs);
        assert(verify_field_elements.size() == verifying_field_element_size());
        return verify_field_elements;
    }

    void generate_r1cs_witness(
        const libff::bit_vector& root,
        const libff::bit_vector& leaf,
        const GuneroMerklePath& path,
        const uint8_t Status
    )
    {
        // // Witness `zero`
        // this->pb.val(ZERO) = FieldT::zero();

        // zk_merkle_root->generate_r1cs_witness(root);
        // Witness rt. This is not a sanity check.
        //
        // This ensures the read gadget constrains
        // the intended root in the event that
        // both inputs are zero-valued.
        zk_merkle_root->bits.fill_with_bits(
            this->pb,
            root
        );

        // leaf_digest->generate_r1cs_witness(leaf);
        // Witness leaf
        leaf_digest->bits.fill_with_bits(
            this->pb,
            leaf
        );

        // Witness merkle tree authentication path
        witness_input->generate_r1cs_witness(path);

        // Witness Status bits
        status_uint2.fill_with_bits(
            this->pb,
            uint8_to_bool_vector(Status, 2)
        );

        // [SANITY CHECK] Ensure that the intended root
        // was witnessed by the inputs, even if the read
        // gadget overwrote it. This allows the prover to
        // fail instead of the verifier, in the event that
        // the roots of the inputs do not match the
        // treestate provided to the proving API.
        zk_merkle_root->bits.fill_with_bits(
            this->pb,
            root
        );

        // // This happens last, because only by now are all the
        // // verifier inputs resolved.
        // unpacker->generate_r1cs_witness_from_bits();
    }

    // void verify(
    //     const libff::bit_vector& address_bits,
    //     const libff::bit_vector& leaf,
    //     const libff::bit_vector& root,
    //     const std::string& vkPath
    // )
    // {
    //     libff::print_header("Gunero verify");

    //     r1cs_ppzksnark_verification_key<BaseT> vk;
    //     loadFromFile(vkPath, vk);

    //     r1cs_ppzksnark_processed_verification_key<BaseT> vk_precomp = r1cs_ppzksnark_verifier_process_vk(vk);

    //     /* make sure that read checker didn't accidentally overwrite anything */
    //     // address_bits_va.fill_with_bits(this->pb, address_bits);
    //     // leaf_digest.generate_r1cs_witness(leaf);
    //     zk_merkle_root.generate_r1cs_witness(root);
    //     assert(this->pb.is_satisfied());

    //     const size_t num_constraints = this->pb.num_constraints();
    //     const size_t expected_constraints = merkle_tree_check_read_gadget<FieldT, HashT>::expected_constraints(tree_depth);
    //     assert(num_constraints == expected_constraints);
    //     printf("\n"); libff::print_indent(); libff::print_mem("after verify"); libff::print_time("after verify");
    // }

    void alloc_uint256(
        pb_variable_array<FieldT>& packed_into,
        std::shared_ptr<digest_variable<FieldT>>& var
    ) {
        var.reset(new digest_variable<FieldT>(this->pb, 256, ""));
        packed_into.insert(packed_into.end(), var->bits.begin(), var->bits.end());
    }
};

// class PaymentAddress {
// public:
//     uint256 a_pk;
//     uint256 pk_enc;

//     PaymentAddress() : a_pk(), pk_enc() { }
//     PaymentAddress(uint256 a_pk, uint256 pk_enc) : a_pk(a_pk), pk_enc(pk_enc) { }

//     ADD_SERIALIZE_METHODS;

//     template <typename Stream, typename Operation>
//     inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
//         READWRITE(a_pk);
//         READWRITE(pk_enc);
//     }

//     //! Get the 256-bit SHA256d hash of this payment address.
//     uint256 GetHash() const;

//     friend inline bool operator==(const PaymentAddress& a, const PaymentAddress& b) {
//         return a.a_pk == b.a_pk && a.pk_enc == b.pk_enc;
//     }
//     friend inline bool operator<(const PaymentAddress& a, const PaymentAddress& b) {
//         return (a.a_pk < b.a_pk ||
//                 (a.a_pk == b.a_pk && a.pk_enc < b.pk_enc));
//     }
// };

// class ViewingKey : public uint256 {
// public:
//     ViewingKey(uint256 sk_enc) : uint256(sk_enc) { }

//     uint256 pk_enc();
// };

// class SpendingKey : public uint252 {
// public:
//     SpendingKey() : uint252() { }
//     SpendingKey(uint252 a_sk) : uint252(a_sk) { }

//     static SpendingKey random();

//     ViewingKey viewing_key() const;
//     PaymentAddress address() const;
// };

// class Note {
// public:
//     uint256 a_pk;
//     uint64_t value;
//     uint256 rho;
//     uint256 r;

//     Note(uint256 a_pk, uint64_t value, uint256 rho, uint256 r)
//         : a_pk(a_pk), value(value), rho(rho), r(r) {}

//     Note();

//     uint256 cm() const;
//     uint256 nullifier(const SpendingKey& a_sk) const;
// };

// template<typename FieldT>
// class note_gadget : public gadget<FieldT> {
// public:
//     pb_variable_array<FieldT> value;
//     std::shared_ptr<digest_variable<FieldT>> r;

//     note_gadget(protoboard<FieldT> &pb) : gadget<FieldT>(pb) {
//         value.allocate(pb, 64);
//         r.reset(new digest_variable<FieldT>(pb, 256, ""));
//     }

//     void generate_r1cs_constraints() {
//         for (size_t i = 0; i < 64; i++) {
//             generate_boolean_r1cs_constraint<FieldT>(
//                 this->pb,
//                 value[i],
//                 "boolean_value"
//             );
//         }

//         r->generate_r1cs_constraints();
//     }

//     void generate_r1cs_witness(const Note& note) {
//         r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note.r));
//         value.fill_with_bits(this->pb, uint64_to_bool_vector(note.value));
//     }
// };

// template<typename FieldT>
// class note_commitment_gadget : gadget<FieldT> {
// private:
//     std::shared_ptr<block_variable<FieldT>> block1;
//     std::shared_ptr<block_variable<FieldT>> block2;
//     std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher1;
//     std::shared_ptr<digest_variable<FieldT>> intermediate_hash;
//     std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher2;

// public:
//     note_commitment_gadget(
//         protoboard<FieldT> &pb,
//         pb_variable<FieldT>& ZERO,
//         pb_variable_array<FieldT>& a_pk,
//         pb_variable_array<FieldT>& v,
//         pb_variable_array<FieldT>& rho,
//         pb_variable_array<FieldT>& r,
//         std::shared_ptr<digest_variable<FieldT>> result
//     ) : gadget<FieldT>(pb) {
//         pb_variable_array<FieldT> leading_byte =
//             from_bits({1, 0, 1, 1, 0, 0, 0, 0}, ZERO);

//         pb_variable_array<FieldT> first_of_rho(rho.begin(), rho.begin()+184);
//         pb_variable_array<FieldT> last_of_rho(rho.begin()+184, rho.end());

//         intermediate_hash.reset(new digest_variable<FieldT>(pb, 256, ""));

//         // final padding
//         pb_variable_array<FieldT> length_padding =
//             from_bits({
//                 // padding
//                 1,0,0,0,0,0,0,0,
//                 0,0,0,0,0,0,0,0,
//                 0,0,0,0,0,0,0,0,
//                 0,0,0,0,0,0,0,0,
//                 0,0,0,0,0,0,0,0,
//                 0,0,0,0,0,0,0,0,
//                 0,0,0,0,0,0,0,0,
//                 0,0,0,0,0,0,0,0,
//                 0,0,0,0,0,0,0,0,
//                 0,0,0,0,0,0,0,0,
//                 0,0,0,0,0,0,0,0,
//                 0,0,0,0,0,0,0,0,
//                 0,0,0,0,0,0,0,0,
//                 0,0,0,0,0,0,0,0,
//                 0,0,0,0,0,0,0,0,

//                 // length of message (840 bits)
//                 0,0,0,0,0,0,0,0,
//                 0,0,0,0,0,0,0,0,
//                 0,0,0,0,0,0,0,0,
//                 0,0,0,0,0,0,0,0,
//                 0,0,0,0,0,0,0,0,
//                 0,0,0,0,0,0,0,0,
//                 0,0,0,0,0,0,1,1,
//                 0,1,0,0,1,0,0,0
//             }, ZERO);

//         block1.reset(new block_variable<FieldT>(pb, {
//             leading_byte,
//             a_pk,
//             v,
//             first_of_rho
//         }, ""));

//         block2.reset(new block_variable<FieldT>(pb, {
//             last_of_rho,
//             r,
//             length_padding
//         }, ""));

//         pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

//         hasher1.reset(new sha256_compression_function_gadget<FieldT>(
//             pb,
//             IV,
//             block1->bits,
//             *intermediate_hash,
//         ""));

//         pb_linear_combination_array<FieldT> IV2(intermediate_hash->bits);

//         hasher2.reset(new sha256_compression_function_gadget<FieldT>(
//             pb,
//             IV2,
//             block2->bits,
//             *result,
//         ""));
//     }

//     void generate_r1cs_constraints() {
//         hasher1->generate_r1cs_constraints();
//         hasher2->generate_r1cs_constraints();
//     }

//     void generate_r1cs_witness() {
//         hasher1->generate_r1cs_witness();
//         hasher2->generate_r1cs_witness();
//     }
// };

// template<typename FieldT>
// class PRF_gadget : gadget<FieldT> {
// private:
//     std::shared_ptr<block_variable<FieldT>> block;
//     std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher;
//     std::shared_ptr<digest_variable<FieldT>> result;

// public:
//     PRF_gadget(
//         protoboard<FieldT>& pb,
//         pb_variable<FieldT>& ZERO,
//         bool a,
//         bool b,
//         bool c,
//         bool d,
//         pb_variable_array<FieldT> x,
//         pb_variable_array<FieldT> y,
//         std::shared_ptr<digest_variable<FieldT>> result
//     ) : gadget<FieldT>(pb), result(result) {

//         pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

//         pb_variable_array<FieldT> discriminants;
//         discriminants.emplace_back(a ? ONE : ZERO);
//         discriminants.emplace_back(b ? ONE : ZERO);
//         discriminants.emplace_back(c ? ONE : ZERO);
//         discriminants.emplace_back(d ? ONE : ZERO);

//         block.reset(new block_variable<FieldT>(pb, {
//             discriminants,
//             x,
//             y
//         }, "PRF_block"));

//         hasher.reset(new sha256_compression_function_gadget<FieldT>(
//             pb,
//             IV,
//             block->bits,
//             *result,
//         "PRF_hasher"));
//     }

//     void generate_r1cs_constraints() {
//         hasher->generate_r1cs_constraints();
//     }

//     void generate_r1cs_witness() {
//         hasher->generate_r1cs_witness();
//     }
// };

// template<typename FieldT>
// pb_variable_array<FieldT> gen256zeroes(pb_variable<FieldT>& ZERO) {
//     pb_variable_array<FieldT> ret;
//     while (ret.size() < 256) {
//         ret.emplace_back(ZERO);
//     }

//     return ret;
// }

// template<typename FieldT>
// class PRF_addr_a_pk_gadget : public PRF_gadget<FieldT> {
// public:
//     PRF_addr_a_pk_gadget(
//         protoboard<FieldT>& pb,
//         pb_variable<FieldT>& ZERO,
//         pb_variable_array<FieldT>& a_sk,
//         std::shared_ptr<digest_variable<FieldT>> result
//     ) : PRF_gadget<FieldT>(pb, ZERO, 1, 1, 0, 0, a_sk, gen256zeroes(ZERO), result) {}
// };

// template<typename FieldT>
// class PRF_nf_gadget : public PRF_gadget<FieldT> {
// public:
//     PRF_nf_gadget(
//         protoboard<FieldT>& pb,
//         pb_variable<FieldT>& ZERO,
//         pb_variable_array<FieldT>& a_sk,
//         pb_variable_array<FieldT>& rho,
//         std::shared_ptr<digest_variable<FieldT>> result
//     ) : PRF_gadget<FieldT>(pb, ZERO, 1, 1, 1, 0, a_sk, rho, result) {}
// };

// template<typename FieldT>
// class PRF_pk_gadget : public PRF_gadget<FieldT> {
// public:
//     PRF_pk_gadget(
//         protoboard<FieldT>& pb,
//         pb_variable<FieldT>& ZERO,
//         pb_variable_array<FieldT>& a_sk,
//         pb_variable_array<FieldT>& h_sig,
//         bool nonce,
//         std::shared_ptr<digest_variable<FieldT>> result
//     ) : PRF_gadget<FieldT>(pb, ZERO, 0, nonce, 0, 0, a_sk, h_sig, result) {}
// };

// template<typename FieldT>
// class PRF_rho_gadget : public PRF_gadget<FieldT> {
// public:
//     PRF_rho_gadget(
//         protoboard<FieldT>& pb,
//         pb_variable<FieldT>& ZERO,
//         pb_variable_array<FieldT>& phi,
//         pb_variable_array<FieldT>& h_sig,
//         bool nonce,
//         std::shared_ptr<digest_variable<FieldT>> result
//     ) : PRF_gadget<FieldT>(pb, ZERO, 0, nonce, 1, 0, phi, h_sig, result) {}
// };

// template<typename FieldT, typename HashT, size_t tree_depth>
// class input_note_gadget : public note_gadget<FieldT> {
// private:
//     std::shared_ptr<digest_variable<FieldT>> a_pk;
//     std::shared_ptr<digest_variable<FieldT>> rho;

//     std::shared_ptr<digest_variable<FieldT>> commitment;
//     std::shared_ptr<note_commitment_gadget<FieldT>> commit_to_inputs;

//     pb_variable<FieldT> value_enforce;
//     std::shared_ptr<gunero_merkle_tree_gadget<FieldT, HashT, tree_depth>> witness_input;

//     std::shared_ptr<PRF_addr_a_pk_gadget<FieldT>> spend_authority;
//     std::shared_ptr<PRF_nf_gadget<FieldT>> expose_nullifiers;
// public:
//     std::shared_ptr<digest_variable<FieldT>> a_sk;

//     input_note_gadget(
//         protoboard<FieldT>& pb,
//         pb_variable<FieldT>& ZERO,
//         std::shared_ptr<digest_variable<FieldT>> nullifier,
//         digest_variable<FieldT> rt
//     ) : note_gadget<FieldT>(pb) {
//         a_sk.reset(new digest_variable<FieldT>(pb, 252, ""));
//         a_pk.reset(new digest_variable<FieldT>(pb, 256, ""));
//         rho.reset(new digest_variable<FieldT>(pb, 256, ""));
//         commitment.reset(new digest_variable<FieldT>(pb, 256, ""));

//         spend_authority.reset(new PRF_addr_a_pk_gadget<FieldT>(
//             pb,
//             ZERO,
//             a_sk->bits,
//             a_pk
//         ));

//         expose_nullifiers.reset(new PRF_nf_gadget<FieldT>(
//             pb,
//             ZERO,
//             a_sk->bits,
//             rho->bits,
//             nullifier
//         ));

//         commit_to_inputs.reset(new note_commitment_gadget<FieldT>(
//             pb,
//             ZERO,
//             a_pk->bits,
//             this->value,
//             rho->bits,
//             this->r->bits,
//             commitment
//         ));

//         value_enforce.allocate(pb);

//         witness_input.reset(new gunero_merkle_tree_gadget<FieldT, HashT, tree_depth>(
//             pb,
//             *commitment,
//             rt,
//             value_enforce
//         ));
//     }

//     void generate_r1cs_constraints() {
//         note_gadget<FieldT>::generate_r1cs_constraints();

//         a_sk->generate_r1cs_constraints();
//         rho->generate_r1cs_constraints();

//         spend_authority->generate_r1cs_constraints();
//         expose_nullifiers->generate_r1cs_constraints();

//         commit_to_inputs->generate_r1cs_constraints();

//         // value * (1 - enforce) = 0
//         // Given `enforce` is boolean constrained:
//         // If `value` is zero, `enforce` _can_ be zero.
//         // If `value` is nonzero, `enforce` _must_ be one.
//         generate_boolean_r1cs_constraint<FieldT>(this->pb, value_enforce,"");

//         this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
//             packed_addition(this->value),
//             (1 - value_enforce),
//             0
//         ), "");

//         witness_input->generate_r1cs_constraints();
//     }

//     void generate_r1cs_witness(
//         const GuneroMerklePath& path,
//         const SpendingKey& key,
//         const Note& note
//     ) {
//         note_gadget<FieldT>::generate_r1cs_witness(note);

//         // Witness a_sk for the input
//         a_sk->bits.fill_with_bits(
//             this->pb,
//             uint252_to_bool_vector(key)
//         );

//         // Witness a_pk for a_sk with PRF_addr
//         spend_authority->generate_r1cs_witness();

//         // [SANITY CHECK] Witness a_pk with note information
//         a_pk->bits.fill_with_bits(
//             this->pb,
//             uint256_to_bool_vector(note.a_pk)
//         );

//         // Witness rho for the input note
//         rho->bits.fill_with_bits(
//             this->pb,
//             uint256_to_bool_vector(note.rho)
//         );

//         // Witness the nullifier for the input note
//         expose_nullifiers->generate_r1cs_witness();

//         // Witness the commitment of the input note
//         commit_to_inputs->generate_r1cs_witness();

//         // [SANITY CHECK] Ensure the commitment is
//         // valid.
//         commitment->bits.fill_with_bits(
//             this->pb,
//             uint256_to_bool_vector(note.cm())
//         );

//         // Set enforce flag for nonzero input value
//         this->pb.val(value_enforce) = (note.value != 0) ? FieldT::one() : FieldT::zero();

//         // Witness merkle tree authentication path
//         witness_input->generate_r1cs_witness(path);
//     }
// };

// template<typename FieldT>
// class output_note_gadget : public note_gadget<FieldT> {
// private:
//     std::shared_ptr<digest_variable<FieldT>> rho;
//     std::shared_ptr<digest_variable<FieldT>> a_pk;

//     std::shared_ptr<PRF_rho_gadget<FieldT>> prevent_faerie_gold;
//     std::shared_ptr<note_commitment_gadget<FieldT>> commit_to_outputs;

// public:
//     output_note_gadget(
//         protoboard<FieldT>& pb,
//         pb_variable<FieldT>& ZERO,
//         pb_variable_array<FieldT>& phi,
//         pb_variable_array<FieldT>& h_sig,
//         bool nonce,
//         std::shared_ptr<digest_variable<FieldT>> commitment
//     ) : note_gadget<FieldT>(pb) {
//         rho.reset(new digest_variable<FieldT>(pb, 256, ""));
//         a_pk.reset(new digest_variable<FieldT>(pb, 256, ""));

//         // Do not allow the caller to choose the same "rho"
//         // for any two valid notes in a given view of the
//         // blockchain. See protocol specification for more
//         // details.
//         prevent_faerie_gold.reset(new PRF_rho_gadget<FieldT>(
//             pb,
//             ZERO,
//             phi,
//             h_sig,
//             nonce,
//             rho
//         ));

//         // Commit to the output notes publicly without
//         // disclosing them.
//         commit_to_outputs.reset(new note_commitment_gadget<FieldT>(
//             pb,
//             ZERO,
//             a_pk->bits,
//             this->value,
//             rho->bits,
//             this->r->bits,
//             commitment
//         ));
//     }

//     void generate_r1cs_constraints() {
//         note_gadget<FieldT>::generate_r1cs_constraints();

//         a_pk->generate_r1cs_constraints();

//         prevent_faerie_gold->generate_r1cs_constraints();

//         commit_to_outputs->generate_r1cs_constraints();
//     }

//     void generate_r1cs_witness(const Note& note) {
//         note_gadget<FieldT>::generate_r1cs_witness(note);

//         prevent_faerie_gold->generate_r1cs_witness();

//         // [SANITY CHECK] Witness rho ourselves with the
//         // note information.
//         rho->bits.fill_with_bits(
//             this->pb,
//             uint256_to_bool_vector(note.rho)
//         );

//         a_pk->bits.fill_with_bits(
//             this->pb,
//             uint256_to_bool_vector(note.a_pk)
//         );

//         commit_to_outputs->generate_r1cs_witness();
//     }
// };

// template<typename FieldT, typename HashT, size_t tree_depth>
// class gunerotransfer_gadget : gadget<FieldT> {
// private:
//     // Verifier inputs
//     pb_variable_array<FieldT> zk_packed_inputs;
//     pb_variable_array<FieldT> zk_unpacked_inputs;
//     std::shared_ptr<multipacking_gadget<FieldT>> unpacker;

//     std::shared_ptr<digest_variable<FieldT>> zk_merkle_root;
//     std::shared_ptr<digest_variable<FieldT>> zk_h_sig;
//     std::shared_ptr<digest_variable<FieldT>> zk_input_nullifiers;
//     std::shared_ptr<digest_variable<FieldT>> zk_input_macs;
//     std::shared_ptr<digest_variable<FieldT>> zk_output_commitments;
//     pb_variable_array<FieldT> zk_vpub_old;
//     pb_variable_array<FieldT> zk_vpub_new;

//     // Aux inputs
//     pb_variable<FieldT> ZERO;
//     std::shared_ptr<digest_variable<FieldT>> zk_phi;
//     pb_variable_array<FieldT> zk_total_uint64;

//     // Input note gadgets
//     std::shared_ptr<input_note_gadget<FieldT, HashT, tree_depth>> zk_input_notes;
//     std::shared_ptr<PRF_pk_gadget<FieldT>> zk_mac_authentication;

//     // Output note gadgets
//     std::shared_ptr<output_note_gadget<FieldT>> zk_output_notes;

// public:
//     gunerotransfer_gadget(protoboard<FieldT> &pb) : gadget<FieldT>(pb) {
//         // Verification
//         {
//             // The verification inputs are all bit-strings of various
//             // lengths (256-bit digests and 64-bit integers) and so we
//             // pack them into as few field elements as possible. (The
//             // more verification inputs you have, the more expensive
//             // verification is.)
//             zk_packed_inputs.allocate(pb, verifying_field_element_size());
//             pb.set_input_sizes(verifying_field_element_size());

//             alloc_uint256(zk_unpacked_inputs, zk_merkle_root);
//             alloc_uint256(zk_unpacked_inputs, zk_h_sig);

//             // for (size_t i = 0; i < NumInputs; i++) {
//                 alloc_uint256(zk_unpacked_inputs, zk_input_nullifiers);
//                 alloc_uint256(zk_unpacked_inputs, zk_input_macs);
//             // }

//             // for (size_t i = 0; i < NumOutputs; i++) {
//                 alloc_uint256(zk_unpacked_inputs, zk_output_commitments);
//             // }

//             alloc_uint64(zk_unpacked_inputs, zk_vpub_old);
//             alloc_uint64(zk_unpacked_inputs, zk_vpub_new);

//             assert(zk_unpacked_inputs.size() == verifying_input_bit_size());

//             // This gadget will ensure that all of the inputs we provide are
//             // boolean constrained.
//             unpacker.reset(new multipacking_gadget<FieldT>(
//                 pb,
//                 zk_unpacked_inputs,
//                 zk_packed_inputs,
//                 FieldT::capacity(),
//                 "unpacker"
//             ));
//         }

//         // We need a constant "zero" variable in some contexts. In theory
//         // it should never be necessary, but libsnark does not synthesize
//         // optimal circuits.
//         // 
//         // The first variable of our constraint system is constrained
//         // to be one automatically for us, and is known as `ONE`.
//         ZERO.allocate(pb);

//         zk_phi.reset(new digest_variable<FieldT>(pb, 252, ""));

//         zk_total_uint64.allocate(pb, 64);

//         // for (size_t i = 0; i < NumInputs; i++) {
//             // Input note gadget for commitments, macs, nullifiers,
//             // and spend authority.
//             zk_input_notes.reset(new input_note_gadget<FieldT, HashT,  tree_depth>(
//                 pb,
//                 ZERO,
//                 zk_input_nullifiers,
//                 *zk_merkle_root
//             ));

//             // The input keys authenticate h_sig to prevent
//             // malleability.
//             zk_mac_authentication.reset(new PRF_pk_gadget<FieldT>(
//                 pb,
//                 ZERO,
//                 zk_input_notes->a_sk->bits,
//                 zk_h_sig->bits,
//                 false,//i ? true : false,
//                 zk_input_macs
//             ));
//         // }

//         // for (size_t i = 0; i < NumOutputs; i++) {
//             zk_output_notes.reset(new output_note_gadget<FieldT>(
//                 pb,
//                 ZERO,
//                 zk_phi->bits,
//                 zk_h_sig->bits,
//                 false,//i ? true : false,
//                 zk_output_commitments
//             ));
//         // }
//     }

//     void generate_r1cs_constraints() {
//         // The true passed here ensures all the inputs
//         // are boolean constrained.
//         unpacker->generate_r1cs_constraints(true);

//         // Constrain `ZERO`
//         generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero(), "ZERO");

//         // Constrain bitness of phi
//         zk_phi->generate_r1cs_constraints();

//         // for (size_t i = 0; i < NumInputs; i++) {
//             // Constrain the JoinSplit input constraints.
//             zk_input_notes->generate_r1cs_constraints();

//             // Authenticate h_sig with a_sk
//             zk_mac_authentication->generate_r1cs_constraints();
//         // }

//         // for (size_t i = 0; i < NumOutputs; i++) {
//             // Constrain the JoinSplit output constraints.
//             zk_output_notes->generate_r1cs_constraints();
//         // }

//         // Value balance
//         {
//             linear_combination<FieldT> left_side = packed_addition(zk_vpub_old);
//             // for (size_t i = 0; i < NumInputs; i++) {
//                 left_side = left_side + packed_addition(zk_input_notes->value);
//             // }

//             linear_combination<FieldT> right_side = packed_addition(zk_vpub_new);
//             // for (size_t i = 0; i < NumOutputs; i++) {
//                 right_side = right_side + packed_addition(zk_output_notes->value);
//             // }

//             // Ensure that both sides are equal
//             this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
//                 1,
//                 left_side,
//                 right_side
//             ));

//             // #854: Ensure that left_side is a 64-bit integer.
//             for (size_t i = 0; i < 64; i++) {
//                 generate_boolean_r1cs_constraint<FieldT>(
//                     this->pb,
//                     zk_total_uint64[i],
//                     ""
//                 );
//             }

//             this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
//                 1,
//                 left_side,
//                 packed_addition(zk_total_uint64)
//             ));
//         }
//     }

//     void generate_r1cs_witness(
//         const uint252& phi,
//         const uint256& rt,
//         const uint256& h_sig,
//         const JSInput& inputs,
//         const Note& outputs,
//         uint64_t vpub_old,
//         uint64_t vpub_new
//     ) {
//         // Witness `zero`
//         this->pb.val(ZERO) = FieldT::zero();

//         // Witness rt. This is not a sanity check.
//         //
//         // This ensures the read gadget constrains
//         // the intended root in the event that
//         // both inputs are zero-valued.
//         zk_merkle_root->bits.fill_with_bits(
//             this->pb,
//             uint256_to_bool_vector(rt)
//         );

//         // Witness public balance values
//         zk_vpub_old.fill_with_bits(
//             this->pb,
//             uint64_to_bool_vector(vpub_old)
//         );
//         zk_vpub_new.fill_with_bits(
//             this->pb,
//             uint64_to_bool_vector(vpub_new)
//         );

//         {
//             // Witness total_uint64 bits
//             uint64_t left_side_acc = vpub_old;
//             // for (size_t i = 0; i < NumInputs; i++) {
//                 left_side_acc += inputs.note.value;
//             // }

//             zk_total_uint64.fill_with_bits(
//                 this->pb,
//                 uint64_to_bool_vector(left_side_acc)
//             );
//         }

//         // Witness phi
//         zk_phi->bits.fill_with_bits(
//             this->pb,
//             uint252_to_bool_vector(phi)
//         );

//         // Witness h_sig
//         zk_h_sig->bits.fill_with_bits(
//             this->pb,
//             uint256_to_bool_vector(h_sig)
//         );

//         // for (size_t i = 0; i < NumInputs; i++) {
//             // Witness the input information.
//             auto merkle_path = inputs.witness.path();
//             zk_input_notes->generate_r1cs_witness(
//                 merkle_path,
//                 inputs.key,
//                 inputs.note
//             );

//             // Witness macs
//             zk_mac_authentication->generate_r1cs_witness();
//         // }

//         // for (size_t i = 0; i < NumOutputs; i++) {
//             // Witness the output information.
//             zk_output_notes->generate_r1cs_witness(outputs);
//         // }

//         // [SANITY CHECK] Ensure that the intended root
//         // was witnessed by the inputs, even if the read
//         // gadget overwrote it. This allows the prover to
//         // fail instead of the verifier, in the event that
//         // the roots of the inputs do not match the
//         // treestate provided to the proving API.
//         zk_merkle_root->bits.fill_with_bits(
//             this->pb,
//             uint256_to_bool_vector(rt)
//         );

//         // This happens last, because only by now are all the
//         // verifier inputs resolved.
//         unpacker->generate_r1cs_witness_from_bits();
//     }

//     static r1cs_primary_input<FieldT> witness_map(
//         const uint256& rt,
//         const uint256& h_sig,
//         const uint256& macs,
//         const uint256& nullifiers,
//         const uint256& commitments,
//         uint64_t vpub_old,
//         uint64_t vpub_new
//     ) {
//         std::vector<bool> verify_inputs;

//         insert_uint256(verify_inputs, rt);
//         insert_uint256(verify_inputs, h_sig);
        
//         // for (size_t i = 0; i < NumInputs; i++) {
//             insert_uint256(verify_inputs, nullifiers);
//             insert_uint256(verify_inputs, macs);
//         // }

//         // for (size_t i = 0; i < NumOutputs; i++) {
//             insert_uint256(verify_inputs, commitments);
//         // }

//         insert_uint64(verify_inputs, vpub_old);
//         insert_uint64(verify_inputs, vpub_new);

//         assert(verify_inputs.size() == verifying_input_bit_size());
//         auto verify_field_elements = libff::pack_bit_vector_into_field_element_vector<FieldT>(verify_inputs);
//         assert(verify_field_elements.size() == verifying_field_element_size());
//         return verify_field_elements;
//     }

//     static size_t verifying_input_bit_size() {
//         size_t acc = 0;

//         acc += 256; // the merkle root (anchor)
//         acc += 256; // h_sig
//         // for (size_t i = 0; i < NumInputs; i++) {
//             acc += 256; // nullifier
//             acc += 256; // mac
//         // }
//         // for (size_t i = 0; i < NumOutputs; i++) {
//             acc += 256; // new commitment
//         // }
//         acc += 64; // vpub_old
//         acc += 64; // vpub_new

//         return acc;
//     }

//     static size_t verifying_field_element_size() {
//         return div_ceil(verifying_input_bit_size(), FieldT::capacity());
//     }

//     void alloc_uint256(
//         pb_variable_array<FieldT>& packed_into,
//         std::shared_ptr<digest_variable<FieldT>>& var
//     ) {
//         var.reset(new digest_variable<FieldT>(this->pb, 256, ""));
//         packed_into.insert(packed_into.end(), var->bits.begin(), var->bits.end());
//     }

//     void alloc_uint64(
//         pb_variable_array<FieldT>& packed_into,
//         pb_variable_array<FieldT>& integer
//     ) {
//         integer.allocate(this->pb, 64, "");
//         packed_into.insert(packed_into.end(), integer.begin(), integer.end());
//     }
// };

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

// template<typename FieldT, typename BaseT, typename HashT, size_t tree_depth>
// void Gunero_test_merkle_tree_check_read_gadget()
// {
//     libff::start_profiling();
//     //const size_t digest_len = HashT::get_digest_len();

//     std::string r1csPath = "r1cs.bin";
//     std::string vkPath = "vk.bin";
//     std::string pkPath = "pk.bin";

//     /* generate circuit */
//     libff::print_header("Gunero Generator");

//     guneromembership_gadget<FieldT, BaseT, HashT, tree_depth> gunero;

//     //protoboard<FieldT> pb;
//     // pb_variable_array<FieldT> address_bits_va;
//     // address_bits_va.allocate(pb, tree_depth, "address_bits");
//     // digest_variable<FieldT> leaf_digest(pb, digest_len, "input_block");
//     // digest_variable<FieldT> root_digest(pb, digest_len, "output_digest");
//     // merkle_authentication_path_variable<FieldT, HashT> path_var(pb, tree_depth, "path_var");
//     // merkle_tree_check_read_gadget<FieldT, HashT> ml(pb, tree_depth, address_bits_va, leaf_digest, root_digest, path_var, ONE, "ml");

//     // path_var.generate_r1cs_constraints();
//     // ml.generate_r1cs_constraints();

//     // {/* produce constraints */
//     //     libff::print_header("Gunero constraints");
//     //     const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

//     //     saveToFile(r1csPath, constraint_system);

//     //     r1cs_ppzksnark_keypair<BaseT> keypair = r1cs_ppzksnark_generator<BaseT>(constraint_system);

//     //     saveToFile(vkPath, keypair.vk);
//     //     saveToFile(pkPath, keypair.pk);

//     //     printf("\n"); libff::print_indent(); libff::print_mem("after constraints"); libff::print_time("after constraints");
//     // }

//     gunero.generate_r1cs_constraints(r1csPath, pkPath, vkPath);

//     /* prepare test variables */
//     libff::print_header("Gunero prepare test variables");
//     std::vector<merkle_authentication_node> path(tree_depth);

//     libff::bit_vector prev_hash(gunero.digest_len);
//     std::generate(prev_hash.begin(), prev_hash.end(), [&]() { return std::rand() % 2; });
//     libff::bit_vector leaf = prev_hash;

//     libff::bit_vector address_bits;

//     size_t address = 0;
//     for (long level = tree_depth-1; level >= 0; --level)
//     {
//         const bool computed_is_right = (std::rand() % 2);
//         address |= (computed_is_right ? 1ul << (tree_depth-1-level) : 0);
//         address_bits.push_back(computed_is_right);
//         libff::bit_vector other(gunero.digest_len);
//         std::generate(other.begin(), other.end(), [&]() { return std::rand() % 2; });

//         libff::bit_vector block = prev_hash;
//         block.insert(computed_is_right ? block.begin() : block.end(), other.begin(), other.end());
//         libff::bit_vector h = HashT::get_hash(block);

//         path[level] = other;

//         prev_hash = h;
//     }
//     libff::bit_vector root = prev_hash;
//     printf("\n"); libff::print_indent(); libff::print_mem("after prepare test variables"); libff::print_time("after prepare test variables");

//     /* witness (proof) */
//     // libff::print_header("Gunero witness (proof)");
//     // gunero.address_bits_va.fill_with_bits(gunero.pb, address_bits);
//     // assert(gunero.address_bits_va.get_field_element_from_bits(gunero.pb).as_ulong() == address);
//     // gunero.leaf_digest.generate_r1cs_witness(leaf);
//     // gunero.path_var.generate_r1cs_witness(address, path);
//     // gunero.ml.generate_r1cs_witness();
//     // printf("\n"); libff::print_indent(); libff::print_mem("after witness (proof)"); libff::print_time("after witness (proof)");
//     gunero.prove(address, address_bits, leaf, path, pkPath);

//     /* verify */
//     // libff::print_header("Gunero verify");
//     // {
//     //     r1cs_ppzksnark_verification_key<BaseT> vk;
//     //     loadFromFile(vkPath, vk);

//     //     r1cs_ppzksnark_processed_verification_key<BaseT> vk_precomp = r1cs_ppzksnark_verifier_process_vk(vk);
//     // }

//     // /* make sure that read checker didn't accidentally overwrite anything */
//     // address_bits_va.fill_with_bits(pb, address_bits);
//     // leaf_digest.generate_r1cs_witness(leaf);
//     // root_digest.generate_r1cs_witness(root);
//     // assert(pb.is_satisfied());

//     // const size_t num_constraints = pb.num_constraints();
//     // const size_t expected_constraints = merkle_tree_check_read_gadget<FieldT, HashT>::expected_constraints(tree_depth);
//     // assert(num_constraints == expected_constraints);
//     // printf("\n"); libff::print_indent(); libff::print_mem("after verify"); libff::print_time("after verify");
//     gunero.verify(address_bits, leaf, root, vkPath);

//     libff::clear_profiling_counters();
// }

const unsigned char G1_PREFIX_MASK = 0x02;
const unsigned char G2_PREFIX_MASK = 0x0a;

void static inline WriteBE64(unsigned char* ptr, uint64_t x)
{
    *((uint64_t*)ptr) = htobe64(x);
}

// Element in the base field
class Fq {
private:
    base_blob<256> data;
public:
    Fq() : data() { }

    template<typename libsnark_Fq>
    Fq(libsnark_Fq element);

    template<typename libsnark_Fq>
    libsnark_Fq to_libsnark_fq() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(data);
    }

    friend bool operator==(const Fq& a, const Fq& b)
    {
        return (
            a.data == b.data
        );
    }

    friend bool operator!=(const Fq& a, const Fq& b)
    {
        return !(a == b);
    }

    friend std::ostream& operator<<(std::ostream &out, const Fq &a)
    {
        out << a.data;

        return out;
    }

    friend std::istream& operator>>(std::istream &in, Fq &a)
    {
        in >> a.data;

        return in;
    }
};

// FE2IP as defined in the protocol spec and IEEE Std 1363a-2004.
libff::bigint<8> fq2_to_bigint(const curve_Fq2 &e)
{
    auto modq = curve_Fq::field_char();
    auto c0 = e.c0.as_bigint();
    auto c1 = e.c1.as_bigint();

    libff::bigint<8> temp = c1 * modq;
    temp += c0;
    return temp;
}

// Writes a bigint in big endian
template<mp_size_t LIMBS>
void write_bigint(base_blob<8 * LIMBS * sizeof(mp_limb_t)> &blob, const libff::bigint<LIMBS> &val)
{
    auto ptr = blob.begin();
    for (ssize_t i = LIMBS-1; i >= 0; i--, ptr += 8) {
        WriteBE64(ptr, val.data[i]);
    }
}

uint64_t static inline ReadBE64(const unsigned char* ptr)
{
    return be64toh(*((uint64_t*)ptr));
}

// Reads a bigint from big endian
template<mp_size_t LIMBS>
libff::bigint<LIMBS> read_bigint(const base_blob<8 * LIMBS * sizeof(mp_limb_t)> &blob)
{
    libff::bigint<LIMBS> ret;

    auto ptr = blob.begin();

    for (ssize_t i = LIMBS-1; i >= 0; i--, ptr += 8) {
        ret.data[i] = ReadBE64(ptr);
    }

    return ret;
}

template<typename libsnark_Fq>
Fq::Fq(libsnark_Fq element) : data()
{
    write_bigint<4>(data, element.as_bigint());
}

template<>
curve_Fq Fq::to_libsnark_fq() const
{
    auto element_bigint = read_bigint<4>(data);

    // Check that the integer is smaller than the modulus
    auto modq = curve_Fq::field_char();
    element_bigint.limit(modq, "element is not in Fq");

    return curve_Fq(element_bigint);
}

// Element in the extension field
class Fq2 {
private:
    base_blob<512> data;
public:
    Fq2() : data() { }

    template<typename libsnark_Fq2>
    Fq2(libsnark_Fq2 element);

    template<typename libsnark_Fq2>
    libsnark_Fq2 to_libsnark_fq2() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(data);
    }

    friend bool operator==(const Fq2& a, const Fq2& b)
    {
        return (
            a.data == b.data
        );
    }

    friend bool operator!=(const Fq2& a, const Fq2& b)
    {
        return !(a == b);
    }

    friend std::ostream& operator<<(std::ostream &out, const Fq2 &a)
    {
        out << a.data;

        return out;
    }

    friend std::istream& operator>>(std::istream &in, Fq2 &a)
    {
        in >> a.data;

        return in;
    }
};

template<typename libsnark_Fq2>
Fq2::Fq2(libsnark_Fq2 element) : data()
{
    write_bigint<8>(data, fq2_to_bigint(element));
}

template<>
curve_Fq2 Fq2::to_libsnark_fq2() const
{
    libff::bigint<4> modq = curve_Fq::field_char();
    libff::bigint<8> combined = read_bigint<8>(data);
    libff::bigint<5> res;
    libff::bigint<4> c0;
    libff::bigint<8>::div_qr(res, c0, combined, modq);
    libff::bigint<4> c1 = res.shorten(modq, "element is not in Fq2");

    return curve_Fq2(curve_Fq(c0), curve_Fq(c1));
}

// Compressed point in G1
class CompressedG1 {
private:
    bool y_lsb;
    Fq x;

public:
    CompressedG1() : y_lsb(false), x() { }

    template<typename libsnark_G1>
    CompressedG1(libsnark_G1 point);

    template<typename libsnark_G1>
    libsnark_G1 to_libsnark_g1() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        unsigned char leadingByte = G1_PREFIX_MASK;

        if (y_lsb) {
            leadingByte |= 1;
        }

        READWRITE(leadingByte);

        if ((leadingByte & (~1)) != G1_PREFIX_MASK) {
            throw std::ios_base::failure("lead byte of G1 point not recognized");
        }

        y_lsb = leadingByte & 1;

        READWRITE(x);
    }

    friend bool operator==(const CompressedG1& a, const CompressedG1& b)
    {
        return (
            a.y_lsb == b.y_lsb &&
            a.x == b.x
        );
    }

    friend bool operator!=(const CompressedG1& a, const CompressedG1& b)
    {
        return !(a == b);
    }

    friend std::ostream& operator<<(std::ostream &out, const CompressedG1 &a)
    {
        out << a.y_lsb;
        out << a.x;

        return out;
    }

    friend std::istream& operator>>(std::istream &in, CompressedG1 &a)
    {
        in >> a.y_lsb;
        in >> a.x;

        return in;
    }
};

template<typename libsnark_G1>
CompressedG1::CompressedG1(libsnark_G1 point)
{
    if (point.is_zero()) {
        throw std::domain_error("curve point is zero");
    }

    point.to_affine_coordinates();

    x = Fq(point.X);
    y_lsb = point.Y.as_bigint().data[0] & 1;
}

template<>
curve_G1 CompressedG1::to_libsnark_g1() const
{
    curve_Fq x_coordinate = x.to_libsnark_fq<curve_Fq>();

#ifdef ALT_BN128
    // y = +/- sqrt(x^3 + b)
    auto y_coordinate = ((x_coordinate.squared() * x_coordinate) + libff::alt_bn128_coeff_b).sqrt();
#else
    CARP();
#endif

    if ((y_coordinate.as_bigint().data[0] & 1) != y_lsb) {
        y_coordinate = -y_coordinate;
    }

    curve_G1 r = curve_G1::one();
    r.X = x_coordinate;
    r.Y = y_coordinate;
    r.Z = curve_Fq::one();

    assert(r.is_well_formed());

    return r;
}

// Compressed point in G2
class CompressedG2 {
private:
    bool y_gt;
    Fq2 x;

public:
    CompressedG2() : y_gt(false), x() { }

    template<typename libsnark_G2>
    CompressedG2(libsnark_G2 point);

    template<typename libsnark_G2>
    libsnark_G2 to_libsnark_g2() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        unsigned char leadingByte = G2_PREFIX_MASK;

        if (y_gt) {
            leadingByte |= 1;
        }

        READWRITE(leadingByte);

        if ((leadingByte & (~1)) != G2_PREFIX_MASK) {
            throw std::ios_base::failure("lead byte of G2 point not recognized");
        }

        y_gt = leadingByte & 1;

        READWRITE(x);
    }

    friend bool operator==(const CompressedG2& a, const CompressedG2& b)
    {
        return (
            a.y_gt == b.y_gt &&
            a.x == b.x
        );
    }

    friend bool operator!=(const CompressedG2& a, const CompressedG2& b)
    {
        return !(a == b);
    }

    friend std::ostream& operator<<(std::ostream &out, const CompressedG2 &a)
    {
        out << a.y_gt;
        out << a.x;

        return out;
    }

    friend std::istream& operator>>(std::istream &in, CompressedG2 &a)
    {
        in >> a.y_gt;
        in >> a.x;

        return in;
    }
};

template<typename libsnark_G2>
CompressedG2::CompressedG2(libsnark_G2 point)
{
    if (point.is_zero()) {
        throw std::domain_error("curve point is zero");
    }

    point.to_affine_coordinates();

    x = Fq2(point.X);
    y_gt = fq2_to_bigint(point.Y) > fq2_to_bigint(-(point.Y));
}

template<>
curve_G2 CompressedG2::to_libsnark_g2() const
{
    auto x_coordinate = x.to_libsnark_fq2<curve_Fq2>();

    // y = +/- sqrt(x^3 + b)
#ifdef ALT_BN128
    auto y_coordinate = ((x_coordinate.squared() * x_coordinate) + libff::alt_bn128_twist_coeff_b).sqrt();
#else
    CARP();
#endif
    auto y_coordinate_neg = -y_coordinate;

    if ((fq2_to_bigint(y_coordinate) > fq2_to_bigint(y_coordinate_neg)) != y_gt) {
        y_coordinate = y_coordinate_neg;
    }

    curve_G2 r = curve_G2::one();
    r.X = x_coordinate;
    r.Y = y_coordinate;
    r.Z = curve_Fq2::one();

    assert(r.is_well_formed());

#ifdef ALT_BN128
    if (libff::alt_bn128_modulus_r * r != curve_G2::zero()) {
#else
    CARP(); {
#endif
        throw std::runtime_error("point is not in G2");
    }

    return r;
}

// Compressed zkSNARK proof
class ZCProof {
private:
    CompressedG1 g_A;
    CompressedG1 g_A_prime;
    CompressedG2 g_B;
    CompressedG1 g_B_prime;
    CompressedG1 g_C;
    CompressedG1 g_C_prime;
    CompressedG1 g_K;
    CompressedG1 g_H;

public:
    ZCProof() : g_A(), g_A_prime(), g_B(), g_B_prime(), g_C(), g_C_prime(), g_K(), g_H() { }

    // Produces a compressed proof using a libsnark zkSNARK proof
    template<typename libsnark_proof>
    ZCProof(const libsnark_proof& proof);

    // Produces a libsnark zkSNARK proof out of this proof,
    // or throws an exception if it is invalid.
    template<typename libsnark_proof>
    libsnark_proof to_libsnark_proof() const;

    static ZCProof random_invalid();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(g_A);
        READWRITE(g_A_prime);
        READWRITE(g_B);
        READWRITE(g_B_prime);
        READWRITE(g_C);
        READWRITE(g_C_prime);
        READWRITE(g_K);
        READWRITE(g_H);
    }

    friend bool operator==(const ZCProof& a, const ZCProof& b)
    {
        return (
            a.g_A == b.g_A &&
            a.g_A_prime == b.g_A_prime &&
            a.g_B == b.g_B &&
            a.g_B_prime == b.g_B_prime &&
            a.g_C == b.g_C &&
            a.g_C_prime == b.g_C_prime &&
            a.g_K == b.g_K &&
            a.g_H == b.g_H
        );
    }

    friend bool operator!=(const ZCProof& a, const ZCProof& b)
    {
        return !(a == b);
    }

    friend std::ostream& operator<<(std::ostream &out, const ZCProof &proof)
    {
        out << proof.g_A;
        out << proof.g_A_prime;
        out << proof.g_B;
        out << proof.g_B_prime;
        out << proof.g_C;
        out << proof.g_C_prime;
        out << proof.g_K;
        out << proof.g_H;

        return out;
    }

    friend std::istream& operator>>(std::istream &in, ZCProof &proof)
    {
        in >> proof.g_A;
        in >> proof.g_A_prime;
        in >> proof.g_B;
        in >> proof.g_B_prime;
        in >> proof.g_C;
        in >> proof.g_C_prime;
        in >> proof.g_K;
        in >> proof.g_H;

        return in;
    }
};

template<typename libsnark_proof>
ZCProof::ZCProof(const libsnark_proof& proof)
{
    g_A = CompressedG1(proof.g_A.g);
    g_A_prime = CompressedG1(proof.g_A.h);
    g_B = CompressedG2(proof.g_B.g);
    g_B_prime = CompressedG1(proof.g_B.h);
    g_C = CompressedG1(proof.g_C.g);
    g_C_prime = CompressedG1(proof.g_C.h);
    g_K = CompressedG1(proof.g_K);
    g_H = CompressedG1(proof.g_H);
}

template<>
r1cs_ppzksnark_proof<BaseT> ZCProof::to_libsnark_proof() const
{
    r1cs_ppzksnark_proof<BaseT> proof;

    proof.g_A.g = g_A.to_libsnark_g1<curve_G1>();
    proof.g_A.h = g_A_prime.to_libsnark_g1<curve_G1>();
    proof.g_B.g = g_B.to_libsnark_g2<curve_G2>();
    proof.g_B.h = g_B_prime.to_libsnark_g1<curve_G1>();
    proof.g_C.g = g_C.to_libsnark_g1<curve_G1>();
    proof.g_C.h = g_C_prime.to_libsnark_g1<curve_G1>();
    proof.g_K = g_K.to_libsnark_g1<curve_G1>();
    proof.g_H = g_H.to_libsnark_g1<curve_G1>();

    return proof;
}

class ProofVerifier {
private:
    bool perform_verification;

    ProofVerifier(bool perform_verification) : perform_verification(perform_verification) { }

public:
    // ProofVerifier should never be copied
    ProofVerifier(const ProofVerifier&) = delete;
    ProofVerifier& operator=(const ProofVerifier&) = delete;
    ProofVerifier(ProofVerifier&&);
    ProofVerifier& operator=(ProofVerifier&&);

    // Creates a verification context that strictly verifies
    // all proofs using libsnark's API.
    static ProofVerifier Strict();

    // Creates a verification context that performs no
    // verification, used when avoiding duplicate effort
    // such as during reindexing.
    static ProofVerifier Disabled();

    template <typename VerificationKey,
              typename ProcessedVerificationKey,
              typename PrimaryInput,
              typename Proof
              >
    bool check(
        const VerificationKey& vk,
        const ProcessedVerificationKey& pvk,
        const PrimaryInput& pi,
        const Proof& p
    );
};

template<>
bool ProofVerifier::check(
    const r1cs_ppzksnark_verification_key<BaseT>& vk,
    const r1cs_ppzksnark_processed_verification_key<BaseT>& pvk,
    const r1cs_ppzksnark_primary_input<BaseT>& primary_input,
    const r1cs_ppzksnark_proof<BaseT>& proof
)
{
    if (perform_verification) {
        return r1cs_ppzksnark_online_verifier_strong_IC<BaseT>(pvk, primary_input, proof);
    } else {
        return true;
    }
}

std::ostream& operator<<(std::ostream &out, const libff::bit_vector &a)
{
    // out << a.size();
    // for(int i = 0; i < a.size(); i++)
    // {
    //     out << a[i];
    // }

    // return out;
    libff::serialize_bit_vector(out, a);
}

std::istream& operator>>(std::istream &in, libff::bit_vector &a)
{
    // std::size_t size = a.size();
    // for(int i = 0; i < size; i++)
    // {
    //     in >> a[i];
    // }

    // return in;
    libff::deserialize_bit_vector(in, a);
}

std::ostream& operator<<(std::ostream &out, const std::vector<libff::bit_vector> &a)
{
    out << a.size();
    for(int i = 0; i < a.size(); i++)
    {
        out << a[i];
    }

    return out;
}

std::istream& operator>>(std::istream &in, std::vector<libff::bit_vector> &a)
{
    std::size_t size = a.size();
    for(int i = 0; i < size; i++)
    {
        in >> a[i];
    }

    return in;
}

std::once_flag init_public_params_once_flag;

void initialize_curve_params()
{
    std::call_once (init_public_params_once_flag, BaseT::init_public_params);
}

ProofVerifier ProofVerifier::Strict() {
    initialize_curve_params();
    return ProofVerifier(true);
}

ProofVerifier ProofVerifier::Disabled() {
    initialize_curve_params();
    return ProofVerifier(false);
}

const size_t Keccak256_digest_size = 256;
const size_t Keccak256_block_size = 512;

template<typename FieldT>
pb_linear_combination_array<FieldT> Keccak256_default_IV(protoboard<FieldT> &pb);

template<typename FieldT>
class keccak256_message_schedule_gadget : public gadget<FieldT> {
public:
    std::vector<pb_variable_array<FieldT> > W_bits;
    std::vector<std::shared_ptr<packing_gadget<FieldT> > > pack_W;

    std::vector<pb_variable<FieldT> > sigma0;
    std::vector<pb_variable<FieldT> > sigma1;
    std::vector<std::shared_ptr<small_sigma_gadget<FieldT> > > compute_sigma0;
    std::vector<std::shared_ptr<small_sigma_gadget<FieldT> > > compute_sigma1;
    std::vector<pb_variable<FieldT> > unreduced_W;
    std::vector<std::shared_ptr<lastbits_gadget<FieldT> > > mod_reduce_W;
public:
    pb_variable_array<FieldT> M;
    pb_variable_array<FieldT> packed_W;
    keccak256_message_schedule_gadget(protoboard<FieldT> &pb,
                                   const pb_variable_array<FieldT> &M,
                                   const pb_variable_array<FieldT> &packed_W,
                                   const std::string &annotation_prefix);
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename FieldT>
class keccak256_round_function_gadget : public gadget<FieldT> {
public:
    pb_variable<FieldT> sigma0;
    pb_variable<FieldT> sigma1;
    std::shared_ptr<big_sigma_gadget<FieldT> > compute_sigma0;
    std::shared_ptr<big_sigma_gadget<FieldT> > compute_sigma1;
    pb_variable<FieldT> choice;
    pb_variable<FieldT> majority;
    std::shared_ptr<choice_gadget<FieldT> > compute_choice;
    std::shared_ptr<majority_gadget<FieldT> > compute_majority;
    pb_variable<FieldT> packed_d;
    std::shared_ptr<packing_gadget<FieldT> > pack_d;
    pb_variable<FieldT> packed_h;
    std::shared_ptr<packing_gadget<FieldT> > pack_h;
    pb_variable<FieldT> unreduced_new_a;
    pb_variable<FieldT> unreduced_new_e;
    std::shared_ptr<lastbits_gadget<FieldT> > mod_reduce_new_a;
    std::shared_ptr<lastbits_gadget<FieldT> > mod_reduce_new_e;
    pb_variable<FieldT> packed_new_a;
    pb_variable<FieldT> packed_new_e;
public:
    pb_linear_combination_array<FieldT> a;
    pb_linear_combination_array<FieldT> b;
    pb_linear_combination_array<FieldT> c;
    pb_linear_combination_array<FieldT> d;
    pb_linear_combination_array<FieldT> e;
    pb_linear_combination_array<FieldT> f;
    pb_linear_combination_array<FieldT> g;
    pb_linear_combination_array<FieldT> h;
    pb_variable<FieldT> W;
    long K;
    pb_linear_combination_array<FieldT> new_a;
    pb_linear_combination_array<FieldT> new_e;

    keccak256_round_function_gadget(protoboard<FieldT> &pb,
                                 const pb_linear_combination_array<FieldT> &a,
                                 const pb_linear_combination_array<FieldT> &b,
                                 const pb_linear_combination_array<FieldT> &c,
                                 const pb_linear_combination_array<FieldT> &d,
                                 const pb_linear_combination_array<FieldT> &e,
                                 const pb_linear_combination_array<FieldT> &f,
                                 const pb_linear_combination_array<FieldT> &g,
                                 const pb_linear_combination_array<FieldT> &h,
                                 const pb_variable<FieldT> &W,
                                 const long &K,
                                 const pb_linear_combination_array<FieldT> &new_a,
                                 const pb_linear_combination_array<FieldT> &new_e,
                                 const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

/**
 * Gadget for the Keccak256 compression function.
 */
template<typename FieldT>
class keccak256_compression_function_gadget : public gadget<FieldT> {
public:
    std::vector<pb_linear_combination_array<FieldT> > round_a;
    std::vector<pb_linear_combination_array<FieldT> > round_b;
    std::vector<pb_linear_combination_array<FieldT> > round_c;
    std::vector<pb_linear_combination_array<FieldT> > round_d;
    std::vector<pb_linear_combination_array<FieldT> > round_e;
    std::vector<pb_linear_combination_array<FieldT> > round_f;
    std::vector<pb_linear_combination_array<FieldT> > round_g;
    std::vector<pb_linear_combination_array<FieldT> > round_h;

    pb_variable_array<FieldT> packed_W;
    std::shared_ptr<keccak256_message_schedule_gadget<FieldT> > message_schedule;
    std::vector<keccak256_round_function_gadget<FieldT> > round_functions;

    pb_variable_array<FieldT> unreduced_output;
    pb_variable_array<FieldT> reduced_output;
    std::vector<lastbits_gadget<FieldT> > reduce_output;
public:
    pb_linear_combination_array<FieldT> prev_output;
    pb_variable_array<FieldT> new_block;
    digest_variable<FieldT> output;

    keccak256_compression_function_gadget(protoboard<FieldT> &pb,
                                       const pb_linear_combination_array<FieldT> &prev_output,
                                       const pb_variable_array<FieldT> &new_block,
                                       const digest_variable<FieldT> &output,
                                       const std::string &annotation_prefix);
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

/**
 * Gadget for the Keccak256 compression function, viewed as a 2-to-1 hash
 * function, and using the pre-standardized SHA3 initialization vector but
 * otherwise the same as SHA3-256 variant specifications.
 * Note that for NULL input the compression returns
 * c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
 */
template<typename FieldT>
class keccak256_two_to_one_hash_gadget : public gadget<FieldT> {
public:
    typedef libff::bit_vector hash_value_type;
    typedef merkle_authentication_path merkle_authentication_path_type;

    std::shared_ptr<sha256_compression_function_gadget<FieldT> > f;

    keccak256_two_to_one_hash_gadget(protoboard<FieldT> &pb,
                                  const digest_variable<FieldT> &left,
                                  const digest_variable<FieldT> &right,
                                  const digest_variable<FieldT> &output,
                                  const std::string &annotation_prefix);
    keccak256_two_to_one_hash_gadget(protoboard<FieldT> &pb,
                                  const size_t block_length,
                                  const block_variable<FieldT> &input_block,
                                  const digest_variable<FieldT> &output,
                                  const std::string &annotation_prefix);

    //void generate_r1cs_constraints(const bool ensure_output_bitness=true); // ignored
    void generate_r1cs_witness();

    static size_t get_block_len();
    static size_t get_digest_len();
    static libff::bit_vector get_hash(const libff::bit_vector &input);

    //static size_t expected_constraints(const bool ensure_output_bitness=true); // ignored
};

template<typename FieldT, typename BaseT, typename HashT, size_t tree_depth>
class GuneroMembershipCircuit
{
public:
    const size_t digest_len;

    GuneroMembershipCircuit()
        : digest_len(HashT::get_digest_len())
    {}
    ~GuneroMembershipCircuit() {}

    // r1cs_constraint_system<FieldT> generate_r1cs() {
    //     protoboard<FieldT> pb;

    //     guneromembership_gadget<FieldT, BaseT, HashT, tree_depth> g(pb);
    //     g.generate_r1cs_constraints();

    //     return pb.get_constraint_system();
    // }

    void generate(
        const std::string& r1csPath,
        const std::string& pkPath,
        r1cs_ppzksnark_verification_key<BaseT> vk
    ) {
        // const r1cs_constraint_system<FieldT> constraint_system = generate_r1cs();
        // r1cs_ppzksnark_keypair<BaseT> keypair = r1cs_ppzksnark_generator<BaseT>(constraint_system);

        // pk = keypair.pk;
        // vk = keypair.vk;
        // processVerifyingKey();

        protoboard<FieldT> pb;
        guneromembership_gadget<FieldT, BaseT, HashT, tree_depth> gunero(pb);

        r1cs_ppzksnark_proving_key<BaseT> pk;
        // r1cs_ppzksnark_verification_key<BaseT> vk;
        gunero.generate_r1cs_constraints(r1csPath, pk, vk);

        if (pkPath.length() > 0)
        {
            saveToFile(pkPath, pk);
        }
        // if (vkPath.length() > 0)
        // {
        //     saveToFile(vkPath, vk);

        //     //Verify
        //     {
        //         r1cs_ppzksnark_verification_key<BaseT> vk_verify;
        //         loadFromFile(vkPath, vk_verify);

        //         assert(vk == vk_verify);
        //     }
        // }
     }

    static void makeTestVariables(
        GuneroMerklePath& p_path,
        libff::bit_vector& leaf,
        libff::bit_vector& root,
        uint256& root_uint256,
        size_t digest_len_static,
        size_t tree_depth_static
    )
    {
        /* prepare test variables */
        libff::print_header("Gunero prepare test variables");
        std::vector<merkle_authentication_node> path(tree_depth_static);

        libff::bit_vector prev_hash(digest_len_static);
        std::generate(prev_hash.begin(), prev_hash.end(), [&]() { return std::rand() % 2; });
        leaf = prev_hash;

        libff::bit_vector address_bits;

        size_t address = 0;
        for (long level = tree_depth_static-1; level >= 0; --level)
        {
            //Generate random uncle position
            const bool computed_is_right = (std::rand() % 2);
            address |= (computed_is_right ? 1ul << (tree_depth_static-1-level) : 0);
            address_bits.push_back(computed_is_right);

            //Generate random uncle
            libff::bit_vector uncle(digest_len_static);
            std::generate(uncle.begin(), uncle.end(), [&]() { return std::rand() % 2; });

            //Create block of prev_hash + uncle
            libff::bit_vector block = prev_hash;
            block.insert(computed_is_right ? block.begin() : block.end(), uncle.begin(), uncle.end());
            //Compress block to new hash
            libff::bit_vector h = HashT::get_hash(block);

            //Add uncle to path
            path[level] = uncle;

            prev_hash = h;
        }

        root = prev_hash;

        p_path = GuneroMerklePath(path, address_bits);

        root_uint256 = bool_vector_to_uint256(root);
        libff::bit_vector root_uint256_bit_vector = uint256_to_bool_vector(root_uint256);
        assert(root == root_uint256_bit_vector);

        printf("\n"); libff::print_indent(); libff::print_mem("after prepare test variables"); libff::print_time("after prepare test variables");
    }

    bool prove(
        const libff::bit_vector& root,
        const GuneroMerklePath& path,
        const libff::bit_vector& leaf,
        const uint8_t status,
        r1cs_ppzksnark_verification_key<BaseT>& vk,
        r1cs_primary_input<FieldT>& primary_input,
        r1cs_ppzksnark_proof<BaseT>& r1cs_proof
    ) {
        libff::print_header("Gunero witness (proof)");

        // ZCProof proof;
        {
            // libff::print_header("Gunero loadFromFile(pk)");
            // r1cs_ppzksnark_proving_key<BaseT> pk;
            // loadFromFile(pkPath, pk);
            // printf("\n"); libff::print_indent(); libff::print_mem("after Gunero loadFromFile(pk)"); libff::print_time("after Gunero loadFromFile(pk)");

            r1cs_ppzksnark_proving_key<BaseT> pk;
            r1cs_auxiliary_input<FieldT> aux_input;
            {
                protoboard<FieldT> pb;
                {
                    libff::print_header("Gunero guneromembership_gadget.load_r1cs_constraints()");

                    guneromembership_gadget<FieldT, BaseT, HashT, tree_depth> g(pb);
                    g.generate_r1cs_constraints(
                        std::string(),
                        pk,
                        vk);
                    g.generate_r1cs_witness(
                        root,
                        leaf,
                        path,
                        status
                    );

                    printf("\n"); libff::print_indent(); libff::print_mem("after guneromembership_gadget.load_r1cs_constraints()"); libff::print_time("after guneromembership_gadget.load_r1cs_constraints()");
                }

                // The constraint system must be satisfied or there is an unimplemented
                // or incorrect sanity check above. Or the constraint system is broken!
                assert(pb.is_satisfied());

                // TODO: These are copies, which is not strictly necessary.
                primary_input = pb.primary_input();
                aux_input = pb.auxiliary_input();

                // Swap A and B if it's beneficial (less arithmetic in G2)
                // In our circuit, we already know that it's beneficial
                // to swap, but it takes so little time to perform this
                // estimate that it doesn't matter if we check every time.
                // pb.constraint_system.swap_AB_if_beneficial();
            }

            r1cs_proof = r1cs_ppzksnark_prover<BaseT>(
                pk,
                primary_input,
                aux_input
            );

            // proof = ZCProof(r1cs_proof);

            printf("\n"); libff::print_indent(); libff::print_mem("after witness (proof)"); libff::print_time("after witness (proof)");
        }

        //Verify
        {
            bool verified = verify_after_generate(primary_input, r1cs_proof, vk);
        }
    }

    // bool verify(
    //     const r1cs_primary_input<FieldT>& primary_input,
    //     const r1cs_ppzksnark_proof<BaseT>& r1cs_proof,
    //     ProofVerifier& verifier,
    //     const r1cs_ppzksnark_verification_key<BaseT>& vk
    // ) {
    //     libff::print_header("Gunero verify");

    //     // r1cs_ppzksnark_verification_key<BaseT> vk;
    //     // loadFromFile(vkPath, vk);

    //     r1cs_ppzksnark_processed_verification_key<BaseT> vk_precomp = r1cs_ppzksnark_verifier_process_vk(vk);



    //     // /* make sure that read checker didn't accidentally overwrite anything */
    //     // address_bits_va.fill_with_bits(this->pb, address_bits);
    //     // leaf_digest.generate_r1cs_witness(leaf);
    //     // root_digest.generate_r1cs_witness(root);
    //     // assert(this->pb.is_satisfied());

    //     // const size_t num_constraints = this->pb.num_constraints();
    //     // const size_t expected_constraints = merkle_tree_check_read_gadget<FieldT, HashT>::expected_constraints(tree_depth);
    //     // assert(num_constraints == expected_constraints);



    //     // if (!vk || !vk_precomp) {
    //     //     throw std::runtime_error("GuneroMembershipCircuit verifying key not loaded");
    //     // }

    //     try {
    //         // r1cs_ppzksnark_proof<BaseT> r1cs_proof = proof.to_libsnark_proof<r1cs_ppzksnark_proof<BaseT>>();

    //         // uint256 h_sig = this->h_sig(randomSeed, nullifiers, pubKeyHash);
            
    //         // uint256 root_uint256 = bool_vector_to_uint256(root);

    //         // r1cs_primary_input<FieldT> witness = guneromembership_gadget<FieldT, BaseT, HashT, tree_depth>::witness_map(
    //         //     root_uint256
    //         // );

    //         printf("\n"); libff::print_indent(); libff::print_mem("after verify"); libff::print_time("after verify");

    //         return verifier.check(
    //             vk,
    //             vk_precomp,
    //             primary_input,
    //             r1cs_proof
    //         );
    //     } catch (...) {
    //         return false;
    //     }
    // }

    bool verify(
        const r1cs_primary_input<FieldT>& primary_input,
        const r1cs_ppzksnark_proof<BaseT>& r1cs_proof)
    {
        r1cs_ppzksnark_verification_key<BaseT> vk;
        {
            generate(std::string(), std::string(), vk);
        }

        return verify_after_generate(primary_input, r1cs_proof, vk);
    }

    bool verify_after_generate(
        const r1cs_primary_input<FieldT>& primary_input,
        const r1cs_ppzksnark_proof<BaseT>& r1cs_proof,
        const r1cs_ppzksnark_verification_key<BaseT>& vk)
    {
        r1cs_ppzksnark_processed_verification_key<BaseT> vk_precomp = r1cs_ppzksnark_verifier_process_vk(vk);
        try
        {
            // uint256 root_uint256 = bool_vector_to_uint256(root);

            // r1cs_primary_input<FieldT> r1cs_primary_input = guneromembership_gadget<FieldT, BaseT, HashT, tree_depth>::witness_map(
            //     root_uint256
            // );

            // assert(primary_input == r1cs_primary_input);

            // r1cs_ppzksnark_proof<BaseT> r1cs_proof = proof.to_libsnark_proof<r1cs_ppzksnark_proof<BaseT>>();

            ProofVerifier verifierEnabled = ProofVerifier::Strict();

            bool verified = verifierEnabled.check(
                vk,
                vk_precomp,
                primary_input,
                r1cs_proof
            );

            printf("\n"); libff::print_indent(); libff::print_mem("after verify"); libff::print_time("after verify");

            if (verified)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        catch (...)
        {
            return false;
        }
    }
};

int main () {
    libff::start_profiling();

#ifdef CURVE_BN128
    // //bn128_pp
    // libff::bn128_pp::init_public_params();
#endif

#ifdef ALT_BN128
    //alt_bn128_pp
    libff::init_alt_bn128_params();
#endif

#define MERKLE_TREE_DEPTH 1

    std::string r1csPath = "/home/sean/Silencer/build/src/r1cs.bin";
    std::string pkPath = "/home/sean/Silencer/build/src/pk.bin";
    // std::string vkPath = "/home/sean/Silencer/build/src/vk.bin";

    // std::string addressPath = "/home/sean/Silencer/build/src/p_address.bin";
    // std::string leafPath = "/home/sean/Silencer/build/src/p_leaf.bin";
    // std::string pathPath = "/home/sean/Silencer/build/src/p_path.bin";
    // std::string rootPath = "/home/sean/Silencer/build/src/p_root.bin";
    std::string proofPath = "/home/sean/Silencer/build/src/proof.bin";

    //Given secret key s [512b]
    //P = secp256k1multiply(G, s) [512b]
    //A = right(keccak256(P), 20) [160b]
    //leaf = keccak256compress(A, status)
    // libff::bit_vector secretKey;
    // libff::bit_vector account;
    // libff::bit_vector status;
    libff::bit_vector leaf;
    libff::bit_vector root;
    uint256 root_uint256;
    GuneroMerklePath path;
    uint8_t status = 1;

    {
        GuneroMembershipCircuit<FieldT, BaseT, sha256_two_to_one_hash_gadget<FieldT>, MERKLE_TREE_DEPTH>::makeTestVariables(path, leaf, root, root_uint256, sha256_two_to_one_hash_gadget<FieldT>::get_digest_len(), MERKLE_TREE_DEPTH);

        // saveToFile(leafPath, leaf);
        // saveToFile(pathPath, path);
        // saveToFile(rootPath, root);
    }

    r1cs_ppzksnark_verification_key<BaseT> vk;
    {
        /* generate circuit */
        libff::print_header("Gunero Generator");

        GuneroMembershipCircuit<FieldT, BaseT, sha256_two_to_one_hash_gadget<FieldT>, MERKLE_TREE_DEPTH> gmc;

        gmc.generate(r1csPath, pkPath, vk);
    }

    r1cs_primary_input<FieldT> primary_input;
    r1cs_ppzksnark_proof<BaseT> r1cs_proof;
    {
        GuneroMembershipCircuit<FieldT, BaseT, sha256_two_to_one_hash_gadget<FieldT>, MERKLE_TREE_DEPTH> gmc;

        r1cs_ppzksnark_verification_key<BaseT> vk_proof;
        bool proven = gmc.prove(root, path, leaf, status, vk_proof, primary_input, r1cs_proof);

        bool verified = gmc.verify_after_generate(primary_input, r1cs_proof, vk_proof);
    }

    {
        GuneroMembershipCircuit<FieldT, BaseT, sha256_two_to_one_hash_gadget<FieldT>, MERKLE_TREE_DEPTH> gmc;

        // libff::bit_vector root;
        // loadFromFile(rootPath, root);

        // ZCProof proof;
        // loadFromFile(proofPath, proof);

        // ProofVerifier verifierEnabled = ProofVerifier::Strict();
        // ProofVerifier verifierDisabled = ProofVerifier::Disabled();

        bool verified = gmc.verify(primary_input, r1cs_proof);

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

    return 0;
}

