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
//#include <libff/algebra/curves/bn128/bn128_pp.hpp>
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

template<typename FieldT>
pb_variable_array<FieldT> gen256zeroes(pb_variable<FieldT>& ZERO) {
    pb_variable_array<FieldT> ret;
    while (ret.size() < 256) {
        ret.emplace_back(ZERO);
    }

    return ret;
}

template<typename FieldT>
class PRF_gadget : gadget<FieldT> {
private:
    std::shared_ptr<block_variable<FieldT>> block;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher;
    std::shared_ptr<digest_variable<FieldT>> result;

public:
    PRF_gadget(
        protoboard<FieldT>& pb,
        pb_variable<FieldT>& ZERO,
        bool a,
        bool b,
        bool c,
        bool d,
        pb_variable_array<FieldT> x,
        pb_variable_array<FieldT> y,
        std::shared_ptr<digest_variable<FieldT>> result
    ) : gadget<FieldT>(pb), result(result) {

        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        pb_variable_array<FieldT> discriminants;
        discriminants.emplace_back(a ? ONE : ZERO);
        discriminants.emplace_back(b ? ONE : ZERO);
        discriminants.emplace_back(c ? ONE : ZERO);
        discriminants.emplace_back(d ? ONE : ZERO);

        block.reset(new block_variable<FieldT>(pb, {
            discriminants,
            x,
            y
        }, "PRF_block"));

        hasher.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block->bits,
            *result,
        "PRF_hasher"));
    }

    void generate_r1cs_constraints() {
        hasher->generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        hasher->generate_r1cs_witness();
    }
};

template<typename FieldT>
class PRF_addr_a_pk_gadget : public PRF_gadget<FieldT> {
public:
    PRF_addr_a_pk_gadget(
        protoboard<FieldT>& pb,
        pb_variable<FieldT>& ZERO,
        pb_variable_array<FieldT>& a_sk,
        std::shared_ptr<digest_variable<FieldT>> result
    ) : PRF_gadget<FieldT>(pb, ZERO, 1, 1, 0, 0, a_sk, gen256zeroes(ZERO), result) {}
};

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
    std::shared_ptr<digest_variable<FieldT>> status_uint2;

    // Aux inputs
    pb_variable<FieldT> ZERO;
    std::shared_ptr<digest_variable<FieldT>> a_sk;
    std::shared_ptr<digest_variable<FieldT>> a_pk;
    std::shared_ptr<PRF_addr_a_pk_gadget<FieldT>> spend_authority;
    std::shared_ptr<digest_variable<FieldT>> leaf_digest;
    std::shared_ptr<gunero_merkle_tree_gadget<FieldT, HashT, tree_depth>> witness_input;

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

            // status_uint2.allocate(pb, 2);
            status_uint2.reset(new digest_variable<FieldT>(pb, 2, "status"));

            pb.set_input_sizes(verifying_field_element_size());
        }

        // We need a constant "zero" variable in some contexts. In theory
        // it should never be necessary, but libsnark does not synthesize
        // optimal circuits.
        // 
        // The first variable of our constraint system is constrained
        // to be one automatically for us, and is known as `ONE`.
        ZERO.allocate(pb);

        a_sk.reset(new digest_variable<FieldT>(pb, 252, ""));

        a_pk.reset(new digest_variable<FieldT>(pb, 256, ""));

        spend_authority.reset(new PRF_addr_a_pk_gadget<FieldT>(
            pb,
            ZERO,
            a_sk->bits,
            a_pk
        ));

        leaf_digest.reset(new digest_variable<FieldT>(pb, 256, "leaf"));

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

        //zk_merkle_root
        acc += HashT::get_digest_len(); // the merkle root (anchor) => libff::bit_vector root(digest_len); 

        //status_uint2
        acc += 2;

        return acc;
    }

    static size_t verifying_field_element_size() {
        return div_ceil(verifying_input_bit_size(), FieldT::capacity());
    }

    void generate_r1cs_constraints(
        const std::string& r1csPath,
        r1cs_ppzksnark_proving_key<BaseT>& pk,
        r1cs_ppzksnark_verification_key<BaseT>& vk
        )
    {
        libff::print_header("Gunero constraints");

        // // The true passed here ensures all the inputs
        // // are boolean constrained.
        // unpacker->generate_r1cs_constraints(true);

        zk_merkle_root->generate_r1cs_constraints();

        status_uint2->generate_r1cs_constraints();

        // Constrain `ZERO`
        generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero(), "ZERO");

        a_sk->generate_r1cs_constraints();

        spend_authority->generate_r1cs_constraints();

        // Constrain bitness of leaf_digest
        leaf_digest->generate_r1cs_constraints();

        // Constrain bitness of merkle_tree
        witness_input->generate_r1cs_constraints();

        {
            r1cs_constraint_system<FieldT> constraint_system = this->pb.get_constraint_system();

            if (r1csPath.length() > 0)
            {
                saveToFile(r1csPath, constraint_system);
            }

            printf("\n"); libff::print_indent(); libff::print_mem("after generator"); libff::print_time("after generator");

            r1cs_ppzksnark_keypair<BaseT> keypair = r1cs_ppzksnark_generator<BaseT>(constraint_system);

            pk = keypair.pk;

            vk = keypair.vk;
        }

        printf("\n"); libff::print_indent(); libff::print_mem("after constraints"); libff::print_time("after constraints");
    }

    void generate_r1cs_witness(
        const libff::bit_vector& root,
        const SpendingKey& key,
        const libff::bit_vector& leaf,
        const GuneroMerklePath& path,
        const uint8_t Status
    )
    {
        // Witness rt. This is not a sanity check.
        zk_merkle_root->bits.fill_with_bits(
            this->pb,
            root
        );

        // Witness `zero`
        this->pb.val(ZERO) = FieldT::zero();

        // Witness a_sk for the input
        a_sk->bits.fill_with_bits(
            this->pb,
            uint252_to_bool_vector(key)
        );

        // Witness a_pk for a_sk with PRF_addr
        spend_authority->generate_r1cs_witness();

        // leaf_digest->generate_r1cs_witness(leaf);
        // Witness leaf
        leaf_digest->bits.fill_with_bits(
            this->pb,
            leaf
        );

        // Witness merkle tree authentication path
        witness_input->generate_r1cs_witness(path);

        // Witness Status bits
        status_uint2->bits.fill_with_bits(
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

    static r1cs_primary_input<FieldT> witness_map(
        const uint256& rt,
        const uint8_t& status
    ) {
        std::vector<bool> verify_inputs;

        insert_uint256(verify_inputs, rt);

        insert_uint_bits(verify_inputs, status, 2);

        assert(verify_inputs.size() == verifying_input_bit_size());
        auto verify_field_elements = libff::pack_bit_vector_into_field_element_vector<FieldT>(verify_inputs);
        assert(verify_field_elements.size() == verifying_field_element_size());
        return verify_field_elements;
    }
};

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
        const PrimaryInput& primary_input,
        const Proof& proof
    ){
        if (perform_verification) {
            return r1cs_ppzksnark_online_verifier_strong_IC<BaseT>(pvk, primary_input, proof);
            //return r1cs_ppzksnark_verifier_strong_IC<BaseT>(vk, primary_input, proof);
        } else {
            return true;
        }
    }
};

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
    // const size_t digest_len;

    GuneroMembershipCircuit()
        // : digest_len(HashT::get_digest_len())
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
        const std::string& vkPath
    ) {
        // const r1cs_constraint_system<FieldT> constraint_system = generate_r1cs();
        // r1cs_ppzksnark_keypair<BaseT> keypair = r1cs_ppzksnark_generator<BaseT>(constraint_system);

        // pk = keypair.pk;
        // vk = keypair.vk;
        // processVerifyingKey();

        protoboard<FieldT> pb;
        guneromembership_gadget<FieldT, BaseT, HashT, tree_depth> gunero(pb);

        r1cs_ppzksnark_proving_key<BaseT> pk;
        r1cs_ppzksnark_verification_key<BaseT> vk;
        //r1cs_ppzksnark_processed_verification_key<BaseT> vk_precomp;
        gunero.generate_r1cs_constraints(r1csPath, pk, vk);//, vk_precomp);

        if (pkPath.length() > 0)
        {
            saveToFile(pkPath, pk);
        }
        if (vkPath.length() > 0)
        {
            saveToFile(vkPath, vk);

            // //Verify
            // {
            //     r1cs_ppzksnark_processed_verification_key<BaseT> vk_precomp_2 = r1cs_ppzksnark_verifier_process_vk(vk);

            //     assert(vk_precomp == vk_precomp_2);
            // }
        }
     }

    //template<typename FieldT, typename BaseT, typename HashT, size_t tree_depth>
    static void makeTestVariables(
        GuneroMerklePath& p_path,
        libff::bit_vector& leaf,
        libff::bit_vector& root,
        uint256& root_uint256
    )
    {
        /* prepare test variables */
        libff::print_header("Gunero prepare test variables");
        std::vector<merkle_authentication_node> path(tree_depth);

        libff::bit_vector prev_hash(HashT::get_digest_len());
        std::generate(prev_hash.begin(), prev_hash.end(), [&]() { return std::rand() % 2; });
        leaf = prev_hash;

        libff::bit_vector address_bits;

        size_t address = 0;
        for (long level = tree_depth-1; level >= 0; --level)
        {
            //Generate random uncle position
            const bool computed_is_right = (std::rand() % 2);
            address |= (computed_is_right ? 1ul << (tree_depth-1-level) : 0);
            address_bits.push_back(computed_is_right);

            //Generate random uncle
            libff::bit_vector uncle(HashT::get_digest_len());
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
        const SpendingKey& key,
        const GuneroMerklePath& path,
        const libff::bit_vector& leaf,
        const uint8_t status,
        const r1cs_ppzksnark_proving_key<BaseT>& pk,
        r1cs_primary_input<FieldT>& primary_input,
        ZCProof& proof
    ) {
        libff::print_header("Gunero witness (proof)");

        {
            // libff::print_header("Gunero loadFromFile(pk)");
            // r1cs_ppzksnark_proving_key<BaseT> pk;
            // loadFromFile(pkPath, pk);
            // printf("\n"); libff::print_indent(); libff::print_mem("after Gunero loadFromFile(pk)"); libff::print_time("after Gunero loadFromFile(pk)");

            r1cs_auxiliary_input<FieldT> aux_input;
            {
                protoboard<FieldT> pb;
                {
                    libff::print_header("Gunero guneromembership_gadget.load_r1cs_constraints()");

                    guneromembership_gadget<FieldT, BaseT, HashT, tree_depth> g(pb);
                    // g.generate_r1cs_constraints(
                    //     std::string(),
                    //     pk,
                    //     vk);
                    g.generate_r1cs_witness(
                        root,
                        key,
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

            r1cs_ppzksnark_proof<BaseT> r1cs_proof = r1cs_ppzksnark_prover<BaseT>(
                pk,
                primary_input,
                aux_input
            );

            proof = ZCProof(r1cs_proof);

            printf("\n"); libff::print_indent(); libff::print_mem("after witness (proof)"); libff::print_time("after witness (proof)");
        }

        return true;
    }

    bool verify(
        const r1cs_primary_input<FieldT>& primary_input,
        //const r1cs_ppzksnark_proof<BaseT>& r1cs_proof,
        const ZCProof& proof,
        const r1cs_ppzksnark_verification_key<BaseT>& vk,
        const r1cs_ppzksnark_processed_verification_key<BaseT>& vk_precomp
        )
    {
        // r1cs_ppzksnark_processed_verification_key<BaseT> vk_precomp = r1cs_ppzksnark_verifier_process_vk(vk);
        try
        {
            // uint256 root_uint256 = bool_vector_to_uint256(root);

            // r1cs_primary_input<FieldT> r1cs_primary_input = guneromembership_gadget<FieldT, BaseT, HashT, tree_depth>::witness_map(
            //     root_uint256
            // );

            // assert(primary_input == r1cs_primary_input);

            r1cs_ppzksnark_proof<BaseT> r1cs_proof = proof.to_libsnark_proof<r1cs_ppzksnark_proof<BaseT>>();

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
    std::string vkPath = "/home/sean/Silencer/build/src/vk.bin";

    // std::string addressPath = "/home/sean/Silencer/build/src/p_address.bin";
    // std::string leafPath = "/home/sean/Silencer/build/src/p_leaf.bin";
    // std::string pathPath = "/home/sean/Silencer/build/src/p_path.bin";
    // std::string rootPath = "/home/sean/Silencer/build/src/p_root.bin";
    std::string proofPath = "/home/sean/Silencer/build/src/proof.bin";

    //Given secret key s [512b]
    //P = secp256k1multiply(G, s) [512b]
    //A = right(keccak256(P), 20) [160b]
    //leaf = keccak256compress(A, status)
    // libff::bit_vector a_sk;//secretKey
    // libff::bit_vector a_pk;//account
    SpendingKey key;
    uint8_t status = 1;
    libff::bit_vector leaf;
    libff::bit_vector root;
    uint256 root_uint256;
    GuneroMerklePath path;

    //Make test
    {
        GuneroMembershipCircuit<FieldT, BaseT, sha256_two_to_one_hash_gadget<FieldT>, MERKLE_TREE_DEPTH>::makeTestVariables(path, leaf, root, root_uint256);

        // saveToFile(leafPath, leaf);
        // saveToFile(pathPath, path);
        // saveToFile(rootPath, root);
    }

    //Generate
    {
        /* generate circuit */
        libff::print_header("Gunero Generator");

        GuneroMembershipCircuit<FieldT, BaseT, sha256_two_to_one_hash_gadget<FieldT>, MERKLE_TREE_DEPTH> gmc;

        gmc.generate(r1csPath, pkPath, vkPath);
    }

    // //Verify online vk
    // if (false) {
    //     r1cs_ppzksnark_verification_key<BaseT> vk;
    //     loadFromFile(vkPath, vk);

    //     r1cs_ppzksnark_processed_verification_key<BaseT> vk_precomp = r1cs_ppzksnark_verifier_process_vk<BaseT>(vk);
    // }

    //Prove
    r1cs_primary_input<FieldT> primary_input;
    {
        r1cs_ppzksnark_proving_key<BaseT> pk;
        loadFromFile(pkPath, pk);

        GuneroMembershipCircuit<FieldT, BaseT, sha256_two_to_one_hash_gadget<FieldT>, MERKLE_TREE_DEPTH> gmc;

        ZCProof proof;
        bool proven = gmc.prove(root, key, path, leaf, status, pk, primary_input, proof);
        
        saveToFile(proofPath, proof);
    }

    //Verify
    {
        r1cs_ppzksnark_verification_key<BaseT> vk;
        loadFromFile(vkPath, vk);

        r1cs_ppzksnark_processed_verification_key<BaseT> vk_precomp = r1cs_ppzksnark_verifier_process_vk<BaseT>(vk);

        // libff::bit_vector root;
        // loadFromFile(rootPath, root);

        ZCProof proof;
        loadFromFile(proofPath, proof);

        // ProofVerifier verifierEnabled = ProofVerifier::Strict();
        // ProofVerifier verifierDisabled = ProofVerifier::Disabled();

        GuneroMembershipCircuit<FieldT, BaseT, sha256_two_to_one_hash_gadget<FieldT>, MERKLE_TREE_DEPTH> gmc;

        bool verified = gmc.verify(primary_input, proof, vk, vk_precomp);

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

