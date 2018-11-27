#ifndef GUNEROPROOF_H_
#define GUNEROPROOF_H_

#include <deque>
#include <mutex>
#include <boost/optional.hpp>
#include <boost/static_assert.hpp>
#include <libff/common/utils.hpp>
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
#include <libff/algebra/curves/edwards/edwards_pp.hpp>
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp>
#include <libff/common/utils.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>

#include "gunero_merkle_tree.hpp"
#include "guneromembership_gadget.hpp"

using namespace libsnark;

namespace gunero {

const unsigned char G1_PREFIX_MASK = 0x02;
const unsigned char G2_PREFIX_MASK = 0x0a;

typedef libff::alt_bn128_pp::G1_type curve_G1;
typedef libff::alt_bn128_pp::G2_type curve_G2;
typedef libff::alt_bn128_pp::GT_type curve_GT;
typedef libff::alt_bn128_pp::Fp_type curve_Fr;
typedef libff::alt_bn128_pp::Fq_type curve_Fq;
typedef libff::alt_bn128_pp::Fqe_type curve_Fq2;

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
};

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
};

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
};

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
};

// Compressed zkSNARK proof
class GuneroProof {
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
    GuneroProof() : g_A(), g_A_prime(), g_B(), g_B_prime(), g_C(), g_C_prime(), g_K(), g_H() { }

    // Produces a compressed proof using a libsnark zkSNARK proof
    template<typename libsnark_proof>
    GuneroProof(const libsnark_proof& proof);

    // Produces a libsnark zkSNARK proof out of this proof,
    // or throws an exception if it is invalid.
    template<typename libsnark_proof>
    libsnark_proof to_libsnark_proof() const;

    static GuneroProof random_invalid();

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

    friend bool operator==(const GuneroProof& a, const GuneroProof& b)
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

    friend bool operator!=(const GuneroProof& a, const GuneroProof& b)
    {
        return !(a == b);
    }

    friend std::ostream& operator<<(std::ostream &out, const GuneroProof &proof)
    {
        ::Serialize(out, proof, 1, 1);

        return out;
    }

    friend std::istream& operator>>(std::istream &in, GuneroProof &proof)
    {
        ::Unserialize(in, proof, 1, 1);

        return in;
    }
};

template<typename BaseT>
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
        } else {
            return true;
        }
    }
};

} // end namespace `gunero`

#endif /* GUNEROPROOF_H_ */