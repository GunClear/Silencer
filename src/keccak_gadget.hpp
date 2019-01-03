#ifndef KECCAK_GADGET_H_
#define KECCAK_GADGET_H_

#include <deque>
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

#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>

#include "uint256.h"
#include "serialize.h"

using namespace libsnark;

namespace gunero {

template<typename FieldT>
class xor10_gadget : public gadget<FieldT> {
private:
    std::vector<pb_variable<FieldT>> tmp_vars;
public:
    std::shared_ptr<pb_linear_combination_array<FieldT>> Am0;
    std::shared_ptr<pb_linear_combination_array<FieldT>> Am1;
    std::shared_ptr<pb_linear_combination_array<FieldT>> Am2;
    std::shared_ptr<pb_linear_combination_array<FieldT>> Am3;
    std::shared_ptr<pb_linear_combination_array<FieldT>> Am4;
    std::shared_ptr<pb_linear_combination_array<FieldT>> Ap0;
    std::shared_ptr<pb_linear_combination_array<FieldT>> Ap1;
    std::shared_ptr<pb_linear_combination_array<FieldT>> Ap2;
    std::shared_ptr<pb_linear_combination_array<FieldT>> Ap3;
    std::shared_ptr<pb_linear_combination_array<FieldT>> Ap4;
    std::shared_ptr<pb_linear_combination_array<FieldT>> result;

    xor10_gadget(protoboard<FieldT> &pb,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &Am0,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &Am1,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &Am2,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &Am3,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &Am4,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &Ap0,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &Ap1,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &Ap2,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &Ap3,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &Ap4,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &result,
                const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename FieldT>
class rot_xor2_gadget : public gadget<FieldT> {
public:
    std::shared_ptr<pb_linear_combination_array<FieldT>> A;
    std::shared_ptr<pb_linear_combination_array<FieldT>> D;
    uint64_t r;
    std::shared_ptr<pb_linear_combination_array<FieldT>> B;

    rot_xor2_gadget(protoboard<FieldT> &pb,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &A,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &D,
                const uint64_t &r,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &B,
                const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename FieldT>
class xor_not_and_xor : public gadget<FieldT> {
private:
    std::vector<pb_variable<FieldT>> tmp_vars;
public:
    std::shared_ptr<pb_linear_combination_array<FieldT>> B1;
    std::shared_ptr<pb_linear_combination_array<FieldT>> B2;
    std::shared_ptr<pb_linear_combination_array<FieldT>> B3;
    const uint64_t RC;
    pb_linear_combination_array<FieldT> RC_bits;
    std::shared_ptr<pb_linear_combination_array<FieldT>> A_out;

    xor_not_and_xor(protoboard<FieldT> &pb,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &B1,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &B2,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &B3,
                const uint64_t &RC,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &A_out,
                const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename FieldT>
class xor_not_and : public gadget<FieldT> {
private:
    std::vector<pb_variable<FieldT>> tmp_vars;
public:
    std::shared_ptr<pb_linear_combination_array<FieldT>> B1;
    std::shared_ptr<pb_linear_combination_array<FieldT>> B2;
    std::shared_ptr<pb_linear_combination_array<FieldT>> B3;
    std::shared_ptr<pb_linear_combination_array<FieldT>> A_out;

    xor_not_and(protoboard<FieldT> &pb,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &B1,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &B2,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &B3,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &A_out,
                const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

// ========================================================================================
// keccakf1600_round algorithm
// ========================================================================================
template<typename FieldT>
class keccakf1600_round_gadget : public gadget<FieldT> {
public:
    std::vector<std::shared_ptr<xor10_gadget<FieldT>>> compute_xor10;
    std::vector<std::shared_ptr<rot_xor2_gadget<FieldT>>> compute_rot_xor2;
    std::vector<std::shared_ptr<pb_linear_combination_array<FieldT>>> D;
    std::vector<std::shared_ptr<pb_linear_combination_array<FieldT>>> B;
    std::shared_ptr<xor_not_and_xor<FieldT>> compute_xor_not_and_xor;
    std::vector<std::shared_ptr<xor_not_and<FieldT>>> compute_xor_not_and;
public:
    std::vector<std::shared_ptr<pb_linear_combination_array<FieldT>>> round_A;
    std::vector<std::shared_ptr<pb_linear_combination_array<FieldT>>> round_A_out;
    uint64_t RC;

    keccakf1600_round_gadget(protoboard<FieldT> &pb,
                                const std::vector<std::shared_ptr<pb_linear_combination_array<FieldT>>> &round_A,
                                const uint64_t &RC,
                                const std::vector<std::shared_ptr<pb_linear_combination_array<FieldT>>> &round_A_out,
                                const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

// ========================================================================================
// keccakf1600 algorithm
// ========================================================================================
// IN: A[25]
// OUT: A_OUT[25]
// VARIABLES: A_TMP[25](23)
// CIRCUITS: keccakf1600_round(24)
template<typename FieldT>
class keccakf1600_gadget : public gadget<FieldT> {
public:
    const uint8_t delim;
    std::vector<std::vector<std::shared_ptr<pb_linear_combination_array<FieldT>>>> round_As;
    std::vector<keccakf1600_round_gadget<FieldT>> round_functions;

public:
    block_variable<FieldT> input;
    digest_variable<FieldT> output;

    keccakf1600_gadget(protoboard<FieldT> &pb,
                const uint8_t delim,
                const block_variable<FieldT> &input,
                const digest_variable<FieldT> &output,
                const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename FieldT>
class keccak256_message_schedule_gadget : public gadget<FieldT> {
public:
    std::vector<pb_variable_array<FieldT> > A_bits;
    std::vector<std::shared_ptr<packing_gadget<FieldT> > > pack_A;

public:
    pb_variable_array<FieldT> A;
    pb_variable_array<FieldT> packed_A;
    keccak256_message_schedule_gadget(protoboard<FieldT> &pb,
                                   const pb_variable_array<FieldT> &A,
                                   const pb_variable_array<FieldT> &packed_A,
                                   const std::string &annotation_prefix);
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

#define KECCAK256_digest_size   256

template<typename FieldT>
class keccak256_gadget : gadget<FieldT> {
public:
    const static uint8_t delim = 0x01;
    std::shared_ptr<block_variable<FieldT>> block1;
    std::shared_ptr<block_variable<FieldT>> block2;
    std::shared_ptr<keccakf1600_gadget<FieldT>> hasher;

public:

    keccak256_gadget(protoboard<FieldT> &pb,
                                const digest_variable<FieldT> &left,
                                const digest_variable<FieldT> &right,
                                const digest_variable<FieldT> &output,
                                const std::string &annotation_prefix) :
        gadget<FieldT>(pb, annotation_prefix)
    {
        /* concatenate block = left || right */
        pb_variable_array<FieldT> input_block;
        input_block.insert(input_block.end(), left.bits.begin(), left.bits.end());
        input_block.insert(input_block.end(), right.bits.begin(), right.bits.end());

        /* compute the hash itself */
        pb_variable<FieldT> ZERO;

        ZERO.allocate(pb, "ZERO");
        pb.val(ZERO) = 0;

        hasher.reset(new keccakf1600_gadget<FieldT>(
            pb,
            input_block,
            output,
        "hasher"));
    }

    keccak256_gadget(protoboard<FieldT> &pb,
                                const size_t block_length,
                                const block_variable<FieldT> &input_block,
                                const digest_variable<FieldT> &output,
                                const std::string &annotation_prefix) : gadget<FieldT>(pb, "sha256_ethereum") {

        pb_variable<FieldT> ZERO;

        ZERO.allocate(pb, "ZERO");
        pb.val(ZERO) = 0;

        hasher.reset(new keccakf1600_gadget<FieldT>(
            pb,
            input_block.bits,
            output,
        "hasher"));
    }

    void generate_r1cs_constraints(const bool ensure_output_bitness=true) {
        libff::UNUSED(ensure_output_bitness);
        hasher->generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        hasher->generate_r1cs_witness();
    }

    static size_t get_digest_len()
    {
        return 256;
    }

    static libff::bit_vector get_hash(const libff::bit_vector &input)
    {
        protoboard<FieldT> pb;

        block_variable<FieldT> input_variable(pb, input.size(), "input");
        digest_variable<FieldT> output_variable(pb, KECCAK256_digest_size, "output");

        keccakf1600_gadget<FieldT> f(pb, delim, input_variable, output_variable, "f");

        input_variable.generate_r1cs_witness(input);
        f.generate_r1cs_witness();

        return output_variable.get_digest();
    }

    static size_t expected_constraints(const bool ensure_output_bitness)
    {
        libff::UNUSED(ensure_output_bitness);
        return 54560; /* hardcoded for now */
    }
};


} // end namespace `gunero`

#endif /* KECCAK_GADGET_H_ */