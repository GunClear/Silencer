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
    //typedef merkle_authentication_path merkle_authentication_path_type;

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

} // end namespace `gunero`

#endif /* KECCAK_GADGET_H_ */