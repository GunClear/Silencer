#ifndef GUNERO_ALT_GADGET_H_
#define GUNERO_ALT_GADGET_H_

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

#include "gunero_merkle_tree_gadget.hpp"
#include "uint252.h"

using namespace libsnark;

namespace gunero {

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

template<typename FieldT>
class PRF_simple_gadget : gadget<FieldT> {
private:
    std::shared_ptr<block_variable<FieldT>> block;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher;
    std::shared_ptr<digest_variable<FieldT>> result;

public:
    PRF_simple_gadget(
        protoboard<FieldT>& pb,
        pb_variable_array<FieldT> x,
        pb_variable_array<FieldT> y,
        std::shared_ptr<digest_variable<FieldT>> result
    ) : gadget<FieldT>(pb), result(result) {

        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        block.reset(new block_variable<FieldT>(pb, {
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
class PRF_addr_a_pk_simple_gadget : public PRF_simple_gadget<FieldT> {
public:
    PRF_addr_a_pk_simple_gadget(
        protoboard<FieldT>& pb,
        pb_variable<FieldT>& ZERO,
        pb_variable_array<FieldT>& a_sk,
        std::shared_ptr<digest_variable<FieldT>> result
    ) : PRF_simple_gadget<FieldT>(pb, a_sk, gen256zeroes(ZERO), result) {}
};

} // end namespace `gunero`

#endif /* GUNERO_ALT_GADGET_H_ */