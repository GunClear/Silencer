#ifndef GUNERO_MERKLE_TREE_GADGET_H_
#define GUNERO_MERKLE_TREE_GADGET_H_

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

#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>

#include "uint256.h"
#include "serialize.h"
#include "gunero_merkle_tree.hpp"

using namespace libsnark;

namespace gunero {

template<typename FieldT, typename HashT, size_t tree_depth>
class gunero_merkle_tree_gadget : gadget<FieldT> {
private:
    pb_variable_array<FieldT> positions;
    std::shared_ptr<gunero_merkle_authentication_path_variable<FieldT, HashT>> authvars;
    std::shared_ptr<gunero_merkle_tree_check_read_gadget<FieldT, HashT>> auth;

public:
    gunero_merkle_tree_gadget(
        protoboard<FieldT>& pb,
        digest_variable<FieldT>& leaf,
        digest_variable<FieldT>& root,
        const pb_variable<FieldT>& enforce,
        const std::string &annotation_prefix
    ) : gadget<FieldT>(pb, annotation_prefix) {
        positions.allocate(pb, tree_depth);
        authvars.reset(new gunero_merkle_authentication_path_variable<FieldT, HashT>(
            pb, tree_depth, "auth"
        ));
        auth.reset(new gunero_merkle_tree_check_read_gadget<FieldT, HashT>(
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

    void generate_r1cs_witness(const std::vector<gunero_merkle_authentication_node>& M_account, const libff::bit_vector& A_account)
    {
        // size_t path_index_account = convertVectorToInt(path.index_account);
        // uint256 path_A_account = bool_vector_to_uint256(A_account);
        // size_t path_index_account = convertVectorToInt(A_account);

        // positions.fill_with_bits_of_ulong(this->pb, path_index_account);
        libff::bit_vector A_account_LSB(tree_depth);
        for(size_t i = 0; i < tree_depth; i++)
        {
            A_account_LSB.at(i) = A_account.at(tree_depth - 1 - i);
        }
        positions.fill_with_bits(this->pb, A_account_LSB);

        // authvars->generate_r1cs_witness(path_index_account, path.authentication_path);
        // auth->generate_r1cs_witness();

        // positions.fill_with_bits(this->pb, A_account);

        authvars->generate_r1cs_witness(A_account, M_account);
        auth->generate_r1cs_witness();
    }
};

} // end namespace `gunero`

#endif /* GUNERO_MERKLE_TREE_GADGET_H_ */