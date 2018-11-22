#ifndef GUNEROTRANSACTIONRECEIVE_GADGET_H_
#define GUNEROTRANSACTIONRECEIVE_GADGET_H_

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

#include "zcash/uint256.h"
#include "serialize.h"

#include "zcash/Zcash.h"

using namespace libsnark;

namespace gunero {

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
template<typename FieldT, typename BaseT, typename HashT>
class gunerotransactionreceive_gadget : public gadget<FieldT> {
public:
    // Verifier inputs
    pb_variable_array<FieldT> zk_packed_inputs;
    pb_variable_array<FieldT> zk_unpacked_inputs;
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker;
    std::shared_ptr<digest_variable<FieldT>> W;
    std::shared_ptr<digest_variable<FieldT>> T;

    // Aux inputs

    // Computed variables

    gunerotransactionreceive_gadget(protoboard<FieldT>& pb)
        : gadget<FieldT>(pb, "guneromembership_gadget")
    {
        // Verifier inputs
        {
            // The verification inputs are all bit-strings of various
            // lengths (256-bit digests and 64-bit integers) and so we
            // pack them into as few field elements as possible. (The
            // more verification inputs you have, the more expensive
            // verification is.)
            zk_packed_inputs.allocate(pb, verifying_field_element_size());
            pb.set_input_sizes(verifying_field_element_size());

            alloc_uint256(zk_unpacked_inputs, W);
            alloc_uint256(zk_unpacked_inputs, T);

            assert(zk_unpacked_inputs.size() == verifying_input_bit_size());

            // This gadget will ensure that all of the inputs we provide are
            // boolean constrained.
            unpacker.reset(new multipacking_gadget<FieldT>(
                pb,
                zk_unpacked_inputs,
                zk_packed_inputs,
                FieldT::capacity(),
                "unpacker"
            ));
        }
    }

    ~gunerotransactionreceive_gadget()
    {

    }

    static size_t verifying_input_bit_size() {
        size_t acc = 0;

        //W
        acc += HashT::get_digest_len(); // the merkle root (anchor) => libff::bit_vector root(digest_len); 

        //T
        acc += 256;

        //V_account
        acc += HashT::get_digest_len();

        return acc;
    }

    static size_t verifying_field_element_size() {
        return div_ceil(verifying_input_bit_size(), FieldT::capacity());
    }

    void generate_r1cs_constraints(
        const std::string& r1csPath,
        const std::string& pkPath,
        const std::string& vkPath
        )
    {
        libff::print_header("Gunero constraints");

        // The true passed here ensures all the inputs
        // are boolean constrained.
        unpacker->generate_r1cs_constraints(true);

        r1cs_constraint_system<FieldT> constraint_system = this->pb.get_constraint_system();

        if (r1csPath.length() > 0)
        {
            saveToFile(r1csPath, constraint_system);
        }

        printf("\n"); libff::print_indent(); libff::print_mem("after generator"); libff::print_time("after generator");

        r1cs_ppzksnark_keypair<BaseT> keypair = r1cs_ppzksnark_generator<BaseT>(constraint_system);

        //Verify
        r1cs_ppzksnark_processed_verification_key<BaseT> vk_precomp = r1cs_ppzksnark_verifier_process_vk<BaseT>(keypair.vk);

        if (pkPath.length() > 0)
        {
            saveToFile(pkPath, keypair.pk);
        }

        if (vkPath.length() > 0)
        {
            saveToFile(vkPath, keypair.vk);
        }

        printf("\n"); libff::print_indent(); libff::print_mem("after constraints"); libff::print_time("after constraints");
    }

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
    void generate_r1cs_witness(
        const uint256& pW,
        const uint256& pT,
        const uint256& pV_S,
        const uint256& pV_R,
        const uint256& pL,
        const uint252& ps_R,
        const uint256& pr_R,
        const uint160& pA_S,
        const uint256& pr_S,
        const uint256& pF,
        const uint256& pj
    )
    {
        // Witness rt. This is not a sanity check.
        W->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pW)
        );

        // This happens last, because only by now are all the
        // verifier inputs resolved.
        unpacker->generate_r1cs_witness_from_bits();
    }

    static r1cs_primary_input<FieldT> witness_map(
        const uint256& pW,
        const uint256& pT,
        const uint256& pV_S,
        const uint256& pV_R,
        const uint256& pL
    ) {
        std::vector<bool> verify_inputs;

        insert_uint256(verify_inputs, pW);

        insert_uint256(verify_inputs, pT);

        assert(verify_inputs.size() == verifying_input_bit_size());
        auto verify_field_elements = libff::pack_bit_vector_into_field_element_vector<FieldT>(verify_inputs);
        assert(verify_field_elements.size() == verifying_field_element_size());
        return verify_field_elements;
    }

    void alloc_uint256(
        pb_variable_array<FieldT>& packed_into,
        std::shared_ptr<digest_variable<FieldT>>& var
    ) {
        var.reset(new digest_variable<FieldT>(this->pb, 256, ""));
        packed_into.insert(packed_into.end(), var->bits.begin(), var->bits.end());
    }
};

} // end namespace `gunero`

#endif /* GUNEROTRANSACTIONRECEIVE_GADGET_H_ */