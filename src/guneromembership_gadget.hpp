#ifndef GUNEROMEMBERSHIP_GADGET_H_
#define GUNEROMEMBERSHIP_GADGET_H_

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

#include "uint252.h"
#include "gunero_merkle_tree_gadget.hpp"
#include "gunero_alt_gadget.hpp"

using namespace libsnark;

namespace gunero {

///// MEMBERSHIP PROOF /////
// Public Parameters:
// Authorization Root Hash (W)
// Account Status (N_account)
// Account View Hash (V_account)

// Private Parameters:
// Account Secret Key (s_account)
// alt: Account (A_account)
// Authorization Merkle Path (M_account[160])
// Account View Randomizer (r_account)

//1) Obtain A_account from s_account through EDCSA (secp256k1) operations
//1 alt) Obtain P_proof from s_account through PRF operations
//2) Validate W == calc_root(A_account, N_account, M_account[160]) (User is authorized)
//2 alt) Validate W == calc_root(A_account, keccak256(P_proof,N_account), M_account[160]) (User is authorized)
//3) Validate V_account == keccak256(A_account, keccak256(W,r_account) (View Hash is consistent)
//3 alt) Validate V_account == keccak256(P_proof, keccak256(W,r_account) (View Hash is consistent)
template<typename FieldT, typename BaseT, typename HashT, size_t tree_depth>
class guneromembership_gadget : public gadget<FieldT> {
public:
    // Verifier inputs
    pb_variable_array<FieldT> zk_packed_inputs;
    pb_variable_array<FieldT> zk_unpacked_inputs;
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker;
    std::shared_ptr<digest_variable<FieldT>> W;
    std::shared_ptr<digest_variable<FieldT>> N_account;
    std::shared_ptr<digest_variable<FieldT>> V_account;

    // Aux inputs
    pb_variable<FieldT> ZERO;
    std::shared_ptr<digest_variable<FieldT>> s_account;
    std::shared_ptr<gunero_merkle_tree_gadget<FieldT, HashT, tree_depth>> gunero_merkle_tree;
    std::shared_ptr<digest_variable<FieldT>> r_account;
    std::shared_ptr<digest_variable<FieldT>> A_account;

    // Computed variables
    std::shared_ptr<digest_variable<FieldT>> P_proof;
    std::shared_ptr<PRF_addr_a_pk_simple_gadget<FieldT>> spend_authority;
    std::shared_ptr<digest_variable<FieldT>> leaf_digest;
    std::shared_ptr<HashT> leaf_hasher;
    std::shared_ptr<digest_variable<FieldT>> view_hash_1_digest;
    std::shared_ptr<HashT> view_hash_1_hasher;
    std::shared_ptr<HashT> view_hash_2_hasher;

    guneromembership_gadget(protoboard<FieldT>& pb)
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
            alloc_uint256(zk_unpacked_inputs, N_account);
            alloc_uint256(zk_unpacked_inputs, V_account);

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

        // We need a constant "zero" variable in some contexts. In theory
        // it should never be necessary, but libsnark does not synthesize
        // optimal circuits.
        //
        // The first variable of our constraint system is constrained
        // to be one automatically for us, and is known as `ONE`.
        ZERO.allocate(pb);

        //We enforce 256 bits instead of 252 because of hash size compliance
        s_account.reset(new digest_variable<FieldT>(pb, 256, ""));//252

        P_proof.reset(new digest_variable<FieldT>(pb, 256, ""));

        spend_authority.reset(new PRF_addr_a_pk_simple_gadget<FieldT>(
            pb,
            ZERO,
            s_account->bits,
            P_proof
        ));

        leaf_digest.reset(new digest_variable<FieldT>(pb, 256, ""));

        leaf_hasher.reset(new HashT(
            pb,
            *P_proof,
            *N_account,
            *leaf_digest,
            "leaf_hasher"));

        gunero_merkle_tree.reset(new gunero_merkle_tree_gadget<FieldT, HashT, tree_depth>(
            pb,
            *leaf_digest,
            *W,
            ONE,
            "gunero_merkle_tree"));

        r_account.reset(new digest_variable<FieldT>(pb, 256, ""));

        view_hash_1_digest.reset(new digest_variable<FieldT>(pb, 256, ""));

        view_hash_1_hasher.reset(new HashT(
            pb,
            *W,
            *r_account,
            *view_hash_1_digest,
            "view_hash_1_hasher"));

        A_account.reset(new digest_variable<FieldT>(pb, 256, ""));

        view_hash_2_hasher.reset(new HashT(
            pb,
            *P_proof,
            *view_hash_1_digest,
            *V_account,
            "view_hash_2_hasher"));
    }

    ~guneromembership_gadget()
    {

    }

    static size_t verifying_input_bit_size() {
        size_t acc = 0;

        //W
        acc += HashT::get_digest_len(); // the merkle root (anchor) => libff::bit_vector root(digest_len); 

        //N_account
        //acc += 2;
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
#if DEBUG
        libff::print_header("Gunero constraints");
#endif

        // The true passed here ensures all the inputs
        // are boolean constrained.
        unpacker->generate_r1cs_constraints(true);

        // Constrain `ZERO`
        generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero(), "ZERO");

        s_account->generate_r1cs_constraints();

        P_proof->generate_r1cs_constraints();

        spend_authority->generate_r1cs_constraints();

        leaf_digest->generate_r1cs_constraints();

        leaf_hasher->generate_r1cs_constraints();

        // Constrain bitness of merkle_tree
        gunero_merkle_tree->generate_r1cs_constraints();

        r_account->generate_r1cs_constraints();

        view_hash_1_digest->generate_r1cs_constraints();

        view_hash_1_hasher->generate_r1cs_constraints();

        A_account->generate_r1cs_constraints();

        view_hash_2_hasher->generate_r1cs_constraints();

        //Calculate constraints
        r1cs_constraint_system<FieldT> constraint_system = this->pb.get_constraint_system();

        if (r1csPath.length() > 0)
        {
            saveToFile(r1csPath, constraint_system);
        }

#if DEBUG
        printf("\n"); libff::print_indent(); libff::print_mem("after generator"); libff::print_time("after generator");
#endif

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

#if DEBUG
        printf("\n"); libff::print_indent(); libff::print_mem("after constraints"); libff::print_time("after constraints");
#endif
    }

    // Public Parameters:
    // Authorization Root Hash (W)
    // Account Status (N_account)
    // Account View Hash (V_account)

    // Private Parameters:
    // alt X: Account Secret Key (s_account)
    // alt: Proof Secret Key (s_account)
    // alt: Account (A_account)
    // Authorization Merkle Path (M_account[160])
    // Account View Randomizer (r_account)
    void generate_r1cs_witness(
        const uint256& pW,
        const uint8_t pN_account,
        const uint256& pV_account,
        const uint252& ps_account,
        const std::vector<gunero_merkle_authentication_node>& pM_account,
        const uint160& pA_account,
        const uint256& pr_account
    )
    {
        // Witness rt. This is not a sanity check.
        W->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pW)
        );

        // Witness Status bits
        N_account->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(uint8_to_uint256(pN_account))
        );

        // Witness view hash. This is not a sanity check.
        V_account->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pV_account)
        );

        // Witness `zero`
        this->pb.val(ZERO) = FieldT::zero();

        // Witness s_account for the input
        s_account->bits.fill_with_bits(
            this->pb,
            uint252_to_bool_vector_256(ps_account)
        );

        // Witness P_proof for s_account with PRF_addr
        spend_authority->generate_r1cs_witness();

        // Witness hash(P_proof, N_account) = leaf_digest
        leaf_hasher->generate_r1cs_witness();

        //Trim account to correct size
        // A_account_padded = libff::bit_vector(HashT::get_digest_len() - A_account.size());
        // A_account_padded.insert(A_account_padded.begin(), A_account.begin(), A_account.end());
        libff::bit_vector A_account_padded = uint160_to_bool_vector_256_rpad(pA_account);
        if (A_account_padded.size() > tree_depth)
        {
            A_account_padded.erase(A_account_padded.begin() + tree_depth, A_account_padded.end());
        }
        else if (A_account_padded.size() < tree_depth)
        {
            throw std::runtime_error(strprintf("pA_account cannot be a size less than %lu", tree_depth));
        }

        // Witness merkle tree authentication path
        gunero_merkle_tree->generate_r1cs_witness(pM_account, A_account_padded);

        // Witness r_account for the input
        r_account->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pr_account)
        );

        // Witness hash(W, r_account) = view_hash_1_digest
        view_hash_1_hasher->generate_r1cs_witness();

        // Witness A_account for the input
        A_account->bits.fill_with_bits(
            this->pb,
            uint160_to_bool_vector_256_rpad(pA_account)
        );

        // Witness hash(P_proof, view_hash_1_digest) = V_account
        view_hash_2_hasher->generate_r1cs_witness();

        // [SANITY CHECK] Ensure that the intended root
        // was witnessed by the inputs, even if the read
        // gadget overwrote it. This allows the prover to
        // fail instead of the verifier, in the event that
        // the roots of the inputs do not match the
        // treestate provided to the proving API.
        W->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pW)
        );

        // [SANITY CHECK] Ensure that the intended root
        // was witnessed by the inputs, even if the read
        // gadget overwrote it. This allows the prover to
        // fail instead of the verifier, in the event that
        // the roots of the inputs do not match the
        // hash provided to the proving hashers.
        V_account->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pV_account)
        );

        // This happens last, because only by now are all the
        // verifier inputs resolved.
        unpacker->generate_r1cs_witness_from_bits();
    }

    static r1cs_primary_input<FieldT> witness_map(
        const uint256& pW,
        const uint8_t& pN_account,
        const uint256& pV_account
    ) {
        std::vector<bool> verify_inputs;

        insert_uint256(verify_inputs, pW);

        //insert_uint_bits(verify_inputs, status, 2);
        insert_uint256(verify_inputs, uint8_to_uint256(pN_account));

        insert_uint256(verify_inputs, pV_account);

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

#endif /* GUNEROMEMBERSHIP_GADGET_H_ */