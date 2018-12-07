#ifndef GUNEROTRANSACTIONSEND_GADGET_H_
#define GUNEROTRANSACTIONSEND_GADGET_H_

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

#include "uint252.h"

using namespace libsnark;

namespace gunero {

///// TRANSACTION SEND PROOF /////
// With this proof, we are validating that the sender of the token is accepting that this token's ownership should
// be transferred to the new transaction hash given. The "account view hash" validates that this proof is consistent
// with the others generated, and also serves as an additional precaution for others using this proof to validate an
// unauthorized release of the token to a party not covered in the transaction.
// Public Parameters:
// Current Authorization Root Hash (W)
// Token UID (T)
// Sender Account View Hash (V_S)
// Receiver Account View Hash (V_R)
// Previous Transaction Hash (L_P)

// Private Parameters:
// Sender Private Key (s_S)
// Sender Account View Randomizer (r_S)
// Receiver Account View Randomizer (r_R)
// Previous Sender Account Address (A_PS)
// Previous Authorization Root Hash (W_P)
// alt: Receiver Proof Public Key (P_proof_R)

//1) Obtain A_S from s_S through EDCSA operations
//1 alt) Obtain P_proof_S from s_S through PRF operations
//2) Validate V_S == hash(A_S, hash(W, r_S)) (View Hash is consistent for Sender)
//2 alt) Validate V_S == hash(P_proof_S, hash(W, r_S)) (View Hash is consistent for Sender)
//3) Validate V_R == hash(A_R, hash(W, r_R)) (View Hash is consistent for Receiver)
//3 alt) Validate V_R == hash(P_proof_R, hash(W, r_R)) (View Hash is consistent for Receiver)
//4) Validate L_P == hash(A_PS, hash(s_S, hash(T, W_P))) (The send proof is valid, sender owns token)
template<typename FieldT, typename BaseT, typename HashT>
class gunerotransactionsend_gadget : public gadget<FieldT> {
public:
    // Verifier inputs
    pb_variable_array<FieldT> zk_packed_inputs;
    pb_variable_array<FieldT> zk_unpacked_inputs;
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker;
    std::shared_ptr<digest_variable<FieldT>> W;
    std::shared_ptr<digest_variable<FieldT>> T;
    std::shared_ptr<digest_variable<FieldT>> V_S;
    std::shared_ptr<digest_variable<FieldT>> V_R;
    std::shared_ptr<digest_variable<FieldT>> L_P;

    // Aux inputs
    // pb_variable<FieldT> ZERO;
    std::shared_ptr<digest_variable<FieldT>> ZERO;
    std::shared_ptr<digest_variable<FieldT>> s_S;
    std::shared_ptr<digest_variable<FieldT>> r_S;
    std::shared_ptr<digest_variable<FieldT>> r_R;
    std::shared_ptr<digest_variable<FieldT>> A_PS;
    std::shared_ptr<digest_variable<FieldT>> W_P;
    std::shared_ptr<digest_variable<FieldT>> P_proof_R;//alt

    // Computed variables
    std::shared_ptr<digest_variable<FieldT>> P_proof_S;
    // std::shared_ptr<PRF_addr_a_pk_simple_gadget<FieldT>> spend_authority;
    std::shared_ptr<HashT> spend_authority;
    std::shared_ptr<digest_variable<FieldT>> view_hash_1_digest;
    std::shared_ptr<HashT> view_hash_1_hasher;
    std::shared_ptr<HashT> view_hash_2_hasher;
    std::shared_ptr<digest_variable<FieldT>> view_hash_2_digest;
    std::shared_ptr<HashT> view_hash_3_hasher;
    std::shared_ptr<HashT> view_hash_4_hasher;
    std::shared_ptr<digest_variable<FieldT>> transaction_hash_1_digest;
    std::shared_ptr<HashT> transaction_hash_1_hasher;
    std::shared_ptr<digest_variable<FieldT>> transaction_hash_2_digest;
    std::shared_ptr<HashT> transaction_hash_2_hasher;
    std::shared_ptr<HashT> transaction_hash_3_hasher;

    gunerotransactionsend_gadget(protoboard<FieldT>& pb)
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
            alloc_uint256(zk_unpacked_inputs, V_S);
            alloc_uint256(zk_unpacked_inputs, V_R);
            alloc_uint256(zk_unpacked_inputs, L_P);

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
        // ZERO.allocate(pb);
        ZERO.reset(new digest_variable<FieldT>(pb, 256, ""));

        //We enforce 256 bits instead of 252 because of hash size compliance
        s_S.reset(new digest_variable<FieldT>(pb, 256, ""));//252

        r_S.reset(new digest_variable<FieldT>(pb, 256, ""));

        r_R.reset(new digest_variable<FieldT>(pb, 256, ""));

        A_PS.reset(new digest_variable<FieldT>(pb, 256, ""));

        W_P.reset(new digest_variable<FieldT>(pb, 256, ""));

        P_proof_R.reset(new digest_variable<FieldT>(pb, 256, ""));

        P_proof_S.reset(new digest_variable<FieldT>(pb, 256, ""));

        // spend_authority.reset(new PRF_addr_a_pk_simple_gadget<FieldT>(
        //     pb,
        //     ZERO,
        //     s_S->bits,
        //     P_proof_S
        // ));
        spend_authority.reset(new HashT(
            pb,
            *s_S,
            *ZERO,
            *P_proof_S,
            "spend_authority"));

        //hash(P_proof_S, hash(W, r_S)) == V_S
        view_hash_1_digest.reset(new digest_variable<FieldT>(pb, 256, ""));

        view_hash_1_hasher.reset(new HashT(
            pb,
            *W,
            *r_S,
            *view_hash_1_digest,
            "view_hash_1_hasher"));

        view_hash_2_hasher.reset(new HashT(
            pb,
            *P_proof_S,
            *view_hash_1_digest,
            *V_S,
            "view_hash_2_hasher"));

        //hash(P_proof_R, hash(W, r_R)) == V_R
        view_hash_2_digest.reset(new digest_variable<FieldT>(pb, 256, ""));

        view_hash_3_hasher.reset(new HashT(
            pb,
            *W,
            *r_R,
            *view_hash_2_digest,
            "view_hash_3_hasher"));

        view_hash_4_hasher.reset(new HashT(
            pb,
            *P_proof_R,
            *view_hash_2_digest,
            *V_R,
            "view_hash_4_hasher"));

        //hash(A_PS, hash(s_S, hash(T, W_P))) == L_P
        transaction_hash_1_digest.reset(new digest_variable<FieldT>(pb, 256, ""));

        transaction_hash_1_hasher.reset(new HashT(
            pb,
            *T,
            *W_P,
            *transaction_hash_1_digest,
            "transaction_hash_1_hasher"));

        transaction_hash_2_digest.reset(new digest_variable<FieldT>(pb, 256, ""));

        transaction_hash_2_hasher.reset(new HashT(
            pb,
            *s_S,
            *transaction_hash_1_digest,
            *transaction_hash_2_digest,
            "transaction_hash_2_hasher"));

        transaction_hash_3_hasher.reset(new HashT(
            pb,
            *A_PS,
            *transaction_hash_2_digest,
            *L_P,
            "transaction_hash_3_hasher"));
    }

    ~gunerotransactionsend_gadget()
    {

    }

    static size_t verifying_input_bit_size() {
        size_t acc = 0;

        //W
        acc += HashT::get_digest_len(); // the merkle root (anchor) => libff::bit_vector root(digest_len); 

        //T
        acc += HashT::get_digest_len();

        //V_S
        acc += HashT::get_digest_len();

        //V_R
        acc += HashT::get_digest_len();

        //L_P
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
#ifdef DEBUG
        libff::print_header("Gunero constraints");
#endif

        // The true passed here ensures all the inputs
        // are boolean constrained.
        unpacker->generate_r1cs_constraints(true);

        // Constrain `ZERO`
        // generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero(), "ZERO");
        ZERO->generate_r1cs_constraints();

        s_S->generate_r1cs_constraints();

        r_S->generate_r1cs_constraints();

        r_R->generate_r1cs_constraints();

        A_PS->generate_r1cs_constraints();

        W_P->generate_r1cs_constraints();

        P_proof_R->generate_r1cs_constraints();

        P_proof_S->generate_r1cs_constraints();

        spend_authority->generate_r1cs_constraints();

        view_hash_1_digest->generate_r1cs_constraints();

        view_hash_1_hasher->generate_r1cs_constraints();

        view_hash_2_hasher->generate_r1cs_constraints();

        view_hash_2_digest->generate_r1cs_constraints();

        view_hash_3_hasher->generate_r1cs_constraints();

        view_hash_4_hasher->generate_r1cs_constraints();

        transaction_hash_1_digest->generate_r1cs_constraints();

        transaction_hash_1_hasher->generate_r1cs_constraints();

        transaction_hash_2_digest->generate_r1cs_constraints();

        transaction_hash_2_hasher->generate_r1cs_constraints();

        transaction_hash_3_hasher->generate_r1cs_constraints();

        //Calculate constraints
        r1cs_constraint_system<FieldT> constraint_system = this->pb.get_constraint_system();

        if (r1csPath.length() > 0)
        {
            saveToFile(r1csPath, constraint_system);
        }

#ifdef DEBUG
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

#ifdef DEBUG
        printf("\n"); libff::print_indent(); libff::print_mem("after constraints"); libff::print_time("after constraints");
#endif
    }

    // Public Parameters:
    // Current Authorization Root Hash (W)
    // Token UID (T)
    // Sender Account View Hash (V_S)
    // Receiver Account View Hash (V_R)
    // Previous Transaction Hash (L_P)

    // Private Parameters:
    // Sender Private Key (s_S)
    // Sender Account View Randomizer (r_S)
    // Receiver Account View Randomizer (r_R)
    // Previous Sender Account Address (A_PS)
    // Previous Authorization Root Hash (W_P)
    // alt: Receiver Proof Public Key (P_proof_R)
    void generate_r1cs_witness(
        const uint256& pW,
        const uint256& pT,
        const uint256& pV_S,
        const uint256& pV_R,
        const uint256& pL_P,
        const uint252& ps_S,
        const uint256& pr_S,
        const uint256& pr_R,
        const uint160& pA_PS,
        const uint256& pW_P,
        const uint256& pP_proof_R
    )
    {
        // Witness W
        W->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pW)
        );

        // Witness T
        T->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pT)
        );

        // Witness view hash. This is not a sanity check.
        V_S->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pV_S)
        );

        // Witness view hash. This is not a sanity check.
        V_R->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pV_R)
        );

        // Witness view hash. This is not a sanity check.
        L_P->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pL_P)
        );

        // Witness `zero`
        // this->pb.val(ZERO) = FieldT::zero();
        ZERO->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(uint256())
        );

        // Witness s_S for the input
        s_S->bits.fill_with_bits(
            this->pb,
            uint252_to_bool_vector_256(ps_S)
        );

        // Witness P_proof_S for s_S with PRF_addr
        spend_authority->generate_r1cs_witness();

        // Witness r_S for the input
        r_S->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pr_S)
        );

        // Witness r_R for the input
        r_R->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pr_R)
        );

        // Witness A_PS for the input
        A_PS->bits.fill_with_bits(
            this->pb,
            uint160_to_bool_vector_256_rpad(pA_PS)
        );

        // Witness W_P for the input
        W_P->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pW_P)
        );

        // Witness P_proof_R for the input
        P_proof_R->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pP_proof_R)
        );

        // Witness hash(W, r_S) = view_hash_1_digest
        view_hash_1_hasher->generate_r1cs_witness();

        // Witness hash(P_proof_S, view_hash_1_digest) = V_S
        view_hash_2_hasher->generate_r1cs_witness();

        // Witness hash(W, r_R) = view_hash_2_digest
        view_hash_3_hasher->generate_r1cs_witness();

        // Witness hash(P_proof_R, view_hash_2_digest) = V_R
        view_hash_4_hasher->generate_r1cs_witness();

        // Witness //transaction_hash_1_digest = hash(T, W_P)
        transaction_hash_1_hasher->generate_r1cs_witness();

        // Witness //transaction_hash_2_digest = hash(s_S, transaction_hash_1_digest)
        transaction_hash_2_hasher->generate_r1cs_witness();

        // Witness //L_P == hash(A_PS, transaction_hash_2_digest)
        transaction_hash_3_hasher->generate_r1cs_witness();

        // [SANITY CHECK] Ensure that the intended root
        // was witnessed by the inputs, even if the read
        // gadget overwrote it. This allows the prover to
        // fail instead of the verifier, in the event that
        // the roots of the inputs do not match the
        // hash provided to the proving hashers.
        V_S->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pV_S)
        );

        // [SANITY CHECK] Ensure that the intended root
        // was witnessed by the inputs, even if the read
        // gadget overwrote it. This allows the prover to
        // fail instead of the verifier, in the event that
        // the roots of the inputs do not match the
        // hash provided to the proving hashers.
        V_R->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pV_R)
        );

        // [SANITY CHECK] Ensure that the intended root
        // was witnessed by the inputs, even if the read
        // gadget overwrote it. This allows the prover to
        // fail instead of the verifier, in the event that
        // the roots of the inputs do not match the
        // hash provided to the proving hashers.
        L_P->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pL_P)
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
        const uint256& pL_P
    ) {
        std::vector<bool> verify_inputs;

        insert_uint256(verify_inputs, pW);

        insert_uint256(verify_inputs, pT);

        insert_uint256(verify_inputs, pV_S);

        insert_uint256(verify_inputs, pV_R);

        insert_uint256(verify_inputs, pL_P);

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

#endif /* GUNEROTRANSACTIONSEND_GADGET_H_ */