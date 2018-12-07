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

#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>

#include "uint252.h"

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
// Receiver Account Secret Key (s_R)
// Receiver Account View Randomizer (r_R)
// Sender Account Address (A_S)
// Sender Account View Randomizer (r_S)
// Firearm Serial Number (F)
// Firearm View Randomizer (j)
// alt: Receiver Account (A_R)
// alt: Sender Proof Public Key (P_proof_S)

//1) Obtain A_R from s_R through EDCSA operations
//1 alt) Obtain P_proof_R from s_R through PRF operations
//2) Validate V_S == hash(A_S, hash(W, r_S)) (View Hash is consistent for Sender)
//2 alt) Validate V_S == hash(P_proof_S, hash(W, r_S)) (View Hash is consistent for Sender)
//3) Validate V_R == hash(A_R, hash(W, r_R) (View Hash is consistent for Receiver)
//3 alt) Validate V_R == hash(P_proof_R, hash(W, r_R)) (View Hash is consistent for Receiver)
//4) Validate T == hash(F, j) (Both parties know the serial number)
//5) Validate L == hash(A_S, hash(s_R, hash(T, W)) (The send proof is consistent, not forged)
template<typename FieldT, typename BaseT, typename HashT>
class gunerotransactionreceive_gadget : public gadget<FieldT> {
public:
    // Verifier inputs
    pb_variable_array<FieldT> zk_packed_inputs;
    pb_variable_array<FieldT> zk_unpacked_inputs;
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker;
    std::shared_ptr<digest_variable<FieldT>> W;
    std::shared_ptr<digest_variable<FieldT>> T;
    std::shared_ptr<digest_variable<FieldT>> V_S;
    std::shared_ptr<digest_variable<FieldT>> V_R;
    std::shared_ptr<digest_variable<FieldT>> L;

    // Aux inputs
    // pb_variable<FieldT> ZERO;
    std::shared_ptr<digest_variable<FieldT>> ZERO;
    std::shared_ptr<digest_variable<FieldT>> s_R;
    std::shared_ptr<digest_variable<FieldT>> r_R;
    std::shared_ptr<digest_variable<FieldT>> A_S;
    std::shared_ptr<digest_variable<FieldT>> r_S;
    std::shared_ptr<digest_variable<FieldT>> F;
    std::shared_ptr<digest_variable<FieldT>> j;
    std::shared_ptr<digest_variable<FieldT>> A_R;//alt
    std::shared_ptr<digest_variable<FieldT>> P_proof_S;//alt

    // Computed variables
    std::shared_ptr<digest_variable<FieldT>> P_proof_R;
    // std::shared_ptr<PRF_addr_a_pk_simple_gadget<FieldT>> spend_authority;
    std::shared_ptr<HashT> spend_authority;
    std::shared_ptr<digest_variable<FieldT>> view_hash_1_digest;
    std::shared_ptr<HashT> view_hash_1_hasher;
    std::shared_ptr<HashT> view_hash_2_hasher;
    std::shared_ptr<digest_variable<FieldT>> view_hash_2_digest;
    std::shared_ptr<HashT> view_hash_3_hasher;
    std::shared_ptr<HashT> view_hash_4_hasher;
    std::shared_ptr<HashT> token_hasher;
    std::shared_ptr<digest_variable<FieldT>> transaction_hash_1_digest;
    std::shared_ptr<HashT> transaction_hash_1_hasher;
    std::shared_ptr<digest_variable<FieldT>> transaction_hash_2_digest;
    std::shared_ptr<HashT> transaction_hash_2_hasher;
    std::shared_ptr<HashT> transaction_hash_3_hasher;

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
            alloc_uint256(zk_unpacked_inputs, V_S);
            alloc_uint256(zk_unpacked_inputs, V_R);
            alloc_uint256(zk_unpacked_inputs, L);

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
        s_R.reset(new digest_variable<FieldT>(pb, 256, ""));//252

        r_R.reset(new digest_variable<FieldT>(pb, 256, ""));

        A_S.reset(new digest_variable<FieldT>(pb, 256, ""));

        r_S.reset(new digest_variable<FieldT>(pb, 256, ""));

        F.reset(new digest_variable<FieldT>(pb, 256, ""));

        j.reset(new digest_variable<FieldT>(pb, 256, ""));

        A_R.reset(new digest_variable<FieldT>(pb, 256, ""));

        P_proof_S.reset(new digest_variable<FieldT>(pb, 256, ""));

        P_proof_R.reset(new digest_variable<FieldT>(pb, 256, ""));

        // spend_authority.reset(new PRF_addr_a_pk_simple_gadget<FieldT>(
        //     pb,
        //     ZERO,
        //     s_R->bits,
        //     P_proof_R
        // ));
        spend_authority.reset(new HashT(
            pb,
            *s_R,
            *ZERO,
            *P_proof_R,
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

        //T == hash(F, j)
        token_hasher.reset(new HashT(
            pb,
            *F,
            *j,
            *T,
            "token_hasher"));

        //L == hash(A_S, hash(s_R, hash(T, W))
        transaction_hash_1_digest.reset(new digest_variable<FieldT>(pb, 256, ""));

        transaction_hash_1_hasher.reset(new HashT(
            pb,
            *T,
            *W,
            *transaction_hash_1_digest,
            "transaction_hash_1_hasher"));

        transaction_hash_2_digest.reset(new digest_variable<FieldT>(pb, 256, ""));

        transaction_hash_2_hasher.reset(new HashT(
            pb,
            *s_R,
            *transaction_hash_1_digest,
            *transaction_hash_2_digest,
            "transaction_hash_2_hasher"));

        transaction_hash_3_hasher.reset(new HashT(
            pb,
            *A_S,
            *transaction_hash_2_digest,
            *L,
            "transaction_hash_3_hasher"));
    }

    ~gunerotransactionreceive_gadget()
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

        //L
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

        s_R->generate_r1cs_constraints();

        r_R->generate_r1cs_constraints();

        A_S->generate_r1cs_constraints();

        r_S->generate_r1cs_constraints();

        F->generate_r1cs_constraints();

        j->generate_r1cs_constraints();

        A_R->generate_r1cs_constraints();

        P_proof_S->generate_r1cs_constraints();

        P_proof_R->generate_r1cs_constraints();

        spend_authority->generate_r1cs_constraints();

        view_hash_1_digest->generate_r1cs_constraints();

        view_hash_1_hasher->generate_r1cs_constraints();

        view_hash_2_hasher->generate_r1cs_constraints();

        view_hash_2_digest->generate_r1cs_constraints();

        view_hash_3_hasher->generate_r1cs_constraints();

        view_hash_4_hasher->generate_r1cs_constraints();

        token_hasher->generate_r1cs_constraints();

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
    // alt: Account (A_R)
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
        const uint256& pj,
        const uint160& pA_R,
        const uint256& pP_proof_S
    )
    {
        // Witness W
        W->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pW)
        );

        // Witness T. This is not a sanity check.
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
        L->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pL)
        );

        // Witness `zero`
        // this->pb.val(ZERO) = FieldT::zero();
        ZERO->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(uint256())
        );

        // Witness s_R for the input
        s_R->bits.fill_with_bits(
            this->pb,
            uint252_to_bool_vector_256(ps_R)
        );

        // Witness P_proof_R for s_R with PRF_addr
        spend_authority->generate_r1cs_witness();

        // Witness r_R for the input
        r_R->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pr_R)
        );

        // Witness A_S for the input
        A_S->bits.fill_with_bits(
            this->pb,
            uint160_to_bool_vector_256_rpad(pA_S)
        );

        // Witness r_S for the input
        r_S->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pr_S)
        );

        // Witness F for the input
        F->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pF)
        );

        // Witness j for the input
        j->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pj)
        );

        // Witness A_R for the input
        A_R->bits.fill_with_bits(
            this->pb,
            uint160_to_bool_vector_256_rpad(pA_R)
        );

        // Witness P_proof_S for the input
        P_proof_S->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pP_proof_S)
        );

        // Witness hash(W, r_S) = view_hash_1_digest
        view_hash_1_hasher->generate_r1cs_witness();

        // Witness hash(P_proof_S, view_hash_1_digest) = V_S
        view_hash_2_hasher->generate_r1cs_witness();

        // Witness hash(W, r_R) = view_hash_2_digest
        view_hash_3_hasher->generate_r1cs_witness();

        // Witness hash(P_proof_R, view_hash_2_digest) = V_R
        view_hash_4_hasher->generate_r1cs_witness();

        // Witness hash(F, j) = T
        token_hasher->generate_r1cs_witness();

        // Witness //transaction_hash_1_digest = hash(T, W)
        transaction_hash_1_hasher->generate_r1cs_witness();

        // Witness //transaction_hash_2_digest = hash(s_R, transaction_hash_1_digest)
        transaction_hash_2_hasher->generate_r1cs_witness();

        // Witness //L == hash(A_S, transaction_hash_2_digest)
        transaction_hash_3_hasher->generate_r1cs_witness();

        // [SANITY CHECK] Ensure that the intended root
        // was witnessed by the inputs, even if the read
        // gadget overwrote it. This allows the prover to
        // fail instead of the verifier, in the event that
        // the roots of the inputs do not match the
        // hash provided to the proving hashers.
        T->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pT)
        );

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
        L->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(pL)
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

        insert_uint256(verify_inputs, pV_S);

        insert_uint256(verify_inputs, pV_R);

        insert_uint256(verify_inputs, pL);

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