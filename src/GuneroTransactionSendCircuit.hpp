#ifndef GUNEROTRANSACTIONSENDCIRCUIT_H_
#define GUNEROTRANSACTIONSENDCIRCUIT_H_

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

#include "gunerotransactionsend_gadget.hpp"
#include "GuneroProof.hpp"

using namespace libsnark;

namespace gunero {

class GuneroTransactionSendWitness{
public:
    uint256 W;
    uint256 T;
    uint256 V_S;
    uint256 V_R;
    uint256 L_P;

    GuneroTransactionSendWitness() {}
    GuneroTransactionSendWitness(
        const uint256& pW,
        const uint256& pT,
        const uint256& pV_S,
        const uint256& pV_R,
        const uint256& pL_P
    ) : W(pW),
        T(pT),
        V_S(pV_S),
        V_R(pV_R),
        L_P(pL_P)
    {
    }
    ~GuneroTransactionSendWitness() {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(W);
        READWRITE(T);
        READWRITE(V_S);
        READWRITE(V_R);
        READWRITE(L_P);
    }

    friend std::ostream& operator<<(std::ostream &out, const GuneroTransactionSendWitness &witness)
    {
        ::Serialize(out, witness, 1, 1);

        return out;
    }

    friend std::istream& operator>>(std::istream &in, GuneroTransactionSendWitness &witness)
    {
        ::Unserialize(in, witness, 1, 1);

        return in;
    }
};

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
class GuneroTransactionSendCircuit
{
public:
    GuneroTransactionSendCircuit()
    {}
    ~GuneroTransactionSendCircuit() {}

    void generate(
        const std::string& r1csPath,
        const std::string& pkPath,
        const std::string& vkPath
    ) {
        protoboard<FieldT> pb;
        gunerotransactionsend_gadget<FieldT, BaseT, HashT> gunero(pb);

        gunero.generate_r1cs_constraints(r1csPath, pkPath, vkPath);
    }

    bool prove(
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
        const uint256& pP_proof_R,
        const r1cs_ppzksnark_proving_key<BaseT>& pk,
        const r1cs_ppzksnark_verification_key<BaseT>& vk,
        GuneroProof& proof
    )
    {
#ifdef DEBUG
        libff::print_header("Gunero witness (proof)");
#endif

        {
            r1cs_primary_input<FieldT> primary_input;
            r1cs_auxiliary_input<FieldT> aux_input;
            {
                protoboard<FieldT> pb;
                {
#ifdef DEBUG
                    libff::print_header("Gunero gunerotransactionsend_gadget.load_r1cs_constraints()");
#endif

                    gunerotransactionsend_gadget<FieldT, BaseT, HashT> gunero(pb);

                    gunero.generate_r1cs_witness(
                        pW,
                        pT,
                        pV_S,
                        pV_R,
                        pL_P,
                        ps_S,
                        pr_S,
                        pr_R,
                        pA_PS,
                        pW_P,
                        pP_proof_R
                    );

#ifdef DEBUG
                    printf("\n"); libff::print_indent(); libff::print_mem("after gunerotransactionsend_gadget.load_r1cs_constraints()"); libff::print_time("after gunerotransactionsend_gadget.load_r1cs_constraints()");
#endif
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

                //Test witness_map()
                {
                    r1cs_primary_input<FieldT> primary_input_test = gunerotransactionsend_gadget<FieldT, BaseT, HashT>::witness_map(
                        pW,
                        pT,
                        pV_S,
                        pV_R,
                        pL_P
                    );
                    assert(primary_input == primary_input_test);
                }
            }

            r1cs_ppzksnark_proof<BaseT> r1cs_proof = r1cs_ppzksnark_prover<BaseT>(
                pk,
                primary_input,
                aux_input
            );

            proof = GuneroProof(r1cs_proof);

#ifdef DEBUG
            printf("\n"); libff::print_indent(); libff::print_mem("after witness (proof)"); libff::print_time("after witness (proof)");
#endif
        }

        //Verify
        {
            r1cs_primary_input<FieldT> primary_input = gunerotransactionsend_gadget<FieldT, BaseT, HashT>::witness_map(
                pW,
                pT,
                pV_S,
                pV_R,
                pL_P
            );

            return r1cs_ppzksnark_verifier_strong_IC<BaseT>(vk, primary_input, proof.to_libsnark_proof<r1cs_ppzksnark_proof<BaseT>>());
        }
    }

    bool verify(
        const uint256& pW,
        const uint256& pT,
        const uint256& pV_S,
        const uint256& pV_R,
        const uint256& pL_P,
        const GuneroProof& proof,
        const r1cs_ppzksnark_verification_key<BaseT>& vk,
        const r1cs_ppzksnark_processed_verification_key<BaseT>& vk_precomp
        )
    {
        try
        {
            r1cs_primary_input<FieldT> primary_input = gunerotransactionsend_gadget<FieldT, BaseT, HashT>::witness_map(
                pW,
                pT,
                pV_S,
                pV_R,
                pL_P
            );

            r1cs_ppzksnark_proof<BaseT> r1cs_proof = proof.to_libsnark_proof<r1cs_ppzksnark_proof<BaseT>>();

            ProofVerifier<BaseT> verifierEnabled = ProofVerifier<BaseT>::Strict();

            bool verified = verifierEnabled.check(
                vk,
                vk_precomp,
                primary_input,
                r1cs_proof
            );

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

} // end namespace `gunero`

#endif /* GUNEROTRANSACTIONSENDCIRCUIT_H_ */