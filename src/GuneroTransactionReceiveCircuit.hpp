#ifndef GUNEROTRANSACTIONRECEIVECIRCUIT_H_
#define GUNEROTRANSACTIONRECEIVECIRCUIT_H_

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

#include "gunerotransactionreceive_gadget.hpp"
#include "GuneroProof.hpp"

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
class GuneroTransactionReceiveCircuit
{
public:
    GuneroTransactionReceiveCircuit()
    {}
    ~GuneroTransactionReceiveCircuit() {}

    void generate(
        const std::string& r1csPath,
        const std::string& pkPath,
        const std::string& vkPath
    ) {
        protoboard<FieldT> pb;
        gunerotransactionreceive_gadget<FieldT, BaseT, HashT> gunero(pb);

        gunero.generate_r1cs_constraints(r1csPath, pkPath, vkPath);
    }

    bool prove(
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
        const uint256& pP_proof_S,
        const r1cs_ppzksnark_proving_key<BaseT>& pk,
        const r1cs_ppzksnark_verification_key<BaseT>& vk,
        GuneroProof& proof
    )
    {
        libff::print_header("Gunero witness (proof)");

        {
            r1cs_primary_input<FieldT> primary_input;
            r1cs_auxiliary_input<FieldT> aux_input;
            {
                protoboard<FieldT> pb;
                {
                    libff::print_header("Gunero gunerotransactionreceive_gadget.load_r1cs_constraints()");

                    gunerotransactionreceive_gadget<FieldT, BaseT, HashT> gunero(pb);

                    gunero.generate_r1cs_witness(
                        pW,
                        pT,
                        pV_S,
                        pV_R,
                        pL,
                        ps_R,
                        pr_R,
                        pA_S,
                        pr_S,
                        pF,
                        pj,
                        pA_R,
                        pP_proof_S
                    );

                    printf("\n"); libff::print_indent(); libff::print_mem("after gunerotransactionreceive_gadget.load_r1cs_constraints()"); libff::print_time("after gunerotransactionreceive_gadget.load_r1cs_constraints()");
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
                    r1cs_primary_input<FieldT> primary_input_test = gunerotransactionreceive_gadget<FieldT, BaseT, HashT>::witness_map(
                        pW,
                        pT,
                        pV_S,
                        pV_R,
                        pL
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

            printf("\n"); libff::print_indent(); libff::print_mem("after witness (proof)"); libff::print_time("after witness (proof)");
        }

        //Verify
        {
            r1cs_primary_input<FieldT> primary_input = gunerotransactionreceive_gadget<FieldT, BaseT, HashT>::witness_map(
                pW,
                pT,
                pV_S,
                pV_R,
                pL
            );

            return r1cs_ppzksnark_verifier_strong_IC<BaseT>(vk, primary_input, proof.to_libsnark_proof<r1cs_ppzksnark_proof<BaseT>>());
        }
    }

    bool verify(
        const uint256& pW,
        const uint256& pT,
        const uint256& pV_S,
        const uint256& pV_R,
        const uint256& pL,
        const GuneroProof& proof,
        const r1cs_ppzksnark_verification_key<BaseT>& vk,
        const r1cs_ppzksnark_processed_verification_key<BaseT>& vk_precomp
        )
    {
        try
        {
            r1cs_primary_input<FieldT> primary_input = gunerotransactionreceive_gadget<FieldT, BaseT, HashT>::witness_map(
                pW,
                pT,
                pV_S,
                pV_R,
                pL
            );

            r1cs_ppzksnark_proof<BaseT> r1cs_proof = proof.to_libsnark_proof<r1cs_ppzksnark_proof<BaseT>>();

            ProofVerifier<BaseT> verifierEnabled = ProofVerifier<BaseT>::Strict();

            bool verified = verifierEnabled.check(
                vk,
                vk_precomp,
                primary_input,
                r1cs_proof
            );

            printf("\n"); libff::print_indent(); libff::print_mem("after verify"); libff::print_time("after verify");

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

#endif /* GUNEROTRANSACTIONRECEIVECIRCUIT_H_ */