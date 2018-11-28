#ifndef GUNEROMEMBERSHIPCIRCUIT_H_
#define GUNEROMEMBERSHIPCIRCUIT_H_

#include <deque>
#include <mutex>
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
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>

#include "gunero_merkle_tree.hpp"
#include "guneromembership_gadget.hpp"
#include "GuneroProof.hpp"

using namespace libsnark;

namespace gunero {

class GuneroMembershipWitness{
public:
    uint256 W;
    uint8_t N_account;
    uint256 V_account;

    GuneroMembershipWitness() {}
    GuneroMembershipWitness(
        const uint256& pW,
        const uint8_t& pN_account,
        const uint256& pV_account
    ) : W(pW),
        N_account(pN_account),
        V_account(pV_account)
    {
    }
    ~GuneroMembershipWitness() {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(W);
        READWRITE(N_account);
        READWRITE(V_account);
    }

    friend std::ostream& operator<<(std::ostream &out, const GuneroMembershipWitness &witness)
    {
        ::Serialize(out, witness, 1, 1);

        return out;
    }

    friend std::istream& operator>>(std::istream &in, GuneroMembershipWitness &witness)
    {
        ::Unserialize(in, witness, 1, 1);

        return in;
    }
};

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
//3) alt) Validate V_account == keccak256(P_proof, keccak256(W,r_account) (View Hash is consistent)
template<typename FieldT, typename BaseT, typename HashT, size_t tree_depth>
class GuneroMembershipCircuit
{
public:
    GuneroMembershipCircuit()
    {}
    ~GuneroMembershipCircuit() {}

    void generate(
        const std::string& r1csPath,
        const std::string& pkPath,
        const std::string& vkPath
    ) {
        protoboard<FieldT> pb;
        guneromembership_gadget<FieldT, BaseT, HashT, tree_depth> gunero(pb);

        gunero.generate_r1cs_constraints(r1csPath, pkPath, vkPath);
    }

    static void makeTestVariables(
        const uint252& s_account,
        const uint8_t& N_account,
        const uint256& r_account,
        libff::bit_vector& P_proof,
        libff::bit_vector& leaf,
        std::vector<gunero_merkle_authentication_node>& M_account,
        libff::bit_vector& A_account_padded,
        libff::bit_vector& W,
        libff::bit_vector& view_hash_1,
        libff::bit_vector& V_account
    )
    {
        /* prepare test variables */
#if DEBUG
        libff::print_header("Gunero prepare test variables");
#endif
        M_account = std::vector<gunero_merkle_authentication_node>(tree_depth);

        libff::bit_vector s_account_256(uint252_to_bool_vector_256(s_account));
        assert(s_account_256.size() == HashT::get_digest_len());

        libff::bit_vector N_account_lsb(uint256_to_bool_vector(uint8_to_uint256(N_account)));
        assert(N_account_lsb.size() == HashT::get_digest_len());

        {//P_proof = Hash(0000b | (s_account&252b), 0)
            libff::bit_vector block(HashT::get_digest_len());
            block.insert(block.begin(), s_account_256.begin(), s_account_256.end());
            assert(block.at(0) == false);
            assert(block.at(1) == false);
            assert(block.at(2) == false);
            assert(block.at(3) == false);

            P_proof = HashT::get_hash(block);

            block = P_proof;
            block.insert(block.end(), N_account_lsb.begin(), N_account_lsb.end());
            leaf = HashT::get_hash(block);//hash(P_proof,N_account)
        }

        // libff::bit_vector prev_hash(HashT::get_digest_len());
        // std::generate(prev_hash.begin(), prev_hash.end(), [&]() { return std::rand() % 2; });
        // leaf = prev_hash;
        assert(leaf.size() == HashT::get_digest_len());
        libff::bit_vector prev_hash = leaf;

        // libff::bit_vector address_bits;
        libff::bit_vector A_account(tree_depth);

        size_t address = 0;
        for (long level = tree_depth-1; level >= 0; --level)
        {
            //Generate random uncle position
            const bool computed_is_right = (std::rand() % 2);
            address |= (computed_is_right ? 1ul << (tree_depth-1-level) : 0);
            // address_bits.push_back(computed_is_right);
            A_account.at(level) = computed_is_right;

            //Generate random uncle
            libff::bit_vector uncle(HashT::get_digest_len());
            std::generate(uncle.begin(), uncle.end(), [&]() { return std::rand() % 2; });

            //Create block of prev_hash + uncle
            libff::bit_vector block = prev_hash;
            block.insert(computed_is_right ? block.begin() : block.end(), uncle.begin(), uncle.end());
            //Compress block to new hash
            libff::bit_vector h = HashT::get_hash(block);

            //Add uncle to path
            M_account[level] = uncle;

            prev_hash = h;
        }

        W = prev_hash;

        A_account_padded = libff::bit_vector(HashT::get_digest_len() - A_account.size());
        A_account_padded.insert(A_account_padded.begin(), A_account.begin(), A_account.end());

        assert(A_account_padded.size() == HashT::get_digest_len());

        libff::bit_vector r_account_lsb(uint256_to_bool_vector(r_account));
        assert(r_account_lsb.size() == HashT::get_digest_len());

        {//view_hash_1 = hash(W, r_account_lsb)
            libff::bit_vector block = W;
            block.insert(block.end(), r_account_lsb.begin(), r_account_lsb.end());
            view_hash_1 = HashT::get_hash(block);//hash(W, r_account_lsb)

            //V_account = hash(P_proof, hash(W, r_account_lsb))
            block = P_proof;
            block.insert(block.end(), view_hash_1.begin(), view_hash_1.end());
            V_account = HashT::get_hash(block);//hash(P_proof, view_hash_1)
        }

#if DEBUG
        printf("\n"); libff::print_indent(); libff::print_mem("after prepare test variables"); libff::print_time("after prepare test variables");
#endif
    }

    bool prove(
        const uint256& pW,
        const uint8_t& pN_account,
        const uint256& pV_account,
        const uint252& ps_account,
        const std::vector<gunero_merkle_authentication_node>& pM_account,
        const uint160& pA_account,
        const uint256& pr_account,
        const r1cs_ppzksnark_proving_key<BaseT>& pk,
        const r1cs_ppzksnark_verification_key<BaseT>& vk,
        GuneroProof& proof
    )
    {
#if DEBUG
        libff::print_header("Gunero witness (proof)");
#endif

        {
            r1cs_primary_input<FieldT> primary_input;
            r1cs_auxiliary_input<FieldT> aux_input;
            {
                protoboard<FieldT> pb;
                {
#if DEBUG
                    libff::print_header("Gunero guneromembership_gadget.load_r1cs_constraints()");
#endif

                    guneromembership_gadget<FieldT, BaseT, HashT, tree_depth> gunero(pb);

                    gunero.generate_r1cs_witness(
                        pW,
                        pN_account,
                        pV_account,
                        ps_account,
                        pM_account,
                        pA_account,
                        pr_account
                    );

#if DEBUG
                    printf("\n"); libff::print_indent(); libff::print_mem("after guneromembership_gadget.load_r1cs_constraints()"); libff::print_time("after guneromembership_gadget.load_r1cs_constraints()");
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
                    r1cs_primary_input<FieldT> primary_input_test = guneromembership_gadget<FieldT, BaseT, HashT, tree_depth>::witness_map(
                        pW,
                        pN_account,
                        pV_account
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

#if DEBUG
            printf("\n"); libff::print_indent(); libff::print_mem("after witness (proof)"); libff::print_time("after witness (proof)");
#endif
        }

        //Verify
        {
            r1cs_primary_input<FieldT> primary_input = guneromembership_gadget<FieldT, BaseT, HashT, tree_depth>::witness_map(
                pW,
                pN_account,
                pV_account
            );

            return r1cs_ppzksnark_verifier_strong_IC<BaseT>(vk, primary_input, proof.to_libsnark_proof<r1cs_ppzksnark_proof<BaseT>>());
        }
    }

    bool verify(
        const uint256& W,
        const uint8_t& N_account,
        const uint256& V_account,
        const GuneroProof& proof,
        const r1cs_ppzksnark_verification_key<BaseT>& vk,
        const r1cs_ppzksnark_processed_verification_key<BaseT>& vk_precomp
        )
    {
        try
        {
            r1cs_primary_input<FieldT> primary_input = guneromembership_gadget<FieldT, BaseT, HashT, tree_depth>::witness_map(
                W,
                N_account,
                V_account
            );

            r1cs_ppzksnark_proof<BaseT> r1cs_proof = proof.to_libsnark_proof<r1cs_ppzksnark_proof<BaseT>>();

            ProofVerifier<BaseT> verifierEnabled = ProofVerifier<BaseT>::Strict();

            bool verified = verifierEnabled.check(
                vk,
                vk_precomp,
                primary_input,
                r1cs_proof
            );

#if DEBUG
            printf("\n"); libff::print_indent(); libff::print_mem("after verify"); libff::print_time("after verify");
#endif

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

#endif /* GUNEROMEMBERSHIPCIRCUIT_H_ */