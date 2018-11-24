#include "uint256.h"
#include "uint252.h"
#include "util.h"
#include "serialize.h"
#include "keccak_gadget.hpp"
#include "GuneroProof.hpp"
#include "GuneroMembershipCircuit.hpp"
#include "GuneroTransactionReceiveCircuit.hpp"

using namespace libsnark;
using namespace gunero;

int main ()
{
    const size_t MERKLE_TREE_DEPTH  = 160L;
    const bool TEST_SHA256 = false;
    const bool EXECUTE_MEMBERSHIP = true;
    const bool EXECUTE_TRANSACTION = true;
    const bool FAKE_s_R_WITH_REAL_V_R = false;
    const bool FAKE_r_S_WITH_REAL_V_S = false;

    std::srand(std::time(NULL));

    libff::start_profiling();

    //alt_bn128_pp
    libff::init_alt_bn128_params();

    //Test SHA256
    if (TEST_SHA256)
    {
        const libff::bit_vector left_bv = libff::int_list_to_bits({0x426bc2d8, 0x4dc86782, 0x81e8957a, 0x409ec148, 0xe6cffbe8, 0xafe6ba4f, 0x9c6f1978, 0xdd7af7e9}, 32);
        const libff::bit_vector right_bv = libff::int_list_to_bits({0x038cce42, 0xabd366b8, 0x3ede7e00, 0x9130de53, 0x72cdf73d, 0xee825114, 0x8cb48d1b, 0x9af68ad0}, 32);
        const libff::bit_vector hash_bv = libff::int_list_to_bits({0xeffd0b7f, 0x1ccba116, 0x2ee816f7, 0x31c62b48, 0x59305141, 0x990e5c0a, 0xce40d33d, 0x0b1167d1}, 32);

        libff::bit_vector block;
        block.insert(block.end(), left_bv.begin(), left_bv.end());
        block.insert(block.end(), right_bv.begin(), right_bv.end());
        libff::bit_vector hash_bv_calc = sha256_two_to_one_hash_gadget<FieldType>::get_hash(block);

        assert(hash_bv_calc == hash_bv);
    }

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

    //Public Input variables
    uint256 W;//set
    uint8_t N_account = 1;//1 = authorized
    uint256 V_account;//set

    //Private Input variables
    uint252 s_account = random_uint252();//alt
    uint160 A_account;//set
    std::vector<gunero_merkle_authentication_node> M_account;//set
    uint256 r_account = random_uint256();

    //Make test
    {
        libff::bit_vector P_proof;//alt
        libff::bit_vector leaf;//alt
        libff::bit_vector W_lsb;
        libff::bit_vector view_hash_1_lsb;//alt
        libff::bit_vector A_account_padded_lsb;
        libff::bit_vector V_account_lsb;

        GuneroMembershipCircuit<FieldType, BaseType, sha256_two_to_one_hash_gadget<FieldType>, MERKLE_TREE_DEPTH>::makeTestVariables(
            s_account,
            N_account,
            r_account,
            P_proof,
            leaf,
            M_account,
            A_account_padded_lsb,
            W_lsb,
            view_hash_1_lsb,
            V_account_lsb
            );

        // uint256 P_proof_msb = bool_vector_to_uint256(P_proof);

        // assert(P_proof_msb == PRF_addr_a_pk_one_calc);

        // uint256 leaf_msb = bool_vector_to_uint256(leaf);

        // assert(leaf_msb == leaf_calc);

        A_account = bool_vector_left_to_uint160(A_account_padded_lsb);

        W = bool_vector_to_uint256(W_lsb);

        V_account = bool_vector_to_uint256(V_account_lsb);
    }

    if (EXECUTE_MEMBERSHIP)
    {
        std::string r1csPath = "/home/sean/Silencer/build/src/r1cs.bin";
        std::string pkPath = "/home/sean/Silencer/build/src/pk.bin";
        std::string vkPath = "/home/sean/Silencer/build/src/vk.bin";

        std::string proofPath = "/home/sean/Silencer/build/src/proof.bin";

        //Generate Membership
        {
            /* generate circuit */
            libff::print_header("Gunero Generator");

            GuneroMembershipCircuit<FieldType, BaseType, sha256_two_to_one_hash_gadget<FieldType>, MERKLE_TREE_DEPTH> gmc;

            gmc.generate(r1csPath, pkPath, vkPath);
        }

        //Prove Membership
        {
            r1cs_ppzksnark_proving_key<BaseType> pk;
            loadFromFile(pkPath, pk);

            r1cs_ppzksnark_verification_key<BaseType> vk;
            loadFromFile(vkPath, vk);

            GuneroMembershipCircuit<FieldType, BaseType, sha256_two_to_one_hash_gadget<FieldType>, MERKLE_TREE_DEPTH> gmc;

            GuneroProof proof;
            bool proven = gmc.prove(
                W,
                N_account,
                V_account,
                s_account,
                M_account,
                A_account,
                r_account,
                pk,
                vk,
                proof);

            assert(proven);

            saveToFile(proofPath, proof);
        }

        //Verify Membership
        {
            r1cs_ppzksnark_verification_key<BaseType> vk;
            loadFromFile(vkPath, vk);

            r1cs_ppzksnark_processed_verification_key<BaseType> vk_precomp = r1cs_ppzksnark_verifier_process_vk<BaseType>(vk);

            GuneroProof proof;
            loadFromFile(proofPath, proof);

            GuneroMembershipCircuit<FieldType, BaseType, sha256_two_to_one_hash_gadget<FieldType>, MERKLE_TREE_DEPTH> gmc;

            bool verified = gmc.verify(
                W,
                N_account,
                V_account,
                proof,
                vk,
                vk_precomp);

            assert(verified);

            printf("verified: ");
            if (verified)
            {
                printf("true");
            }
            else
            {
                printf("false");
            }
            printf("\n");
        }
    }


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
    //2) Validate V_S == hash(A_S + W + r_S) (View Hash is consistent for Sender)
    //2 alt) Validate V_S == hash(P_proof_S + W + r_S) (View Hash is consistent for Sender)
    //3) Validate V_R == hash(A_R + W + r_R) (View Hash is consistent for Receiver)
    //3 alt) Validate V_R == hash(P_proof_R, hash(W, r_R)) (View Hash is consistent for Receiver)
    //4) Validate T == hash(F + j) (Both parties know the serial number)
    //5) Validate L == hash(A_S + s_R + T + W) (The send proof is consistent, not forged)

    //Public Input variables
    // uint256 W = W;
    uint256 T;//set = hash(F, j)
    uint256 V_S;//set = hash(P_proof_S, hash(W, r_S))
    uint256 V_R = V_account;
    uint256 L;//set = hash(A_S, hash(s_R, hash(T, W)))

    //Private Input variables
    uint252 s_R = s_account;
    uint256 r_R = r_account;
    uint160 A_S = random_uint160();
    uint256 r_S = random_uint256();
    uint256 F = random_uint256();
    uint256 j = random_uint256();
    uint160 A_R = A_account;//Alt
    uint256 P_proof_S = random_uint256();//Alt

    //Make test
    {
        if (FAKE_s_R_WITH_REAL_V_R)
        {
            s_R = random_uint252();
        }

        {//T = hash(F, j)
            libff::bit_vector F_lsb = uint256_to_bool_vector(F);
            libff::bit_vector j_lsb = uint256_to_bool_vector(j);

            libff::bit_vector block;
            block.insert(block.end(), F_lsb.begin(), F_lsb.end());
            block.insert(block.end(), j_lsb.begin(), j_lsb.end());

            libff::bit_vector T_lsb = sha256_two_to_one_hash_gadget<FieldType>::get_hash(block);

            T = bool_vector_to_uint256(T_lsb);
        }
        {//V_S = hash(P_proof_S, hash(W, r_S))
            libff::bit_vector W_lsb = uint256_to_bool_vector(W);
            libff::bit_vector r_S_lsb = uint256_to_bool_vector(r_S);

            libff::bit_vector block_1;
            block_1.insert(block_1.end(), W_lsb.begin(), W_lsb.end());
            block_1.insert(block_1.end(), r_S_lsb.begin(), r_S_lsb.end());

            libff::bit_vector hash_1 = sha256_two_to_one_hash_gadget<FieldType>::get_hash(block_1);

            libff::bit_vector P_proof_S_lsb = uint256_to_bool_vector(P_proof_S);

            libff::bit_vector block_2;
            block_2.insert(block_2.end(), P_proof_S_lsb.begin(), P_proof_S_lsb.end());
            block_2.insert(block_2.end(), hash_1.begin(), hash_1.end());

            libff::bit_vector V_S_lsb = sha256_two_to_one_hash_gadget<FieldType>::get_hash(block_2);

            V_S = bool_vector_to_uint256(V_S_lsb);
        }
        {//L = hash(A_S, hash(s_R, hash(T, W)))
            libff::bit_vector T_lsb = uint256_to_bool_vector(T);
            libff::bit_vector W_lsb = uint256_to_bool_vector(W);

            libff::bit_vector block_1;
            block_1.insert(block_1.end(), T_lsb.begin(), T_lsb.end());
            block_1.insert(block_1.end(), W_lsb.begin(), W_lsb.end());

            libff::bit_vector hash_1 = sha256_two_to_one_hash_gadget<FieldType>::get_hash(block_1);

            libff::bit_vector s_R_lsb = uint252_to_bool_vector_256(s_R);

            libff::bit_vector block_2;
            block_2.insert(block_2.end(), s_R_lsb.begin(), s_R_lsb.end());
            block_2.insert(block_2.end(), hash_1.begin(), hash_1.end());

            libff::bit_vector hash_2 = sha256_two_to_one_hash_gadget<FieldType>::get_hash(block_2);

            libff::bit_vector A_S_lsb = uint160_to_bool_vector_256_rpad(A_S);

            libff::bit_vector block_3;
            block_3.insert(block_3.end(), A_S_lsb.begin(), A_S_lsb.end());
            block_3.insert(block_3.end(), hash_2.begin(), hash_2.end());

            libff::bit_vector L_lsb = sha256_two_to_one_hash_gadget<FieldType>::get_hash(block_3);

            L = bool_vector_to_uint256(L_lsb);
        }

        if (FAKE_r_S_WITH_REAL_V_S)
        {
            r_S = random_uint256();
        }
    }

    if (EXECUTE_TRANSACTION)
    {
        std::string GTRr1csPath = "/home/sean/Silencer/build/src/GTR.r1cs.bin";
        std::string GTRpkPath = "/home/sean/Silencer/build/src/GTR.pk.bin";
        std::string GTRvkPath = "/home/sean/Silencer/build/src/GTR.vk.bin";

        std::string GTRproofPath = "/home/sean/Silencer/build/src/GTR.proof.bin";

        //Generate Transaction Receive
        {
            /* generate circuit */
            libff::print_header("Gunero Generator");

            GuneroTransactionReceiveCircuit<FieldType, BaseType, sha256_two_to_one_hash_gadget<FieldType>> gtrc;

            gtrc.generate(GTRr1csPath, GTRpkPath, GTRvkPath);
        }

        //Prove Transaction Receive
        {
            r1cs_ppzksnark_proving_key<BaseType> pk;
            loadFromFile(GTRpkPath, pk);

            r1cs_ppzksnark_verification_key<BaseType> vk;
            loadFromFile(GTRvkPath, vk);

            GuneroTransactionReceiveCircuit<FieldType, BaseType, sha256_two_to_one_hash_gadget<FieldType>> gtrc;

            GuneroProof proof;
            bool proven = gtrc.prove(
                W,
                T,
                V_S,
                V_R,
                L,
                s_R,
                r_R,
                A_S,
                r_S,
                F,
                j,
                A_R,
                P_proof_S,
                pk,
                vk,
                proof);

            assert(proven);

            saveToFile(GTRproofPath, proof);
        }

        //Verify Transaction Receive
        {
            r1cs_ppzksnark_verification_key<BaseType> vk;
            loadFromFile(GTRvkPath, vk);

            r1cs_ppzksnark_processed_verification_key<BaseType> vk_precomp = r1cs_ppzksnark_verifier_process_vk<BaseType>(vk);

            GuneroProof proof;
            loadFromFile(GTRproofPath, proof);

            GuneroTransactionReceiveCircuit<FieldType, BaseType, sha256_two_to_one_hash_gadget<FieldType>> gtrc;

            bool verified = gtrc.verify(
                W,
                T,
                V_S,
                V_R,
                L,
                proof,
                vk,
                vk_precomp);

            assert(verified);

            printf("verified: ");
            if (verified)
            {
                printf("true");
            }
            else
            {
                printf("false");
            }
            printf("\n");
        }
    }

    return 0;
}
