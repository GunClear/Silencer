#include "uint256.h"
#include "uint252.h"
#include "util.h"
#include "serialize.h"
#include "keccak_gadget.hpp"
#include "GuneroProof.hpp"
#include "GuneroMembershipCircuit.hpp"
#include "GuneroTransactionSendCircuit.hpp"
#include "GuneroTransactionReceiveCircuit.hpp"
#include "sha256_ethereum.hpp"

using namespace libsnark;
using namespace gunero;

//Verify Membership
extern "C" int verify_membership(
    const char* WHex,
    uint8_t N_account,
    const char* V_accountHex,
    const char* vkPath,
    const char* proofPath
    );

//Verify Transaction Send
extern "C" int verify_send(
    const char* WHex,
    const char* THex,
    const char* V_SHex,
    const char* V_RHex,
    const char* L_PHex,
    const char* vkPath,
    const char* proofPath
    );

//Verify Transaction Send Witness
extern "C" int verify_send_wit(
    const char* witnessPath,
    const char* vkPath,
    const char* proofPath
    );

//Verify Transaction Receive
extern "C" int verify_receive(
    const char* WHex,
    const char* THex,
    const char* V_SHex,
    const char* V_RHex,
    const char* LHex,
    const char* vkPath,
    const char* proofPath
    );

//Prove Membership
extern "C" int prove_membership(
    const char* WHex,
    uint8_t N_account,
    const char* V_accountHex,
    const char* s_accountHex,
    const char* M_accountHexArray,
    const char* A_accountHex,
    const char* r_accountHex,
    const char* pkPath,
    const char* vkPath,
    const char* proofPath
    );

//Prove Transaction Send
extern "C" int prove_send(
    const char* WHex,
    const char* THex,
    const char* V_SHex,
    const char* V_RHex,
    const char* L_PHex,
    const char* s_SHex,
    const char* r_SHex,
    const char* r_RHex,
    const char* A_PSHex,
    const char* W_PHex,
    const char* P_proof_RHex,
    const char* pkPath,
    const char* vkPath,
    const char* proofPath
    );

//Prove Transaction Receive
extern "C" int prove_receive(
    const char* WHex,
    const char* THex,
    const char* V_SHex,
    const char* V_RHex,
    const char* LHex,
    const char* s_RHex,
    const char* r_RHex,
    const char* A_SHex,
    const char* r_SHex,
    const char* FHex,
    const char* jHex,
    const char* A_RHex,
    const char* P_proof_SHex,
    const char* pkPath,
    const char* vkPath,
    const char* proofPath
    );

//Full test
extern "C" int full_test(const char* path);

//Verify Membership
extern "C" int verify_membership(
    const char* WHex,
    uint8_t N_account,
    const char* V_accountHex,
    const char* vkPath,
    const char* proofPath
    )
{
    libff::start_profiling();

    //alt_bn128_pp
    libff::init_alt_bn128_params();

    const size_t MERKLE_TREE_DEPTH  = 160UL;

    uint256 W;
    W.SetHex(WHex);

    uint256 V_account;
    V_account.SetHex(V_accountHex);

    r1cs_ppzksnark_verification_key<BaseType> vk;
    loadFromFile(vkPath, vk);

    r1cs_ppzksnark_processed_verification_key<BaseType> vk_precomp = r1cs_ppzksnark_verifier_process_vk<BaseType>(vk);

    GuneroProof proof;
    loadFromFile(proofPath, proof);

    GuneroMembershipCircuit<FieldType, BaseType, sha256_ethereum<FieldType>, MERKLE_TREE_DEPTH> gmc;

    bool verified = gmc.verify(
        W,
        N_account,
        V_account,
        proof,
        vk,
        vk_precomp);

    if (verified)
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

//Verify Transaction Send
extern "C" int verify_send(
    const char* WHex,
    const char* THex,
    const char* V_SHex,
    const char* V_RHex,
    const char* L_PHex,
    const char* vkPath,
    const char* proofPath
    )
{
    libff::start_profiling();

    //alt_bn128_pp
    libff::init_alt_bn128_params();

    uint256 W;
    W.SetHex(WHex);

    uint256 T;
    T.SetHex(THex);

    uint256 V_S;
    V_S.SetHex(V_SHex);

    uint256 V_R;
    V_R.SetHex(V_RHex);

    uint256 L_P;
    L_P.SetHex(L_PHex);

    r1cs_ppzksnark_verification_key<BaseType> vk;
    loadFromFile(vkPath, vk);

    r1cs_ppzksnark_processed_verification_key<BaseType> vk_precomp = r1cs_ppzksnark_verifier_process_vk<BaseType>(vk);

    GuneroProof proof;
    loadFromFile(proofPath, proof);

    GuneroTransactionSendCircuit<FieldType, BaseType, sha256_ethereum<FieldType>> gtsc;

    bool verified = gtsc.verify(
        W,
        T,
        V_S,
        V_R,
        L_P,
        proof,
        vk,
        vk_precomp);

    if (verified)
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

//Verify Transaction Send Witness
extern "C" int verify_send_wit(
    const char* witnessPath,
    const char* vkPath,
    const char* proofPath
    )
{
    GuneroTransactionSendWitness gtsw;
    loadFromFile(witnessPath, gtsw);

    std::string WHex = gtsw.W.GetHex();
    std::string THex = gtsw.T.GetHex();
    std::string V_SHex = gtsw.V_S.GetHex();
    std::string V_RHex = gtsw.V_R.GetHex();
    std::string L_PHex = gtsw.L_P.GetHex();

#ifdef DEBUG
    std::cout << "WHex: " << WHex << "\n";
    std::cout << "THex: " << THex << "\n";
    std::cout << "V_SHex: " << V_SHex << "\n";
    std::cout << "V_RHex: " << V_RHex << "\n";
    std::cout << "L_PHex: " << L_PHex << "\n";
    std::cout << "vkPath: " << vkPath << "\n";
    std::cout << "proofPath: " << proofPath << "\n";
#endif

    return verify_send(
        WHex.c_str(),
        THex.c_str(),
        V_SHex.c_str(),
        V_RHex.c_str(),
        L_PHex.c_str(),
        vkPath,
        proofPath
    );
}

//Verify Transaction Receive
extern "C" int verify_receive(
    const char* WHex,
    const char* THex,
    const char* V_SHex,
    const char* V_RHex,
    const char* LHex,
    const char* vkPath,
    const char* proofPath
    )
{
    libff::start_profiling();

    //alt_bn128_pp
    libff::init_alt_bn128_params();

    uint256 W;
    W.SetHex(WHex);

    uint256 T;
    T.SetHex(THex);

    uint256 V_S;
    V_S.SetHex(V_SHex);

    uint256 V_R;
    V_R.SetHex(V_RHex);

    uint256 L;
    L.SetHex(LHex);

    r1cs_ppzksnark_verification_key<BaseType> vk;
    loadFromFile(vkPath, vk);

    r1cs_ppzksnark_processed_verification_key<BaseType> vk_precomp = r1cs_ppzksnark_verifier_process_vk<BaseType>(vk);

    GuneroProof proof;
    loadFromFile(proofPath, proof);

    GuneroTransactionReceiveCircuit<FieldType, BaseType, sha256_ethereum<FieldType>> gtrc;

    bool verified = gtrc.verify(
        W,
        T,
        V_S,
        V_R,
        L,
        proof,
        vk,
        vk_precomp);

    if (verified)
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

//Prove Membership
extern "C" int prove_membership(
    const char* WHex,
    uint8_t N_account,
    const char* V_accountHex,
    const char* s_accountHex,
    const char* M_accountHexArray,
    const char* A_accountHex,
    const char* r_accountHex,
    const char* pkPath,
    const char* vkPath,
    const char* proofPath
    )
{
    libff::start_profiling();

    //alt_bn128_pp
    libff::init_alt_bn128_params();

    const size_t MERKLE_TREE_DEPTH  = 160UL;

    uint256 W;
    W.SetHex(WHex);

    uint256 V_account;
    V_account.SetHex(V_accountHex);

    uint252 s_account;
    V_account.SetHex(s_accountHex);

    std::vector<gunero_merkle_authentication_node> M_account;
    {
        const int MaxPossibleSize = 67 * 160;//64 hex, plus possible "0x" start, plus possible ";" end
        int M_accountHexArray_len = strnlen(M_accountHexArray, MaxPossibleSize + 1);
        if ((M_accountHexArray_len <= 0) || (M_accountHexArray_len > MaxPossibleSize))
        {//Malformed M_account
            return -2;
        }
        char node_buffer[67];//64 hex, plus possible "0x" start, plus null
        uint256 node_uint256;
        libff::bit_vector node;
        const char* start = M_accountHexArray;
        while (true)
        {
            const char* next = strchr(start, ';');
            memset(node_buffer, 0, 67);
            if (next == NULL)
            {
                if (strlen(start) > 66)
                {//Malformed M_account
                    return -2;
                }
                strcpy(node_buffer, start);
                node_uint256.SetHex(node_buffer);
                node = uint256_to_bool_vector(node_uint256);

                M_account.push_back(node);

                //Done
                break;
            }
            else
            {
                if ((next - start) > 66)
                {//Malformed M_account
                    return -2;
                }
                strncpy(node_buffer, start, next - start);
                node_uint256.SetHex(node_buffer);
                node = uint256_to_bool_vector(node_uint256);

                M_account.push_back(node);

                //Look for next
                start = next + 1;
            }
        }
        if (M_account.size() != 160)
        {//Malformed M_account
            return -3;
        }
    }

    uint160 A_account;
    A_account.SetHex(A_accountHex);

    uint256 r_account;
    r_account.SetHex(r_accountHex);

    r1cs_ppzksnark_proving_key<BaseType> pk;
    loadFromFile(pkPath, pk);

    r1cs_ppzksnark_verification_key<BaseType> vk;
    loadFromFile(vkPath, vk);

    GuneroMembershipCircuit<FieldType, BaseType, sha256_ethereum<FieldType>, MERKLE_TREE_DEPTH> gmc;

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

    if (proven)
    {
        saveToFile(proofPath, proof);

        return 0;
    }
    else
    {
        return -1;
    }
}

//Prove Transaction Send
extern "C" int prove_send(
    const char* WHex,
    const char* THex,
    const char* V_SHex,
    const char* V_RHex,
    const char* L_PHex,
    const char* s_SHex,
    const char* r_SHex,
    const char* r_RHex,
    const char* A_PSHex,
    const char* W_PHex,
    const char* P_proof_RHex,
    const char* pkPath,
    const char* vkPath,
    const char* proofPath
    )
{
#ifdef DEBUG
    std::cout << "WHex: " << WHex << "\n";
    std::cout << "THex: " << THex << "\n";
    std::cout << "V_SHex: " << V_SHex << "\n";
    std::cout << "V_RHex: " << V_RHex << "\n";
    std::cout << "L_PHex: " << L_PHex << "\n";
    std::cout << "s_SHex: " << s_SHex << "\n";
    std::cout << "r_SHex: " << r_SHex << "\n";
    std::cout << "r_RHex: " << r_RHex << "\n";
    std::cout << "A_PSHex: " << A_PSHex << "\n";
    std::cout << "W_PHex: " << W_PHex << "\n";
    std::cout << "P_proof_RHex: " << P_proof_RHex << "\n";
    std::cout << "pkPath: " << pkPath << "\n";
    std::cout << "vkPath: " << vkPath << "\n";
    std::cout << "proofPath: " << proofPath << "\n";
#endif

    libff::start_profiling();

    //alt_bn128_pp
    libff::init_alt_bn128_params();

    uint256 W;
    W.SetHex(WHex);
#ifdef DEBUG
    std::cout << "W: " << W.GetHex() << "\n";
#endif

    uint256 T;
    T.SetHex(THex);
#ifdef DEBUG
    std::cout << "T: " << T.GetHex() << "\n";
#endif

    uint256 V_S;
    V_S.SetHex(V_SHex);
#ifdef DEBUG
    std::cout << "V_S: " << V_S.GetHex() << "\n";
#endif

    uint256 V_R;
    V_R.SetHex(V_RHex);
#ifdef DEBUG
    std::cout << "V_R: " << V_R.GetHex() << "\n";
#endif

    uint256 L_P;
    L_P.SetHex(L_PHex);
#ifdef DEBUG
    std::cout << "L_P: " << L_P.GetHex() << "\n";
#endif

    uint256 s_S_256;
    s_S_256.SetHex(s_SHex);
    uint252 s_S(s_S_256);
#ifdef DEBUG
    std::cout << "s_S: " << s_S_256.GetHex() << "\n";
#endif

    uint256 r_S;
    r_S.SetHex(r_SHex);
#ifdef DEBUG
    std::cout << "r_S: " << r_S.GetHex() << "\n";
#endif

    uint256 r_R;
    r_R.SetHex(r_RHex);
#ifdef DEBUG
    std::cout << "r_R: " << r_R.GetHex() << "\n";
#endif

    uint160 A_PS;
    A_PS.SetHex(A_PSHex);
#ifdef DEBUG
    std::cout << "A_PS: " << A_PS.GetHex() << "\n";
#endif

    uint256 W_P;
    W_P.SetHex(W_PHex);
#ifdef DEBUG
    std::cout << "W_P: " << W_P.GetHex() << "\n";
#endif

    uint256 P_proof_R;
    P_proof_R.SetHex(P_proof_RHex);
#ifdef DEBUG
    std::cout << "P_proof_R: " << P_proof_R.GetHex() << "\n";
#endif

    r1cs_ppzksnark_proving_key<BaseType> pk;
    loadFromFile(pkPath, pk);

    r1cs_ppzksnark_verification_key<BaseType> vk;
    loadFromFile(vkPath, vk);

    r1cs_ppzksnark_processed_verification_key<BaseType> vk_precomp = r1cs_ppzksnark_verifier_process_vk<BaseType>(vk);

    GuneroTransactionSendCircuit<FieldType, BaseType, sha256_ethereum<FieldType>> gtsc;

    GuneroProof proof;
    bool proven = gtsc.prove(
        W,
        T,
        V_S,
        V_R,
        L_P,
        s_S,
        r_S,
        r_R,
        A_PS,
        W_P,
        P_proof_R,
        pk,
        vk,
        proof);

    if (proven)
    {
        saveToFile(proofPath, proof);

        return 0;
    }
    else
    {
        return -1;
    }
}

//Prove Transaction Receive
extern "C" int prove_receive(
    const char* WHex,
    const char* THex,
    const char* V_SHex,
    const char* V_RHex,
    const char* LHex,
    const char* s_RHex,
    const char* r_RHex,
    const char* A_SHex,
    const char* r_SHex,
    const char* FHex,
    const char* jHex,
    const char* A_RHex,
    const char* P_proof_SHex,
    const char* pkPath,
    const char* vkPath,
    const char* proofPath
    )
{
    libff::start_profiling();

    //alt_bn128_pp
    libff::init_alt_bn128_params();

    uint256 W;
    W.SetHex(WHex);

    uint256 T;
    T.SetHex(THex);

    uint256 V_S;
    V_S.SetHex(V_SHex);

    uint256 V_R;
    V_R.SetHex(V_RHex);

    uint256 L;
    L.SetHex(LHex);

    uint256 s_R_256;
    s_R_256.SetHex(s_RHex);
    uint252 s_R(s_R_256);

    uint256 r_R;
    r_R.SetHex(r_RHex);

    uint160 A_S;
    A_S.SetHex(A_SHex);

    uint256 r_S;
    r_S.SetHex(r_SHex);

    uint256 F;
    F.SetHex(FHex);

    uint256 j;
    j.SetHex(jHex);

    uint160 A_R;
    A_R.SetHex(A_RHex);

    uint256 P_proof_S;
    P_proof_S.SetHex(P_proof_SHex);

    r1cs_ppzksnark_proving_key<BaseType> pk;
    loadFromFile(pkPath, pk);

    r1cs_ppzksnark_verification_key<BaseType> vk;
    loadFromFile(vkPath, vk);

    r1cs_ppzksnark_processed_verification_key<BaseType> vk_precomp = r1cs_ppzksnark_verifier_process_vk<BaseType>(vk);

    GuneroTransactionReceiveCircuit<FieldType, BaseType, sha256_ethereum<FieldType>> gtrc;

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

    if (proven)
    {
        saveToFile(proofPath, proof);

        return 0;
    }
    else
    {
        return -1;
    }
}

extern "C" int full_test(const char* path)
{
    const size_t MERKLE_TREE_DEPTH  = 160UL;
    // const bool TEST_SHA256 = false;
    const bool EXECUTE_MEMBERSHIP = false;
    const bool EXECUTE_TRANSACTION_SEND = true;
    const bool EXECUTE_TRANSACTION_RECEIVE = false;

    std::srand(std::time(NULL));

    libff::start_profiling();

    //alt_bn128_pp
    libff::init_alt_bn128_params();

    // //Test SHA256
    // if (TEST_SHA256)
    // {
    //     const libff::bit_vector left_bv = libff::int_list_to_bits({0x426bc2d8, 0x4dc86782, 0x81e8957a, 0x409ec148, 0xe6cffbe8, 0xafe6ba4f, 0x9c6f1978, 0xdd7af7e9}, 32);
    //     const libff::bit_vector right_bv = libff::int_list_to_bits({0x038cce42, 0xabd366b8, 0x3ede7e00, 0x9130de53, 0x72cdf73d, 0xee825114, 0x8cb48d1b, 0x9af68ad0}, 32);
    //     const libff::bit_vector hash_bv = libff::int_list_to_bits({0xeffd0b7f, 0x1ccba116, 0x2ee816f7, 0x31c62b48, 0x59305141, 0x990e5c0a, 0xce40d33d, 0x0b1167d1}, 32);

    //     libff::bit_vector block;
    //     block.insert(block.end(), left_bv.begin(), left_bv.end());
    //     block.insert(block.end(), right_bv.begin(), right_bv.end());
    //     libff::bit_vector hash_bv_calc = sha256_ethereum<FieldType>::get_hash(block);

    //     assert(hash_bv_calc == hash_bv);
    // }

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
    uint252 s_account = random_uint252();
    uint160 A_account;//set
    std::vector<gunero_merkle_authentication_node> M_account;//set
    uint256 r_account = random_uint256();

    uint256 P_proof;//set

    //Make test
    {
        libff::bit_vector P_proof_lsb;//alt
        libff::bit_vector leaf;//alt
        libff::bit_vector W_lsb;
        libff::bit_vector view_hash_1_lsb;//alt
        libff::bit_vector A_account_padded_lsb;
        libff::bit_vector V_account_lsb;

        GuneroMembershipCircuit<FieldType, BaseType, sha256_ethereum<FieldType>, MERKLE_TREE_DEPTH>::makeTestVariables(
            s_account,
            N_account,
            r_account,
            P_proof_lsb,
            leaf,
            M_account,
            A_account_padded_lsb,
            W_lsb,
            view_hash_1_lsb,
            V_account_lsb
            );

        A_account = bool_vector_left_to_uint160(A_account_padded_lsb);

        W = bool_vector_to_uint256(W_lsb);

        V_account = bool_vector_to_uint256(V_account_lsb);

        P_proof = bool_vector_to_uint256(P_proof_lsb);
    }

    if (EXECUTE_MEMBERSHIP)
    {
        std::string GTMr1csPath(path);
        GTMr1csPath.append("GTM.r1cs.bin");
        std::string GTMpkPath(path);
        GTMpkPath.append("GTM.pk.bin");
        std::string GTMvkPath(path);
        GTMvkPath.append("GTM.vk.bin");
        std::string GTMwitnessPath(path);
        GTMwitnessPath.append("GTM.witness.bin");
        std::string GTMproofPath(path);
        GTMproofPath.append("GTM.proof.bin");

        //Generate Membership
        {
            /* generate circuit */
#ifdef DEBUG
            libff::print_header("Gunero Generator");
#endif

            GuneroMembershipCircuit<FieldType, BaseType, sha256_ethereum<FieldType>, MERKLE_TREE_DEPTH> gmc;

            gmc.generate(GTMr1csPath, GTMpkPath, GTMvkPath);
        }

        //Prove Membership
        {
            r1cs_ppzksnark_proving_key<BaseType> pk;
            loadFromFile(GTMpkPath, pk);

            r1cs_ppzksnark_verification_key<BaseType> vk;
            loadFromFile(GTMvkPath, vk);

            GuneroMembershipCircuit<FieldType, BaseType, sha256_ethereum<FieldType>, MERKLE_TREE_DEPTH> gmc;

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

            saveToFile(GTMproofPath, proof);

            GuneroMembershipWitness gmw(
                W,
                N_account,
                V_account);
            saveToFile(GTMwitnessPath, gmw);
        }

        //Verify Membership
        {
            r1cs_ppzksnark_verification_key<BaseType> vk;
            loadFromFile(GTMvkPath, vk);

            r1cs_ppzksnark_processed_verification_key<BaseType> vk_precomp = r1cs_ppzksnark_verifier_process_vk<BaseType>(vk);

            GuneroProof proof;
            loadFromFile(GTMproofPath, proof);

            GuneroMembershipCircuit<FieldType, BaseType, sha256_ethereum<FieldType>, MERKLE_TREE_DEPTH> gmc;

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

    //Public Input variables
    // uint256 W = W;
    uint256 T;//set = hash(F, j)
    uint256 V_S;//set = hash(P_proof_S, hash(W, r_S))
    uint256 V_R = V_account;//hash(P_proof_R, hash(W, r_R)
    uint256 L_P;//set = hash(A_PS, hash(s_S, hash(T, W_P)))

    //Private Input variables
    uint252 s_S = random_uint252();
    uint256 r_S = random_uint256();
    uint256 r_R = r_account;
    uint160 A_PS = random_uint160();
    uint256 W_P = random_uint256();
    uint256 P_proof_R = P_proof;

    //Storage variables
    uint256 F = random_uint256();
    uint256 j = random_uint256();
    uint256 L;//set = hash(A_S, hash(s_R, hash(T, W)))
    uint256 P_proof_S;//set = PRF(s_S)
    uint160 A_R = A_account;//Alt
    uint252 s_R = s_account;
    uint160 A_S = random_uint160();

    //Make test
    {
        {//T = hash(F, j)
            libff::bit_vector F_lsb = uint256_to_bool_vector(F);
            libff::bit_vector j_lsb = uint256_to_bool_vector(j);

            libff::bit_vector block;
            block.insert(block.end(), F_lsb.begin(), F_lsb.end());
            block.insert(block.end(), j_lsb.begin(), j_lsb.end());

            libff::bit_vector T_lsb = sha256_ethereum<FieldType>::get_hash(block);

            T = bool_vector_to_uint256(T_lsb);
        }
        {//P_proof_S = PRF(s_S)
            libff::bit_vector s_S_lsb = uint252_to_bool_vector_256(s_S);

            libff::bit_vector block(sha256_ethereum<FieldType>::get_digest_len());
            block.insert(block.begin(), s_S_lsb.begin(), s_S_lsb.end());

            libff::bit_vector P_proof_S_lsb = sha256_ethereum<FieldType>::get_hash(block);

            P_proof_S = bool_vector_to_uint256(P_proof_S_lsb);
        }
        {//V_S = hash(P_proof_S, hash(W, r_S))
            libff::bit_vector W_lsb = uint256_to_bool_vector(W);
            libff::bit_vector r_S_lsb = uint256_to_bool_vector(r_S);

            libff::bit_vector block_1;
            block_1.insert(block_1.end(), W_lsb.begin(), W_lsb.end());
            block_1.insert(block_1.end(), r_S_lsb.begin(), r_S_lsb.end());

            libff::bit_vector hash_1 = sha256_ethereum<FieldType>::get_hash(block_1);

            libff::bit_vector P_proof_S_lsb = uint256_to_bool_vector(P_proof_S);

            libff::bit_vector block_2;
            block_2.insert(block_2.end(), P_proof_S_lsb.begin(), P_proof_S_lsb.end());
            block_2.insert(block_2.end(), hash_1.begin(), hash_1.end());

            libff::bit_vector V_S_lsb = sha256_ethereum<FieldType>::get_hash(block_2);

            V_S = bool_vector_to_uint256(V_S_lsb);
        }
        {//L_P = hash(A_PS, hash(s_S, hash(T, W_P)))
            libff::bit_vector T_lsb = uint256_to_bool_vector(T);
            libff::bit_vector W_P_lsb = uint256_to_bool_vector(W_P);

            libff::bit_vector block_1;
            block_1.insert(block_1.end(), T_lsb.begin(), T_lsb.end());
            block_1.insert(block_1.end(), W_P_lsb.begin(), W_P_lsb.end());

            libff::bit_vector hash_1 = sha256_ethereum<FieldType>::get_hash(block_1);

            libff::bit_vector s_S_lsb = uint252_to_bool_vector_256(s_S);

            libff::bit_vector block_2;
            block_2.insert(block_2.end(), s_S_lsb.begin(), s_S_lsb.end());
            block_2.insert(block_2.end(), hash_1.begin(), hash_1.end());

            libff::bit_vector hash_2 = sha256_ethereum<FieldType>::get_hash(block_2);

            libff::bit_vector A_PS_lsb = uint160_to_bool_vector_256_rpad(A_PS);

            libff::bit_vector block_3;
            block_3.insert(block_3.end(), A_PS_lsb.begin(), A_PS_lsb.end());
            block_3.insert(block_3.end(), hash_2.begin(), hash_2.end());

            libff::bit_vector L_P_lsb = sha256_ethereum<FieldType>::get_hash(block_3);

            L_P = bool_vector_to_uint256(L_P_lsb);
        }
        {//L = hash(A_S, hash(s_R, hash(T, W)))
            libff::bit_vector T_lsb = uint256_to_bool_vector(T);
            libff::bit_vector W_lsb = uint256_to_bool_vector(W);

            libff::bit_vector block_1;
            block_1.insert(block_1.end(), T_lsb.begin(), T_lsb.end());
            block_1.insert(block_1.end(), W_lsb.begin(), W_lsb.end());

            libff::bit_vector hash_1 = sha256_ethereum<FieldType>::get_hash(block_1);

            libff::bit_vector s_R_lsb = uint252_to_bool_vector_256(s_R);

            libff::bit_vector block_2;
            block_2.insert(block_2.end(), s_R_lsb.begin(), s_R_lsb.end());
            block_2.insert(block_2.end(), hash_1.begin(), hash_1.end());

            libff::bit_vector hash_2 = sha256_ethereum<FieldType>::get_hash(block_2);

            libff::bit_vector A_S_lsb = uint160_to_bool_vector_256_rpad(A_S);

            libff::bit_vector block_3;
            block_3.insert(block_3.end(), A_S_lsb.begin(), A_S_lsb.end());
            block_3.insert(block_3.end(), hash_2.begin(), hash_2.end());

            libff::bit_vector L_lsb = sha256_ethereum<FieldType>::get_hash(block_3);

            L = bool_vector_to_uint256(L_lsb);
        }
    }

    if (EXECUTE_TRANSACTION_SEND)
    {
// #ifdef DEBUG
        std::cout << "GuneroTransactionSendCircuit:\n";

        std::cout << "s_S: " << s_S.inner().GetHex() << "\n";
        std::cout << "r_S: " << r_S.GetHex() << "\n";
        std::cout << "A_PS: " << A_PS.GetHex() << "\n";
        std::cout << "W_P: " << W_P.GetHex() << "\n";
        std::cout << "F: " << F.GetHex() << "\n";
        std::cout << "j: " << j.GetHex() << "\n";

        std::cout << "\n";

        std::cout << "W: " << W.GetHex() << "\n";
        std::cout << "T: " << T.GetHex() << "\n";
        std::cout << "V_S: " << V_S.GetHex() << "\n";
        std::cout << "V_R: " << V_R.GetHex() << "\n";
        std::cout << "L_P: " << L_P.GetHex() << "\n";
        std::cout << "s_S: " << s_S.inner().GetHex() << "\n";
        std::cout << "r_S: " << r_S.GetHex() << "\n";
        std::cout << "r_R: " << r_R.GetHex() << "\n";
        std::cout << "A_PS: " << A_PS.GetHex() << "\n";
        std::cout << "W_P: " << W_P.GetHex() << "\n";
        std::cout << "P_proof_R: " << P_proof_R.GetHex() << "\n";
// #endif

        std::string GTSr1csPath(path);
        GTSr1csPath.append("GTS.r1cs.bin");
        std::string GTSpkPath(path);
        GTSpkPath.append("GTS.pk.bin");
        std::string GTSvkPath(path);
        GTSvkPath.append("GTS.vk.bin");
        std::string GTSwitnessPath(path);
        GTSwitnessPath.append("GTS.witness.bin");
        std::string GTSproofPath(path);
        GTSproofPath.append("GTS.proof.bin");

//         //Generate Transaction Send
//         {
//             /* generate circuit */
// #ifdef DEBUG
//             libff::print_header("Gunero Generator");
// #endif

//             GuneroTransactionSendCircuit<FieldType, BaseType, sha256_ethereum<FieldType>> gtsc;

//             gtsc.generate(GTSr1csPath, GTSpkPath, GTSvkPath);
//         }

        //Prove Transaction Receive
        {
            r1cs_ppzksnark_proving_key<BaseType> pk;
            loadFromFile(GTSpkPath, pk);

            r1cs_ppzksnark_verification_key<BaseType> vk;
            loadFromFile(GTSvkPath, vk);

            GuneroTransactionSendCircuit<FieldType, BaseType, sha256_ethereum<FieldType>> gtsc;

            GuneroProof proof;
            bool proven = gtsc.prove(
                W,
                T,
                V_S,
                V_R,
                L_P,
                s_S,
                r_S,
                r_R,
                A_PS,
                W_P,
                P_proof_R,
                pk,
                vk,
                proof);

            assert(proven);

            saveToFile(GTSproofPath, proof);

            GuneroTransactionSendWitness gtsw(
                W,
                T,
                V_S,
                V_R,
                L_P);
            saveToFile(GTSwitnessPath, gtsw);
        }

        //Verify Transaction Send
        {
            r1cs_ppzksnark_verification_key<BaseType> vk;
            loadFromFile(GTSvkPath, vk);

            r1cs_ppzksnark_processed_verification_key<BaseType> vk_precomp = r1cs_ppzksnark_verifier_process_vk<BaseType>(vk);

            GuneroProof proof;
            loadFromFile(GTSproofPath, proof);

            GuneroTransactionSendCircuit<FieldType, BaseType, sha256_ethereum<FieldType>> gtsc;

            bool verified = gtsc.verify(
                W,
                T,
                V_S,
                V_R,
                L_P,
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

    if (EXECUTE_TRANSACTION_RECEIVE)
    {
        std::string GTRr1csPath(path);
        GTRr1csPath.append("GTR.r1cs.bin");
        std::string GTRpkPath(path);
        GTRpkPath.append("GTR.pk.bin");
        std::string GTRvkPath(path);
        GTRvkPath.append("GTR.vk.bin");
        std::string GTRwitnessPath(path);
        GTRwitnessPath.append("GTR.witness.bin");
        std::string GTRproofPath(path);
        GTRproofPath.append("GTR.proof.bin");

        //Generate Transaction Receive
        {
            /* generate circuit */
#ifdef DEBUG
            libff::print_header("Gunero Generator");
#endif

            GuneroTransactionReceiveCircuit<FieldType, BaseType, sha256_ethereum<FieldType>> gtrc;

            gtrc.generate(GTRr1csPath, GTRpkPath, GTRvkPath);
        }

        //Prove Transaction Receive
        {
            r1cs_ppzksnark_proving_key<BaseType> pk;
            loadFromFile(GTRpkPath, pk);

            r1cs_ppzksnark_verification_key<BaseType> vk;
            loadFromFile(GTRvkPath, vk);

            GuneroTransactionReceiveCircuit<FieldType, BaseType, sha256_ethereum<FieldType>> gtrc;

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

            GuneroTransactionReceiveWitness gtrw(
                W,
                T,
                V_S,
                V_R,
                L);
            saveToFile(GTRwitnessPath, gtrw);
        }

        //Verify Transaction Receive
        {
            r1cs_ppzksnark_verification_key<BaseType> vk;
            loadFromFile(GTRvkPath, vk);

            r1cs_ppzksnark_processed_verification_key<BaseType> vk_precomp = r1cs_ppzksnark_verifier_process_vk<BaseType>(vk);

            GuneroProof proof;
            loadFromFile(GTRproofPath, proof);

            GuneroTransactionReceiveCircuit<FieldType, BaseType, sha256_ethereum<FieldType>> gtrc;

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
