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

extern "C" int prove_membership_with_files(const char* path, int argc, const char* argv[]);

//Test Keccak hash
extern "C" int test_keccak(
    const char* LeftHex,
    const char* RightHex,
    char* HashHex,
    const unsigned int HashHexSize
    );

//Test SHA-3 256 hash
extern "C" int test_sha3_256(
    const char* LeftHex,
    const char* RightHex,
    char* HashHex,
    const unsigned int HashHexSize
    );

//Helper functions
int sha3_256(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen);
int keccak_256(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen);

std::string bit_vectorToHex(libff::bit_vector blob)
{
    char psz[(blob.size() / 4) + 1];
    for (unsigned int i = 0; i < (blob.size() / 8); i++)
    {
        int data = 0;
        for (unsigned int j = 0; j < 8; j++)
            if (blob[(i * 8) + j])
                data |= (1 << (7 - j));
        sprintf(psz + (i * 2), "%02x", data);
    }
    return std::string(psz);
}

libff::bit_vector HexTobit_vector(std::string s)
{
    libff::bit_vector blob;
    if (s.length() % 2 > 0)
    {
        throw std::runtime_error("bad hex length");
    }
    int start = 0;
    if ((s[1] == 'x') || (s[1] == 'X'))
    {
        start = 2;
    }
    for (unsigned int i = start; i < s.length(); i += 2)
    {
        int value = 0;
        switch (s[i])
        {
            case '0'://dec 48
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                value |= (((int)s[i]) - 48) << 4;
                break;
            case 'A'://dec 65
            case 'B':
            case 'C':
            case 'D':
            case 'E':
            case 'F':
                value |= (((int)s[i]) - 65 + 10) << 4;
                break;
            case 'a'://dec 97
            case 'b':
            case 'c':
            case 'd':
            case 'e':
            case 'f':
                value |= (((int)s[i]) - 97 + 10) << 4;
                break;
            default:
                throw std::runtime_error("bad hex value");
        }
        switch (s[i + 1])
        {
            case '0'://dec 48
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                value |= ((int)s[i + 1]) - 48;
                break;
            case 'A'://dec 65
            case 'B':
            case 'C':
            case 'D':
            case 'E':
            case 'F':
                value |= ((int)s[i + 1]) - 65 + 10;
                break;
            case 'a'://dec 97
            case 'b':
            case 'c':
            case 'd':
            case 'e':
            case 'f':
                value |= ((int)s[i + 1]) - 97 + 10;
                break;
            default:
                throw std::runtime_error("bad hex value");
        }

        for (unsigned int j = 0; j < 8; j++)
        {//LSB!
            if (value & (1 << j))
            {
                blob.push_back(true);
            }
            else
            {
                blob.push_back(false);
            }
        }
    }
    return blob;
}

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
                if (strlen(start) > 0)
                {
                    strcpy(node_buffer, start);
                    node_uint256.SetHex(node_buffer);
                    node = uint256_to_bool_vector(node_uint256);

                    M_account.push_back(node);
                }

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

extern "C" int calculate_Merkle_root(
    const libff::bit_vector &A_account,
    const libff::bit_vector &leaf,
    const std::vector<gunero_merkle_authentication_node> &M_account,
    const int UseNewFormat,
    uint256 &W
)
{
    const size_t MERKLE_TREE_DEPTH  = 160UL;

    assert(M_account.size() == MERKLE_TREE_DEPTH);

    libff::bit_vector W_lsb;

    GuneroMembershipCircuit<FieldType, BaseType, sha256_ethereum<FieldType>, MERKLE_TREE_DEPTH>::calculateMerkleRoot(
        A_account,
        leaf,
        M_account,
        W_lsb
        );

    W = bool_vector_to_uint256(W_lsb);

    return 0;
}

extern "C" int create_Merkle_root()
{
    const size_t MERKLE_TREE_DEPTH  = 160UL;

    libff::start_profiling();

    //alt_bn128_pp
    libff::init_alt_bn128_params();

    {//6813eb9362372eef6200f3b1dbc3f819671cba69
        libff::bit_vector A_account = HexTobit_vector("6813eb9362372eef6200f3b1dbc3f819671cba69");

        libff::bit_vector leaf = HexTobit_vector("eaee3b22f11239998357d2c23a7048d6749c2bfd0f17ecc14b7d54a685ab19fe");

        std::vector<gunero_merkle_authentication_node> M_account;
        M_account.push_back(HexTobit_vector("4198e670e134cb5f2dd63c4e8cfda0651cda9cf8e40d18a7febc3da3f7548d30"));
        M_account.push_back(HexTobit_vector("b54533e20baf0255d6f2af35c98af7b8cd3c93ba61884b4ebb8e5949e4956c6a"));
        M_account.push_back(HexTobit_vector("c8b18d590e35bb284b4002d7c03f70bd783892f0960e4e55871bf0a5547511a6"));
        M_account.push_back(HexTobit_vector("b6c4f60be12e6d9ecec4ec0358b649cb928964a1cceb3ad0f5489e3370cec062"));
        M_account.push_back(HexTobit_vector("bee732a3c6dfbbfaadb9571c6542fbec04207fc2656ead80e0cf577324ceae9f"));
        M_account.push_back(HexTobit_vector("a316fde664d514b20d6cc1587758099b3ae6476683a9cd90a4e1de5c29d29c20"));
        M_account.push_back(HexTobit_vector("ee3786d68d6ca3c612bdacf44b0135ce9685e8eeaf3af1367528c666eba1014f"));
        M_account.push_back(HexTobit_vector("45e03835d71ffc452d0fee926e55d1993e16248e63d4102f0ab5b827c0008a1a"));
        M_account.push_back(HexTobit_vector("604f6a314d9a59e674d6762b73455ff002989c25d2c2ee1eb29995f5a8a2fd34"));
        M_account.push_back(HexTobit_vector("12d266c3318468db851b331832364b5cf18958b38f39acd60fff19c74483082e"));
        M_account.push_back(HexTobit_vector("f0fab3033a8f9806b668419c01d3cf5cbd11fabf0d0941ede7d9d1edb22a6689"));
        M_account.push_back(HexTobit_vector("7c447af8ffaf5dc7fdd08192aadb798f2c7d180071bf50bd9f02781678a19f21"));
        M_account.push_back(HexTobit_vector("e973a908616f923a8cc7a3627c814c22eebc1dccb0a07d67c3407ac0ed31a05d"));
        M_account.push_back(HexTobit_vector("7e5ef24baafa3611268ec841551a75cdc9b6910736da1efe95c15f3394db2ef7"));
        M_account.push_back(HexTobit_vector("76045029202766652a9f6e3093f61bd53df9f846ce45d6f75c9e5a2e22d98c58"));
        M_account.push_back(HexTobit_vector("69b7727b7a787b545496af8abac5650d147d4875b64af595178b11722fb89274"));
        M_account.push_back(HexTobit_vector("4f188410d21f930b49722cc19dbf980bf667b44bc14efbabb8039ff57ec1f307"));
        M_account.push_back(HexTobit_vector("a2cd9a18195f155343c8399ce8aca459842ad9092da15d3848730a58228fa7fa"));
        M_account.push_back(HexTobit_vector("842ec2a7addc813a464cd51abcb3096ab52a324feec7f9293125913ed465ef19"));
        M_account.push_back(HexTobit_vector("d070a00e3b4af331a2460b76df47887750d563ee3b132e55edaa51f0174f9f53"));
        M_account.push_back(HexTobit_vector("0d5c24f0e8de0798b61a58d99af78c105f316294b4c7034444c1e098a8d4d7e0"));
        M_account.push_back(HexTobit_vector("6b7fa81308e61ccd5a1ad5a083fd73a768bc66021024fc0cfedc1cf76860b2ef"));
        M_account.push_back(HexTobit_vector("f04a3d4bc43c29bc69b6a25b9436b149516f7b7dc84f24f29e328b3d64df6378"));
        M_account.push_back(HexTobit_vector("1dfcdbcbcbec533855539fad0aba04ac94bb14a7e2acbe21fd941b521c5f69bd"));
        M_account.push_back(HexTobit_vector("e367c2abf636ae52507ce0aba2f1d90b847e2d34283cfa87ff4a32820d3df009"));
        M_account.push_back(HexTobit_vector("c755bcdbb6fd2ca7b04265709c25ecbe7be01a3cb2ad38090f82e6fcbd5772c6"));
        M_account.push_back(HexTobit_vector("409876688cd608f23ac6f11d8c9acd09614db3b28646659da200c24ef3b486ac"));
        M_account.push_back(HexTobit_vector("d53f6a9442493bdb5cf6a9815597bb956ec335261389c785b6f4afd85d51a923"));
        M_account.push_back(HexTobit_vector("68b38265302710c46df3ea590a668dbf4e5aea2e7e493740d1afbee71771dc8c"));
        M_account.push_back(HexTobit_vector("e91d487ecfc02f5f414ddf6eaa374ffe23d13fcec8a60a24b8079bd898faf46c"));
        M_account.push_back(HexTobit_vector("7b25de284944ac154469c9d5f1ac508140e994474744a7a197f8e84737b6018c"));
        M_account.push_back(HexTobit_vector("9fdc8ba0ade0ff2e1233f78c4e99e9e1dd912706075fff1456ea96a2e2777d2d"));
        M_account.push_back(HexTobit_vector("d68a5cba2a08d36b0ddbbb65416196fce977512ddcf04fc7685aac539a70df56"));
        M_account.push_back(HexTobit_vector("34558a7cc5307c8b3915648023f2ab1bd3fbd0cd097d38e63467f05804522753"));
        M_account.push_back(HexTobit_vector("03074f71919d8ab53c2b6e31f04e7f747844e5796cccaf4f8a0643a50ca380d9"));
        M_account.push_back(HexTobit_vector("09e0b77278bd0dc0918d4df36992b3dacfff285b8bb55bae223eb729f09c978f"));
        M_account.push_back(HexTobit_vector("489640c42efc6bfea72ab92c7f7c1776028ec32122860607b7ea289b849a70d7"));
        M_account.push_back(HexTobit_vector("dd569211f2d6d4378fbc510cbeb387b0c24d4c30db3fb7a106752542e2a05c91"));
        M_account.push_back(HexTobit_vector("82fc7e994072bd75b99eed35a39c7fe89748ee73a697705b1c8812c7f3c43338"));
        M_account.push_back(HexTobit_vector("d4e27385b84022df09c6ffbce3d74d326281e8b68281053cf135d44901ff29ba"));
        M_account.push_back(HexTobit_vector("69ecfb8475168d7279557cb7d36a9728effb70886a2193a217de91aeab01f52f"));
        M_account.push_back(HexTobit_vector("46d8ded1d233844e7f70c89cdde53506c3d2992e5c88ce5296f8a8e0c5017572"));
        M_account.push_back(HexTobit_vector("a9cbbe14b86c9abae0a90035436910d2fb897f81c77a9f69495c7c54a1aefb1f"));
        M_account.push_back(HexTobit_vector("a3a23a338696ec24d12538856fb1c7979d8cddcdbdccb8800d0dcef820bda560"));
        M_account.push_back(HexTobit_vector("5de259b6403ce925249e652ff29f4001cee98fe9a889bfe3d85ea51374b595f4"));
        M_account.push_back(HexTobit_vector("ebd0b35ac9a3ec5f08de902d6685fae7430bb0996cb1ca10b7d3ad8b30da2c2d"));
        M_account.push_back(HexTobit_vector("664ca174220c844f559a89c41d512952db9eabd0db10ca1208b752f635af6722"));
        M_account.push_back(HexTobit_vector("0af74f6ca7c5c2e94fca3072822fdca11b369cb730338c5a79da0cbd07936151"));
        M_account.push_back(HexTobit_vector("cbf03e8c8c43d91be8450628c74dad2f21b9aa7b8ff1942c36add2014070da9c"));
        M_account.push_back(HexTobit_vector("432451b14dfb149240c821bb124b5510c0ab55f999538431fe92ec4cf23cf5b0"));
        M_account.push_back(HexTobit_vector("74260b5036ce2374515e18aa3688df67ce7c9e4c6d778c7d3409886b8882aec6"));
        M_account.push_back(HexTobit_vector("0634973763af05a4ecf5198f42a9a0b92fd32d8c0540823617a9c0fc28a1906e"));
        M_account.push_back(HexTobit_vector("b6365a98669575aed2f14a7afac61ad8c72a03c564b1396ec56dd20e0d3c8829"));
        M_account.push_back(HexTobit_vector("464b6467691319ca5680246686a73acab9f1909f6784927e821f25ab9c432fb5"));
        M_account.push_back(HexTobit_vector("e13296cb401f9b30bb3568463194b052b345408a204367544a889a5a24a609f2"));
        M_account.push_back(HexTobit_vector("8cce004a60b8abafd84b20bef4c89ee682bfb5a4ccfcece87cdb8340b234ca79"));
        M_account.push_back(HexTobit_vector("b1a239925ae26d678a4ce3ecd15461c9ba30cd9c99f2cc658dff6872d488f758"));
        M_account.push_back(HexTobit_vector("ce79ae2307b1f8f158c7f7f2960dbf69b5c04c59723738e3ee3bdabd4d63b2ce"));
        M_account.push_back(HexTobit_vector("de292b7f9990aa7e1f672639f34ba3e74adb214dc5c16ce5bbc90c0ca7bbf42a"));
        M_account.push_back(HexTobit_vector("ce0ce3d35ed5b99b08522ca9c6edfde39c445e0fb2f96a0bc9510af6ab4cd573"));
        M_account.push_back(HexTobit_vector("eb9360f77d100479eaf20016d33f62ff656bd0e6f07049331150a6d47aa81ed1"));
        M_account.push_back(HexTobit_vector("8309dd1eaebeae29f2de21e0017e60ec0e9ac0739634cd7ea2a5e505f55a8a70"));
        M_account.push_back(HexTobit_vector("8dd0c70e2403e9e5e0ec845f0e5425d9b714eed0a945a6bcd4665a506b6583d4"));
        M_account.push_back(HexTobit_vector("c580141132ef38a68b1a7c5acdf542dcb057c74343e0acb1f36017515bcf9a5a"));
        M_account.push_back(HexTobit_vector("6429c632e34990ff4d9d5de7a7bc3e75c85b318a722abc8b1171765b419b3662"));
        M_account.push_back(HexTobit_vector("55662ace228351deaafc038357b0c401db11908fad00e30ee0a826d33002f6d6"));
        M_account.push_back(HexTobit_vector("cf055c0364e5cffbea9a36f85ae1c3e5fe0f19467ee9440c07e5ef0ae278821d"));
        M_account.push_back(HexTobit_vector("deacece9baa1ff11f59f7d2bf93142d9a134088d900ab072d958e24b5fcffba3"));
        M_account.push_back(HexTobit_vector("445050aa4dce1b297f886e7ae3d04104e425f98bccc2c1efe87d18e597125698"));
        M_account.push_back(HexTobit_vector("fe1ae38f91c4c9e40ca1e2f0bb5d3bda499c57b144c20767832586a309c2272d"));
        M_account.push_back(HexTobit_vector("0ccc816b5dc603945e9c3217a5ce2ba3717429ae7a5e0e2e54eb51d9b09ce8f6"));
        M_account.push_back(HexTobit_vector("5e8e8c7422f0323f1b058f820ec73f0b5e1eef7450abb8f4c1cbba79bcef4547"));
        M_account.push_back(HexTobit_vector("fb248b949e408d815cbd7671cc8feaddf3d64d615bab89d6c3df308a33f6e48a"));
        M_account.push_back(HexTobit_vector("24263e8c589c2052017fb01c39743931f824bc6975508b299fff2125f2d561a0"));
        M_account.push_back(HexTobit_vector("26b07301dba28fce5f446bb9401b83bfac58bc97c4114d32e7fbec16acc6caa0"));
        M_account.push_back(HexTobit_vector("ca6e3e4c93e74cfa946a2b21cf27ef2091ca5a4be800138ed783441edd16c239"));
        M_account.push_back(HexTobit_vector("10dc9a7ab60507d8dc1ad6228373edff15ddcb0f2eaa5705932ec0b198937e3c"));
        M_account.push_back(HexTobit_vector("bff9521f19964264878b2693b0756c1188c705536ff5c81a7d1fcfcd6e3e49c8"));
        M_account.push_back(HexTobit_vector("d4c92b2ac1498495f9c541fb1505bf0d0285b49e72cb890e5df2d77bdd7e8d54"));
        M_account.push_back(HexTobit_vector("a281924f2e3db920685ff946f560f5c4ccf764dc1a9ef88e2489cd02d58c80be"));
        M_account.push_back(HexTobit_vector("fa17e2fb29deee4506cf8e5be3d3b7150284f9d63d5de8d73fb67f7591080f27"));
        M_account.push_back(HexTobit_vector("453a4ae7322a7ac70a381664afe86f0d60240dd829e568cc82e5a7f5b0ac2151"));
        M_account.push_back(HexTobit_vector("ea7afc558db5ef1cf5206bbdac7df5d0430900792ba1423410f2f96e17145434"));
        M_account.push_back(HexTobit_vector("ed005043dc2af7180a4616444fcf4f38023011541deb3c41c105f3383b4557f3"));
        M_account.push_back(HexTobit_vector("4b7359985640ed9ed470a4ed62440595ba8b1921f37632b16d591ec7066f9c25"));
        M_account.push_back(HexTobit_vector("6d524baf186ede5f753019d58bded4cdf70ea7e21c625b6dc2ce1dae721ec20d"));
        M_account.push_back(HexTobit_vector("cb84287a5ae21983db7d7abada6d369f2cec272ba2dd69287d9984b83ff82441"));
        M_account.push_back(HexTobit_vector("c23b40531d2c82b3c57303347d1407f65215b3d625f35c7d04894649a049a6b6"));
        M_account.push_back(HexTobit_vector("90e60ac67707bd72f41a09d54fd1cde004346fac44dc60d22b14f1b535901c52"));
        M_account.push_back(HexTobit_vector("0be9a13d5c428f3f3dc9a924b4ec73f85a28ec3bec448eb1f59346b61efa879e"));
        M_account.push_back(HexTobit_vector("67a1c8473d9828e66a369273796930f3db0beef9e4ae1a13557611fd48e0eef3"));
        M_account.push_back(HexTobit_vector("9789a0af2de647fbd2c47a6ebfdd1a377bfe49405bfed00a057ce8663780f564"));
        M_account.push_back(HexTobit_vector("b44dfd3fc6cb424d4ed36e46843ad66d31f327f88c08221905d5b37d950e632e"));
        M_account.push_back(HexTobit_vector("83cb8442095dd81c8fdf2a208fd81fe42f2b6355805b7fca159364521dec9772"));
        M_account.push_back(HexTobit_vector("8a86104d9ae7db701b130af78086cd3089dd7ed67f1099d1123b3a5d1615284d"));
        M_account.push_back(HexTobit_vector("18e2965f592e2a599b9e75d126ba070951fe5417646597e93f26d7da2f169052"));
        M_account.push_back(HexTobit_vector("1532bb09f55b72ec6dfc919c8688b83f9bf0ed3a4b91f0b59950c68e6271461b"));
        M_account.push_back(HexTobit_vector("8d52d044e44b9262fe31b1880b83390cf334670be4770a7aa7f9bc8fb5657dc8"));
        M_account.push_back(HexTobit_vector("01d2c82d77fec1700b78d9a5d6f540591fad44a74feb008d40f88dfcd3dd9297"));
        M_account.push_back(HexTobit_vector("2fbf6da799c23faef9d23cbec5256b427f808c26aa9e37d48554d0db043861e4"));
        M_account.push_back(HexTobit_vector("3e6f4b3aac7d400f129bd7218df240b7e2ea78b4f37cdc953bac0736895da8f4"));
        M_account.push_back(HexTobit_vector("653bd5cda2a6bb9b3e48c7a7dcbe7d7b6ee386d22a89ad0889a2c3eefe717997"));
        M_account.push_back(HexTobit_vector("2e31273dbc55ac88da1625e2ade93d4401cc40f1966c3d5232575cc3dd03dacc"));
        M_account.push_back(HexTobit_vector("f3f8cf3525984ad0990d48a017ce71132380332a01514969e083db9d644e5a8f"));
        M_account.push_back(HexTobit_vector("1422e517a8d20c5ba05ebd6ee5420f5595ae21d5e27e7a83d35094e5e89c649a"));
        M_account.push_back(HexTobit_vector("9835bd3683beb63bb9f536bc86483d914b5cd7382e88e809aedd9048f12bf062"));
        M_account.push_back(HexTobit_vector("ce977a153e3d9137d286dc7ea2f2a47f76c2656ab0e8ab9d3b31a7eccf262990"));
        M_account.push_back(HexTobit_vector("7a7252698dd7c254cd0a2aa4a128a5b5fc1843f891041986e7190d33b073c62c"));
        M_account.push_back(HexTobit_vector("3fbd3335b294601cbe2226e647811782765a6808a073fd2a55fadbd632e94635"));
        M_account.push_back(HexTobit_vector("81d949efa1b7a6ed205fa0d9ce67fdeabc7210b2bfe97ba19211fab6a9173d32"));
        M_account.push_back(HexTobit_vector("d00225165ea94b5658d5f7163a566af4674f3d4d08e0fd4d9e4307cb52b10036"));
        M_account.push_back(HexTobit_vector("7dd23ea31739a4aa6492b88ea55550e1fb7310132a4a2c6216a9086ec7b0b0eb"));
        M_account.push_back(HexTobit_vector("9eb888025b77cb5bc498dff5a8866ea10c0c1445a9f2629ba80e658534f9f644"));
        M_account.push_back(HexTobit_vector("60b27a6a4919085983c50151c4782c04d63a3b0147d191f3069581ba900b876b"));
        M_account.push_back(HexTobit_vector("accdd5ca4fb7201c7ee2ca311df98ca8bd7f198618fb0713af5bc2fc0138d3b4"));
        M_account.push_back(HexTobit_vector("c7da7700137a18c926a67ccca40b02bc67d97b181111ce25c673ec13ded5387e"));
        M_account.push_back(HexTobit_vector("b06c021040d65430711e5ed170f23a438febc48d5c1ab67467e589e42920d1f7"));
        M_account.push_back(HexTobit_vector("3bb219a1c1f99ca995b2513efc5bbbac2549b99a24c540a32ae4a3779f337730"));
        M_account.push_back(HexTobit_vector("0b46a8133ecc7bcd278581994a2c722a6de5de26b8d5bcfa4b70e914e2780ee9"));
        M_account.push_back(HexTobit_vector("b4c0ea2bd00ba6cf4daab9a4a71ff6a859f34ca288e6fd0898acc63ec109d313"));
        M_account.push_back(HexTobit_vector("bede9ecb138d16aec10fa57ca5e4bee1cccd554a7798e00f66cda8c4a61f7a2f"));
        M_account.push_back(HexTobit_vector("22a0148908a5497fc85027367806737715fe955c549b1fb89d4894451e765f10"));
        M_account.push_back(HexTobit_vector("a016351bf992bd345c1a62b0b01581d72fe70a0654ebd5d61a1de6665855f64d"));
        M_account.push_back(HexTobit_vector("68bf227918fcf9be2cfa0a8367af0a31e984359d39dc7b3e532c9ed5eff89759"));
        M_account.push_back(HexTobit_vector("f3fdb893e5bc898a552a95334d1f6c20539fe0167236e37b187e75a88b250163"));
        M_account.push_back(HexTobit_vector("fba286fc087d421c3cbe36f5cf3ba2275a4357fcd1c762aa254b36ab4a959ea8"));
        M_account.push_back(HexTobit_vector("ecade1c3abc337e761f7ab287c81a4b3db1458c18c2021c816ea654eeba3f815"));
        M_account.push_back(HexTobit_vector("1285e9d78b68b09180a5abdb1fa64edb0e2ea44976c4d530b806e0851822652a"));
        M_account.push_back(HexTobit_vector("1a0eff154aa681cb5d4d2f3dd0c515d777a911ea46d7d633bb5d6eb5af131011"));
        M_account.push_back(HexTobit_vector("0c1d80cdfb91f9288b1ee7f87a32561d373eb0b580c8984af6d03abae6861b06"));
        M_account.push_back(HexTobit_vector("187dde331178325f51454481df7ee04157d67a78b661bc3d373a8211b1e050e6"));
        M_account.push_back(HexTobit_vector("32a9471c893f882c635c44ab1592781f7ca7c6eb0fc49dbc363873bfbf3919e2"));
        M_account.push_back(HexTobit_vector("7c9cec3d6baea32ef7d3f5e5486554231739039f4323a6779298490d32cd3285"));
        M_account.push_back(HexTobit_vector("7b76197cf72e78c8f3a0f6394ff034e4c5d7a6813df81dd80bcefdd0982ff5d1"));
        M_account.push_back(HexTobit_vector("ae7d1ca162a6727f98c44dc21f5af3c7925a08fa2868125baa71cd0f8268afef"));
        M_account.push_back(HexTobit_vector("b0ec65c21273728bfe12c90fb0aaf63935a0dca4024c0e10a07bf45a3439f06f"));
        M_account.push_back(HexTobit_vector("3c96512d81b4f3e6a364cf0a0870ec6aff2ec41fea8aecfa4a3143d8d12b5ea8"));
        M_account.push_back(HexTobit_vector("c985b578dda9accb3f791dced980ed7e382b75802e10d29f80d142099ad70471"));
        M_account.push_back(HexTobit_vector("5238c925b70fc6fd331caf604d23294e815fbcf4c544b20315357de63852a3b0"));
        M_account.push_back(HexTobit_vector("f5e3f1e8b0d345f208c302dd72e85897e3ad13bbe87c79f215853ff883dd3d61"));
        M_account.push_back(HexTobit_vector("40f0ab822b8d0a9198aa89b4086bbca05044b0db0fa346667c6884c6c41bb83f"));
        M_account.push_back(HexTobit_vector("84021b0e3ec3249d0f4852b56b91430a0a51974555ae733bc9f56c56ad4685ed"));
        M_account.push_back(HexTobit_vector("827c7a8f99b4a410814193c0a8b4545658c709bec084c65ed3d26acb67c6e54e"));
        M_account.push_back(HexTobit_vector("d4d9e6f51ebbda0ba2c93ea829518c7b6bc351bb3854c4a6bff79a984e4b3815"));
        M_account.push_back(HexTobit_vector("5224af6b127abe7a5c2450e9fc819951a60e2fc55df1ad17978440f11171680b"));
        M_account.push_back(HexTobit_vector("8d21f6874101610aefb17f53ca94f078a09ac80bc99280ea13cb8ad190be7fa8"));
        M_account.push_back(HexTobit_vector("c0504757bccfeb7254c85b8439849ccb1bf9e6da23cd3287df2c96d5cb54741c"));
        M_account.push_back(HexTobit_vector("8e64797760b139ebc3aed62a64eb071bda5d5fcb5ae1a4b8fa7bdd4bbaa5840c"));
        M_account.push_back(HexTobit_vector("9e9f905fcacf2532292815f3cfd6b31c4d693754eea88a6d66d179402619b306"));
        M_account.push_back(HexTobit_vector("84cdf1ef0f61667e5af2f0f51ec2881888dc003e6cae80add91f2269ef411fe1"));
        M_account.push_back(HexTobit_vector("3bfa0d01219ad7369c52d6403bd9c8bca42324bb4e0de634a1f20796eb84a47c"));
        M_account.push_back(HexTobit_vector("37e4f6513f361c9e77b4563858d55f6fda51f31a2012a3c88e82685ddf3d9ce5"));
        M_account.push_back(HexTobit_vector("2851b2229de60b499de026aa284df95baaec3e634180c99e1453739da0364621"));
        M_account.push_back(HexTobit_vector("e49fa0acb015ef113f864e406ee3e7c3cdef92f46816adabf72cf5ca7aa68fe7"));
        M_account.push_back(HexTobit_vector("88c673ba4af8c10e4d4dfb8427bc8cc741849992dcee3217b1f3b07523d5aa54"));
        M_account.push_back(HexTobit_vector("569e301cefbd8d4a025d911132f366ddf741b2f93105bbf3b238deda02cdf270"));
        M_account.push_back(HexTobit_vector("df1eadf01aea7fc0c31b5ef13f7002b8c615c2a90e83263200091e0ebcfdd801"));
        M_account.push_back(HexTobit_vector("6f21267e2924835775d03cf48818214cc95760e04b05cfe0320a33f5a5883d59"));
        M_account.push_back(HexTobit_vector("891370df4fadf33f50e41f7c8a791e680c0655695ea3404385a909c8f5e13fb4"));
        M_account.push_back(HexTobit_vector("b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"));

        uint256 W;
        {
            libff::bit_vector W_lsb;

            GuneroMembershipCircuit<FieldType, BaseType, sha256_ethereum<FieldType>, MERKLE_TREE_DEPTH>::calculateMerkleRoot(
                A_account,
                leaf,
                M_account,
                W_lsb
                );

            W = bool_vector_to_uint256(W_lsb);
        }

        std::cout << "A_account: " << bit_vectorToHex(A_account) << "\n";
        std::cout << "W: " << W.GetHex() << "\n";
    }

    {//2b5ad5c4795c026514f8317c7a215e218dccd6cf
        libff::bit_vector A_account = HexTobit_vector("2b5ad5c4795c026514f8317c7a215e218dccd6cf");

        libff::bit_vector leaf = HexTobit_vector("eaee3b22f11239998357d2c23a7048d6749c2bfd0f17ecc14b7d54a685ab19fe");

        std::vector<gunero_merkle_authentication_node> M_account;
        M_account.push_back(HexTobit_vector("c8799ff771efad687405b073db6bc6bc61643cfbaa7265786485dc11ea28ede7"));
        M_account.push_back(HexTobit_vector("e0b935b340807e3f57d9fc41983d8794b25ab8ce6e559ff1b50c11ba37aa5d4a"));
        M_account.push_back(HexTobit_vector("6a843f150e1a7442e37ebbf0b73b688bc7fb1a86ac7189a89fc2f941ac5653d3"));
        M_account.push_back(HexTobit_vector("b43c00574cd8153add705cb54d313ee0e9bd7e258dcfdcf870202fefdd1a2d76"));
        M_account.push_back(HexTobit_vector("41eb163148de1e5c6274aa513a2c4a17378b483f62cd44b0571bc677f0f453ce"));
        M_account.push_back(HexTobit_vector("47504e187ac8b04de847409377ea5e18d21ae989cfd6595b9e4114e54f00485e"));
        M_account.push_back(HexTobit_vector("6d2d9621c92235417891858ec30019cf524e0a80b12d22ab3f553dd5691c79a6"));
        M_account.push_back(HexTobit_vector("76684d6ca82e5d13913dfebea7a68b4d6261bf8852d4417022402179dddc6230"));
        M_account.push_back(HexTobit_vector("a6efc78b71ed4803f530abc4c0e169ddd3a3a845d64d28b1796e295250e0a3ad"));
        M_account.push_back(HexTobit_vector("4f91b51be81094c6cd7bfd8592cd7deb645e8105c27d184ec6db3f55e2a34f5f"));
        M_account.push_back(HexTobit_vector("5bf31a2a2141dbcf0fd3a2a86a2ba6edd73a773047267dff2b57ff8fddb35d89"));
        M_account.push_back(HexTobit_vector("e21aa654e869e16be09e9e20c89ed8071af226f69f665fa6cd1b91914e0325c5"));
        M_account.push_back(HexTobit_vector("ab8d940acd26a857a285d3cd63758d559007c293ebeb271a51286a11b2f21c6a"));
        M_account.push_back(HexTobit_vector("910f6093af88529295710a0869b0fea42e6051cbc43ca318996b15ce9cdf7ed1"));
        M_account.push_back(HexTobit_vector("7930f2265188db645c63d7c7708357dca007ebe8904023b6f8cc5981971ebb96"));
        M_account.push_back(HexTobit_vector("8f582e174fe403ecaf928489f5220fb029a97e9b3a9bf1c409199c94c91e7829"));
        M_account.push_back(HexTobit_vector("3cc08b7221d1b4f2076645a7b5edcd30b0d5e09d8e7efbd4487ab06cb1d01cf1"));
        M_account.push_back(HexTobit_vector("3361771b542f3eececa586044826e1d099a6637a9e3157a8ec33dfa362e418b3"));
        M_account.push_back(HexTobit_vector("afd665823c46e372f46daa47be3a7f52e9899bcffda9b792109a65cee4484344"));
        M_account.push_back(HexTobit_vector("809a47df2a5f079db9a4759285c55536230ad60fcd9b5421f99d626a7e18d9ec"));
        M_account.push_back(HexTobit_vector("e41f3c0036d3cb6a539503c7ba6333e09799e7da64e1fd1c337c29174862d177"));
        M_account.push_back(HexTobit_vector("41cf9442825ebcda04398253b15a083724537f5d0d48886c82de02730c42552c"));
        M_account.push_back(HexTobit_vector("dabcaab0233d6ffd9afa36e32e34d4985c4a7c5a9c941db36ec58c316e2fc9b8"));
        M_account.push_back(HexTobit_vector("3e19399df86b8cf1d7f1590ed4e4887ada9d9ac5486ae984a5665a6b8d3b7798"));
        M_account.push_back(HexTobit_vector("2d7d21975326046ec052b311a40d566d81df250e405299b14ceb366d8f520b9f"));
        M_account.push_back(HexTobit_vector("21d645051d24f14bedc1f5c966ae0a621bfb5988eaa04bfe2a7acb8a8118e919"));
        M_account.push_back(HexTobit_vector("95cf80eba558aef8f5cb829bfa92f48860167ff1aa0c5af57ffa3174cbfebf6d"));
        M_account.push_back(HexTobit_vector("c43a24642af1816207a9be4eeb9ed46667a9538ce1a09e50ea52298b11d88d2a"));
        M_account.push_back(HexTobit_vector("def6f8a9601592da977b3ffa48ecb461031818c02e5fec9fa19b197681fde337"));
        M_account.push_back(HexTobit_vector("72c4c9c665e0c7e713f064c7253c7611cf961682fe1501a2835d300d1d8c2eed"));
        M_account.push_back(HexTobit_vector("a22f7bd22fe94e79af6ca9f877556b1fe4977c26640da70f465d8d52e07ea653"));
        M_account.push_back(HexTobit_vector("713ba847123562793f4d833e275a9fe117b32746dc750e349d14ce26878357ba"));
        M_account.push_back(HexTobit_vector("fc7480fa17f81c3dc69d53b80ebbf7b8029054a62f1e72cd8bb74cc394d87616"));
        M_account.push_back(HexTobit_vector("b042e399a2281e54767cde5bd9d6ac92f1793eed7c6f75d7657c1f3ce286ba6c"));
        M_account.push_back(HexTobit_vector("376957b74a3a9f6f552f9012c67940e3f641f6aaf57977cb0526b0320d3b23c4"));
        M_account.push_back(HexTobit_vector("1f48e207fa7f50d113cc50d6c06ac0e8c1a3c8ddb663ba975f388f3b52f66381"));
        M_account.push_back(HexTobit_vector("f78b6e4364cb20dd06cf853d35b8dd849e7fa32a0e63b12ff7f0185998753072"));
        M_account.push_back(HexTobit_vector("49d77dec3b23f1203e5eae919b9c6345a03faa1c00cc3132cc7b387c82386896"));
        M_account.push_back(HexTobit_vector("96e33987cc130e835c56309cd4c76df9d363104da80b55ccbec0e0642ced45e3"));
        M_account.push_back(HexTobit_vector("a5fc00783dadbdeebfc441cbfb21f2bd5838dd5b6c0cbad693125a492972b009"));
        M_account.push_back(HexTobit_vector("b660c113d8471b1a5b071234c6258bffcebad59f0664af953037b269e34001ff"));
        M_account.push_back(HexTobit_vector("7bc1dd96f4caba1b9c49289557863ed52508c7b0d78c41da40e125525eb0dea7"));
        M_account.push_back(HexTobit_vector("3523565b4b6413dd2796fe486b5b4b6b9d55f0ba212eefb822189c3fee8159b4"));
        M_account.push_back(HexTobit_vector("326c443c4ad047e9c39c1ca9554492227afeb8558e0a256cabb341963d20a23b"));
        M_account.push_back(HexTobit_vector("f8939e7398f806d81d86ea0bddb4088bc24cf38f13e9adb09cdb647d751c5feb"));
        M_account.push_back(HexTobit_vector("ee7605eaed866ad9303ddf6ecc900b883609c060f7f508ecf02c44958ae8117b"));
        M_account.push_back(HexTobit_vector("77b161cfb7b3060bb0e3a5bf75ce4e535fc62c3cae9194c0030bf95b775a4c0a"));
        M_account.push_back(HexTobit_vector("fb4422712e4a1ba4896b8bf113810413a254491190e7a5dbc7274fdea33df61a"));
        M_account.push_back(HexTobit_vector("6f74a0cfee039eb976e53198336b0d45cd83266715da6af3beb3e8361f6bae7e"));
        M_account.push_back(HexTobit_vector("6667afb332211c70cd32987a6cb84bd395e441f0f6146e9947a5c60a8e6f7c08"));
        M_account.push_back(HexTobit_vector("4825751aacffe747b56d7f0938957df134cc81c9dc148d02057d5e9c1154b2ad"));
        M_account.push_back(HexTobit_vector("c540ba06a97aaae2346058be2de01cdffa085bc81b7062186c390e0aaf3cd295"));
        M_account.push_back(HexTobit_vector("d40bb110d71ac88ab1e9bb2d19791dd6f1248e7be825c905b518a4735a413804"));
        M_account.push_back(HexTobit_vector("922f18c567c479d82492f41df84b1027fe5aaa3d7c924f34507268380dd7eacc"));
        M_account.push_back(HexTobit_vector("a546fdfea82b3c2b17108aff1ccafa2edfdf1b60a2fa7968ed711fdabd87a42a"));
        M_account.push_back(HexTobit_vector("26a3045d992f4c16fa4cae2fd88f9cb601e60e3e2a56c0da79031e6222adbf0d"));
        M_account.push_back(HexTobit_vector("6d4960e7946e2640061d8eaa610ef829bab48e9c469fc94f6ad151e7548727cc"));
        M_account.push_back(HexTobit_vector("71e44acc82a6d134a9271245a5a471d23518eb5186b904e674f4bef8e22047bf"));
        M_account.push_back(HexTobit_vector("cf11213a6fac35faf9907b6ff7391bee2400e5c9fde31a613601ee70903e7627"));
        M_account.push_back(HexTobit_vector("14319e9f58149727b9a4ebd06babd29826200dd2d0289ab8f9f035490bd28020"));
        M_account.push_back(HexTobit_vector("bc57de3cd22f7ff211c2060f4123e4bd47c2a30c6e6b225f4b4ae819f67e7bd8"));
        M_account.push_back(HexTobit_vector("3c8665131c9e7241f452d192d367e71d313365a652bf22fd040f24ed66f99b52"));
        M_account.push_back(HexTobit_vector("c00efb8b82ee778c802579dfa71c13c4e25ee9197922696a0fdc559f0082c494"));
        M_account.push_back(HexTobit_vector("14851d8ca892c18ad3b9e5521708a92be1aee31869975a3abf5e605638711343"));
        M_account.push_back(HexTobit_vector("2f6b5471c37d065cd477ec8b3f87bd582c5abb14e8f9518b01761f042b914339"));
        M_account.push_back(HexTobit_vector("a74b7aca9bc921a438386f348ab7062b4a481a74ab1017b144b942c680b814b7"));
        M_account.push_back(HexTobit_vector("8352c9e92b32538726e274019d18e4b568725a549b7005b18fb852924d616a12"));
        M_account.push_back(HexTobit_vector("c7766081608e84a0b3b061d6c68129336f5f10c69cf2c881ca18035adbfa1e13"));
        M_account.push_back(HexTobit_vector("9a9637878c199f27df98038855492ec4c0fd0397cae6097c928fabad907b66c4"));
        M_account.push_back(HexTobit_vector("fcd4d6db10915eb9cb183ca0854a4dd6099c249b443a2950eeb91ea912f3fb4b"));
        M_account.push_back(HexTobit_vector("87fc22049112515d3e3e231e94608877fd065976758fdc42bf014f9a3fcc6775"));
        M_account.push_back(HexTobit_vector("e8a88ed529dbc6e6c0269aea16d92129186fc60425132d8a905bf56641111f9e"));
        M_account.push_back(HexTobit_vector("a2a3428f9f9e67e5c73c2338411ed2be15323c523bce3186b57e679ba6640d52"));
        M_account.push_back(HexTobit_vector("a72fcba4eb6ed0cbbf530bb70088725e14da2c2de70ee31964149fa742ead6e4"));
        M_account.push_back(HexTobit_vector("bfcfa04f71572752daad085a4d76bd5d7b85fcfc9629b90a4bdd9bd8a87f798a"));
        M_account.push_back(HexTobit_vector("f95aade5d3cad3c823fdd77ae18d3bb0b84e44516a85449ed2df65c8df179d88"));
        M_account.push_back(HexTobit_vector("f6df9d7ea78617b5cdf496f2bf79f04f8a93b2cf9d00c8c38a7acd07fdfaa03b"));
        M_account.push_back(HexTobit_vector("8878be920ff5573c57a82f88ccb2775fb6f27f818e79718e9eea95934948e575"));
        M_account.push_back(HexTobit_vector("fb403aca5003cd354dc1fc0bc221caf5691c019a73c3a1bf2d82c739783bfcb3"));
        M_account.push_back(HexTobit_vector("16217797c09a6dbfd4ea6dc960b99132880d35168d0808c049e8d4e1dde22882"));
        M_account.push_back(HexTobit_vector("c9c6804782c73d5f7fb84047e423e6d61d19dff4a9e027d7483e86f3d49ab1a6"));
        M_account.push_back(HexTobit_vector("0614cc9307b79c2ea5df48940a40311e76b68cb4761f8d096ab581afc095433c"));
        M_account.push_back(HexTobit_vector("e2c27504d56afceedb148be65a268e18378c63fdba97782e56464ce746b5ac6a"));
        M_account.push_back(HexTobit_vector("f2d692d926bb7d62f64465c4af88607ab39f08a5c5bafcd6ed77a2e3a3ec17eb"));
        M_account.push_back(HexTobit_vector("4bae57ffe9877bc38c9def88f3ed60e9ccf921105f94725923640ae8889fb363"));
        M_account.push_back(HexTobit_vector("28ca2341cb2ca0e2453e4145e686f48ef451ba90dd8b146ad8612d8dc268c844"));
        M_account.push_back(HexTobit_vector("4b7f7650d3a4041f37743c3a08b768c016c9180196ed476076a2244f5b7cc926"));
        M_account.push_back(HexTobit_vector("3ff8da7332d20cef657a4d9d8b55a6d8d32271c99091e1d12f0b9b52487a6274"));
        M_account.push_back(HexTobit_vector("43b0ef61deede49bcbff2061cf8c85d94106bd2a6cee773f6f0d439afb6b5c92"));
        M_account.push_back(HexTobit_vector("bf1db1efb41eaaad97c3af7866e1018db8b22360d028bc34af222da74f5ad8c4"));
        M_account.push_back(HexTobit_vector("74632935abb5a4b8e1dbeff004f389ebd4e8da46ec8aa616324b2ba3432c35bf"));
        M_account.push_back(HexTobit_vector("3f77c84cedfbb3f80c032b72827a3ec234cdb7497fea992f7986a7108b69f6ac"));
        M_account.push_back(HexTobit_vector("f70349731c34a1a58512309237d3c05559622c2f41fa6af8b92ad8b7591e7bf6"));
        M_account.push_back(HexTobit_vector("325ac80f3fdf8b9752f19cef34d384cf7484777b64e51a7e213f89916acfa530"));
        M_account.push_back(HexTobit_vector("c12270d1d253781ed4593c9cd6e66c96a2512bcf99fa7279d3c0a1da9560557a"));
        M_account.push_back(HexTobit_vector("fc680a95afbc9e7b37e77771186ed9feebcedd8c216ef9c3f59b435274ff2a53"));
        M_account.push_back(HexTobit_vector("72e1509baf210ae1df0e8411e9bbf3256b99622ef9372db487b967d17e7abfc7"));
        M_account.push_back(HexTobit_vector("c870195f1c1c557b77b72e4405aec4c9e490836e441b4f95f35b427df6ee1d6a"));
        M_account.push_back(HexTobit_vector("51439b8558c2c1ef876a207c6dec5de6302ef1d40f682df94bb6f6e3c8e3f768"));
        M_account.push_back(HexTobit_vector("346432ede8c2fdb9f085cc19103f8968f2c29ba4bb1749d4eeed00e8d78d8bfa"));
        M_account.push_back(HexTobit_vector("a4c5b2c851414e6223281219d50b8f24289bb8b43730a427b7ae523596c39963"));
        M_account.push_back(HexTobit_vector("8a4d21fde3cc077647c1b699872cefe4d179b8314a559461d5174bbad1f5a9a2"));
        M_account.push_back(HexTobit_vector("b7b5c9bf966b17d2c66e91d1cbc7f6df004490d41bc1444d1eebb9bf864379e6"));
        M_account.push_back(HexTobit_vector("de97805647c6b27b2639446997ba679c620d26820bc36b01d3c7e23216746d63"));
        M_account.push_back(HexTobit_vector("223f56634b66bb97520d3015b3086586d9b8bacf2574eb60872b55b0fa195f3e"));
        M_account.push_back(HexTobit_vector("e67f027eb45b0e2701cace2a3c6344c820f27442f2d187f9db90ae05f62a5915"));
        M_account.push_back(HexTobit_vector("1e2f467285bf6a2cc108f2edcc35733160abce9f8e32cf727eea4c60de818ffc"));
        M_account.push_back(HexTobit_vector("da709d6ff1b225214f0bb076382df7e20a08521a9161a8ce45464232710af306"));
        M_account.push_back(HexTobit_vector("113201d406a9dae9948b3c07c1c3fab0a822560cb2bbee9abd679d6d06c4cb3d"));
        M_account.push_back(HexTobit_vector("f2577eedd102878b8ce809057bee20388788b1bc9a078a4975276a5e99db145a"));
        M_account.push_back(HexTobit_vector("63972b0c2a8b10cb39447f21872c36e698de3ac8389237372e741502ed49620e"));
        M_account.push_back(HexTobit_vector("4148837effffe969ca913f0e4ed86e933cf148601c7f803ec3dd33271a578a7a"));
        M_account.push_back(HexTobit_vector("436083dc0a145e727fe5f3777a287fe200432e6b95d11bd2a1d0da6262247a86"));
        M_account.push_back(HexTobit_vector("6879c8a8d95fa200fd0bc9e0d8a04dfa89e20359b542bbb551ad8db498129c1d"));
        M_account.push_back(HexTobit_vector("eb321e708a408081c39a5b74f05212209e81728f536d82a521f1ab77b7a38014"));
        M_account.push_back(HexTobit_vector("65278a81180ae0e29066b9241299e5839f0049eab2162f86553edcb64aa3e664"));
        M_account.push_back(HexTobit_vector("5588f5e5e67e9275ea1d2187051859ab7d153acde68f4a6a6c817c7294ea78a0"));
        M_account.push_back(HexTobit_vector("4e274e4f01d37764b6191631b14a6844e5a0a0a7d2c1a935cdd424c8cb436f03"));
        M_account.push_back(HexTobit_vector("2260f8c873ad6a5c9fa57b6fec19110776d70e8c18d7838a31ebb25eec6710f9"));
        M_account.push_back(HexTobit_vector("10c4aa1e938bbdf38c22de9a424fd062ad34cb5968daf9b83c941bfcaa2bbff6"));
        M_account.push_back(HexTobit_vector("0024963622f2468c1fb10fd92773614e111fc5f61a519412782949c4fd9641e9"));
        M_account.push_back(HexTobit_vector("e8f17cf9a3150874472447450ec0a02863fd1603951b76578def39b83dc4d77a"));
        M_account.push_back(HexTobit_vector("e6a3aff8c79004a113b3bb63fb4f47c02f3d129822cf20eaaf58c13528ae2003"));
        M_account.push_back(HexTobit_vector("2d664a62747dbd30968e04703dd7adf13103fc977df2c991682ac3c0102191b8"));
        M_account.push_back(HexTobit_vector("ff89f22ed5843e56bd1098bca5c09853bb9b7283fdfc683c4050e512b48bc30d"));
        M_account.push_back(HexTobit_vector("229fcd927e05416e7f8a1f9e2f3e9aa0ca00f630a8288fdf10afcfe80facce70"));
        M_account.push_back(HexTobit_vector("f22af3f9c27633800f5b2f8ae005978519bf1365950dadff03f76d2ff9a39818"));
        M_account.push_back(HexTobit_vector("3af98163776a3f4887616317cc2252decfade9c1763a9c6bf9cccdd3b275d81b"));
        M_account.push_back(HexTobit_vector("cff833997017b9880a3bec85a6f743380e340c96e5f31a8170a093e5c89c81d0"));
        M_account.push_back(HexTobit_vector("649586031040160ecf51d4068f95417387c74f0448963734e2b4d874d7a00cc2"));
        M_account.push_back(HexTobit_vector("bdff83fe643715938e8b172b0e3c831d360ce801b10e098565ad1e837b0069ed"));
        M_account.push_back(HexTobit_vector("156e09d3871a6edbfae87b75757205ee8637d6956ce94452f6332637819a9272"));
        M_account.push_back(HexTobit_vector("45d73ac836bedc2c058b396337c3e7d2d77580184f93a068e3012327fbe65743"));
        M_account.push_back(HexTobit_vector("e289e896374e6f4d5765776ec20e3ab7941a8c6a0fcddb1b3d3e733b4e7d6260"));
        M_account.push_back(HexTobit_vector("000ed276b71f4dea4cd8b93eb5c65b316fc3bb955ec2097a03dda28b2babd7ae"));
        M_account.push_back(HexTobit_vector("9d9cc41255e9a14d9f359a90308b0717863bed7fe56a0dfedda008472b1f6b75"));
        M_account.push_back(HexTobit_vector("840c4d8a5f8ecd038a0f79c3dc2fd6702c337336d76bfe592daefaae0e30368e"));
        M_account.push_back(HexTobit_vector("8f07c90a8a6d93b5e378b43e89d105cccdaa954f9136418710d96565afffabfb"));
        M_account.push_back(HexTobit_vector("63b12d1ff4aa419c98ce79c0c9ce5ab09aa4feb1df0b6c3444ecae58eb655411"));
        M_account.push_back(HexTobit_vector("21fbffaf2136171184f3187970cb3d0f26a67a9c8c031b44610e35d30cf5f1f2"));
        M_account.push_back(HexTobit_vector("4bf4c2ece3543ac5f07e9068fa379f265e1ee852ff80bb10e1c56456644b7ac3"));
        M_account.push_back(HexTobit_vector("c95a4d356aaf15fd48e2e138611ce27998e34cf34794b3ed3b6008c8926f1100"));
        M_account.push_back(HexTobit_vector("f018c3d5616bbd4d832ec6788447a519a3bf7eede5df5179a853cb706e11dc9f"));
        M_account.push_back(HexTobit_vector("00a906dd68bd593126c09f6f27e040fd38c7be7a03dbfd36f13262967e61f557"));
        M_account.push_back(HexTobit_vector("3e62c6e6d8dde8fd94fd93b864b58f1270a562492e58562b501fbb3b0ee4c276"));
        M_account.push_back(HexTobit_vector("8350314b6ef70401e83a51c151cfa7de7d1310b9ee6129d434d34e97acd1d656"));
        M_account.push_back(HexTobit_vector("a344756c3a58e1e0a327af9f447105389afe9dd59f35020a91c4311f5dc983d2"));
        M_account.push_back(HexTobit_vector("7a83639023e6242eef193316afa48264c080d3ec4f2655db10aded10beb542b3"));
        M_account.push_back(HexTobit_vector("eb5d52ef107815c658ada7e3a778234e8cab30a23972146c2a578904f0de93a7"));
        M_account.push_back(HexTobit_vector("dc131ef91cbce46d8dee2186f0dfd16bbfdd2b1067f296fd39b72d5a42436136"));
        M_account.push_back(HexTobit_vector("6e157dde5deb9aa33974a14e92937fd5342c30c40d1ed41eb4416514f97b2ad9"));
        M_account.push_back(HexTobit_vector("bbe200ac481710840cf63813c0670a0f08fc8702afe3d3685c56759b86c28375"));
        M_account.push_back(HexTobit_vector("dd4791579f4e3dcd7f10a4312014279682c91e6bef8f7cdf2a682ebfe96bf963"));
        M_account.push_back(HexTobit_vector("04c49bf56597acfe26d71592b84e64401bb2af8a7e5b84cfb40e7bf114af8731"));
        M_account.push_back(HexTobit_vector("b78ef94dbf2e7960aec5fcbba3bfb9e2335064bd2b5ec8f5a4a0e263e51fff11"));
        M_account.push_back(HexTobit_vector("87fe9ab31fb222e1e6c9df5a4893b4ff0142e13a60e79532f5dd5810be2f184c"));
        M_account.push_back(HexTobit_vector("d2cda69b164329d552a39b65c38a728b9f96d3f1efa148f93314fe6106a7e9dc"));
        M_account.push_back(HexTobit_vector("3c62a0e3bb5bf7d53b1e3ae2670c48e46e530cffb169bc85445b42f110d2362e"));
        M_account.push_back(HexTobit_vector("891370df4fadf33f50e41f7c8a791e680c0655695ea3404385a909c8f5e13fb4"));
        M_account.push_back(HexTobit_vector("b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"));

        uint256 W;
        {
            libff::bit_vector W_lsb;

            GuneroMembershipCircuit<FieldType, BaseType, sha256_ethereum<FieldType>, MERKLE_TREE_DEPTH>::calculateMerkleRoot(
                A_account,
                leaf,
                M_account,
                W_lsb
                );

            W = bool_vector_to_uint256(W_lsb);
        }

        std::cout << "A_account: " << bit_vectorToHex(A_account) << "\n";
        std::cout << "W: " << W.GetHex() << "\n";
    }

    {//7e5f4552091a69125d5dfcb7b8c2659029395bdf
        libff::bit_vector A_account = HexTobit_vector("7e5f4552091a69125d5dfcb7b8c2659029395bdf");

        libff::bit_vector leaf = HexTobit_vector("eaee3b22f11239998357d2c23a7048d6749c2bfd0f17ecc14b7d54a685ab19fe");

        std::vector<gunero_merkle_authentication_node> M_account;
        M_account.push_back(HexTobit_vector("584bff5266d092086ea27252b241f3bbedef9d640914cb1c45e538aff3529892"));
        M_account.push_back(HexTobit_vector("22bdffddf9462e898308d94071691a9a74b8743ee1c0316cb484f3eb25f72065"));
        M_account.push_back(HexTobit_vector("2da052c569b14de3b8ad7c769a3d5b63833fd13663a22cc20d0fc8890bbde4bd"));
        M_account.push_back(HexTobit_vector("990b1a5576506a33285ba7ba8c11f4198c037f0b1fcfc8e21b85fbc485034271"));
        M_account.push_back(HexTobit_vector("8c681dacadf29399f0a28cf9a68d4bd8539e131bdaef94b4312d93ed2d8c1e95"));
        M_account.push_back(HexTobit_vector("6b18e3ca3b6ee326e571b26f1fbec13a48e956541172243d60e26d7cb2cfd765"));
        M_account.push_back(HexTobit_vector("72d68119677f498664cbf86c3a9640a7fdd9b202f9c3d1a6bf26a0aea4f5b692"));
        M_account.push_back(HexTobit_vector("b497de410fbafd39f173a341df71023119d045e5cb3b6ff418288d8c4f6c58fb"));
        M_account.push_back(HexTobit_vector("ff7c5879f52df70e826049c96cdf5ddae246949d049e0e2ad5a5a916bae3bb5c"));
        M_account.push_back(HexTobit_vector("3dccf4fd787511a08d315ee23153fdda20f151545169af177bcfa9c466bdd2ae"));
        M_account.push_back(HexTobit_vector("19b1d8d37f647b2933a39aa142cbf1658ad67d504f4d6a19884b4ea12f956579"));
        M_account.push_back(HexTobit_vector("b5c777b3dae225b6df429830e6e4bcbf2863a76312fa05f1c7345d4903ba1acc"));
        M_account.push_back(HexTobit_vector("a0355a11eca9f7a0365d8e3b5e091a2ac14f44a492f60cc919cea9b7ba3d12a5"));
        M_account.push_back(HexTobit_vector("4d4ad21d02d57ebc5bc35ad425f357b2c6c6e6ae9b2e71978566ee42afa5278d"));
        M_account.push_back(HexTobit_vector("4a13d66540628b9eb384ebc03b5eb3bc12673c5e44d845b1f748ebd05d881d8f"));
        M_account.push_back(HexTobit_vector("d1bed2956378f3444387e50579fbf12b77940cdabed9d265e6e0cd69c0961599"));
        M_account.push_back(HexTobit_vector("d9bf3081afb4aac6098ae22139fe0203576d09c3fcbae52d3eb7844bc6b33415"));
        M_account.push_back(HexTobit_vector("f5e50eb98fcd1e43af3ea04def835e4aa38263572e7c6aedb3bbb82b42ef6402"));
        M_account.push_back(HexTobit_vector("b70a3a0259fba957b60a980e83460597dbbeead54dc83da2772099751024e344"));
        M_account.push_back(HexTobit_vector("b5853049a8634dab4fe10439d0cce53317853169c7bc44293e247a65f9a874ba"));
        M_account.push_back(HexTobit_vector("86d336d14ab4589e8a3bd8fe97c6858bd604407fe5d863459e7d4728739a8d94"));
        M_account.push_back(HexTobit_vector("406ad2ce12e492f4556cae3d62d6d7adb4eca4f6918ff11f016e6cce81166527"));
        M_account.push_back(HexTobit_vector("5397258f94ec3e1ab4af7c26eb486e865a1fe32ed12253ede00a5f412bfece2b"));
        M_account.push_back(HexTobit_vector("66bb9c2d5ce0445abeb1447effe03bf0838f9f6fdce53dac049386182af3dcab"));
        M_account.push_back(HexTobit_vector("55bb3c4174b3c4ac2c52827668b78385b0e8376b4ce3ddc1a9be1ca4e5c34fb1"));
        M_account.push_back(HexTobit_vector("1493b1726e33ffe4fd7e042d76ff0aa101e270114d425c109e980969662d2f87"));
        M_account.push_back(HexTobit_vector("4b8fbe6e364f561f18baefe9f654747b7e333c02a1238ba6073fcb1d55c3be52"));
        M_account.push_back(HexTobit_vector("4078d5e0b4481e2e844d25b33936debf339cb79564096914055c49f65eb9939b"));
        M_account.push_back(HexTobit_vector("e6419f9489088dcc60d0093d3f201abfe5e1cff72f6431dac39d650de21c4710"));
        M_account.push_back(HexTobit_vector("1cadf8e2c745c063231dd78eb3b2ac1ba8bd7ec34a619c96a45de0c35d462a09"));
        M_account.push_back(HexTobit_vector("663e5b3818cd690e4c8070ead2ef2b7d223f78c93607cdb47efce85c02b761bd"));
        M_account.push_back(HexTobit_vector("d59658f55dc55828ee182a0223ed019b10d122085cc3a271f11a85026279bf86"));
        M_account.push_back(HexTobit_vector("0267d0fc34af8446c4cd7acad1f0666335807cc5ce3bf78019392ceae34ebfd5"));
        M_account.push_back(HexTobit_vector("00b95112786de8fc229014413f15eb9b0bfc8df851fc22a5bef4eb028e6332fc"));
        M_account.push_back(HexTobit_vector("d9646424f1a90e8a76bce094e9f5fcc3ad92b5ea3df2ff1af3ffb11b4ec2d9dd"));
        M_account.push_back(HexTobit_vector("287a1099377b17d259ec684c236b779891d3b79a21f69aa30b18a631ac80c9c9"));
        M_account.push_back(HexTobit_vector("8adf131d03c8fc82742e33005eed3ca86b0400358a094b755a2b5123664aa4e9"));
        M_account.push_back(HexTobit_vector("580a0374633a189e672246e78bf29f87413e737179e10001f999b1c79cfed984"));
        M_account.push_back(HexTobit_vector("c8a320567afc5b56622279d5bab9d79e7ad67cc5d52754ad00d80f93cea1b8f2"));
        M_account.push_back(HexTobit_vector("a38cd99682c2fc6ea53eea3e8c5ac651f4ab02300879450c9f70127c1dbd2b52"));
        M_account.push_back(HexTobit_vector("a160fe571346d27cf5abf9c085bbd3e7cbd29bdaed7d0ee47dd64f2f84c4ca9f"));
        M_account.push_back(HexTobit_vector("a3723164321170d1d455b4572ac36c486a843c1b969c70a0f79b4817fa584a5d"));
        M_account.push_back(HexTobit_vector("7f7974866c0060bedc8cfd2326d5124f52b92995cd4ee232385bf91a636ca2da"));
        M_account.push_back(HexTobit_vector("f833fec5fc1e1619097f5f9b51675587d896b891436bd24fd3299a034da2f6cb"));
        M_account.push_back(HexTobit_vector("82d3bdfa774c00b6c23aa5f3abe748570c96a0165d67d739ea01566b1d436511"));
        M_account.push_back(HexTobit_vector("36cfcaad64527f762d28c2360309a8114a3a5f8d062512a157dab8c01ee4b16a"));
        M_account.push_back(HexTobit_vector("9b16d5a31983c7dd5c94c9fa45997a46573160ffe39cf938e8f26e6afd7de2bc"));
        M_account.push_back(HexTobit_vector("607854a2940242006f969c3e065174e38dd02f6110f29db94363956df1e2e454"));
        M_account.push_back(HexTobit_vector("1eb734a54f142a463ae37111130a47e1c089df65987eaa806624d0d363488e03"));
        M_account.push_back(HexTobit_vector("f74a3ced550a4b9beb754703becb91be252c4c955ccebb3394174f8b97b9ba0c"));
        M_account.push_back(HexTobit_vector("1bbb393944638771c6c2d786a86d03f95c889c54b4e6c507f92937c6ecfa4b1c"));
        M_account.push_back(HexTobit_vector("63eeb111d0d4b7bdac0dc536ab6a604b02874c1311d7f41a98519e1ccf7f9d8c"));
        M_account.push_back(HexTobit_vector("6448f3cf212a96b3b04d3728cd10487ad1163ccac3820a8c1d035a7c7de6adaf"));
        M_account.push_back(HexTobit_vector("53ea29823fd826fb3d8b59ea30a3bee136c1cdd9fd032501bf2e6255520db578"));
        M_account.push_back(HexTobit_vector("268013c49e325926d86fcff4740f864f9ebbe8ad7de00f5a713d7b8581e2cb04"));
        M_account.push_back(HexTobit_vector("9d511935877d1ca28d5710fb81d352d4a13439ae245b76e5be1cc9a6ea3be393"));
        M_account.push_back(HexTobit_vector("a0d29d3eafe018b14985201733bdfecda9ee5eccfc66fd2378fce14a770cfd9d"));
        M_account.push_back(HexTobit_vector("191f33f064534fe0fc91b87e53504ce68cc9e9b2060c6f78e6c6e22c63654956"));
        M_account.push_back(HexTobit_vector("062bc6650ef871cb7bc39d7ec4d47e9a6d4dda34a22268e4bb08e36788c334e6"));
        M_account.push_back(HexTobit_vector("076f251ec50e5639989c6f81cd575947d0f057d160af73068f043706d1a3e6b3"));
        M_account.push_back(HexTobit_vector("c9b292033a2aa06844a999411d8597ec44ec961457c4e410e5909c7cce19e1ae"));
        M_account.push_back(HexTobit_vector("ed827344abd4edc45f14132d8b882ac4049dfdfffce67fc2f6f1cd2e8875a9b6"));
        M_account.push_back(HexTobit_vector("acf0e514dea85cdc150ceca6d7596abb3ea5aa743315230800f009e1227f31a2"));
        M_account.push_back(HexTobit_vector("8de89bec954ce404cf931a184be179cf1b85cedb1882397f07e5d6a0a1fedff0"));
        M_account.push_back(HexTobit_vector("9c47fc06f3b4056e7d06c0c7e3c034af9c49829ff2f9d520841f9830dca6aa91"));
        M_account.push_back(HexTobit_vector("22198aef468b4f1e88ed3d88c0bd9adb64a93a445378718d1cee368132f28838"));
        M_account.push_back(HexTobit_vector("170f3343de7a9ae04aa425e3d5f458a79678d43076002d5d592915cf066702f4"));
        M_account.push_back(HexTobit_vector("2b1529befa95db379e06c67af1dca5e10f811415b6a2c2249b0e54c0dd7e099f"));
        M_account.push_back(HexTobit_vector("629929cbbb36df2b62b6071edc5381e95612d44e8099c7bdc5dcdc88b8cfb4f8"));
        M_account.push_back(HexTobit_vector("928b186b5d044d1616773ffdec27c6658f7edbee1b88a74ee5f54854f5750ea9"));
        M_account.push_back(HexTobit_vector("10befba0f00457c1abd5f82bc4812b22c7a4112bbe6e2e16b4bf3f30bc02e41c"));
        M_account.push_back(HexTobit_vector("3205dc5a4fd1103d16b9556239b2b885d369110b43bd6f03c8864737f648c4b8"));
        M_account.push_back(HexTobit_vector("839e056ed17d562c57d19bdd9d19713672fcafb13dd3b3a6ce43c59a06873f7b"));
        M_account.push_back(HexTobit_vector("641e6a988409f28ca93afad3f989c609688adbbe367f00db8a3ac6f4fbe10bf9"));
        M_account.push_back(HexTobit_vector("bfd67b22b9881ec4b0d77e49fcaed3210ad9d8d5876d65c5b2ed04f955a23bc3"));
        M_account.push_back(HexTobit_vector("ee7e0974734a4b994cbeb07f057ab4ad6da53dc78a8c059d2a6f8893c46c19e8"));
        M_account.push_back(HexTobit_vector("e7f96d89dac578b4da01a3af6f0f5b5574724bca1bfb7fb85250620e7b92be82"));
        M_account.push_back(HexTobit_vector("441bf64d96135809a56899e0ded9dcfe4f6b7a227cd5946c7ea4dcca17df58be"));
        M_account.push_back(HexTobit_vector("8999ef9abf6e0aa4a328d08e651468a76550aa2883a463212dea616f7c50ecd7"));
        M_account.push_back(HexTobit_vector("2e24a27f11c63a82caa4d3a00a09cc4ad9145eec06a6128bad6ccd80adf20545"));
        M_account.push_back(HexTobit_vector("1f29e4a960595e5e3534f7626410439384115f1e7c50bc9d46c803f4b0e8ca30"));
        M_account.push_back(HexTobit_vector("05401b6772c979d879ad4adc6b78dc438b61155f7e246d70e115cbd265e48f3c"));
        M_account.push_back(HexTobit_vector("7b79ac149ae99c07a7625a75a23e478347bf4acbacce48fd903aadfd2195b8d6"));
        M_account.push_back(HexTobit_vector("6cf808209c45026d94763ca60dbbd92658c0e601f387f14014e44357a64fc8c5"));
        M_account.push_back(HexTobit_vector("4c021063d1dfcbecbc528df40c9315298b0227af7cea4649db7cd7fff2559265"));
        M_account.push_back(HexTobit_vector("d31b3352f4b261428e419c8c583036129921a71ff78d339eae37261426f8d535"));
        M_account.push_back(HexTobit_vector("48d739e03589b1cca91836b6ed7879d210610065026f8814948d68b24e370f87"));
        M_account.push_back(HexTobit_vector("d4830ccdeab13c6bd9457b473d32be807e5dbe3cc5ad9cd788d5d595b4dca904"));
        M_account.push_back(HexTobit_vector("ec9370f4185e050ddb2f728aca9311ab6b896ddbf95a1ca9df6f7a361f32ecb8"));
        M_account.push_back(HexTobit_vector("474cd85866f4812e99ca8208db921d5e84178fa992e79ce01471bcf6c91b88ba"));
        M_account.push_back(HexTobit_vector("44d5f5b6177f913eff27025538ba0cf46b76d8f0b7dbf7e57c812665c9a10f64"));
        M_account.push_back(HexTobit_vector("38f89ef0069099d1f919de5103160e1ddc5e48f926c498fe66d24abce988cc64"));
        M_account.push_back(HexTobit_vector("4cb5ffc03a81e92c9a9e3b1a23957bdf2c65c1be7ea133af64e514e5f6f1d067"));
        M_account.push_back(HexTobit_vector("5f9aa8c25bd3341266564300bd081cc176463052a0463978a0fd24f83324b7d1"));
        M_account.push_back(HexTobit_vector("0ceeae8fe3072848a212e245e3105b11da4925a1e434109c6c1f94cf18fe76e6"));
        M_account.push_back(HexTobit_vector("a91d1683984bd9a5d1476cff61a5dca7244d0f2d15880d25bbad555e780230df"));
        M_account.push_back(HexTobit_vector("eb3fc06b599da19f054009860455342c9a0afa9876616630bd70524867831540"));
        M_account.push_back(HexTobit_vector("bdfcca89e52363878cefc87040538db6abd3502f273b02881423508da93ac85a"));
        M_account.push_back(HexTobit_vector("665b8fe0a11f48e248e9adea03e0727473a56b7ae2020cecb95c7ae6e8ed3954"));
        M_account.push_back(HexTobit_vector("ae5ce9bcc6376b87e942861aaa528af62f007c26a4f98dc83e8af98eb4039011"));
        M_account.push_back(HexTobit_vector("9f9758b43330bf3791306d82e83e01c66d5b10d9020fa9e7f066abfb179dd029"));
        M_account.push_back(HexTobit_vector("dc6a82c8008ece74dc23c9c9d5df957610999e5c2859ef0fcbe7d9cb131650aa"));
        M_account.push_back(HexTobit_vector("1a44df549b5d2d7dc472b8403a13408176eedaedba27f4920e7d839ccd0dae40"));
        M_account.push_back(HexTobit_vector("c4765f3f0d10be1750d30354f4dfdd84973e16ccf256086a989c79a81ea3c882"));
        M_account.push_back(HexTobit_vector("d7a048233f10067c7239d268ddf68fb3f2474d340c59712e58392e1a7d3757d1"));
        M_account.push_back(HexTobit_vector("d055859e54e87e5741ad28bb90df4952a9c65ee67869c12b1dcb30aa19da3b8e"));
        M_account.push_back(HexTobit_vector("820ae006a6854c2ad27588fd5510ce5e5ef731ccc6d98b8853d7302f17440b86"));
        M_account.push_back(HexTobit_vector("e3936141d302ef36b833b634f26ff4f38c923b0cddc94919150217e76890b979"));
        M_account.push_back(HexTobit_vector("723c0c7ca706becd0c7050208b696c2ccc1c7311bbaa50f1faabcfe652f9d206"));
        M_account.push_back(HexTobit_vector("d6ccf4c3c22e250fd3704a95d2f82484603d368d5c0f60a2dc3ae11448678808"));
        M_account.push_back(HexTobit_vector("8678aad94d5944bc74bde8c72018be49fafa741cf080fb5ba151d1996629068a"));
        M_account.push_back(HexTobit_vector("9e20ffd7d2bb6333116b9c5f42deffabea99b379b27f5d55962fd34f9a24a6b6"));
        M_account.push_back(HexTobit_vector("b053362798b1d4e4548924b8a7fd2883b5782c5c94a37a0ceeeda7b32202e32c"));
        M_account.push_back(HexTobit_vector("d212f315426e25b76ffcc593546bd86153de7c33acb56cb5d1b50f062396af90"));
        M_account.push_back(HexTobit_vector("4b962973572271f5711f65507a157c013b86f87c5fb2338dc59ba6cd1038e00d"));
        M_account.push_back(HexTobit_vector("87a25e2bf09a4f90db2fde49b800f30e52d148160be64f57b06b683c9e23da95"));
        M_account.push_back(HexTobit_vector("868bb16052aa6f98430ca492dc776ac5d722d1cd8c20c902e7b6424698a650c0"));
        M_account.push_back(HexTobit_vector("4ebed1c6a618b1161998a973c66f468d6747c53ebe8b0443e4812b5790d993ed"));
        M_account.push_back(HexTobit_vector("0c9f38af509c44867c22bcaeefecae75b4b13c81c2636ee2efba08246c22ddca"));
        M_account.push_back(HexTobit_vector("724d76087d5fed945c6fa8f2fe6238201ff07dcdefaa0d7c21b5b77eb6f07a5f"));
        M_account.push_back(HexTobit_vector("a6e8bf1f86537e2df24e094d8fb16c9b345a4f6b21e8f9707cfd71d825a545bd"));
        M_account.push_back(HexTobit_vector("c23975328996a6574f8d32500fb54539d988d7b314fc5e7d4c451e7babac71ec"));
        M_account.push_back(HexTobit_vector("ab767e01036483069df3a647d7fa4beaf1223c074691a79e558e4e1f43bc2598"));
        M_account.push_back(HexTobit_vector("35b3fb61ffbfb16d3b5df462062d751c65039f8f9f2a376a7d8e677b9bb307b5"));
        M_account.push_back(HexTobit_vector("e98d47ce7f67a95455a03d9ed5d15a0fda5c844b5bfb6eae32bbd5c0ed118e5a"));
        M_account.push_back(HexTobit_vector("7e01ee800cbb286e5c107ae3ac29995d3f75d8a750a0d7cbfda33e6970a9ae65"));
        M_account.push_back(HexTobit_vector("b0de79e9dc3988c6770806ad65240db37411fa67787fa702941fb30981cc717c"));
        M_account.push_back(HexTobit_vector("db017705c66188ba725360eddbd22b51e791031e5ce4fd09cfdcb7b698f178f0"));
        M_account.push_back(HexTobit_vector("1d54a484be53dbf0b078f7991ccc7f86f71f4151df821de6bceeb2d5f05c626d"));
        M_account.push_back(HexTobit_vector("20591d9c3ffe53e45e2655eebe9731fa9848caec811a7a1a492e70191f0e2457"));
        M_account.push_back(HexTobit_vector("a28242697578e1ce902b6298308a5819acc98d9e47532b7f206619a88723bf65"));
        M_account.push_back(HexTobit_vector("74ad770e8cc1ad718df76e532b1b160e9bdba1a7bb5cc3c49e634def8f7b9fd5"));
        M_account.push_back(HexTobit_vector("351972eda2330606e75c41b9eea623ca4ef5634ed783f0a4935cac72cdb8843f"));
        M_account.push_back(HexTobit_vector("5c138d276c3aac96dc285772e67d7e360904e73b5d704386a8189a3dfa326820"));
        M_account.push_back(HexTobit_vector("0d99d41f38b7b848f3b726441f9a0b0e3ae942cf330302dce61502f2102af09c"));
        M_account.push_back(HexTobit_vector("47eca1e640d5799bfc5a56dbbd4727da217bc17e3d541e132c33e8da418e6095"));
        M_account.push_back(HexTobit_vector("eff623255dcde86e33ea85f130fee4eaf3e36b36cc4efc421247eb148b063735"));
        M_account.push_back(HexTobit_vector("b430ba70e706a07aacb648db5112446df7759378b3001f2b47989fc6b266e9a8"));
        M_account.push_back(HexTobit_vector("34880af3147124fea6aad5c3fbfc4c140c0b897948c8f897ec9af2a841fa3a0c"));
        M_account.push_back(HexTobit_vector("2002b8d52f0a06ef5b87d8a41bedb7fd26bedc3e57037ce48c33c7b3f532afae"));
        M_account.push_back(HexTobit_vector("6016894efe230b891cb8cbb0ae2dbac67028d3b17bc1f47e752bfd87bf6d0d4b"));
        M_account.push_back(HexTobit_vector("67f5d4a10a1d84d4b8c51f99894e6ac00da75172a2e25ba11c4bdc946a401602"));
        M_account.push_back(HexTobit_vector("dc572b3201b87abcc940e61b63319a20cc99ba3b826b6cac667e2463c5d3ff73"));
        M_account.push_back(HexTobit_vector("0d86c6a28b0719173b2ef84bd92553628dd31aff3ba054c3f171fcc6c105532a"));
        M_account.push_back(HexTobit_vector("7b0ecbf243872ac77a3adb6af6c38b3ff14c66fcc965d78ae07ee12c1fb987fe"));
        M_account.push_back(HexTobit_vector("926a6d5b794460c669ea218b1afa19e3a524bb2a565584ced44474767c5aa564"));
        M_account.push_back(HexTobit_vector("bf559a70fc3090359d0064a1648e6398d11a4b9171d06823a492c5b9fb713060"));
        M_account.push_back(HexTobit_vector("62f1b7cba71b0b605979c9393575abedff11ce5e7bf44d2fece016a0728cf8a6"));
        M_account.push_back(HexTobit_vector("236fa1612b0342f67f1824261882cd5dfd613e2e471481b410aa074b2f78aa4f"));
        M_account.push_back(HexTobit_vector("dfc376133dd665d071e5627c6f85f4ecd2fcbb1fe7162d7a457ba4a8e7a3966c"));
        M_account.push_back(HexTobit_vector("87574a76b3556dd79bacf5c2f02bc92c4770a18f3f47827bda9c902ab6a14bda"));
        M_account.push_back(HexTobit_vector("b41bf61428a68b2d6dc74e05a4f4149e4a294d934b6f4917831e94366713a6b3"));
        M_account.push_back(HexTobit_vector("ded7eec1ba56175e99c4ac13e9b8acb309004bc558183ae22a6a631ae58e3e19"));
        M_account.push_back(HexTobit_vector("3c9984907159d6ba3cf7715a82e6463dd857c7e85b947509defba9a94da35629"));
        M_account.push_back(HexTobit_vector("2768e5ef7fa5542ea89593e51daa349c3634645c39fa43fb5a1fc3cc496bd32a"));
        M_account.push_back(HexTobit_vector("87fe9ab31fb222e1e6c9df5a4893b4ff0142e13a60e79532f5dd5810be2f184c"));
        M_account.push_back(HexTobit_vector("d2cda69b164329d552a39b65c38a728b9f96d3f1efa148f93314fe6106a7e9dc"));
        M_account.push_back(HexTobit_vector("3c62a0e3bb5bf7d53b1e3ae2670c48e46e530cffb169bc85445b42f110d2362e"));
        M_account.push_back(HexTobit_vector("891370df4fadf33f50e41f7c8a791e680c0655695ea3404385a909c8f5e13fb4"));
        M_account.push_back(HexTobit_vector("b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"));

        uint256 W;
        {
            libff::bit_vector W_lsb;

            GuneroMembershipCircuit<FieldType, BaseType, sha256_ethereum<FieldType>, MERKLE_TREE_DEPTH>::calculateMerkleRoot(
                A_account,
                leaf,
                M_account,
                W_lsb
                );

            W = bool_vector_to_uint256(W_lsb);
        }

        std::cout << "A_account: " << bit_vectorToHex(A_account) << "\n";
        std::cout << "W: " << W.GetHex() << "\n";
    }
}

extern "C" int full_test(const char* path)
{
    const size_t MERKLE_TREE_DEPTH  = 160UL;
    const bool EXECUTE_MEMBERSHIP = true;
    const bool EXECUTE_TRANSACTION_SEND = true;
    const bool EXECUTE_TRANSACTION_RECEIVE = true;

    std::srand(std::time(NULL));

    libff::start_profiling();

    //alt_bn128_pp
    libff::init_alt_bn128_params();

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
#ifdef DEBUG
        std::cout << "GuneroMembershipCircuit:\n";
        std::cout << "W: " << W.GetHex() << "\n";
        std::cout << "N_account: " << (int)N_account << "\n";
        std::cout << "V_account: " << V_account.GetHex() << "\n";
        std::cout << "s_account: " << s_account.inner().GetHex() << "\n";
        std::cout << "A_account: " << A_account.GetHex() << "\n";
        std::cout << "r_account: " << r_account.GetHex() << "\n";
        for (int loop_M_account = 0; loop_M_account < M_account.size(); loop_M_account++)
        {
            std::cout << "M_account[" << loop_M_account << "]: " << bit_vectorToHex(M_account[loop_M_account]) << "\n";
        }
#endif

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
#ifdef DEBUG
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
#endif

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

        //Generate Transaction Send
        {
            /* generate circuit */
#ifdef DEBUG
            libff::print_header("Gunero Generator");
#endif

            GuneroTransactionSendCircuit<FieldType, BaseType, sha256_ethereum<FieldType>> gtsc;

            gtsc.generate(GTSr1csPath, GTSpkPath, GTSvkPath);
        }

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

void array_to_hex(const uint8_t* input, const unsigned int inputLengthBytes, char* output, const unsigned int outputLengthBytes)
{
    assert(outputLengthBytes >= ((2 * inputLengthBytes) + 1));
    for (unsigned int i = 0; i < inputLengthBytes; i++)
    {
        sprintf(output + (i * 2), "%02x", input[i]);
    }
}

extern "C" int test_sha3_256(
    const char* LeftHex,
    const char* RightHex,
    char* HashHex,
    const unsigned int HashHexSize
    )
{
    assert(HashHexSize >= ((256/4) + 1));//256 bits in nibbles plus NULL

    uint256 left;
    left.SetHex(LeftHex);

    uint256 right;
    right.SetHex(RightHex);

    uint8_t input[512/8];//512 bits
    memcpy(input, left.begin(), 256/8);
    memcpy((&input[0]) + (256/8), right.begin(), 256/8);

    uint8_t output[256/8];//256 bits

    int ret = sha3_256(output, 256/8, input, 512/8);

    //char* hashHex = new char[(256/4) + 1];//256 bits in nibbles
    array_to_hex(output, 256/8, HashHex, (256/4) + 1);

    return ret;
}

extern "C" int test_keccak(
    const char* LeftHex,
    const char* RightHex,
    char* HashHex,
    const unsigned int HashHexSize
    )
{
    assert(HashHexSize >= ((256/4) + 1));//256 bits in nibbles plus NULL

    uint256 left;
    left.SetHex(LeftHex);

    uint256 right;
    right.SetHex(RightHex);

    uint8_t input[512/8];//512 bits
    memcpy(input, left.begin(), 256/8);
    memcpy((&input[0]) + (256/8), right.begin(), 256/8);

    uint8_t output[256/8];//256 bits

    int ret = keccak_256(output, 256/8, input, 512/8);
    if (ret)
    {
        return ret;
    }

    //char* hashHex = new char[(256/4) + 1];//256 bits in nibbles
    array_to_hex(output, 256/8, HashHex, (256/4) + 1);

    //keccak256
    libff::start_profiling();

    //alt_bn128_pp
    libff::init_alt_bn128_params();

    libff::bit_vector left_lsb = uint256_to_bool_vector(left);
    libff::bit_vector right_lsb = uint256_to_bool_vector(right);

    libff::bit_vector block;
    block.insert(block.end(), left_lsb.begin(), left_lsb.end());
    block.insert(block.end(), right_lsb.begin(), right_lsb.end());

    libff::bit_vector output_lsb = keccak256_gadget<FieldType>::get_hash(block);

    uint256 output_uint256 = bool_vector_to_uint256(output_lsb);

    std::string outputHex = output_uint256.GetHex();

    int difference = outputHex.compare(HashHex);

    return difference;
}

/*** Constants. ***/
static const uint8_t rho[24] = \
  { 1,  3,   6, 10, 15, 21,
    28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43,
    62, 18, 39, 61, 20, 44};
static const uint8_t pi[24] = \
  {10,  7, 11, 17, 18, 3,
    5, 16,  8, 21, 24, 4,
   15, 23, 19, 13, 12, 2,
   20, 14, 22,  9, 6,  1};
static const uint64_t RC[24] = \
  {1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
   0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
   0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
   0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
   0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
   0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};

/*** Helper macros to unroll the permutation. ***/
#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))
#define REPEAT6(e) e e e e e e
#define REPEAT24(e) REPEAT6(e e e e)
#define REPEAT5(e) e e e e e
#define FOR5(v, s, e) \
  v = 0;            \
REPEAT5(e; v += s;)

/*** Keccak-f[1600] ***/
static inline void keccakf(void* state) {
  uint64_t* a = (uint64_t*)state;
  uint64_t b[5] = {0};
  uint64_t t = 0;
  uint8_t x, y, i = 0;

  REPEAT24(
      // Theta
      FOR5(x, 1,
           b[x] = 0;
           FOR5(y, 5,
                b[x] ^= a[x + y]; ))
      FOR5(x, 1,
           FOR5(y, 5,
                a[y + x] ^= b[(x + 4) % 5] ^ rol(b[(x + 1) % 5], 1); ))
      // Rho and pi
      t = a[1];
      x = 0;
      REPEAT24(b[0] = a[pi[x]];
               a[pi[x]] = rol(t, rho[x]);
               t = b[0];
               x++; )
      // Chi
      FOR5(y,
         5,
         FOR5(x, 1,
              b[x] = a[y + x];)
         FOR5(x, 1,
              a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]); ))
      // Iota
      a[0] ^= RC[i];
      i++; )
}
/** The sponge-based hash construction. **/
static inline int hash(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen, size_t rate, uint8_t delim) {
    if ((out == NULL) || ((in == NULL) && inlen != 0) || (rate >= 200 /*1600 bits*/)) {
        return -1;
    }
    uint8_t a[200] = {0};

    // Absorb input.
    // N/A

    // Xor in the DS and pad frame.
    a[inlen] ^= delim;
    a[rate - 1] ^= 0x80;

    // Xor in the last block.
    memcpy(a, in, inlen);

    // Apply P
    keccakf(a);

    // Squeeze output.
    // N/A

    memcpy(out, a, outlen);

    return 0;
}
int sha3_256(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen) {
    if (outlen > (256/8)) {
        return -1;
    }
    return hash(out, outlen, in, inlen, 200 - (256 / 4), 0x06);
}
int keccak_256(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen) {
    if (outlen > (256/8)) {
        return -1;
    }
    return hash(out, outlen, in, inlen, 200 - (256 / 4), 0x01);
}

extern "C" int prove_membership_with_files(const char* path, int argc, const char* argv[])
{
    libff::start_profiling();

    //alt_bn128_pp
    libff::init_alt_bn128_params();

    //Constants
    uint8_t N_account = 1;

    uint256 r_account = uint8_to_uint256(1);
    std::string r_accountHex = r_account.GetHex();

    uint256 s_account_256 = uint8_to_uint256(1);
    std::string s_accountHex = s_account_256.GetHex();
    libff::bit_vector s_account_lsb(uint256_to_bool_vector(s_account_256));

    //Constants calculated
    libff::bit_vector N_account_lsb(uint256_to_bool_vector(uint8_to_uint256(N_account)));
    assert(N_account_lsb.size() == sha256_ethereum<FieldType>::get_digest_len());

    libff::bit_vector P_proof;
    libff::bit_vector leaf;
    {//P_proof = Hash(0000b | (s_account&252b), 0)
        libff::bit_vector block(sha256_ethereum<FieldType>::get_digest_len());
        block.insert(block.begin(), s_account_lsb.begin(), s_account_lsb.end());
        assert(block.at(0) == false);
        assert(block.at(1) == false);
        assert(block.at(2) == false);
        assert(block.at(3) == false);

        P_proof = sha256_ethereum<FieldType>::get_hash(block);

        block = P_proof;
        block.insert(block.end(), N_account_lsb.begin(), N_account_lsb.end());
        leaf = sha256_ethereum<FieldType>::get_hash(block);//hash(P_proof,N_account)
    }

    //Load from files
    std::string GTMpkPath(path);
    GTMpkPath.append("GTM.pk.bin");
    std::string GTMvkPath(path);
    GTMvkPath.append("GTM.vk.bin");
    std::string GTMproofPath(path);
    GTMproofPath.append("GTM.demo.proof.bin");

    std::string GTMaccountPath(path);
    GTMaccountPath.append("demo.acct");//argv[2]);
    std::string A_accountHex;
    loadFromFile(GTMaccountPath, A_accountHex);
    // uint160 A_account;
    // A_account.SetHex(A_accountHex);
    libff::bit_vector A_account_LSB(HexTobit_vector(A_accountHex));

    std::string GTMmerklePath(path);
    GTMmerklePath.append("demo.ls");//argv[3]);
    std::string M_accountHexArray;
    {
        std::stringstream ss;
        std::ifstream fh(GTMmerklePath);

        if(!fh.is_open()) {
            throw std::runtime_error(strprintf("could not load param file at %s", GTMmerklePath));
        }

        std::string line;
        while (std::getline(fh, line))
        {
            M_accountHexArray += line;
            M_accountHexArray += ";";
        }

        fh.close();
    }
    std::vector<gunero_merkle_authentication_node> M_account;
    {
        const int MaxPossibleSize = 67 * 160;//64 hex, plus possible "0x" start, plus possible ";" end
        int M_accountHexArray_len = strnlen(M_accountHexArray.c_str(), MaxPossibleSize + 1);
        if ((M_accountHexArray_len <= 0) || (M_accountHexArray_len > MaxPossibleSize))
        {//Malformed M_account
            return -2;
        }
        char node_buffer[67];//64 hex, plus possible "0x" start, plus null
        uint256 node_uint256;
        libff::bit_vector node;
        const char* start = M_accountHexArray.c_str();
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
                if (strlen(start) > 0)
                {
                    strcpy(node_buffer, start);
                    node_uint256.SetHex(node_buffer);
                    node = uint256_to_bool_vector(node_uint256);

                    M_account.push_back(node);
                }

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

    // std::string GTMWPath(path);
    // GTMWPath.append(argv[4]);
    // std::string WHex;
    // loadFromFile(GTMWPath, WHex);
    uint256 W;
    int ret = calculate_Merkle_root(A_account_LSB, leaf, M_account, 0, W);
    std::string WHex = W.GetHex();

    std::string V_accountHex;//V_account == keccak256(P_proof, keccak256(W,r_account)
    {
        uint256 r_account;
        r_account.SetHex(r_accountHex);

        libff::bit_vector r_account_lsb(uint256_to_bool_vector(r_account));
        assert(r_account_lsb.size() == sha256_ethereum<FieldType>::get_digest_len());

        {//view_hash_1 = hash(W, r_account_lsb)
            libff::bit_vector W(HexTobit_vector(WHex));

            libff::bit_vector block = W;
            block.insert(block.end(), r_account_lsb.begin(), r_account_lsb.end());
            libff::bit_vector view_hash_1 = sha256_ethereum<FieldType>::get_hash(block);//hash(W, r_account_lsb)

            //V_account = hash(P_proof, hash(W, r_account_lsb))
            block = P_proof;
            block.insert(block.end(), view_hash_1.begin(), view_hash_1.end());
            libff::bit_vector V_account = sha256_ethereum<FieldType>::get_hash(block);//hash(P_proof, view_hash_1)

            V_accountHex = bit_vectorToHex(V_account);
        }
    }

    ret = prove_membership(
        WHex.c_str(),
        N_account,
        V_accountHex.c_str(),
        s_accountHex.c_str(),
        M_accountHexArray.c_str(),
        A_accountHex.c_str(),
        r_accountHex.c_str(),
        GTMpkPath.c_str(),
        GTMvkPath.c_str(),
        GTMproofPath.c_str()
    );

    printf("proven: ");
    if (ret)
    {
        printf("false");
    }
    else
    {
        printf("true");
    }
    printf("\n");

    return ret;
}