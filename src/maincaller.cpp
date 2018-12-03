#include "uint256.h"
#include "uint252.h"
#include "util.h"
#include "serialize.h"
#include "keccak_gadget.hpp"
#include "GuneroProof.hpp"
#include "GuneroMembershipCircuit.hpp"
#include "GuneroTransactionSendCircuit.hpp"
#include "GuneroTransactionReceiveCircuit.hpp"

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

int get_executable_path(char* pBuf, const int len)
{
    char szTmp[32];
    sprintf(szTmp, "/proc/%d/exe", getpid());
    int bytes = readlink(szTmp, pBuf, len);
    if ((bytes >= 0) && (bytes <= (len - 1)))
    {
        pBuf[bytes] = '\0';
        return bytes;
    }
    else
    {
        return 0;
    }
}

void show_command_line()
{
    printf("\nusage: silencer [option]\n");

    const int len = 4096;
    char pBuf[len];
    if (get_executable_path(pBuf, len))
    {
        printf("%s\n", pBuf);
    }
}

int main(int argc, const char* argv[])
{
    if (argc <= 1)
    {
        // show_command_line();
        // return -1;

        // const char** argv_n = new const char*[2];
        // argv_n[0] = argv[0];
        // argv_n[1] = "9";
        // return main(2, argv_n);

        const int len = 4096;
        char pBuf[len];
        char *path = NULL;
        if (get_executable_path(pBuf, len))
        {
            path = pBuf;
            char *last_slash = strrchr(path, '/');
            if (last_slash)
            {
                *(last_slash + 1) = '\0';
            }
        }
        else
        {
            printf("\nUnable to discover root path!\n");
            return -1;
        }

        printf("\nverify_send_wit\n");

        std::string GTSvkPath(path);
        GTSvkPath.append("GTS.vk.bin");
        std::string GTSwitnessPath(path);
        GTSwitnessPath.append("GTS.witness.bin");
        std::string GTSproofPath(path);
        GTSproofPath.append("GTS.proof.bin");

        int ret = verify_send_wit(
            GTSwitnessPath.c_str(),
            GTSvkPath.c_str(),
            GTSproofPath.c_str()
        );

        printf("verified: ");
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

    const int len = 4096;
    char pBuf[len];
    char *path = NULL;
    if (get_executable_path(pBuf, len))
    {
        path = pBuf;
        char *last_slash = strrchr(path, '/');
        if (last_slash)
        {
            *(last_slash + 1) = '\0';
        }
    }
    else
    {
        printf("\nUnable to discover root path!\n");
        return -1;
    }

    libff::start_profiling();

    //alt_bn128_pp
    libff::init_alt_bn128_params();

    //full_test
    if (std::string(argv[1]) == "1")
    {
        printf("\nfull_test\n");

        return full_test(path);
    }

    //verify_membership
    if (std::string(argv[1]) == "2")
    {
        printf("\nverify_membership\n");

        std::string GTMvkPath(path);
        GTMvkPath.append("GTM.vk.bin");
        std::string GTMwitnessPath(path);
        GTMwitnessPath.append("GTM.witness.bin");
        std::string GTMproofPath(path);
        GTMproofPath.append("GTM.proof.bin");

        GuneroMembershipWitness gmw;
        loadFromFile(GTMwitnessPath, gmw);

        std::string WHex = gmw.W.GetHex();
        std::string V_accountHex = gmw.V_account.GetHex();

        int ret = verify_membership(
            WHex.c_str(),
            gmw.N_account,
            V_accountHex.c_str(),
            GTMvkPath.c_str(),
            GTMproofPath.c_str()
        );

        printf("verified: ");
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

    //verify_send
    if (std::string(argv[1]) == "3")
    {
        printf("\nverify_send\n");

        std::string GTSvkPath(path);
        GTSvkPath.append("GTS.vk.bin");
        std::string GTSwitnessPath(path);
        GTSwitnessPath.append("GTS.witness.bin");
        std::string GTSproofPath(path);
        GTSproofPath.append("GTS.proof.bin");

        GuneroTransactionSendWitness gtsw;
        loadFromFile(GTSwitnessPath, gtsw);

        std::string WHex = gtsw.W.GetHex();
        std::string THex = gtsw.T.GetHex();
        std::string V_SHex = gtsw.V_S.GetHex();
        std::string V_RHex = gtsw.V_R.GetHex();
        std::string L_PHex = gtsw.L_P.GetHex();

        int ret = verify_send(
            WHex.c_str(),
            THex.c_str(),
            V_SHex.c_str(),
            V_RHex.c_str(),
            L_PHex.c_str(),
            GTSvkPath.c_str(),
            GTSproofPath.c_str()
        );

        printf("verified: ");
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

    //verify_receive
    if (std::string(argv[1]) == "4")
    {
        printf("\nverify_receive\n");

        std::string GTRvkPath(path);
        GTRvkPath.append("GTR.vk.bin");
        std::string GTRwitnessPath(path);
        GTRwitnessPath.append("GTR.witness.bin");
        std::string GTRproofPath(path);
        GTRproofPath.append("GTR.proof.bin");

        GuneroTransactionReceiveWitness gtrw;
        loadFromFile(GTRwitnessPath, gtrw);

        std::string WHex = gtrw.W.GetHex();
        std::string THex = gtrw.T.GetHex();
        std::string V_SHex = gtrw.V_S.GetHex();
        std::string V_RHex = gtrw.V_R.GetHex();
        std::string LHex = gtrw.L.GetHex();

        int ret = verify_receive(
            WHex.c_str(),
            THex.c_str(),
            V_SHex.c_str(),
            V_RHex.c_str(),
            LHex.c_str(),
            GTRvkPath.c_str(),
            GTRproofPath.c_str()
        );

        printf("verified: ");
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

    //prove_membership
    if (std::string(argv[1]) == "5")
    {
        printf("\nprove_membership\n");

        std::string GTMpkPath(path);
        GTMpkPath.append("GTM.pk.bin");
        std::string GTMvkPath(path);
        GTMvkPath.append("GTM.vk.bin");
        std::string GTMwitnessPath(path);
        GTMwitnessPath.append("GTM.witness.bin");
        std::string GTMproofPath(path);
        GTMproofPath.append("GTM.proof.bin");

        GuneroMembershipWitness gmw;
        loadFromFile(GTMwitnessPath, gmw);

        std::string WHex = gmw.W.GetHex();
        std::string V_accountHex = gmw.V_account.GetHex();

        std::string s_accountHex;// = CARP;
        std::string M_accountHexArray;// = CARP;
        std::string A_accountHex;// = CARP;
        std::string r_accountHex;// = CARP;

        int ret = prove_membership(
            WHex.c_str(),
            gmw.N_account,
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

    //prove_send
    if (std::string(argv[1]) == "6")
    {
        printf("\nprove_send\n");

        std::string GTSpkPath(path);
        GTSpkPath.append("GTS.pk.bin");
        std::string GTSvkPath(path);
        GTSvkPath.append("GTS.vk.bin");
        std::string GTSwitnessPath(path);
        GTSwitnessPath.append("GTS.witness.bin");
        std::string GTSproofPath(path);
        GTSproofPath.append("GTS.proof.bin");

        GuneroTransactionSendWitness gtsw;
        loadFromFile(GTSwitnessPath, gtsw);

        std::string WHex = gtsw.W.GetHex();
        std::string THex = gtsw.T.GetHex();
        std::string V_SHex = gtsw.V_S.GetHex();
        std::string V_RHex = gtsw.V_R.GetHex();
        std::string L_PHex = gtsw.L_P.GetHex();

        std::string s_SHex;// = CARP;
        std::string r_SHex;// = CARP;
        std::string r_RHex;// = CARP;
        std::string A_PSHex;// = CARP;
        std::string W_PHex;// = CARP;
        std::string P_proof_RHex;// = CARP;

        int ret = prove_send(
            WHex.c_str(),
            THex.c_str(),
            V_SHex.c_str(),
            V_RHex.c_str(),
            L_PHex.c_str(),
            s_SHex.c_str(),
            r_SHex.c_str(),
            r_RHex.c_str(),
            A_PSHex.c_str(),
            W_PHex.c_str(),
            P_proof_RHex.c_str(),
            GTSpkPath.c_str(),
            GTSvkPath.c_str(),
            GTSproofPath.c_str()
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

    //prove_receive
    if (std::string(argv[1]) == "7")
    {
        printf("\nprove_receive\n");

        std::string GTRpkPath(path);
        GTRpkPath.append("GTR.pk.bin");
        std::string GTRvkPath(path);
        GTRvkPath.append("GTR.vk.bin");
        std::string GTRwitnessPath(path);
        GTRwitnessPath.append("GTR.witness.bin");
        std::string GTRproofPath(path);
        GTRproofPath.append("GTR.proof.bin");

        GuneroTransactionReceiveWitness gtrw;
        loadFromFile(GTRwitnessPath, gtrw);

        std::string WHex = gtrw.W.GetHex();
        std::string THex = gtrw.T.GetHex();
        std::string V_SHex = gtrw.V_S.GetHex();
        std::string V_RHex = gtrw.V_R.GetHex();
        std::string LHex = gtrw.L.GetHex();

        std::string s_RHex;// = CARP;
        std::string r_RHex;// = CARP;
        std::string A_SHex;// = CARP;
        std::string r_SHex;// = CARP;
        std::string FHex;// = CARP;
        std::string jHex;// = CARP;
        std::string A_RHex;// = CARP;
        std::string P_proof_SHex;// = CARP;

        int ret = prove_receive(
            WHex.c_str(),
            THex.c_str(),
            V_SHex.c_str(),
            V_RHex.c_str(),
            LHex.c_str(),
            s_RHex.c_str(),
            r_RHex.c_str(),
            A_SHex.c_str(),
            r_SHex.c_str(),
            FHex.c_str(),
            jHex.c_str(),
            A_RHex.c_str(),
            P_proof_SHex.c_str(),
            GTRpkPath.c_str(),
            GTRvkPath.c_str(),
            GTRproofPath.c_str()
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

    //verify_send_wit
    if (std::string(argv[1]) == "9")
    {
        printf("\nverify_send_wit\n");

        std::string GTSvkPath(path);
        GTSvkPath.append("GTS.vk.bin");
        std::string GTSwitnessPath(path);
        GTSwitnessPath.append("GTS.witness.bin");
        std::string GTSproofPath(path);
        GTSproofPath.append("GTS.proof.bin");

        int ret = verify_send_wit(
            GTSwitnessPath.c_str(),
            GTSvkPath.c_str(),
            GTSproofPath.c_str()
        );

        printf("verified: ");
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

    show_command_line();
    return -1;
}
