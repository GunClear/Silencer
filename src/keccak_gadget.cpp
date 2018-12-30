#include "keccak_gadget.hpp"

namespace gunero {

#define KECCAK256_GADGET_ROTR_1(A) A[(i+1) % 64]

template<typename FieldT>
xor10_gadget<FieldT>::xor10_gadget(protoboard<FieldT> &pb,
                                            const std::shared_ptr<pb_linear_combination_array<FieldT>> &Am0,
                                            const std::shared_ptr<pb_linear_combination_array<FieldT>> &Am1,
                                            const std::shared_ptr<pb_linear_combination_array<FieldT>> &Am2,
                                            const std::shared_ptr<pb_linear_combination_array<FieldT>> &Am3,
                                            const std::shared_ptr<pb_linear_combination_array<FieldT>> &Am4,
                                            const std::shared_ptr<pb_linear_combination_array<FieldT>> &Ap0,
                                            const std::shared_ptr<pb_linear_combination_array<FieldT>> &Ap1,
                                            const std::shared_ptr<pb_linear_combination_array<FieldT>> &Ap2,
                                            const std::shared_ptr<pb_linear_combination_array<FieldT>> &Ap3,
                                            const std::shared_ptr<pb_linear_combination_array<FieldT>> &Ap4,
                                            const std::shared_ptr<pb_linear_combination_array<FieldT>> &result,
                                            const std::string &annotation_prefix) :
    gadget<FieldT>(pb, annotation_prefix),
    Am0(Am0),
    Am1(Am1),
    Am2(Am2),
    Am3(Am3),
    Am4(Am4),
    Ap0(Ap0),
    Ap1(Ap1),
    Ap2(Ap2),
    Ap3(Ap3),
    Ap4(Ap4),
    result(result)
{
#if DEBUG
    printf("xor10_gadget() 0\n");
#endif
    tmp_vars.resize(8*64);
    for (size_t i = 0; i < 8; ++i)//stage
    {
        for (size_t j = 0; j < 64; ++j)
        {
            tmp_vars[(i*64) + j].allocate(pb, FMT(this->annotation_prefix, " tmp_%zu_%zu", i, j));
        }
    }
#if DEBUG
    printf("xor10_gadget() 1\n");
#endif
}

template<typename FieldT>
void xor10_gadget<FieldT>::generate_r1cs_constraints()
{
    /*
      tmp = A + B - 2AB i.e. tmp = A xor B
      out = tmp + C - 2tmp C i.e. out = tmp xor C
    */
    for (size_t j = 0; j < 64; ++j)
    {
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * (*Am0)[j], (*Am1)[j], (*Am0)[j] + (*Am1)[j] - tmp_vars[(0*64) + j]), FMT(this->annotation_prefix, " tmp_0_%zu", j));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * tmp_vars[(0*64) + j], (*Am2)[j], tmp_vars[(0*64) + j] + (*Am2)[j] - tmp_vars[(1*64) + j]), FMT(this->annotation_prefix, " tmp_1_%zu", j));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * tmp_vars[(1*64) + j], (*Am3)[j], tmp_vars[(1*64) + j] + (*Am3)[j] - tmp_vars[(2*64) + j]), FMT(this->annotation_prefix, " tmp_2_%zu", j));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * tmp_vars[(2*64) + j], (*Am4)[j], tmp_vars[(2*64) + j] + (*Am4)[j] - tmp_vars[(3*64) + j]), FMT(this->annotation_prefix, " tmp_3_%zu", j));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * tmp_vars[(3*64) + j], (*Ap0)[(j+1) % 64], tmp_vars[(3*64) + j] + (*Ap0)[(j+1) % 64] - tmp_vars[(4*64) + j]), FMT(this->annotation_prefix, " tmp_4_%zu", j));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * tmp_vars[(4*64) + j], (*Ap1)[(j+1) % 64], tmp_vars[(4*64) + j] + (*Ap1)[(j+1) % 64] - tmp_vars[(5*64) + j]), FMT(this->annotation_prefix, " tmp_5_%zu", j));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * tmp_vars[(5*64) + j], (*Ap2)[(j+1) % 64], tmp_vars[(5*64) + j] + (*Ap2)[(j+1) % 64] - tmp_vars[(6*64) + j]), FMT(this->annotation_prefix, " tmp_6_%zu", j));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * tmp_vars[(6*64) + j], (*Ap3)[(j+1) % 64], tmp_vars[(6*64) + j] + (*Ap3)[(j+1) % 64] - tmp_vars[(7*64) + j]), FMT(this->annotation_prefix, " tmp_7_%zu", j));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * tmp_vars[(7*64) + j], (*Ap4)[(j+1) % 64], tmp_vars[(7*64) + j] + (*Ap4)[(j+1) % 64] - (*result)[j]), FMT(this->annotation_prefix, " result_%zu", j));
    }
}

template<typename FieldT>
void xor10_gadget<FieldT>::generate_r1cs_witness()
{
    for (size_t j = 0; j < 64; ++j)
    {
        this->pb.val(tmp_vars[(0*64) + j]) = this->pb.lc_val((*Am0)[j]) + this->pb.lc_val((*Am1)[j]) - FieldT(2) * this->pb.lc_val((*Am0)[j]) * this->pb.lc_val((*Am1)[j]);
        this->pb.val(tmp_vars[(1*64) + j]) = this->pb.lc_val(tmp_vars[(0*64) + j]) + this->pb.lc_val((*Am2)[j]) - FieldT(2) * this->pb.lc_val(tmp_vars[(0*64) + j]) * this->pb.lc_val((*Am2)[j]);
        this->pb.val(tmp_vars[(2*64) + j]) = this->pb.lc_val(tmp_vars[(1*64) + j]) + this->pb.lc_val((*Am3)[j]) - FieldT(2) * this->pb.lc_val(tmp_vars[(1*64) + j]) * this->pb.lc_val((*Am3)[j]);
        this->pb.val(tmp_vars[(3*64) + j]) = this->pb.lc_val(tmp_vars[(2*64) + j]) + this->pb.lc_val((*Am4)[j]) - FieldT(2) * this->pb.lc_val(tmp_vars[(2*64) + j]) * this->pb.lc_val((*Am4)[j]);
        this->pb.val(tmp_vars[(4*64) + j]) = this->pb.lc_val(tmp_vars[(3*64) + j]) + this->pb.lc_val((*Ap0)[(j+1) % 64]) - FieldT(2) * this->pb.lc_val(tmp_vars[(3*64) + j]) * this->pb.lc_val((*Ap0)[(j+1) % 64]);
        this->pb.val(tmp_vars[(5*64) + j]) = this->pb.lc_val(tmp_vars[(4*64) + j]) + this->pb.lc_val((*Ap1)[(j+1) % 64]) - FieldT(2) * this->pb.lc_val(tmp_vars[(4*64) + j]) * this->pb.lc_val((*Ap1)[(j+1) % 64]);
        this->pb.val(tmp_vars[(6*64) + j]) = this->pb.lc_val(tmp_vars[(5*64) + j]) + this->pb.lc_val((*Ap2)[(j+1) % 64]) - FieldT(2) * this->pb.lc_val(tmp_vars[(5*64) + j]) * this->pb.lc_val((*Ap2)[(j+1) % 64]);
        this->pb.val(tmp_vars[(7*64) + j]) = this->pb.lc_val(tmp_vars[(6*64) + j]) + this->pb.lc_val((*Ap3)[(j+1) % 64]) - FieldT(2) * this->pb.lc_val(tmp_vars[(6*64) + j]) * this->pb.lc_val((*Ap3)[(j+1) % 64]);
        this->pb.lc_val((*result)[j]) = this->pb.val(tmp_vars[(7*64) + j]) + this->pb.lc_val((*Ap4)[(j+1) % 64]) - FieldT(2) * this->pb.val(tmp_vars[(7*64) + j]) * this->pb.lc_val((*Ap4)[(j+1) % 64]);
    }
}

template<typename FieldT>
rot_xor2_gadget<FieldT>::rot_xor2_gadget(protoboard<FieldT> &pb,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &A,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &D,
                const uint64_t &r,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &B,
                const std::string &annotation_prefix) :
    gadget<FieldT>(pb, annotation_prefix),
    A(A),
    D(D),
    r(r),
    B(B)
{
}

template<typename FieldT>
void rot_xor2_gadget<FieldT>::generate_r1cs_constraints()
{
    for (size_t j = 0; j < 64; ++j)
    {
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * (*A)[(j + r) % 64], (*D)[(j + r) % 64], (*A)[(j + r) % 64] + (*D)[(j + r) % 64] - (*B)[j]), FMT(this->annotation_prefix, " xor_%zu", j));
    }
}

template<typename FieldT>
void rot_xor2_gadget<FieldT>::generate_r1cs_witness()
{
    for (size_t j = 0; j < 64; ++j)
    {
        this->pb.lc_val((*B)[j]) = this->pb.lc_val((*A)[(j + r) % 64]) + this->pb.lc_val((*D)[(j + r) % 64]) - FieldT(2) * this->pb.lc_val((*A)[(j + r) % 64]) * this->pb.lc_val((*D)[(j + r) % 64]);
    }
}

template<typename FieldT>
xor_not_and_xor<FieldT>::xor_not_and_xor(protoboard<FieldT> &pb,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &B1,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &B2,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &B3,
                const uint64_t &RC,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &A_out,
                const std::string &annotation_prefix) :
    gadget<FieldT>(pb, annotation_prefix),
    B1(B1),
    B2(B2),
    B3(B3),
    A_out(A_out)
{
    RC_bits.fill_with_bits_of_ulong(pb, RC);

    tmp_vars.resize(128);
    for (size_t j = 0; j < 128; ++j)
    {
        tmp_vars[j].allocate(pb, FMT(this->annotation_prefix, " tmp_%zu", j));
    }
}

template<typename FieldT>
void xor_not_and_xor<FieldT>::generate_r1cs_constraints()
{
    /*
        tmp = (1 - B) * C i.e. tmp = !B and C
        out = A + tmp - 2A tmp i.e. out = A xor tmp
    */
    for (size_t j = 0; j < 64; ++j)
    {
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1 - B2[j], B3[j], tmp_vars[2 * j]), FMT(this->annotation_prefix, " tmp_%zu", 2 * j));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * tmp_vars[2 * j], B1[j], tmp_vars[2 * j] + B1[j] - tmp_vars[(2 * j) + 1]), FMT(this->annotation_prefix, " tmp_%zu", (2 * j) + 1));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * tmp_vars[(2 * j) + 1], RC_bits[j], tmp_vars[(2 * j) + 1] + RC_bits[j] - A_out[j]), FMT(this->annotation_prefix, " result_%zu", j));
    }
}

template<typename FieldT>
void xor_not_and_xor<FieldT>::generate_r1cs_witness()
{
    for (size_t j = 0; j < 64; ++j)
    {
        this->pb.val(tmp_vars[2 * j]) = (FieldT(1) - this->pb.lc_val(B2[j])) * this->pb.lc_val(B3[j]);
        this->pb.val(tmp_vars[(2 * j) + 1]) = this->pb.val(tmp_vars[2 * j]) + this->pb.lc_val(B1[j]) - FieldT(2) * this->pb.val(tmp_vars[2 * j]) * this->pb.lc_val(B1[j]);
        this->pb.lc_val(A_out[j]) = this->pb.val(tmp_vars[(2 * j) + 1]) + this->pb.lc_val(RC_bits[j]) - FieldT(2) * this->pb.val(tmp_vars[(2 * j) + 1]) * this->pb.lc_val(RC_bits[j]);
    }
}

template<typename FieldT>
xor_not_and<FieldT>::xor_not_and(protoboard<FieldT> &pb,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &B1,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &B2,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &B3,
                const std::shared_ptr<pb_linear_combination_array<FieldT>> &A_out,
                const std::string &annotation_prefix) :
    gadget<FieldT>(pb, annotation_prefix),
    B1(B1),
    B2(B2),
    B3(B3),
    A_out(A_out)
{
    tmp_vars.resize(64);
    for (size_t j = 0; j < 64; ++j)
    {
        tmp_vars[j].allocate(pb, FMT(this->annotation_prefix, " tmp_%zu", j));
    }
}

template<typename FieldT>
void xor_not_and<FieldT>::generate_r1cs_constraints()
{
    /*
        tmp = (1 - B) * C i.e. tmp = !B and C
        out = A + tmp - 2A tmp i.e. out = A xor tmp
    */
    for (size_t j = 0; j < 64; ++j)
    {
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1 - B2[j], B3[j], tmp_vars[j]), FMT(this->annotation_prefix, " tmp_%zu", j));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * tmp_vars[j], B1[j], tmp_vars[j] + B1[j] - A_out[j]), FMT(this->annotation_prefix, " result_%zu", j));
    }
}

template<typename FieldT>
void xor_not_and<FieldT>::generate_r1cs_witness()
{
    for (size_t j = 0; j < 64; ++j)
    {
        this->pb.val(tmp_vars[j]) = (FieldT(1) - this->pb.lc_val(B2[j])) * this->pb.lc_val(B3[j]);
        this->pb.lc_val(A_out[j]) = this->pb.val(tmp_vars[j]) + this->pb.lc_val(B1[j]) - FieldT(2) * this->pb.val(tmp_vars[j]) * this->pb.lc_val(B1[j]);
    }
}

#define ROUND_ARRAY_INDEX(A, x, y) A[((((5+(x)%5)%5)*5)+((5+(y)%5)%5)) % 25]

static const uint64_t keccak_r[25] = \
  {0ULL, 36ULL, 3ULL, 41ULL, 18ULL,
   1ULL, 44ULL, 10ULL, 45ULL, 2ULL,
   62ULL, 6ULL, 43ULL, 15ULL, 61ULL,
   28ULL, 55ULL, 25ULL, 21ULL, 56ULL,
   27ULL, 20ULL, 39ULL, 8ULL, 14ULL};

template<typename FieldT>
keccakf1600_round_gadget<FieldT>::keccakf1600_round_gadget(protoboard<FieldT> &pb,
                                                            const std::vector<std::shared_ptr<pb_linear_combination_array<FieldT>>> &round_A,
                                                            const uint64_t &RC,
                                                            const std::vector<std::shared_ptr<pb_linear_combination_array<FieldT>>> &round_A_out,
                                                            const std::string &annotation_prefix) :
    gadget<FieldT>(pb, annotation_prefix),
    round_A(round_A),
    round_A_out(round_A_out),
    RC(RC)
{
#if DEBUG
    printf("keccakf1600_round_gadget() 0:\t%lu\t%lu\n", round_A.size(), round_A_out.size());
#endif

    D.resize(5);
#if DEBUG
    printf("keccakf1600_round_gadget() 0.1\n");
#endif
    compute_xor10.resize(5);
    for (int32_t i = 0; i < 5; ++i)
    {
#if DEBUG
    printf("keccakf1600_round_gadget() 0.2\n");
#endif
        D[i].reset(new pb_linear_combination_array<FieldT>(64));
#if DEBUG
    printf("keccakf1600_round_gadget() 0.3\n");
#endif

        compute_xor10[i].reset(new xor10_gadget<FieldT>(
            pb,
            ROUND_ARRAY_INDEX(round_A,i-1,0),
            ROUND_ARRAY_INDEX(round_A,i-1,1),
            ROUND_ARRAY_INDEX(round_A,i-1,2),
            ROUND_ARRAY_INDEX(round_A,i-1,3),
            ROUND_ARRAY_INDEX(round_A,i-1,4),
            ROUND_ARRAY_INDEX(round_A,i+1,0),
            ROUND_ARRAY_INDEX(round_A,i+1,1),
            ROUND_ARRAY_INDEX(round_A,i+1,2),
            ROUND_ARRAY_INDEX(round_A,i+1,3),
            ROUND_ARRAY_INDEX(round_A,i+1,4),
            D[i],
            FMT(this->annotation_prefix, " compute_xor10_%zu", i)));
    }

#if DEBUG
    printf("keccakf1600_round_gadget() 1\n");
#endif

    B.resize(25);
    compute_rot_xor2.resize(25);
    for (int32_t i = 0; i < 25; ++i)
    {
        B[i].reset(new pb_linear_combination_array<FieldT>(64));
    }
    int32_t x;
    int32_t y;
    for (int32_t i = 0; i < 25; ++i)
    {
        x = i / 5;
        y = i % 5;

        compute_rot_xor2[i].reset(new rot_xor2_gadget<FieldT>(pb, ROUND_ARRAY_INDEX(round_A,x,y), D[x], ROUND_ARRAY_INDEX(keccak_r,x,y), ROUND_ARRAY_INDEX(B,y,2*x+3*y), FMT(this->annotation_prefix, " compute_rot_xor2_%zu", i)));
    }

#if DEBUG
    printf("keccakf1600_round_gadget() 2\n");
#endif

    compute_xor_not_and.resize(24);
    x = 0;
    y = 0;
    compute_xor_not_and_xor.reset(new xor_not_and_xor<FieldT>(pb, ROUND_ARRAY_INDEX(B,x,y), ROUND_ARRAY_INDEX(B,x+1,y), ROUND_ARRAY_INDEX(B,x+2,y), RC, ROUND_ARRAY_INDEX(round_A_out,0,0), FMT(this->annotation_prefix, " compute_xor_not_and_xor")));
    for (int32_t i = 1; i < 25; ++i)
    {
        x = i / 5;
        y = i % 5;

#if DEBUG
    printf("keccakf1600_round_gadget() 3:\t%d\t%d\t%d\n", i, x, y);
#endif

        compute_xor_not_and[i - 1].reset(new xor_not_and<FieldT>(pb, ROUND_ARRAY_INDEX(B,x,y), ROUND_ARRAY_INDEX(B,x+1,y), ROUND_ARRAY_INDEX(B,x+2,y), ROUND_ARRAY_INDEX(round_A_out,x,y), FMT(this->annotation_prefix, " compute_xor_not_and_%zu", i - 1)));
    }

#if DEBUG
    printf("keccakf1600_round_gadget() 4\n");
#endif
}

template<typename FieldT>
void keccakf1600_round_gadget<FieldT>::generate_r1cs_constraints()
{
    for (size_t i = 0; i < 5; ++i)
    {
        compute_xor10[i]->generate_r1cs_constraints();
    }

    for (size_t i = 0; i < 25; ++i)
    {
        compute_rot_xor2[i]->generate_r1cs_constraints();
    }

    // //Constraints for D
    // for (int32_t i = 0; i < 5; ++i)
    // {
    //     D[i]->generate_r1cs_constraints();
    // }

    // //Constraints for B
    // for (int32_t i = 0; i < 25; ++i)
    // {
    //     B[i]->generate_r1cs_constraints();
    // }
}

template<typename FieldT>
void keccakf1600_round_gadget<FieldT>::generate_r1cs_witness()
{
    for (size_t i = 0; i < 5; ++i)
    {
        compute_xor10[i]->generate_r1cs_witness();
    }

    for (size_t i = 0; i < 25; ++i)
    {
        compute_rot_xor2[i]->generate_r1cs_witness();
    }

    // //Witness for D
    // for (int32_t i = 0; i < 5; ++i)
    // {
    //     D[i].generate_r1cs_witness();
    // }

    // //Witness for B
    // for (int32_t i = 0; i < 25; ++i)
    // {
    //     B[i].generate_r1cs_witness();
    // }
}

typedef libff::alt_bn128_pp BaseType;
typedef libff::Fr<BaseType> FieldType;

static const uint64_t RC[24] = \
    {1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
    0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};

const static uint32_t keccakf1600_rate = 1088;//bit 1088 of 1600

template<>
keccakf1600_gadget<FieldType>::keccakf1600_gadget(protoboard<FieldType> &pb,
                                                const uint8_t delim,
                                                const pb_variable_array<FieldType> &input,
                                                const digest_variable<FieldType> &output,
                                                const std::string &annotation_prefix) :
    gadget<FieldType>(pb, annotation_prefix),
    delim(delim),
    input(input),
    output(output)
{
#if DEBUG
    printf("keccakf1600_gadget() 0\n");
#endif

    // /* message schedule and inputs for it */
    // packed_A.allocate(pb, 25, FMT(this->annotation_prefix, " packed_A"));
    // message_schedule.reset(new keccakf1600_message_schedule_gadget<FieldType>(pb, new_block, packed_A, FMT(this->annotation_prefix, " message_schedule")));

    // Absorb input
    // N/A

    //Was: pb_linear_combination_array<FieldT> x
    //Is:  pb_variable_array<FieldT> bits -> pb_variable<FieldT>

    assert(input.size() <= keccakf1600_rate);

#if DEBUG
    printf("keccakf1600_gadget() 1\n");
#endif

    {
        std::vector<std::shared_ptr<pb_linear_combination_array<FieldType>>> round_A(25);
        for (size_t i = 0; i < 17; ++i)
        {
            round_A[i].reset(new pb_linear_combination_array<FieldType>(64));
        }

#if DEBUG
        printf("keccakf1600_gadget() 2\n");
#endif

        // a[rate - 1] ^= 0x80; = b10000000
        round_A[17].reset(new pb_linear_combination_array<FieldType>(64));

#if DEBUG
        printf("keccakf1600_gadget() 3\n");
#endif

        //Emtpy WORDs
        for (size_t i = 18; i < 25; ++i)
        {
            round_A[i].reset(new pb_linear_combination_array<FieldType>(64));
        }
        round_As.push_back(round_A);
    }

#if DEBUG
    printf("keccakf1600_gadget() 4\n");
#endif

    /* do the rounds */
    for (size_t i = 0; i < 24; ++i)
    {
        {
            std::vector<std::shared_ptr<pb_linear_combination_array<FieldType>>> round_A(25);
            for (size_t j = 0; j < 25; ++j)
            {
                round_A[j].reset(new pb_linear_combination_array<FieldType>(64));
            }
            round_As.push_back(round_A);
        }

#if DEBUG
        printf("keccakf1600_gadget() 5: %lu\n", i);
#endif

        round_functions.push_back(keccakf1600_round_gadget<FieldType>(pb,
                                                                    round_As[i],
                                                                    RC[i],
                                                                    round_As[i+1],
                                                                    FMT(this->annotation_prefix, " round_functions_%zu", i)));

#if DEBUG
        printf("keccakf1600_gadget() 6: %lu\n", i);
#endif
    }
}

template<>
void keccakf1600_gadget<FieldType>::generate_r1cs_constraints()
{
    //input.generate_r1cs_constraints();

    // for (size_t i = 0; i < 25; ++i)
    // {
    //     for (size_t j = 0; j < 25; ++j)
    //     {
    //         round_As[i][j]->generate_r1cs_constraints();
    //     }
    // }

    for (size_t i = 0; i < 24; ++i)
    {
        round_functions[i].generate_r1cs_constraints();
    }
}

template<>
void keccakf1600_gadget<FieldType>::generate_r1cs_witness()
{
    // /* message schedule and inputs for it */
    // packed_A.allocate(pb, 25, FMT(this->annotation_prefix, " packed_A"));
    // message_schedule.reset(new keccakf1600_message_schedule_gadget<FieldType>(pb, new_block, packed_A, FMT(this->annotation_prefix, " message_schedule")));

    // Absorb input
    // N/A

    //Was: pb_linear_combination_array<FieldT> x
    //Is:  pb_variable_array<FieldT> bits -> pb_variable<FieldT>

    libff::bit_vector input_bits = input.get_bits(pb);

    unsigned long input_array[17];
    for (size_t i = 0; i < 17; ++i)
    {
        input_array[i] = 0UL;
        for (size_t j = 0; j < 64; ++j)
        {
            input_array[i] |= input_bits[(i * 17) + j] ? (1UL << (63 - j)) : 0UL;
        }
    }

    // Xor in the DS and pad frame.
    // a[inlen] ^= delim;
    {
        size_t i = input_bits.size() / 64;
        size_t j = input_bits.size() % 64;
        if (j > (64 - 8))
        {//Must span multiple WORDs
			throw std::runtime_error("Odd size input not implemented!");
        }
        else
        {//Stored in single WORD
            input_array[i] ^= delim << (64 - 8 - j);
        }
    }

    for (size_t i = 0; i < 17; ++i)
    {
        pb_variable_array<FieldType> inputWORD;
        round_As[0][i]->fill_with_bits_of_ulong(pb, input_array[i]);
    }

    // a[rate - 1] ^= 0x80; = b10000000
    pb_variable_array<FieldType> rateWORD;
    round_As[0][17]->fill_with_bits_of_ulong(pb, 0x8000000000000000ULL);

    //Emtpy WORDs

    /* do the rounds */
    for (size_t i = 0; i < 24; ++i)
    {
        round_functions[i].generate_r1cs_witness();
    }
}


} // end namespace `gunero`