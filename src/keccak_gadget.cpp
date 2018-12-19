#include "keccak_gadget.hpp"

namespace gunero {

#define KECCAK256_GADGET_ROTR_1(A) A[(i+1) % 64]

template<typename FieldT>
xor10_gadget<FieldT>::xor10_gadget(protoboard<FieldT> &pb,
                                            const pb_linear_combination<FieldT> &Am0,
                                            const pb_linear_combination<FieldT> &Am1,
                                            const pb_linear_combination<FieldT> &Am2,
                                            const pb_linear_combination<FieldT> &Am3,
                                            const pb_linear_combination<FieldT> &Am4,
                                            const pb_linear_combination<FieldT> &Ap0,
                                            const pb_linear_combination<FieldT> &Ap1,
                                            const pb_linear_combination<FieldT> &Ap2,
                                            const pb_linear_combination<FieldT> &Ap3,
                                            const pb_linear_combination<FieldT> &Ap4,
                                            const pb_variable<FieldT> &result,
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
    result_bits.allocate(pb, 64, FMT(this->annotation_prefix, " result_bits"));
    tmp_vars.resize(8);
    for (size_t i = 0; i < 8; ++i)//stage
    {
        for (size_t j = 0; j < 64; ++j)
        {
            tmp_vars[(i*64) + j].allocate(pb, FMT(this->annotation_prefix, " tmp_%zu_%zu", i, j));
        }
    }
    pack_result.reset(new packing_gadget<FieldT>(pb, result_bits, result, FMT(this->annotation_prefix, " pack_result")));
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
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * Am0[j], Am1[j], Am0[j] + Am1[j] - tmp_vars[(0*64) + j]), FMT(this->annotation_prefix, " tmp_0_%zu", j));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * tmp_vars[(0*64) + j], Am2[j], tmp_vars[(0*64) + j] + Am2[j] - tmp_vars[(1*64) + j]), FMT(this->annotation_prefix, " tmp_1_%zu", j));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * tmp_vars[(1*64) + j], Am3[j], tmp_vars[(1*64) + j] + Am3[j] - tmp_vars[(2*64) + j]), FMT(this->annotation_prefix, " tmp_2_%zu", j));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * tmp_vars[(2*64) + j], Am4[j], tmp_vars[(2*64) + j] + Am4[j] - tmp_vars[(3*64) + j]), FMT(this->annotation_prefix, " tmp_3_%zu", j));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * tmp_vars[(3*64) + j], Ap0[(j+1) % 64], tmp_vars[(3*64) + j] + Ap0[(j+1) % 64] - tmp_vars[(4*64) + j]), FMT(this->annotation_prefix, " tmp_4_%zu", j));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * tmp_vars[(4*64) + j], Ap1[(j+1) % 64], tmp_vars[(4*64) + j] + Ap1[(j+1) % 64] - tmp_vars[(5*64) + j]), FMT(this->annotation_prefix, " tmp_5_%zu", j));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * tmp_vars[(5*64) + j], Ap2[(j+1) % 64], tmp_vars[(5*64) + j] + Ap2[(j+1) % 64] - tmp_vars[(6*64) + j]), FMT(this->annotation_prefix, " tmp_6_%zu", j));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * tmp_vars[(6*64) + j], Ap3[(j+1) % 64], tmp_vars[(6*64) + j] + Ap3[(j+1) % 64] - tmp_vars[(7*64) + j]), FMT(this->annotation_prefix, " tmp_7_%zu", j));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(2 * tmp_vars[(7*64) + j], Ap4[(j+1) % 64], tmp_vars[(7*64) + j] + Ap4[(j+1) % 64] - result_bits[j]), FMT(this->annotation_prefix, " result_bits_%zu", j));
    }

    pack_result->generate_r1cs_constraints(false);
}

template<typename FieldT>
void xor10_gadget<FieldT>::generate_r1cs_witness()
{
    for (size_t j = 0; j < 64; ++j)
    {
        this->pb.val(tmp_vars[(0*64) + j]) = this->pb.lc_val(Am0[j]) + this->pb.lc_val(Am1[j]) - FieldT(2) * this->pb.lc_val(Am0[j]) * this->pb.lc_val(Am1[j]);
        this->pb.val(tmp_vars[(1*64) + j]) = this->pb.lc_val(tmp_vars[(0*64) + j]) + this->pb.lc_val(Am2[j]) - FieldT(2) * this->pb.lc_val(tmp_vars[(0*64) + j]) * this->pb.lc_val(Am2[j]);
        this->pb.val(tmp_vars[(2*64) + j]) = this->pb.lc_val(tmp_vars[(1*64) + j]) + this->pb.lc_val(Am3[j]) - FieldT(2) * this->pb.lc_val(tmp_vars[(1*64) + j]) * this->pb.lc_val(Am3[j]);
        this->pb.val(tmp_vars[(3*64) + j]) = this->pb.lc_val(tmp_vars[(2*64) + j]) + this->pb.lc_val(Am4[j]) - FieldT(2) * this->pb.lc_val(tmp_vars[(2*64) + j]) * this->pb.lc_val(Am4[j]);
        this->pb.val(tmp_vars[(4*64) + j]) = this->pb.lc_val(tmp_vars[(3*64) + j]) + this->pb.lc_val(Ap0[(j+1) % 64]) - FieldT(2) * this->pb.lc_val(tmp_vars[(3*64) + j]) * this->pb.lc_val(Ap0[(j+1) % 64]);
        this->pb.val(tmp_vars[(5*64) + j]) = this->pb.lc_val(tmp_vars[(4*64) + j]) + this->pb.lc_val(Ap1[(j+1) % 64]) - FieldT(2) * this->pb.lc_val(tmp_vars[(4*64) + j]) * this->pb.lc_val(Ap1[(j+1) % 64]);
        this->pb.val(tmp_vars[(6*64) + j]) = this->pb.lc_val(tmp_vars[(5*64) + j]) + this->pb.lc_val(Ap2[(j+1) % 64]) - FieldT(2) * this->pb.lc_val(tmp_vars[(5*64) + j]) * this->pb.lc_val(Ap2[(j+1) % 64]);
        this->pb.val(tmp_vars[(7*64) + j]) = this->pb.lc_val(tmp_vars[(6*64) + j]) + this->pb.lc_val(Ap3[(j+1) % 64]) - FieldT(2) * this->pb.lc_val(tmp_vars[(6*64) + j]) * this->pb.lc_val(Ap3[(j+1) % 64]);
        this->pb.lc_val(result_bits[j]) = this->pb.val(tmp_vars[(7*64) + j]) + this->pb.lc_val(Ap4[(j+1) % 64]) - FieldT(2) * this->pb.val(tmp_vars[(7*64) + j]) * this->pb.lc_val(Ap4[(j+1) % 64]);
    }

    pack_result->generate_r1cs_witness_from_bits();
}

#define ROUND_ARRAY_INDEX(A, x, y) A[(((x%5)*5)+(y%5)) % 25]

static const uint64_t keccak_r[25] = \
  {0ULL, 36ULL, 3ULL, 41ULL, 18ULL,
   1ULL, 44ULL, 10ULL, 45ULL, 2ULL,
   62ULL, 6ULL, 43ULL, 15ULL, 61ULL,
   28ULL, 55ULL, 25ULL, 21ULL, 56ULL,
   27ULL, 20ULL, 39ULL, 8ULL, 14ULL};

template<typename FieldT>
keccakf1600_round_gadget<FieldT>::keccakf1600_round_gadget(protoboard<FieldT> &pb,
                                                            const std::vector<pb_linear_combination_array<FieldT>> &round_A,
                                                            const uint64_t &RC,
                                                            const std::vector<pb_linear_combination_array<FieldT>> &round_A_out,
                                                            const std::string &annotation_prefix) :
    gadget<FieldT>(pb, annotation_prefix),
    round_A(round_A),
    round_A_out(round_A_out),
    RC(RC)
{
    D.resize(5);
    compute_xor10.resize(5);
    for (int32_t i = 0; i < 5; ++i)
    {
        D[i].allocate(pb, FMT(this->annotation_prefix, " D_%zu", i));
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

    B.resize(25);
    compute_rot_xor2.resize(25);
    for (int32_t i = 0; i < 25; ++i)
    {
        B[i].allocate(pb, FMT(this->annotation_prefix, " B_%zu", i));
    }
    int32_t x;
    int32_t y;
    for (int32_t i = 0; i < 25; ++i)
    {
        x = i / 25;
        y = i % 25;

        compute_rot_xor2[i].reset(new rot_xor2_gadget<FieldT>(pb, ROUND_ARRAY_INDEX(round_A,x,y), D[x], keccak_r[x,y], B[y,2*x+3*y], FMT(this->annotation_prefix, " compute_rot_xor2_%zu", i)));
    }

    x = 0;
    y = 0;
    compute_xor_not_and_xor.reset(new xor_not_and_xor<FieldT>(pb, B[x,y], B[x+1,y], B[x+2,y], RC, round_A_out[0,0], FMT(this->annotation_prefix, " compute_xor_not_and_xor")));
    for (int32_t i = 1; i < 25; ++i)
    {
        x = i / 25;
        y = i % 25;

        compute_xor_not_and[i].reset(new xor_not_and<FieldT>(pb, ROUND_ARRAY_INDEX(B,x,y), ROUND_ARRAY_INDEX(B,x+1,y), ROUND_ARRAY_INDEX(B,x+2,y), ROUND_ARRAY_INDEX(round_A_out,x,y), FMT(this->annotation_prefix, " compute_xor_not_and_%zu", i - 1)));
    }
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

    //Constraints for D
    for (int32_t i = 0; i < 5; ++i)
    {
        D[i]->generate_r1cs_constraints();
    }

    //Constraints for B
    for (int32_t i = 0; i < 25; ++i)
    {
        B[i]->generate_r1cs_constraints();
    }
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

    //Witness for D
    for (int32_t i = 0; i < 5; ++i)
    {
        D[i]->generate_r1cs_witness();
    }

    //Witness for B
    for (int32_t i = 0; i < 25; ++i)
    {
        B[i]->generate_r1cs_witness();
    }
}

static const uint64_t RC[24] = \
  {1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
   0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
   0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
   0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
   0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
   0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};

const size_t inlen = 512;
const size_t rate = 1088;

template<typename FieldT>
keccakf1600_gadget<FieldT>::keccakf1600_gadget(protoboard<FieldT> &pb,
                                                const pb_linear_combination_array<FieldT> &input,
                                                const digest_variable<FieldT> &output,
                                                const std::string &annotation_prefix) :
    gadget<FieldT>(pb, annotation_prefix),
    input(input),
    output(output)
{
    // /* message schedule and inputs for it */
    // packed_A.allocate(pb, 25, FMT(this->annotation_prefix, " packed_A"));
    // message_schedule.reset(new keccakf1600_message_schedule_gadget<FieldT>(pb, new_block, packed_A, FMT(this->annotation_prefix, " message_schedule")));

    // Absorb input
    // N/A

    pb_linear_combination_array<FieldT> round_A(25);
    round_A.push_back(pb_linear_combination_array<FieldT>(input.rbegin() + 7*64, input.rbegin() + 8*64));
    round_A.push_back(pb_linear_combination_array<FieldT>(input.rbegin() + 6*64, input.rbegin() + 7*64));
    round_A.push_back(pb_linear_combination_array<FieldT>(input.rbegin() + 5*64, input.rbegin() + 6*64));
    round_A.push_back(pb_linear_combination_array<FieldT>(input.rbegin() + 4*64, input.rbegin() + 5*64));
    round_A.push_back(pb_linear_combination_array<FieldT>(input.rbegin() + 3*64, input.rbegin() + 4*64));
    round_A.push_back(pb_linear_combination_array<FieldT>(input.rbegin() + 2*64, input.rbegin() + 3*64));
    round_A.push_back(pb_linear_combination_array<FieldT>(input.rbegin() + 1*64, input.rbegin() + 2*64));
    round_A.push_back(pb_linear_combination_array<FieldT>(input.rbegin() + 0*64, input.rbegin() + 1*64));
    for (size_t i = 8; i < 25; ++i)
    {
        round_A.push_back(pb_linear_combination_array<FieldT>());
    }
    round_As.push_back(round_A);

    /* do the rounds */
    for (size_t i = 0; i < 24; ++i)
    {
        // round_As.push_back();

        throw std::runtime_error("Not yet implemented!");

        round_functions.push_back(keccakf1600_round_gadget<FieldT>(pb,
                                                                       round_As[i], RC[i], round_As[i+1],
                                                                       FMT(this->annotation_prefix, " round_functions_%zu", i)));
    }

}

template<typename FieldT>
void keccakf1600_gadget<FieldT>::generate_r1cs_constraints()
{
    throw std::runtime_error("Not yet implemented!");
}

template<typename FieldT>
void keccakf1600_gadget<FieldT>::generate_r1cs_witness()
{
    throw std::runtime_error("Not yet implemented!");
}


} // end namespace `gunero`