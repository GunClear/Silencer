#include "GuneroProof.hpp"

typedef libff::alt_bn128_pp BaseType;

namespace gunero {

std::once_flag init_public_params_once_flag;
void initialize_curve_params()
{
    std::call_once (init_public_params_once_flag, BaseType::init_public_params);
}

// Writes a bigint in big endian
template<mp_size_t LIMBS>
void write_bigint(base_blob<8 * LIMBS * sizeof(mp_limb_t)> &blob, const libff::bigint<LIMBS> &val)
{
    auto ptr = blob.begin();
    for (ssize_t i = LIMBS-1; i >= 0; i--, ptr += 8) {
        WriteBE64(ptr, val.data[i]);
    }
}

uint64_t static inline ReadBE64(const unsigned char* ptr)
{
    return be64toh(*((uint64_t*)ptr));
}

// Reads a bigint from big endian
template<mp_size_t LIMBS>
libff::bigint<LIMBS> read_bigint(const base_blob<8 * LIMBS * sizeof(mp_limb_t)> &blob)
{
    libff::bigint<LIMBS> ret;

    auto ptr = blob.begin();

    for (ssize_t i = LIMBS-1; i >= 0; i--, ptr += 8) {
        ret.data[i] = ReadBE64(ptr);
    }

    return ret;
}

template<typename libsnark_Fq>
Fq::Fq(libsnark_Fq element) : data()
{
    write_bigint<4>(data, element.as_bigint());
}

template<>
curve_Fq Fq::to_libsnark_fq() const
{
    libff::bigint<4> element_bigint = read_bigint<4>(data);

    // Check that the integer is smaller than the modulus
    auto modq = curve_Fq::field_char();
    element_bigint.limit(modq, "element is not in Fq");

    return curve_Fq(element_bigint);
}

template<typename libsnark_Fq2>
Fq2::Fq2(libsnark_Fq2 element) : data()
{
    write_bigint<8>(data, fq2_to_bigint(element));
}

template<>
curve_Fq2 Fq2::to_libsnark_fq2() const
{
    libff::bigint<4> modq = curve_Fq::field_char();
    libff::bigint<8> combined = read_bigint<8>(data);
    libff::bigint<5> res;
    libff::bigint<4> c0;
    libff::bigint<8>::div_qr(res, c0, combined, modq);
    libff::bigint<4> c1 = res.shorten(modq, "element is not in Fq2");

    return curve_Fq2(curve_Fq(c0), curve_Fq(c1));
}


void static inline WriteBE64(unsigned char* ptr, uint64_t x)
{
    *((uint64_t*)ptr) = htobe64(x);
}

// FE2IP as defined in the protocol spec and IEEE Std 1363a-2004.
libff::bigint<8> fq2_to_bigint(const curve_Fq2 &e)
{
    auto modq = curve_Fq::field_char();
    auto c0 = e.c0.as_bigint();
    auto c1 = e.c1.as_bigint();

    libff::bigint<8> temp = c1 * modq;
    temp += c0;
    return temp;
}

template<typename libsnark_G1>
CompressedG1::CompressedG1(libsnark_G1 point)
{
    if (point.is_zero()) {
        throw std::domain_error("curve point is zero");
    }

    point.to_affine_coordinates();

    x = Fq(point.X);
    y_lsb = point.Y.as_bigint().data[0] & 1;
}

template<>
curve_G1 CompressedG1::to_libsnark_g1() const
{
    curve_Fq x_coordinate = x.to_libsnark_fq<curve_Fq>();

    // y = +/- sqrt(x^3 + b)
    auto y_coordinate = ((x_coordinate.squared() * x_coordinate) + libff::alt_bn128_coeff_b).sqrt();

    if ((y_coordinate.as_bigint().data[0] & 1) != y_lsb) {
        y_coordinate = -y_coordinate;
    }

    curve_G1 r = curve_G1::one();
    r.X = x_coordinate;
    r.Y = y_coordinate;
    r.Z = curve_Fq::one();

    assert(r.is_well_formed());

    return r;
}

template<typename libsnark_G2>
CompressedG2::CompressedG2(libsnark_G2 point)
{
    if (point.is_zero()) {
        throw std::domain_error("curve point is zero");
    }

    point.to_affine_coordinates();

    x = Fq2(point.X);
    y_gt = fq2_to_bigint(point.Y) > fq2_to_bigint(-(point.Y));
}

template<>
curve_G2 CompressedG2::to_libsnark_g2() const
{
    auto x_coordinate = x.to_libsnark_fq2<curve_Fq2>();

    // y = +/- sqrt(x^3 + b)
    auto y_coordinate = ((x_coordinate.squared() * x_coordinate) + libff::alt_bn128_twist_coeff_b).sqrt();
    auto y_coordinate_neg = -y_coordinate;

    if ((fq2_to_bigint(y_coordinate) > fq2_to_bigint(y_coordinate_neg)) != y_gt) {
        y_coordinate = y_coordinate_neg;
    }

    curve_G2 r = curve_G2::one();
    r.X = x_coordinate;
    r.Y = y_coordinate;
    r.Z = curve_Fq2::one();

    assert(r.is_well_formed());

    if (libff::alt_bn128_modulus_r * r != curve_G2::zero()) {
        throw std::runtime_error("point is not in G2");
    }

    return r;
}

template<>
GuneroProof::GuneroProof(const r1cs_ppzksnark_proof<BaseType>& proof)
{
    g_A = CompressedG1(proof.g_A.g);
    g_A_prime = CompressedG1(proof.g_A.h);
    g_B = CompressedG2(proof.g_B.g);
    g_B_prime = CompressedG1(proof.g_B.h);
    g_C = CompressedG1(proof.g_C.g);
    g_C_prime = CompressedG1(proof.g_C.h);
    g_K = CompressedG1(proof.g_K);
    g_H = CompressedG1(proof.g_H);
}

template<>
r1cs_ppzksnark_proof<BaseType> GuneroProof::to_libsnark_proof() const
{
    r1cs_ppzksnark_proof<BaseType> proof;

    proof.g_A.g = g_A.to_libsnark_g1<curve_G1>();
    proof.g_A.h = g_A_prime.to_libsnark_g1<curve_G1>();
    proof.g_B.g = g_B.to_libsnark_g2<curve_G2>();
    proof.g_B.h = g_B_prime.to_libsnark_g1<curve_G1>();
    proof.g_C.g = g_C.to_libsnark_g1<curve_G1>();
    proof.g_C.h = g_C_prime.to_libsnark_g1<curve_G1>();
    proof.g_K = g_K.to_libsnark_g1<curve_G1>();
    proof.g_H = g_H.to_libsnark_g1<curve_G1>();

    return proof;
}

template<>
ProofVerifier<BaseType> ProofVerifier<BaseType>::Strict() {
    initialize_curve_params();
    return ProofVerifier(true);
}

template<typename BaseT>
ProofVerifier<BaseT> ProofVerifier<BaseT>::Disabled() {
    initialize_curve_params();
    return ProofVerifier(false);
}

} // end namespace `gunero`
