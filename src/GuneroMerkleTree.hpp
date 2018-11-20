#ifndef GUNEROMERKLETREE_H_
#define GUNEROMERKLETREE_H_

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

#include "zcash/uint256.h"
#include "serialize.h"

#include "zcash/Zcash.h"

using namespace libsnark;
// using namespace libzcash;

// std::ostream& operator<<(std::ostream &out, const libff::bit_vector &a);
// std::istream& operator>>(std::istream &in, libff::bit_vector &a);
// std::ostream& operator<<(std::ostream &out, const std::vector<libff::bit_vector> &a);
// std::istream& operator>>(std::istream &in, std::vector<libff::bit_vector> &a);

namespace gunero {

/**
 * A Merkle tree is maintained as two maps:
 * - a map from addresses to values, and
 * - a map from addresses to hashes.
 *
 * The second map maintains the intermediate hashes of a Merkle tree
 * built atop the values currently stored in the tree (the
 * implementation admits a very efficient support for sparse
 * trees). Besides offering methods to load and store values, the
 * class offers methods to retrieve the root of the Merkle tree and to
 * obtain the authentication paths for (the value at) a given address.
 */

typedef libff::bit_vector gunero_merkle_authentication_node;
typedef std::vector<gunero_merkle_authentication_node> gunero_merkle_authentication_path;

template<typename HashT>
class gunero_merkle_tree {
private:

    typedef typename HashT::hash_value_type hash_value_type;
    typedef typename HashT::merkle_authentication_path_type gunero_merkle_authentication_path_type;

public:

    std::vector<hash_value_type> hash_defaults;
    std::map<size_t, libff::bit_vector> values;
    std::map<size_t, hash_value_type> hashes;

    size_t depth;
    size_t value_size;
    size_t digest_size;

    gunero_merkle_tree(const size_t depth, const size_t value_size);
    gunero_merkle_tree(const size_t depth, const size_t value_size, const std::vector<libff::bit_vector> &contents_as_vector);
    gunero_merkle_tree(const size_t depth, const size_t value_size, const std::map<size_t, libff::bit_vector> &contents);

    libff::bit_vector get_value(const libff::bit_vector address) const;
    void set_value(const libff::bit_vector address, const libff::bit_vector &value);

    hash_value_type get_root() const;
    gunero_merkle_authentication_path_type get_path(const libff::bit_vector address) const;

    void dump() const;
};

template<typename FieldT, typename HashT>
class gunero_merkle_authentication_path_variable : public gadget<FieldT> {
public:

    const size_t tree_depth;
    std::vector<digest_variable<FieldT> > left_digests;
    std::vector<digest_variable<FieldT> > right_digests;

    gunero_merkle_authentication_path_variable(protoboard<FieldT> &pb,
                                        const size_t tree_depth,
                                        const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness(const libff::bit_vector address, const gunero_merkle_authentication_path &path);
    gunero_merkle_authentication_path get_authentication_path(const libff::bit_vector address) const;
};

template<typename FieldT, typename HashT>
class gunero_merkle_tree_check_read_gadget : public gadget<FieldT> {
private:

    std::vector<HashT> hashers;
    std::vector<block_variable<FieldT> > hasher_inputs;
    std::vector<digest_selector_gadget<FieldT> > propagators;
    std::vector<digest_variable<FieldT> > internal_output;

    std::shared_ptr<digest_variable<FieldT> > computed_root;
    std::shared_ptr<bit_vector_copy_gadget<FieldT> > check_root;

public:

    const size_t digest_size;
    const size_t tree_depth;
    pb_linear_combination_array<FieldT> address_bits;
    digest_variable<FieldT> leaf;
    digest_variable<FieldT> root;
    gunero_merkle_authentication_path_variable<FieldT, HashT> path;
    pb_linear_combination<FieldT> read_successful;

    gunero_merkle_tree_check_read_gadget(protoboard<FieldT> &pb,
                                  const size_t tree_depth,
                                  const pb_linear_combination_array<FieldT> &address_bits,
                                  const digest_variable<FieldT> &leaf_digest,
                                  const digest_variable<FieldT> &root_digest,
                                  const gunero_merkle_authentication_path_variable<FieldT, HashT> &path,
                                  const pb_linear_combination<FieldT> &read_successful,
                                  const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();

    static size_t root_size_in_bits();
    /* for debugging purposes */
    static size_t expected_constraints(const size_t tree_depth);
};


} // end namespace `gunero`

#endif /* GUNEROMERKLETREE_H_ */