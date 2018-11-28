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


using namespace libsnark;

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

std::ostream& operator<<(std::ostream &out, const gunero_merkle_authentication_node& node);
std::istream& operator>>(std::istream &in, gunero_merkle_authentication_node& node);
std::ostream& operator<<(std::ostream &out, const std::vector<gunero_merkle_authentication_node>& M_account);
std::istream& operator>>(std::istream &in, std::vector<gunero_merkle_authentication_node>& M_account);

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
                                        const std::string &annotation_prefix) :
        gadget<FieldT>(pb, annotation_prefix),
        tree_depth(tree_depth)
    {
        for (size_t i = 0; i < tree_depth; ++i)
        {
            left_digests.emplace_back(digest_variable<FieldT>(pb, HashT::get_digest_len(), FMT(annotation_prefix, " left_digests_%zu", i)));
            right_digests.emplace_back(digest_variable<FieldT>(pb, HashT::get_digest_len(), FMT(annotation_prefix, " right_digests_%zu", i)));
        }
    }

    void generate_r1cs_constraints()
    {
        for (size_t i = 0; i < tree_depth; ++i)
        {
            left_digests[i].generate_r1cs_constraints();
            right_digests[i].generate_r1cs_constraints();
        }
    }

    void generate_r1cs_witness(const libff::bit_vector address, const gunero_merkle_authentication_path &path)
    {
        assert(address.size() == tree_depth);
        assert(path.size() == tree_depth);

        for (size_t i = 0; i < tree_depth; ++i)
        {
            //if (address & (1ul << (tree_depth-1-i)))
            //if (address.at(tree_depth-1-i))
            if (address.at(i))
            {
                left_digests[i].generate_r1cs_witness(path[i]);
            }
            else
            {
                right_digests[i].generate_r1cs_witness(path[i]);
            }
        }
    }
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
                                  const std::string &annotation_prefix) :
        gadget<FieldT>(pb, annotation_prefix),
        digest_size(HashT::get_digest_len()),
        tree_depth(tree_depth),
        address_bits(address_bits),
        leaf(leaf_digest),
        root(root_digest),
        path(path),
        read_successful(read_successful)
    {
        /*
        The tricky part here is ordering. For Merkle tree
        authentication paths, path[0] corresponds to one layer below
        the root (and path[tree_depth-1] corresponds to the layer
        containing the leaf), while address_bits has the reverse order:
        address_bits[0] is LSB, and corresponds to layer containing the
        leaf, and address_bits[tree_depth-1] is MSB, and corresponds to
        the subtree directly under the root.
        */
        assert(tree_depth > 0);
        assert(tree_depth == address_bits.size());

        for (size_t i = 0; i < tree_depth-1; ++i)
        {
            internal_output.emplace_back(digest_variable<FieldT>(pb, digest_size, FMT(this->annotation_prefix, " internal_output_%zu", i)));
        }

        computed_root.reset(new digest_variable<FieldT>(pb, digest_size, FMT(this->annotation_prefix, " computed_root")));

        for (size_t i = 0; i < tree_depth; ++i)
        {
            block_variable<FieldT> inp(pb, path.left_digests[i], path.right_digests[i], FMT(this->annotation_prefix, " inp_%zu", i));
            hasher_inputs.emplace_back(inp);
            hashers.emplace_back(HashT(pb, 2*digest_size, inp, (i == 0 ? *computed_root : internal_output[i-1]),
                                    FMT(this->annotation_prefix, " load_hashers_%zu", i)));
        }

        for (size_t i = 0; i < tree_depth; ++i)
        {
            /*
            The propagators take a computed hash value (or leaf in the
            base case) and propagate it one layer up, either in the left
            or the right slot of authentication_path_variable.
            */
            propagators.emplace_back(digest_selector_gadget<FieldT>(pb, digest_size, i < tree_depth - 1 ? internal_output[i] : leaf,
                                                                    address_bits[tree_depth-1-i], path.left_digests[i], path.right_digests[i],
                                                                    FMT(this->annotation_prefix, " digest_selector_%zu", i)));
        }

        check_root.reset(new bit_vector_copy_gadget<FieldT>(pb, computed_root->bits, root.bits, read_successful, FieldT::capacity(), FMT(annotation_prefix, " check_root")));
    }

    void generate_r1cs_constraints()
    {
        /* ensure correct hash computations */
        for (size_t i = 0; i < tree_depth; ++i)
        {
            // Note that we check root outside and have enforced booleanity of path.left_digests/path.right_digests outside in path.generate_r1cs_constraints
            hashers[i].generate_r1cs_constraints(false);
        }

        /* ensure consistency of path.left_digests/path.right_digests with internal_output */
        for (size_t i = 0; i < tree_depth; ++i)
        {
            propagators[i].generate_r1cs_constraints();
        }

        check_root->generate_r1cs_constraints(false, false);
    }

    void generate_r1cs_witness()
    {
        /* do the hash computations bottom-up */
        for (int i = tree_depth-1; i >= 0; --i)
        {
            /* propagate previous input */
            propagators[i].generate_r1cs_witness();

            /* compute hash */
            hashers[i].generate_r1cs_witness();
        }

        check_root->generate_r1cs_witness();
    }

    static size_t root_size_in_bits();
    /* for debugging purposes */
    static size_t expected_constraints(const size_t tree_depth);
};


} // end namespace `gunero`

#endif /* GUNEROMERKLETREE_H_ */