#include "gunero_merkle_tree.hpp"

namespace gunero {

template<typename FieldT, typename HashT>
gunero_merkle_authentication_path gunero_merkle_authentication_path_variable<FieldT, HashT>::get_authentication_path(const libff::bit_vector address) const
{
    gunero_merkle_authentication_path result;
    for (size_t i = 0; i < tree_depth; ++i)
    {
        //if (address & (1ul << (tree_depth-1-i)))
        //if (address.at(tree_depth-1-i))
        if (address.at(i))
        {
            result.emplace_back(left_digests[i].get_digest());
        }
        else
        {
            result.emplace_back(right_digests[i].get_digest());
        }
    }

    return result;
}

template<typename FieldT, typename HashT>
size_t gunero_merkle_tree_check_read_gadget<FieldT, HashT>::root_size_in_bits()
{
    return HashT::get_digest_len();
}

template<typename FieldT, typename HashT>
size_t gunero_merkle_tree_check_read_gadget<FieldT, HashT>::expected_constraints(const size_t tree_depth)
{
    /* NB: this includes path constraints */
    const size_t hasher_constraints = tree_depth * HashT::expected_constraints(false);
    const size_t propagator_constraints = tree_depth * HashT::get_digest_len();
    const size_t authentication_path_constraints = 2 * tree_depth * HashT::get_digest_len();
    const size_t check_root_constraints = 3 * libff::div_ceil(HashT::get_digest_len(), FieldT::capacity());

    return hasher_constraints + propagator_constraints + authentication_path_constraints + check_root_constraints;
}

} // end namespace `gunero`