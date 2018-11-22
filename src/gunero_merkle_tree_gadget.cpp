#include "gunero_merkle_tree_gadget.hpp"

namespace gunero {

template<typename FieldT, typename HashT>
gunero_merkle_authentication_path_variable<FieldT, HashT>::gunero_merkle_authentication_path_variable(protoboard<FieldT> &pb,
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

template<typename FieldT, typename HashT>
void gunero_merkle_authentication_path_variable<FieldT, HashT>::generate_r1cs_constraints()
{
    for (size_t i = 0; i < tree_depth; ++i)
    {
        left_digests[i].generate_r1cs_constraints();
        right_digests[i].generate_r1cs_constraints();
    }
}

template<typename FieldT, typename HashT>
void gunero_merkle_authentication_path_variable<FieldT, HashT>::generate_r1cs_witness(const libff::bit_vector address, const gunero_merkle_authentication_path &path)
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

} // end namespace `gunero`