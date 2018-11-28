#include "gunero_merkle_tree.hpp"

namespace gunero {

std::ostream& operator<<(std::ostream &out, const gunero_merkle_authentication_node& node)
{
    out << node.size();
    for(size_t i = 0; i < node.size(); i++)
    {
        out << (uint8_t)(node[i] ? (uint8_t)1 : (uint8_t)0);
    }

    return out;
}

std::istream& operator>>(std::istream &in, gunero_merkle_authentication_node& node)
{
    node.clear();

    size_t size;
    in >> size;

    uint8_t element;
    for(size_t i = 0; i < size; i++)
    {
        in >> element;
        node.insert(node.end(), (bool)(element ? true : false));
    }

    return in;
}

std::ostream& operator<<(std::ostream &out, const std::vector<gunero_merkle_authentication_node>& M_account)
{
    out << M_account.size();
    for(size_t i = 0; i < M_account.size(); i++)
    {
        out << M_account[i];
    }

    return out;
}

std::istream& operator>>(std::istream &in, std::vector<gunero_merkle_authentication_node>& M_account)
{
    M_account.clear();

    size_t size;
    in >> size;

    gunero_merkle_authentication_node node;
    for(size_t i = 0; i < size; i++)
    {
        in >> node;
        M_account.insert(M_account.end(), node);
    }

    return in;
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