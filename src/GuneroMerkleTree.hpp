#ifndef GUNEROMERKLETREE_H_
#define GUNEROMERKLETREE_H_

#include <deque>
#include <boost/optional.hpp>
#include <boost/static_assert.hpp>
#include <libff/common/utils.hpp>

#include "zcash/uint256.h"
#include "serialize.h"

#include "zcash/Zcash.h"

std::ostream& operator<<(std::ostream &out, const libff::bit_vector &a);
std::istream& operator>>(std::istream &in, libff::bit_vector &a);
std::ostream& operator<<(std::ostream &out, const std::vector<libff::bit_vector> &a);
std::istream& operator>>(std::istream &in, std::vector<libff::bit_vector> &a);

namespace gunero {

class GuneroMerklePath {
public:
    std::vector<std::vector<bool>> authentication_path;
    std::vector<bool> index_account;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(authentication_path);
        READWRITE(index_account);
    }

    GuneroMerklePath() { }

    GuneroMerklePath(std::vector<std::vector<bool>> authentication_path, std::vector<bool> index_account)
    : authentication_path(authentication_path), index_account(index_account) { }

    friend std::ostream& operator<<(std::ostream &out, const GuneroMerklePath &a)
    {
        out << a.authentication_path;
        out << a.index_account;

        return out;
    }

    friend std::istream& operator>>(std::istream &in, GuneroMerklePath &a)
    {
        in >> a.authentication_path;
        in >> a.index_account;

        return in;
    }
};

template <size_t Depth, typename Hash>
class GuneroWitness;

template<size_t Depth, typename Hash>
class EmptyMerkleRoots {
public:
    EmptyMerkleRoots() {
        empty_roots.at(0) = Hash();
        for (size_t d = 1; d <= Depth; d++) {
            empty_roots.at(d) = Hash::combine(empty_roots.at(d-1), empty_roots.at(d-1));
        }
    }
    Hash empty_root(size_t depth) {
        return empty_roots.at(depth);
    }
    template <size_t D, typename H>
    friend bool operator==(const EmptyMerkleRoots<D, H>& a,
                           const EmptyMerkleRoots<D, H>& b);
private:
    boost::array<Hash, Depth+1> empty_roots;
};

template<size_t Depth, typename Hash>
class GuneroMerkleTree {

friend class GuneroWitness<Depth, Hash>;

public:
    BOOST_STATIC_ASSERT(Depth >= 1);

    GuneroMerkleTree() { }

    size_t DynamicMemoryUsage() const {
        return 32 + // left
               32 + // right
               parents.size() * 32; // parents
    }

    size_t size() const;

    void append(Hash obj);
    Hash root() const {
        return root(Depth, std::deque<Hash>());
    }
    Hash last() const;

    GuneroWitness<Depth, Hash> witness() const {
        return GuneroWitness<Depth, Hash>(*this);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(left);
        READWRITE(right);
        READWRITE(parents);

        wfcheck();
    }

    static Hash empty_root() {
        return emptyroots.empty_root(Depth);
    }

    template <size_t D, typename H>
    friend bool operator==(const GuneroMerkleTree<D, H>& a,
                           const GuneroMerkleTree<D, H>& b);

private:
    static EmptyMerkleRoots<Depth, Hash> emptyroots;
    boost::optional<Hash> left;
    boost::optional<Hash> right;

    // Collapsed "left" subtrees ordered toward the root of the tree.
    std::vector<boost::optional<Hash>> parents;
    GuneroMerklePath path(std::deque<Hash> filler_hashes = std::deque<Hash>()) const;
    Hash root(size_t depth, std::deque<Hash> filler_hashes = std::deque<Hash>()) const;
    bool is_complete(size_t depth = Depth) const;
    size_t next_depth(size_t skip) const;
    void wfcheck() const;
};

template <size_t Depth, typename Hash>
class GuneroWitness {
friend class GuneroMerkleTree<Depth, Hash>;

public:
    // Required for Unserialize()
    GuneroWitness() {}

    GuneroMerklePath path() const {
        return tree.path(partial_path());
    }

    // Return the element being witnessed (should be a note
    // commitment!)
    Hash element() const {
        return tree.last();
    }

    Hash root() const {
        return tree.root(Depth, partial_path());
    }

    void append(Hash obj);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(tree);
        READWRITE(filled);
        READWRITE(cursor);

        cursor_depth = tree.next_depth(filled.size());
    }

    template <size_t D, typename H>
    friend bool operator==(const GuneroWitness<D, H>& a,
                           const GuneroWitness<D, H>& b);

private:
    GuneroMerkleTree<Depth, Hash> tree;
    std::vector<Hash> filled;
    boost::optional<GuneroMerkleTree<Depth, Hash>> cursor;
    size_t cursor_depth = 0;
    std::deque<Hash> partial_path() const;
    GuneroWitness(GuneroMerkleTree<Depth, Hash> tree) : tree(tree) {}
};


} // end namespace `gunero`

#endif /* GUNEROMERKLETREE_H_ */