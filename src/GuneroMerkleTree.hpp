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
    std::vector<bool> index;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(authentication_path);
        READWRITE(index);
    }

    GuneroMerklePath() { }

    GuneroMerklePath(std::vector<std::vector<bool>> authentication_path, std::vector<bool> index)
    : authentication_path(authentication_path), index(index) { }

    friend std::ostream& operator<<(std::ostream &out, const GuneroMerklePath &a)
    {
        out << a.authentication_path;
        out << a.index;

        return out;
    }

    friend std::istream& operator>>(std::istream &in, GuneroMerklePath &a)
    {
        in >> a.authentication_path;
        in >> a.index;

        return in;
    }
};

} // end namespace `gunero`

#endif /* GUNEROMERKLETREE_H_ */