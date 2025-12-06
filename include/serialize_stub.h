#ifndef SERIALIZE_STUB_H
#define SERIALIZE_STUB_H

#include <vector>
#include <cstddef>

// Stub per serializzazione
class CDataStream {
private:
    std::vector<unsigned char> data;
    size_t pos;

public:
    enum {
        SER_NETWORK = 1,
        SER_GETHASH = 2,
        SER_DISK = 4
    };

    CDataStream(int nTypeIn, int nVersionIn) : pos(0) {}

    template<typename T>
    CDataStream& operator<<(const T& obj) {
        // Stub
        return *this;
    }

    template<typename T>
    CDataStream& operator>>(T& obj) {
        // Stub
        return *this;
    }

    size_t size() const { return data.size(); }
    void clear() { data.clear(); pos = 0; }
};

// Macro per serializzazione
#define ADD_SERIALIZE_METHODS \
template<typename Stream> \
void Serialize(Stream& s) const { \
    const_cast<std::remove_const<decltype(*this)>::type*>(this)->SerializationOp(s, CSerActionSerialize()); \
} \
template<typename Stream> \
void Unserialize(Stream& s) { \
    SerializationOp(s, CSerActionUnserialize()); \
}

class CSerActionSerialize {};
class CSerActionUnserialize {};

#endif
