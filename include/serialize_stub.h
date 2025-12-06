#ifndef SERIALIZE_STUB_H
#define SERIALIZE_STUB_H

#include <vector>
#include <cstddef>

// Simple serialization stub
template<typename T>
inline void READWRITE(T& obj) {
    // Stub implementation
}

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

    CDataStream(int nTypeIn, int nVersionIn) : pos(0) {
        (void)nTypeIn;
        (void)nVersionIn;
    }

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

// Simple serialization macros
#define ADD_SERIALIZE_METHODS \
template<typename Stream> \
void Serialize(Stream& s) const { \
    /* Stub implementation */ \
} \
template<typename Stream> \
void Unserialize(Stream& s) { \
    /* Stub implementation */ \
}

class CSerActionSerialize {};
class CSerActionUnserialize {};

#endif
