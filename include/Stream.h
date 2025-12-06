#ifndef STREAM_H
#define STREAM_H

#include <vector>
#include <iostream>

class CStream {
public:
    // Costruttore di default
    CStream() {}

    // Aggiunge dati al flusso
    void write(const std::vector<unsigned char>& data) {
        stream.insert(stream.end(), data.begin(), data.end());
    }

    // Legge dati dal flusso
    std::vector<unsigned char> read(size_t size) {
        std::vector<unsigned char> result(stream.begin(), stream.begin() + size);
        stream.erase(stream.begin(), stream.begin() + size);
        return result;
    }

    // Per ottenere i dati del flusso in formato esadecimale
    std::string getHex() const {
        std::string result;
        for (auto byte : stream) {
            result += "0123456789ABCDEF"[byte >> 4];
            result += "0123456789ABCDEF"[byte & 0x0F];
        }
        return result;
    }

private:
    std::vector<unsigned char> stream;  // Dati del flusso
};

#endif // STREAM_H
