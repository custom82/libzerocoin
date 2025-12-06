#include <stdexcept>
#include <string>

class bignum_error : public std::exception {
public:
    // Costruttore che accetta una stringa
    explicit bignum_error(const std::string& message)
    : msg(message) {}

    // Funzione che restituisce il messaggio di errore
    const char* what() const noexcept override {
        return msg.c_str();
    }

private:
    std::string msg;  // Messaggio di errore
};
