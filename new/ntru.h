#include <iostream>
#include <string>
#include <stdexcept>
#include <crypto++/ntru.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>

using namespace CryptoPP;

int main() {
    // NTRU parameters
    int N = 509;
    int p = 3;
    int q = 2048;
    int df = 85;
    int dg = 85;
    int d = 85;

    // Generate NTRU key pair
    AutoSeededRandomPool rng;
    NTRUEncrypt::EncryptionPublicKey publicKey;
    NTRUEncrypt::EncryptionPrivateKey privateKey;

    NTRUEncrypt::GenerateKeyPair(rng, N, p, q, df, dg, d, publicKey, privateKey, false);

    // Message to encrypt
    std::string message = "This is a secret message.";

    // Encryption
    std::string ciphertext;
    NTRUEncrypt::Encrypt(rng, publicKey, StringSource(message, true), StringSink(ciphertext, false));

    // Encode ciphertext to base64 for easier handling
    std::string encodedCiphertext;
    Base64Encoder encoder;
    encoder.Put(reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size());
    encoder.MessageEnd();
    
    size_t encodedSize = encoder.MaxRetrievable();
    if (encodedSize)
    {
        encodedCiphertext.resize(encodedSize);
        encoder.Get(reinterpret_cast<unsigned char*>(&encodedCiphertext[0]), encodedCiphertext.size());
    }

    std::cout << "Ciphertext (Base64): " << encodedCiphertext << std::endl;

    // Decode base64 ciphertext
    std::string decodedCiphertext;
    Base64Decoder decoder;
   
    decoder.Put(reinterpret_cast<const unsigned char*>(encodedCiphertext.data()), encodedCiphertext.size());
    decoder.MessageEnd();

    size_t recoveredSize = decoder.MaxRetrievable();
    if (recoveredSize)
    {
       decodedCiphertext.resize(recoveredSize);
       decoder.Get(reinterpret_cast<unsigned char*>(&decodedCiphertext[0]), decodedCiphertext.size());
    }

    // Decryption
    std::string decryptedMessage;
    NTRUEncrypt::Decrypt(rng, privateKey, StringSource(decodedCiphertext, true), StringSink(decryptedMessage, false));

    std::cout << "Decrypted Message: " << decryptedMessage << std::endl;

    return 0;
}
