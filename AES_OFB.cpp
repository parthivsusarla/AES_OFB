#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <cassert>
#include <cstring>

// ---------- AES-128 Core (Encryption Only) ----------
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t Rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

inline uint8_t xtime(uint8_t x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1b : 0x00);
}

void AES_128_KeyExpansion(const uint8_t* key, uint8_t w[44]) {
    for (int i = 0; i < 16; ++i)
        w[i] = key[i];
    for (int i = 4; i < 44; ++i) {
        uint8_t temp[4] = {w[(i-1)*4], w[(i-1)*4+1], w[(i-1)*4+2], w[(i-1)*4+3]};
        if (i % 4 == 0) {
            uint8_t t = temp[0];
            temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
            for (int j = 0; j < 4; ++j)
                temp[j] = sbox[temp[j]];
            temp[0] ^= Rcon[i/4];
        }
        for (int j = 0; j < 4; ++j)
            w[i*4 + j] = w[(i-4)*4 + j] ^ temp[j];
    }
}

void AES_128_Encrypt(const uint8_t* input, const uint8_t* roundKeys, uint8_t* output) {
    uint8_t state[16];
    uint8_t t;  // ✅ Declared once at function scope
    std::memcpy(state, input, 16);

    // AddRoundKey
    for (int i = 0; i < 16; ++i)
        state[i] ^= roundKeys[i];

    for (int round = 1; round < 10; ++round) {
        // SubBytes
        for (int i = 0; i < 16; ++i)
            state[i] = sbox[state[i]];
        // ShiftRows
        t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t;
        t = state[2]; state[2] = state[10]; state[10] = t;
        t = state[6]; state[6] = state[14]; state[14] = t;
        t = state[3]; state[3] = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = t;
        // MixColumns
        for (int i = 0; i < 4; ++i) {
            uint8_t a0 = state[i*4 + 0];
            uint8_t a1 = state[i*4 + 1];
            uint8_t a2 = state[i*4 + 2];
            uint8_t a3 = state[i*4 + 3];
            state[i*4 + 0] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
            state[i*4 + 1] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
            state[i*4 + 2] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
            state[i*4 + 3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
        }
        // AddRoundKey
        for (int i = 0; i < 16; ++i)
            state[i] ^= roundKeys[round*16 + i];
    }

    // Final round (no MixColumns)
    for (int i = 0; i < 16; ++i)
        state[i] = sbox[state[i]];
    t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t;
    t = state[2]; state[2] = state[10]; state[10] = t;
    t = state[6]; state[6] = state[14]; state[14] = t;
    t = state[3]; state[3] = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = t;
    for (int i = 0; i < 16; ++i)
        state[i] ^= roundKeys[160 + i];

    std::memcpy(output, state, 16);
}

// ---------- OFB Mode ----------
void AES_OFB_Process(std::istream& in, std::ostream& out, const uint8_t* key, const uint8_t* iv) {
    uint8_t roundKeys[176];
    AES_128_KeyExpansion(key, reinterpret_cast<uint8_t*>(roundKeys));

    uint8_t feedback[16];
    std::memcpy(feedback, iv, 16);

    uint8_t keystream[16];
    char byte;
    int pos = 0;

    while (in.get(byte)) {
        if (pos == 0) {
            AES_128_Encrypt(feedback, roundKeys, keystream);
            std::memcpy(feedback, keystream, 16);
        }
        out.put(byte ^ keystream[pos]);
        pos = (pos + 1) % 16;
    }
}

// ---------- Helper Functions ----------
std::vector<uint8_t> hexStringToBytes(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Hex string must have even length");
    }
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// ---------- Main ----------
int main() {
    std::string keyHex, ivHex;
    std::cout << "Enter 128-bit key as hex (32 hex chars): ";
    std::cin >> keyHex;
    if (keyHex.length() != 32) {
        std::cerr << "Invalid key length. Must be 32 hex characters (128 bits).\n";
        return 1;
    }

    std::cout << "Enter 128-bit IV as hex (32 hex chars): ";
    std::cin >> ivHex;
    if (ivHex.length() != 32) {
        std::cerr << "Invalid IV length. Must be 32 hex characters (128 bits).\n";
        return 1;
    }

    auto keyBytes = hexStringToBytes(keyHex);
    auto ivBytes = hexStringToBytes(ivHex);

    const char* inputFile = "plaintext_1MB.txt";
    const char* encryptedFile = "ciphertext_ofb.bin";
    const char* decryptedFile = "decrypted_ofb.txt";

    // --- Encryption ---
    auto start = std::chrono::high_resolution_clock::now();
    {
        std::ifstream in(inputFile, std::ios::binary);
        std::ofstream out(encryptedFile, std::ios::binary);
        if (!in || !out) {
            std::cerr << "Error: Cannot open '" << inputFile << "' for reading or output file.\n";
            std::cerr << "Make sure 'plaintext_1MB.txt' exists in the current directory.\n";
            return 1;
        }
        AES_OFB_Process(in, out, keyBytes.data(), ivBytes.data());
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto encryptTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    // --- Decryption ---
    start = std::chrono::high_resolution_clock::now();
    {
        std::ifstream in(encryptedFile, std::ios::binary);
        std::ofstream out(decryptedFile, std::ios::binary);
        if (!in || !out) {
            std::cerr << "Error opening files for decryption.\n";
            return 1;
        }
        AES_OFB_Process(in, out, keyBytes.data(), ivBytes.data());
    }
    end = std::chrono::high_resolution_clock::now();
    auto decryptTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    // --- Verify integrity ---
    {
        std::ifstream orig(inputFile, std::ios::binary);
        std::ifstream dec(decryptedFile, std::ios::binary);
        std::istreambuf_iterator<char> origBegin(orig), origEnd;
        std::istreambuf_iterator<char> decBegin(dec);
        if (!std::equal(origBegin, origEnd, decBegin)) {
            std::cerr << "Decryption failed: output does not match original!\n";
            return 1;
        }
    }

    // --- Get file sizes ---
    std::ifstream encFile(encryptedFile, std::ios::binary | std::ios::ate);
    std::streamsize ciphertextSize = encFile.tellg();

    // --- Output results ---
    std::cout << "\n=== AES-128 OFB Mode Performance Results ===\n";
    std::cout << "File Size (plaintext): 1048576 bytes\n";
    std::cout << "Ciphertext Size: " << ciphertextSize << " bytes\n";
    std::cout << "Encryption Time: " << encryptTime << " ms\n";
    std::cout << "Decryption Time: " << decryptTime << " ms\n";

    // Save report
    std::ofstream report("report.txt");
    report << "=== AES-128 OFB Mode Report ===\n\n";
    report << "Security Analysis:\n";
    report << "- Block Dependencies: OFB is a stream cipher mode. Each keystream block is generated by encrypting the previous keystream block (starting from IV). Thus, keystream blocks are dependent on prior ones, but not on plaintext or ciphertext.\n";
    report << "- IV/Nonce Usage: Requires a unique, unpredictable 128-bit IV for each encryption under the same key. Reusing an IV with the same key leaks plaintext (via XOR of ciphertexts).\n";
    report << "- Error Propagation: Bit errors in ciphertext affect only the corresponding bit in plaintext. No error propagation occurs; synchronization is preserved.\n\n";
    report << "Performance on 1MB file:\n";
    report << "+---------------------+----------+\n";
    report << "| Metric              | Value    |\n";
    report << "+---------------------+----------+\n";
    report << "| Ciphertext Size     | " << std::setw(8) << ciphertextSize << " |\n";
    report << "| Encryption Time     | " << std::setw(8) << encryptTime << " ms |\n";
    report << "| Decryption Time     | " << std::setw(8) << decryptTime << " ms |\n";
    report << "+---------------------+----------+\n";
    report.close();

    std::cout << "\nReport saved to 'report.txt'\n";
    return 0;
}