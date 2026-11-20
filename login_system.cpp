/*
 * Task 2: Login and Registration System (C++ version)
 * ---------------------------------------------------
 * - register function : takes username and password
 * - validates input   : username/password rules + duplicate username check
 * - stores credentials: one file per user inside the "users/" folder
 *                       (the password is NEVER stored, only a salted hash)
 * - login function    : reads the stored record and verifies the identity
 * - clear success / error messages for registration and login
 *
 * Security: passwords are hashed with PBKDF2-HMAC-SHA256 (100,000 rounds)
 * using a random 16-byte salt per user. SHA-256 is implemented below so the
 * program needs no external libraries.
 *
 * Compile: g++ -std=c++17 login_system.cpp -o login_system
 * Run    : ./login_system
 */

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <random>
#include <string>
#include <vector>
#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

using Bytes = std::vector<uint8_t>;

static const std::string USER_DIR = "users";
static const int PBKDF2_ROUNDS = 100000;
static const int SALT_BYTES = 16;
static const int MAX_LOGIN_ATTEMPTS = 3;

/* ======================= SHA-256 / HMAC / PBKDF2 ======================= */

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static std::array<uint8_t, 32> sha256(const Bytes& data) {
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    Bytes msg = data;
    uint64_t bitLen = static_cast<uint64_t>(data.size()) * 8;
    msg.push_back(0x80);
    while (msg.size() % 64 != 56) msg.push_back(0x00);
    for (int i = 7; i >= 0; i--) msg.push_back(static_cast<uint8_t>(bitLen >> (i * 8)));

    for (size_t off = 0; off < msg.size(); off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = (uint32_t(msg[off + 4 * i]) << 24) | (uint32_t(msg[off + 4 * i + 1]) << 16) |
                   (uint32_t(msg[off + 4 * i + 2]) << 8) | uint32_t(msg[off + 4 * i + 3]);
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    std::array<uint8_t, 32> out;
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 4; j++) out[i * 4 + j] = static_cast<uint8_t>(h[i] >> (24 - 8 * j));
    return out;
}

static Bytes hmacSha256(Bytes key, const Bytes& message) {
    if (key.size() > 64) {
        auto k = sha256(key);
        key.assign(k.begin(), k.end());
    }
    key.resize(64, 0x00);

    Bytes inner(64), outer(64);
    for (int i = 0; i < 64; i++) {
        inner[i] = key[i] ^ 0x36;
        outer[i] = key[i] ^ 0x5c;
    }
    inner.insert(inner.end(), message.begin(), message.end());
    auto ih = sha256(inner);
    outer.insert(outer.end(), ih.begin(), ih.end());
    auto oh = sha256(outer);
    return Bytes(oh.begin(), oh.end());
}

// PBKDF2-HMAC-SHA256 producing one 32-byte block.
static Bytes pbkdf2(const std::string& password, const Bytes& salt, int rounds) {
    Bytes pw(password.begin(), password.end());
    Bytes first = salt;
    first.insert(first.end(), {0x00, 0x00, 0x00, 0x01});

    Bytes u = hmacSha256(pw, first);
    Bytes result = u;
    for (int i = 1; i < rounds; i++) {
        u = hmacSha256(pw, u);
        for (size_t j = 0; j < result.size(); j++) result[j] ^= u[j];
    }
    return result;
}

/* ============================== helpers ============================== */

static std::string toHex(const Bytes& b) {
    static const char* digits = "0123456789abcdef";
    std::string s;
    for (uint8_t x : b) { s += digits[x >> 4]; s += digits[x & 0x0f]; }
    return s;
}

static bool fromHex(const std::string& s, Bytes& out) {
    if (s.size() % 2 != 0) return false;
    out.clear();
    for (size_t i = 0; i < s.size(); i += 2) {
        if (!std::isxdigit(static_cast<unsigned char>(s[i])) ||
            !std::isxdigit(static_cast<unsigned char>(s[i + 1]))) return false;
        out.push_back(static_cast<uint8_t>(std::stoi(s.substr(i, 2), nullptr, 16)));
    }
    return true;
}

static Bytes randomSalt() {
    std::random_device rd;
    std::mt19937_64 gen(
        (static_cast<uint64_t>(rd()) << 32) ^ rd() ^
        static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
    Bytes salt(SALT_BYTES);
    for (auto& b : salt) b = static_cast<uint8_t>(gen() & 0xff);
    return salt;
}

// Compares in constant time so timing does not reveal how much matched.
static bool constantTimeEqual(const Bytes& a, const Bytes& b) {
    if (a.size() != b.size()) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

static std::string readLine(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) {
        std::cout << "\nInput ended. Goodbye.\n";
        std::exit(0);
    }
    while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
    return line;
}

// Reads a password without echoing it to the screen.
static std::string readPassword(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string pw;
#ifdef _WIN32
    int c;
    while ((c = _getch()) != '\r' && c != '\n') {
        if (c == 3) std::exit(1);                       // Ctrl+C
        if (c == '\b') { if (!pw.empty()) pw.pop_back(); }
        else if (c >= 32) pw.push_back(static_cast<char>(c));
    }
    std::cout << "\n";
#else
    termios oldt;
    bool hidden = (tcgetattr(STDIN_FILENO, &oldt) == 0);
    if (hidden) {
        termios newt = oldt;
        newt.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }
    if (!std::getline(std::cin, pw)) pw.clear();
    if (hidden) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        std::cout << "\n";
    }
    while (!pw.empty() && pw.back() == '\r') pw.pop_back();
#endif
    return pw;
}

/* ======================== validation & storage ======================== */

// Returns an error message, or "" if the username is valid.
// Only letters, digits and underscore are allowed, which also keeps
// users from writing outside the "users/" folder (e.g. "../x").
static std::string validateUsername(const std::string& u) {
    if (u.size() < 3 || u.size() > 20) return "Username must be 3 to 20 characters long.";
    for (unsigned char c : u)
        if (!std::isalnum(c) && c != '_') return "Username can only contain letters, digits and underscore.";
    return "";
}

static std::string validatePassword(const std::string& p, const std::string& username) {
    if (p.size() < 8) return "Password must be at least 8 characters long.";
    if (p.size() > 64) return "Password must be at most 64 characters long.";
    bool letter = false, digit = false;
    for (unsigned char c : p) {
        if (std::isalpha(c)) letter = true;
        if (std::isdigit(c)) digit = true;
    }
    if (!letter || !digit) return "Password must contain at least one letter and one digit.";
    if (toLower(p) == username) return "Password must not be the same as the username.";
    return "";
}

static std::string userFile(const std::string& username) {
    return USER_DIR + "/" + username + ".txt";
}

static bool userFileExists(const std::string& username) {
    std::ifstream in(userFile(username));
    return in.good();
}

static bool ensureUserDirectory() {
#ifdef _WIN32
    return _mkdir(USER_DIR.c_str()) == 0 || errno == EEXIST;
#else
    return mkdir(USER_DIR.c_str(), 0700) == 0 || errno == EEXIST;
#endif
}

static bool registerUser() {
    std::cout << "\n--- Register ---\n";
    std::string username = toLower(readLine("Choose a username: "));

    std::string err = validateUsername(username);
    if (!err.empty()) { std::cout << "Registration failed: " << err << "\n"; return false; }

    if (userFileExists(username)) {
        std::cout << "Registration failed: username '" << username << "' is already taken.\n";
        return false;
    }

    std::string password = readPassword("Choose a password: ");
    err = validatePassword(password, username);
    if (!err.empty()) { std::cout << "Registration failed: " << err << "\n"; return false; }

    if (readPassword("Confirm password: ") != password) {
        std::cout << "Registration failed: passwords do not match.\n";
        return false;
    }

    std::cout << "Securing your password..." << std::flush;
    Bytes salt = randomSalt();
    Bytes hash = pbkdf2(password, salt, PBKDF2_ROUNDS);

    if (!ensureUserDirectory()) {
        std::cout << "\nRegistration failed: could not create the users folder.\n";
        return false;
    }
    std::ofstream out(userFile(username));
    if (!out) {
        std::cout << "\nRegistration failed: could not write to the users folder.\n";
        return false;
    }
    // File format: username, rounds, salt (hex), hash (hex)
    out << username << "\n" << PBKDF2_ROUNDS << "\n" << toHex(salt) << "\n" << toHex(hash) << "\n";
    out.close();

    std::cout << "\nRegistration successful! You can now log in as '" << username << "'.\n";
    return true;
}

static bool loginUser() {
    std::cout << "\n--- Login ---\n";
    std::string username = toLower(readLine("Username: "));

    // Read the stored record (if the username is valid and the file exists).
    int rounds = 0;
    Bytes salt, storedHash;
    bool found = false;
    if (validateUsername(username).empty() && userFileExists(username)) {
        std::ifstream in(userFile(username));
        std::string storedName, roundsStr, saltHex, hashHex;
        if (std::getline(in, storedName) && std::getline(in, roundsStr) &&
            std::getline(in, saltHex) && std::getline(in, hashHex)) {
            try { rounds = std::stoi(roundsStr); } catch (...) { rounds = 0; }
            found = rounds > 0 && fromHex(saltHex, salt) && fromHex(hashHex, storedHash);
        }
    }

    std::string password = readPassword("Password: ");

    // Same work and same message whether the user exists or not,
    // so an attacker cannot discover which usernames are registered.
    if (!found) {
        pbkdf2(password, randomSalt(), PBKDF2_ROUNDS);
        std::cout << "Login failed: incorrect username or password.\n";
        return false;
    }

    if (constantTimeEqual(pbkdf2(password, salt, rounds), storedHash)) {
        std::cout << "Login successful! Welcome back, " << username << ".\n";
        return true;
    }
    std::cout << "Login failed: incorrect username or password.\n";
    return false;
}

static void loggedInMenu() {
    std::cout << "\nYou are now logged in. Press Enter to log out.";
    std::string dummy;
    std::getline(std::cin, dummy);
    std::cout << "Logged out.\n";
}

/* ================================ main ================================ */

int main() {
    std::cout << "===== LOGIN & REGISTRATION SYSTEM =====\n";
    int failedLogins = 0;

    while (true) {
        std::cout << "\n1. Register\n2. Login\n3. Exit\n";
        std::string choice = readLine("Choose an option (1-3): ");

        if (choice == "1") {
            registerUser();
        } else if (choice == "2") {
            if (loginUser()) {
                failedLogins = 0;
                loggedInMenu();
            } else if (++failedLogins >= MAX_LOGIN_ATTEMPTS) {
                std::cout << "Too many failed attempts. Exiting for security.\n";
                return 1;
            }
        } else if (choice == "3") {
            std::cout << "Goodbye!\n";
            return 0;
        } else {
            std::cout << "Invalid option. Please enter 1, 2 or 3.\n";
        }
    }
}
