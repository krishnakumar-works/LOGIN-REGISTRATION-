# Login and Registration System

A login and registration system that stores user credentials safely. Passwords are never saved as plain text, only as salted hashes. It is available as a C++ command-line program and as a web page.

## Features

- **Registration** with a username and password (the password is asked for twice)
- **Validation:**
  - Username: 3 to 20 characters, letters, digits and underscore only
  - Password: 8 to 64 characters, at least one letter and one digit, and not the same as the username
  - Duplicate usernames are rejected (usernames are case-insensitive, so `Ali` and `ali` are the same user)
- **Secure storage:** one file per user, containing the salt and the hash, never the password
- **Login** that reads the stored record and verifies the user's identity
- **Clear messages** for registration and login success or failure

## Files

| File | Description |
|---|---|
| `login_system.cpp` | C++ command-line version, stores one file per user in a `users/` folder |
| `login_system.html` | Web version (single file), stores accounts in the browser |

## How to Run

**C++**
```
g++ -std=c++17 login_system.cpp -o login_system
./login_system
```
On Windows, run `login_system.exe` instead of `./login_system`. The program creates a `users/` folder the first time someone registers.

**Web version**

Double-click `login_system.html` to open it in a browser. Use the **Register** tab to create an account, then the **Log in** tab.

## Security Features

| Feature | Why it matters |
|---|---|
| Salted PBKDF2-HMAC-SHA256 hashing, 100,000 rounds | A stolen file doesn't reveal passwords, and brute-forcing is slow |
| Random 16-byte salt per user | Two users with the same password get different hashes |
| Hidden password input in the terminal | Nobody can read the password over your shoulder |
| Same error message for wrong username and wrong password | Attackers can't find out which usernames exist |
| Same hashing work for unknown usernames | Timing doesn't reveal which usernames exist |
| Constant-time hash comparison | Timing doesn't reveal how much of a guess was right |
| Strict username rules | Blocks tricks like `../file` that would write outside the `users/` folder |
| Lockout after 3 failed logins | Slows down guessing (the program exits in C++, and the web page locks for 30 seconds) |

## Stored File Format (C++ version)

Each file, for example `users/alice_01.txt`, has four lines:

```
alice_01
100000
<salt in hex>
<hash in hex>
```

The lines are the username, the number of hashing rounds, the salt and the hash.

## Notes and Limitations

- SHA-256 and PBKDF2 are written directly into the C++ file so it needs no external libraries. A production system should use a tested library such as OpenSSL or libsodium.
- The C++ version's hash was checked against Python's `hashlib.pbkdf2_hmac` and gives the same result.
- The web version is a learning demo. It stores data in the browser's `localStorage`, so accounts exist only on that browser. A real website needs a server-side backend and a database, with HTTPS.
- The web version also lets you download and load a `users.json` file, which contains hashes only, no passwords.

## What I Learned

- Why passwords must be hashed and salted, and why slow hashing functions matter
- File handling and input validation in C++
- Common security mistakes, such as user enumeration, timing leaks and path traversal, and how to avoid them
- Using the browser's Web Crypto API

## Author

KRISHNA KUMAR
