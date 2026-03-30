# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
dotnet build                          # Build the project
dotnet run                            # Run the demo application (Program.cs)
dotnet test                           # Run all tests
dotnet test --filter "FullyQualifiedName~MethodName"  # Run a single test
dotnet build --configuration Release  # Release build
```

## Architecture

This is a C# (.NET 10.0) library implementing the **Ethereum v3 keystore specification** for encrypting and decrypting Ethereum wallet private keys.

### Core Files

- **`EthereumKeystore.cs`** — All cryptographic logic and JSON models. This is the only substantive implementation file.
- **`Program.cs`** — Demo/example showing keystore decryption; not part of the library API.
- **`EthWalletDecryptor.Tests/EthereumKeystoreTests.cs`** — xUnit test suite (7 tests).

### Key Design

**Data flow:** JSON keystore + password → scrypt KDF → MAC verification → AES-128-CTR decrypt → private key bytes.

**`EthereumKeystore` static class** exposes three public methods:
- `Decrypt(KeystoreFile, password)` → `byte[]` — throws `CryptographicException` on bad password or `NotSupportedException` for unsupported algorithms
- `Encrypt(privateKey, password, ...)` → `KeystoreFile`
- `Serialize(KeystoreFile)` → JSON string

**Implementation notes:**
- Only `scrypt` KDF and `aes-128-ctr` cipher are supported (others throw `NotSupportedException`)
- AES-CTR is implemented manually (ECB + big-endian counter) since .NET has no native CTR mode
- Derived key is 32 bytes: first 16 bytes → AES key, last 16 bytes → MAC key
- MAC = `Keccak256(macKey || ciphertext)` — uses Keccak-256 (not SHA-3)
- BouncyCastle (`BouncyCastle.Cryptography` v2.6.2) provides scrypt and Keccak-256

### JSON Models (in `EthereumKeystore.cs`)

```
KeystoreFile
  └── CryptoSection
        ├── CipherParams (iv)
        └── KdfParams (salt, n, r, p, dklen)
```
