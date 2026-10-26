# @go/crypto

Protected symmetric/asymmetric encryption, signatures, hashes and key derivation.
See [API reference](README.md) for the complete module guide.

## Prefer AES-GCM with automatic IVs

Use `Symmetric.EncryptAutoIV(*safe.SafeBuf)`, `EncryptBytesAutoIV([]byte)` or
`EncryptAndEraseAutoIV([]byte)` for new data. The last method overwrites plaintext
on both success and failure. All return `([]byte, error)`.

Construct with `NewAESGCM`, `NewAESGCMAndEraseKey` or
`NewAESGCMWithoutEraseKey`, retaining the legacy IV for reading existing data;
pass nil IV if only the new format is needed. Output is exactly
`12-byte random IV || ciphertext || 16-byte tag`, without padding or a custom
header. Rotate keys before 2^32 random-nonce encryptions across all senders.
Consider a new key when migrating from repeated fixed-IV encryption.

Existing Encrypt methods retain their configured-IV behavior and legacy output.
Decrypt/DecryptBytes authenticate the embedded-IV format first, then try the
legacy IV when available. Legacy inputs of at least 28 bytes may require two
full authentication/decryption attempts. Both failures return an error.
TryDecrypt retains its original return-input-on-failure behavior.

Raw AESGCM.Encrypt/Decrypt remain explicit-IV operations. Short GCM IVs return
errors; longer legacy IVs still use their first 12 bytes. CBC, SM4 and hybrid
ECDSA/X25519 framing are unchanged. Optional AutoIVCipher extends the common
Symmetric wrapper without changing SymmetricCipher or requiring custom engines
to implement new methods. Unsupported automatic-IV modes return ErrNotImplemented.
The configured IV and DeriveKey output are unchanged by automatic-IV operations.
Do not call Close concurrently with encryption/decryption.

JavaScript adds EncryptAutoIV(data, key); existing Decrypt(data, key, iv) accepts
both formats. Upgrade receivers before enabling new writers. Old versions cannot
read the new format.
