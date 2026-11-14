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

## Default AES from SafeBuf (v1.5.11)

`SetDefaultAESFromSafeBuf(key, iv *safe.SafeBuf) error` requires distinct buffers, a 16/24/32-byte key and a 12–16-byte IV. Success transfers both buffers to default AES; callers must neither close nor modify them. On error, callers retain ownership and must close them. The setter shares the one-shot installation and observer lock with SetDefaultAES. Register observers during package variable initialization; never set default AES from an observer. Repeated installation returns an error; the legacy setter retains its behavior.

Generated code need not open plaintext; library validation and encryption still briefly use plaintext internally. This does not protect against process inspection. The legacy slice setter and erasure contract remain unchanged. Self-contained Go exports require pending safe v1.5.6 and keys v1.5.13.

Development verification now replaces the complete pending dependency graph, not only safe/crypto. All absolute-path replacements are temporary and must be removed in dependency order before release.

Release v1.5.11: verified with published dependencies and GOWORK=off; all temporary replacements have been removed. Earlier development-validation notes describe historical local checks.
