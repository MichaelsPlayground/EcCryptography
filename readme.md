# EC Cryptography

This app runs Elliptic Curves ("EC") cryptography to encrypt and decrypt data.

As it uses the Android build-in methods it **runs on Android SDK 23+**. 

There are 4 steps to run the encryption/decryption

1) generate an EC keypair using the **curve P-256** for each party "one" and "two"
2) calculate the shared secrets for both parties ("one" and "two")
3) derive the encryption key using HKDF
4) encrypt and decrypt data using the derived encryption key

