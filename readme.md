# EC Cryptography

This app runs Elliptic Curves ("EC") cryptography to encrypt and decrypt data.

As it uses the Android build-in methods it **runs on Android SDK 23+**. 

There are 4 steps to run the encryption/decryption

1) generate an EC keypair using the **curve P-256** for each party "one" and "two"
2) calculate the shared secrets for both parties ("one" and "two")
3) derive the encryption key using HKDF
4) encrypt and decrypt data using the derived encryption key

# What is the field of use for this technology ?

It's main purpose is the secure data transfer between two partners ("sender" and "receiver"). For encryption we use a 
**symmetric encryption** means there is a **shared encryption key** that is used for encryption on sender's side and 
used for decryption on receiver's side. The main issue is the knowledge of the encryption key - how is the key transfered 
from sender to receiver ?

As we not have control over an email it is dangerous to provide encryption keys in emails. Ok, we could call the recipient and 
give the key but in most cases it is unhandy.

At this point the **asymmetric encryption** is our friend. Both partners have to create a key pair and share their public keys to 
the recipient. There is no problem in sending them using unsecure channels like emails. To run an encryption the sender **derives the encryption key** 
with two parameters: his own private key and the recipient's public key. The derived key is used as input to a symmetric encryption method and 
the ciphertext (the encrypted data) is send to the recipient.

On receiver's side the encryption key is derived from receiver's private key and sender's public key - that key is used a input to a symmetric 
decryption method.

The main advantage is: the encryption key was never send over a channel.



