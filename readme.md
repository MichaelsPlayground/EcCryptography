# EC Cryptography

This app runs Elliptic Curves ("EC") cryptography to encrypt and decrypt data.

As it uses the Android build-in methods it **runs on Android SDK 23+**. 

The following describes the workflow of an **ECDH** ("**Elliptic-curve Diffie–Hellman**") based encryption.

There are 4 steps to run the encryption/decryption

1) **generate an EC key pair** using the **curve P-256** for each party "one" and "two"
2) **calculate the shared secrets** for both parties ("one" and "two")
3) **derive the encryption key** using HKDF
4) **encrypt and decrypt data** using the derived encryption key with AES in CBC- or GCM-mode

# What is the field of use for this technology ?

It's main purpose is the secure data transfer between two partners ("sender" and "receiver"). For encryption we use a 
**symmetric encryption** means there is a **shared encryption key** that is used for encryption on sender's side and 
used for decryption on receiver's side. The main issue is the knowledge of the encryption key - how is the key transferred 
from sender to receiver ?

As we not have control over an email it is dangerous to provide encryption keys in emails. Ok, we could call the recipient and 
give the key but in most cases it is unhandy. Same happens to share the key using a public available internet website/forum etc..

At this point the **asymmetric encryption** is our friend. Both partners have to create a key pair and share their **Public keys** to 
the the other party. There is no problem in sending them using unsecure channels like emails. To run an encryption the sender **derives the encryption key** 
with two parameters: his own private key and the recipient's public key. The derived key is used as input to a symmetric encryption method and 
the ciphertext (the encrypted data) is send to the recipient.

On receiver's side the encryption key is derived from receiver's private key and sender's public key - the encryption key is used as input to a symmetric 
decryption method.

The main advantage is: the encryption key was never send over an (unsecure) channel.

There is an alternative variant available: **ECDHE** ("**Elliptic Curve Diffie-Hellman Ephemeral**"). This is the perfect solution for **forward security** 
that is almost identical to ECDH with this difference:

In ECDH the two communication parties exchange their Public Keys but in ECDHE only the recipient sends its Public Key to the sender. The sender generates 
his key pair and calculates the shared secret as shown in step 02 above, derives the encryption key (step 03) and encrypts the data (step 04). Now the sender 
sends the encrypted data **and his own Public Key** to the recipient; after that the sender deletes his own key pair ("Ephemeral").

For decryption the recipient takes the encrypted data together with the accompanied Public Key of the sender and run steps 02, 03 and 04 for decryption.

