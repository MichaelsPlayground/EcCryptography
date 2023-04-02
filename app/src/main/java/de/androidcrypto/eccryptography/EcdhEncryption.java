package de.androidcrypto.eccryptography;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import de.androidcrypto.eccryptography.model.EcdhModel;
import de.androidcrypto.eccryptography.model.PublicKeyModel;

public class EcdhEncryption {

    private static final String TAG = "EcdhEncryption";
    private static final String KEY_STORE_PROVIDER = "AndroidKeyStore";
    private static final String KEY_AGREEMENT_ALG_ECDH = "ECDH";
    private static final String HKDF_KEY = "aes-key";

    public static String generateUuid() {
        UUID uuid = UUID.randomUUID();
        return uuid.toString();
    }

    public static PublicKeyModel generateEcKey(String alias, String keyParameter)  {
        // only P256 or P521 are allowed
        if ((!keyParameter.equals("P_256") & (!keyParameter.equals("P_521")))) return null;
        String keyParam = "P-256";
        if (keyParameter.equals(PublicKeyModel.KEY_PARAMETER.P_521)) keyParam = "P-521";
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, KEY_STORE_PROVIDER);
            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(
                            alias,
                            // todo find a solution for Android SDK < 31
                            KeyProperties.PURPOSE_AGREE_KEY)
                            .setAlgorithmParameterSpec(new ECGenParameterSpec(keyParam))
                            .setUserAuthenticationRequired(false)
                            .setKeyValidityEnd(DateFormat.getDateInstance().parse("Aug 1, 2199"))
                            .build());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKeyModel pkm = new PublicKeyModel(PublicKeyModel.KEY_TYPE.EC.toString(), keyParameter, alias, base64EncodingNpe(keyPair.getPublic().getEncoded()));
            return pkm;
        } catch (NoSuchAlgorithmException | NoSuchProviderException |
                 InvalidAlgorithmParameterException | ParseException e) {
            //throw new RuntimeException(e);
            Log.e(TAG, "Exception: " + e.getMessage());
        }
        return null;
    }

    public static byte[] sharedSecretEc(PrivateKey minePrivateKey, PublicKey remotePublicKey) {
        if ((minePrivateKey == null) | (remotePublicKey == null)) return null;
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALG_ECDH, KEY_STORE_PROVIDER);
            keyAgreement.init(minePrivateKey);
            keyAgreement.doPhase(remotePublicKey, true);
            return keyAgreement.generateSecret();
        } catch (ProviderException | NoSuchAlgorithmException | NoSuchProviderException |
                 InvalidKeyException e) {
            Log.e(TAG, "Exception: " + e.getMessage());
            return null;
        }
    }

    //EcdhModel ecdhCiphertext = EcdhEncryption.encryptData(keyId, remotePublicKey, EcdhModel.ENCRYPTION_TYPE.AES_CBC_PKCS5PADDING, dataToEncrypt);
    public static EcdhModel encryptData(String senderKeyId, String recipientKeyId,  PublicKeyModel remotePublicKey, String deriveAlgorithm, String encryptionAlgorithm, byte[] dataToEncrypt) {
        // todo sanity checks
        // todo remote public key = "EC", keyParameter allowed, encryptionAlgorithm allowed, dataToEncrypt != null

        // deriveAlgorithm
        HKDF hkdf = null;
        if (deriveAlgorithm.equals(EcdhModel.HKDF_ALGORITHM.HMAC_SHA256.toString())) {
            hkdf = HKDF.fromHmacSha256();
        } else if (deriveAlgorithm.equals(EcdhModel.HKDF_ALGORITHM.HMAC_SHA512.toString())) {
            hkdf = HKDF.fromHmacSha512();
        } else {
            // at this pint no valid deriveAlgorithm was found
            Log.e(TAG, "no valid deriveAlgorithm found, aborted");
            return null;
        }
        // encryptionAlgorithm
        String transformation = "";
        if (encryptionAlgorithm.equals(EcdhModel.ENCRYPTION_ALGORITHM.AES_CBC_PKCS5PADDING.toString())) {
            transformation = "AES/CBC/PKCS5PADDING";
        } else if (encryptionAlgorithm.equals(EcdhModel.ENCRYPTION_ALGORITHM.AES_GCM_NOPADDING.toString())) {
            transformation = "AES/GCM/NOPADDING";
        } else {
            // at this point no valid encryptionAlgorithm was found
            Log.e(TAG, "no valid encryptionAlgorithm found, aborted");
            return null;
        }

        // get the private key from AndroidKeystore
        KeyStore ks = null;
        KeyStore.Entry entry;
        try {
            ks = KeyStore.getInstance(KEY_STORE_PROVIDER);
            ks.load(null);
            entry = ks.getEntry(senderKeyId, null);
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                Log.w(TAG, "Not an instance of a PrivateKeyEntry");
                return null;
            }
        } catch (KeyStoreException | UnrecoverableEntryException | CertificateException |
                 IOException | NoSuchAlgorithmException e) {
            //throw new RuntimeException(e);
            Log.e(TAG, "Exception: " + e.getMessage());
            return null;
        }
        PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
        // get public key
        byte[] encodedPublicKey = base64Decoding(remotePublicKey.getKeyEncodedBase64());
        KeyFactory kf = null;
        PublicKey remotePubKey;
        try {
            kf = KeyFactory.getInstance("EC");
            remotePubKey = (PublicKey) kf.generatePublic(new X509EncodedKeySpec(encodedPublicKey));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            //throw new RuntimeException(e);
            Log.e(TAG, "Exception: " + e.getMessage());
            return null;
        }
        // derive the sharedSecret
        byte[] sharedSecret = sharedSecretEc(privateKey, remotePubKey);

        // get the encryption key with hkdf
        byte[] randomSalt32Byte = generateRandomNumber(32);
        byte[] pseudoRandomKey;
        pseudoRandomKey = hkdf.extract(randomSalt32Byte, sharedSecret);
        //create expanded bytes for e.g. AES secret key and IV
        byte[] encryptionKey = hkdf.expand(pseudoRandomKey, HKDF_KEY.getBytes(StandardCharsets.UTF_8), 32);

        EcdhModel ecdhModel = encryptAes(deriveAlgorithm, encryptionAlgorithm, transformation, senderKeyId, recipientKeyId, randomSalt32Byte, HKDF_KEY, encryptionKey, dataToEncrypt);
        return ecdhModel;
    }

    public static byte[] decryptData(EcdhModel encryptedData, PublicKey senderPublicKey) {
        // todo sanity checks
        // todo remote public key = "EC", keyParameter allowed, encryptionAlgorithm allowed, dataToEncrypt != null

        // deriveAlgorithm
        HKDF hkdf = null;
        if (encryptedData.getDeriveAlgorithm().equals(EcdhModel.HKDF_ALGORITHM.HMAC_SHA256.toString())) {
            hkdf = HKDF.fromHmacSha256();
        } else if (encryptedData.getDeriveAlgorithm().equals(EcdhModel.HKDF_ALGORITHM.HMAC_SHA512.toString())) {
            hkdf = HKDF.fromHmacSha512();
        } else {
            // at this pint no valid deriveAlgorithm was found
            Log.e(TAG, "no valid deriveAlgorithm found, aborted");
            return null;
        }

        // encryptionAlgorithm
        String transformation = "";
        if (encryptedData.getEncryptionAlgorithm().equals(EcdhModel.ENCRYPTION_ALGORITHM.AES_CBC_PKCS5PADDING.toString())) {
            transformation = "AES/CBC/PKCS5PADDING";
        } else if (encryptedData.getEncryptionAlgorithm().equals(EcdhModel.ENCRYPTION_ALGORITHM.AES_GCM_NOPADDING.toString())) {
            transformation = "AES/GCM/NOPADDING";
        } else {
            // at this point no valid encryptionAlgorithm was found
            Log.e(TAG, "no valid encryptionAlgorithm found, aborted");
            return null;
        }


        // todo get the private key from keyId lookup

        // get the private key from AndroidKeystore
        KeyStore ks = null;
        KeyStore.Entry entry;
        String keyAlias = encryptedData.getKeyId();
        try {
            ks = KeyStore.getInstance(KEY_STORE_PROVIDER);
            ks.load(null);
            entry = ks.getEntry(keyAlias, null);
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                Log.w(TAG, "Not an instance of a PrivateKeyEntry");
                return null;
            }
        } catch (KeyStoreException | UnrecoverableEntryException | CertificateException |
                 IOException | NoSuchAlgorithmException e) {
            //throw new RuntimeException(e);
            Log.e(TAG, "Exception: " + e.getMessage());
            return null;
        }
        PrivateKey recipientPrivateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
        System.out.println("*** found recipientPrivateKey");
        // get public key

        // derive the sharedSecret
        byte[] sharedSecret = sharedSecretEc(recipientPrivateKey, senderPublicKey);
        System.out.println("*** sharedSecret: " + MainActivity.bytesToHexNpe(sharedSecret));

        // get the encryption key with hkdf
        //byte[] randomSalt32Byte = generateRandomNumber(32);
        byte[] randomSalt32Byte = base64Decoding(encryptedData.getDeriveSaltBase64());
        byte[] pseudoRandomKey;
        //HKDF hkdf = HKDF.fromHmacSha256();
        pseudoRandomKey = hkdf.extract(randomSalt32Byte, sharedSecret);
        //create expanded bytes for e.g. AES secret key and IV
        //byte[] encryptionKey = hkdf.expand(pseudoRandomKey, HKDF_KEY.getBytes(StandardCharsets.UTF_8), 32);
        byte[] encryptionKey = hkdf.expand(pseudoRandomKey, encryptedData.getDeriveName().getBytes(StandardCharsets.UTF_8), 32);
        byte[] initVector = base64Decoding(encryptedData.getIvBase64());
        byte[] ciphertext = base64Decoding(encryptedData.getCiphertextBase64());
        System.out.println("*** encKey: " + MainActivity.bytesToHexNpe(encryptionKey));

        byte[] decryptedData = decryptAes(encryptedData.getEncryptionAlgorithm(), transformation,"alias", encryptionKey, initVector, ciphertext);
        return decryptedData;
    }


    public static EcdhModel encryptAes(String deriveAlgorithm, String encryptionAlgorithm, String transformation, String alias, String aliasRecipient, byte[] deriveSalt, String deriveName, byte[] encryptionKey, byte[] data) {
        // todo check for encryptionAlgorithm allowed, nulled key + data
        //String encAlgo = EcdhModel.ENCRYPTION_TYPE.AES_CBC_PKCS5PADDING.toString();
        //String encAlgorithm = "AES/CBC/PKCS5PADDING";
        // todo cases CBC or GCM
        byte[] initVector = new byte[0];
        byte[] ciphertext;
        SecretKey key;
        key = new SecretKeySpec(encryptionKey, "AES"); //AES-256 key
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(transformation);
            if (encryptionAlgorithm.equals(EcdhModel.ENCRYPTION_ALGORITHM.AES_CBC_PKCS5PADDING.toString())) {
                initVector = generateRandomNumber(16);
                cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(initVector));
            } else if (encryptionAlgorithm.equals(EcdhModel.ENCRYPTION_ALGORITHM.AES_GCM_NOPADDING.toString())) {
                initVector = generateRandomNumber(12);
                cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(16, initVector));
            }
            ciphertext = cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException |
                 BadPaddingException | NoSuchPaddingException |
                 InvalidAlgorithmParameterException | InvalidKeyException e) {
            //throw new RuntimeException(e);
            return null;
        }
        // build the return model
        //return new EcdhModel(alias, base64EncodingNpe(deriveSalt), deriveName, encryptionAlgorithm, base64EncodingNpe(initVector), base64EncodingNpe(ciphertext));
        return new EcdhModel(aliasRecipient, base64EncodingNpe(deriveSalt), deriveName, deriveAlgorithm, encryptionAlgorithm, base64EncodingNpe(initVector), base64EncodingNpe(ciphertext));
    }

    public static byte[] decryptAes(String encryptionAlgorithm, String transformation, String alias, byte[] encryptionKey, byte[] initVector, byte[] ciphertext) {
    //public static byte[] decryptAes(EcdhModel encryptedData, PrivateKey recipientPrivateKey, PublicKey senderPublicKey) {
        // todo get the private key by the keyId

        // todo check for encryptionAlgorithm allowed, nulled key + data
        //String encAlgo = EcdhModel.ENCRYPTION_TYPE.AES_CBC_PKCS5PADDING.toString();
        //String encAlgorithm = "AES/CBC/PKCS5PADDING";
        // todo cases CBC or GCM
        byte[] decryptedData;
        SecretKey key;
        key = new SecretKeySpec(encryptionKey, "AES"); //AES-256 key
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(transformation);
            if (encryptionAlgorithm.equals(EcdhModel.ENCRYPTION_ALGORITHM.AES_CBC_PKCS5PADDING.toString())) {
                cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(initVector));
            } else if (encryptionAlgorithm.equals(EcdhModel.ENCRYPTION_ALGORITHM.AES_GCM_NOPADDING.toString())) {
                cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(16, initVector));
            }
            decryptedData = cipher.doFinal(ciphertext);
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException |
                 BadPaddingException | NoSuchPaddingException |
                 InvalidAlgorithmParameterException | InvalidKeyException e) {
            //throw new RuntimeException(e);
            System.out.println("** Exception: " + e.getMessage());
            return null;
        }
        // build the return model
        return decryptedData;
    }
    private static byte[] generateRandomNumber(int length) {
        if (length < 1) return null;
        byte[] number = new byte[length];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(number);
        return number;
    }


    private static String base64EncodingNpe(byte[] input) {
        if (input == null) return null;
        return Base64.encodeToString(input, Base64.NO_WRAP);
    }

    private static byte[] base64Decoding(String input) {
        if (TextUtils.isEmpty(input)) return null;
        return Base64.decode(input, Base64.NO_WRAP);
    }

}
