package de.androidcrypto.eccryptography;

import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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
import de.androidcrypto.eccryptography.model.EncryptionModel;
import de.androidcrypto.eccryptography.model.PrivateKeyModel;
import de.androidcrypto.eccryptography.model.PublicKeyModel;

/**
 * This class does all the work with low level methods. It does NOT use the Android Keystore
 * to create and store the EC keys.
 * Security warning: This app exposes the private key and is for demonstration only.
 * The main problem is the secure storage of the private key material generated by the class.
 */

public class EcEncryption {

    private static final String TAG = "EcEncryption";
    private static final String HKDF_AES_KEY = "aes-key";

    /**
     * encapsulated methods
     */

    public static PrivateKeyModel generateEcKeyPair(KEY_PARAMETER key_parameter) {
        int keyLength;
        if (key_parameter == KEY_PARAMETER.P_256) {
            keyLength = 256;
        } else if (key_parameter == KEY_PARAMETER.P_521) {
            keyLength = 521;
        } else {
            Log.d(TAG, "unsupported key parameter, aborted");
            return null;
        }
        KeyPair keyPair = generateEcKeyPairInternal(key_parameter);
        if (keyPair == null) {
            Log.e(TAG, "could not generate PrivateKeyModel, aborted");
            return null;
        }
        String keyId = generateUuid();
        PrivateKeyModel pkm = new PrivateKeyModel(
                KEY_TYPE.EC.toString(),
                key_parameter.toString(),
                keyId,
                base64EncodingNpe(keyPair.getPrivate().getEncoded()),
                base64EncodingNpe(keyPair.getPublic().getEncoded())
        );
        Log.d(TAG, "PrivateKeyModel generated with keyId: " + keyId + " and keyLength: " + keyLength);
        return pkm;
    }

    public static PublicKeyModel getPublicKeyModelFromPrivateKeyModel(PrivateKeyModel pkm) {
        if (pkm == null) {
            Log.d(TAG, "PrivateKeyModel is NULL, aborted");
            return null;
        }
        return new PublicKeyModel(
                pkm.getKeyType(),
                pkm.getKeyParameter(),
                pkm.getKeyId(),
                pkm.getPublicKeyEncodedBase64()
        );
    }

    public static EncryptionModel ecdhEncryption(
            PrivateKeyModel privateKeyModel,
            PublicKeyModel remotePublicKeyModel,
            HKDF_ALGORITHM hkdf_algorithm,
            ENCRYPTION_ALGORITHM encryptionAlgorithm,
            byte[] dataToEncrypt,
            boolean isEcdhe) {
        if (privateKeyModel == null) {
            Log.d(TAG, "privateKeyModel is NULL, aborted");
            return null;
        }
        if (remotePublicKeyModel == null) {
            Log.d(TAG, "remotePublicModel is NULL, aborted");
            return null;
        }
        if (dataToEncrypt == null) {
            Log.d(TAG, "dataToEncrypt is NULL, aborted");
            return null;
        }
        // check that keyParameter and keyType are equals for private and public key
        if (!privateKeyModel.getKeyParameter().equals(remotePublicKeyModel.getKeyParameter())) {
            Log.d(TAG, "the key parameter are not equals in PrivateKeyModel and PublicKeyModel, aborted");
            return null;
        }
        if (!privateKeyModel.getKeyType().equals(remotePublicKeyModel.getKeyType())) {
            Log.d(TAG, "the key type are not equals in PrivateKeyModel and PublicKeyModel, aborted");
            return null;
        }
        if (isEcdhe) {
            Log.d(TAG, "the encryption is running in ECDHE mode");
        } else {
            Log.d(TAG, "the encryption is running in ECDH mode");
        }

        // get shared secret
        // private key
        PrivateKey privateKey = getPrivateKeyFromEncoded(base64Decoding(privateKeyModel.getPrivateKeyEncodedBase64()));
        PublicKey remotePublicKey = getPublicKeyFromEncoded(base64Decoding(remotePublicKeyModel.getPublicKeyEncodedBase64()));
        if (privateKey == null) {
            Log.e(TAG, "could not retrieve the Private Key, aborted");
            return null;
        }
        if (remotePublicKey == null) {
            Log.e(TAG, "could not retrieve the remote Public Key, aborted");
            return null;
        }
        byte[] sharedSecret = getEcdhSharedSecret(privateKey, remotePublicKey);
        if (sharedSecret == null) {
            Log.e(TAG, "could not calculate the shared secret, aborted");
            return null;
        }

        // derive the encryption key
        byte[][] encryptionKeyArray = deriveEncryptionKeyHkdf(hkdf_algorithm, HKDF_NAME.AES_KEY, sharedSecret);
        if (encryptionKeyArray == null) {
            Log.e(TAG, "can not derive the encryption key, aborted");
            return null;
        }

        // encryptionTransformation
        String transformation = "";
        if (encryptionAlgorithm == ENCRYPTION_ALGORITHM.AES_CBC_PKCS5PADDING) {
            transformation = "AES/CBC/PKCS5PADDING";
        } else if (encryptionAlgorithm == ENCRYPTION_ALGORITHM.AES_GCM_NOPADDING) {
            transformation = "AES/GCM/NOPADDING";
        } else {
            // at this point no valid encryptionAlgorithm was found
            Log.e(TAG, "no valid encryptionAlgorithm found, aborted");
            return null;
        }
        // run the encryption
        EncryptionModel encryptionModel = encryptAesInternal(
                HKDF_ALGORITHM.HMAC_SHA256.toString(),
                encryptionAlgorithm.toString(),
                transformation,
                privateKeyModel.getKeyId(),
                remotePublicKeyModel.getKeyId(),
                encryptionKeyArray[1], // derive salt
                EcEncryption.HKDF_NAME.AES_KEY.toString(),
                encryptionKeyArray[0],
                dataToEncrypt,
                isEcdhe,
                privateKeyModel.getPublicKeyEncodedBase64()
        );
        if (encryptionModel == null) {
            Log.e(TAG, "Error during encryption");
            return null;
        }
        Log.d(TAG, "the data was encrypted");
        return encryptionModel;
    }

    public static byte[] ecdhDecryption(PrivateKeyModel privateKeyModel, PublicKeyModel remotePublicKeyModel, EncryptionModel encryptionModel) {
        boolean isEcdheMode = false;
        if (privateKeyModel == null) {
            Log.d(TAG, "privateKeyModel is NULL, aborted");
            return null;
        }

        if (encryptionModel == null) {
            Log.d(TAG, "encryption model is NULL, aborted");
            return null;
        }

        // check if senderPublicKeyBase is present, if yes we are running in ECDHE mode
        String senderPublicKeyBase64 = encryptionModel.getSenderPublicKeyBase64();
        if (!TextUtils.isEmpty(senderPublicKeyBase64)) {
            // we are running in ECDHE mode
            Log.d(TAG, "found a senderPublicKeyBase64 in encryptionModel, running ECDHE mode");
            isEcdheMode = true;
        } else {
            Log.d(TAG, "not found a senderPublicKeyBase64 in encryptionModel, running ECDH mode");
        }
        if (!isEcdheMode) {
            // check only if it is the ECDH mode

            if (remotePublicKeyModel == null) {
                Log.d(TAG, "remotePublicModel is NULL, aborted");
                return null;
            }

            // check that keyParameter and keyType are equals for private and public key
            if (!privateKeyModel.getKeyParameter().equals(remotePublicKeyModel.getKeyParameter())) {
                Log.d(TAG, "the key parameter are not equals in PrivateKeyModel and PublicKeyModel, aborted");
                return null;
            }
            if (!privateKeyModel.getKeyType().equals(remotePublicKeyModel.getKeyType())) {
                Log.d(TAG, "the key type are not equals in PrivateKeyModel and PublicKeyModel, aborted");
                return null;
            }
        }

        // get shared secret
        // private key
        PrivateKey privateKey = getPrivateKeyFromEncoded(base64Decoding(privateKeyModel.getPrivateKeyEncodedBase64()));
        PublicKey remotePublicKey;
        if (isEcdheMode) {
            remotePublicKey = getPublicKeyFromEncoded(base64Decoding(senderPublicKeyBase64));
        } else {
            remotePublicKey = getPublicKeyFromEncoded(base64Decoding(remotePublicKeyModel.getPublicKeyEncodedBase64()));
        }
        if (privateKey == null) {
            Log.e(TAG, "could not retrieve the Private Key, aborted");
            return null;
        }
        if (remotePublicKey == null) {
            Log.e(TAG, "could not retrieve the remote Public Key, aborted");
            return null;
        }
        byte[] sharedSecret = getEcdhSharedSecret(privateKey, remotePublicKey);
        if (sharedSecret == null) {
            Log.e(TAG, "could not calculate the shared secret, aborted");
            return null;
        }

        // check that the presented keys do have the same keyId as the ones in encryptionModel
        if (!privateKeyModel.getKeyId().equals(encryptionModel.getRecipientKeyId())) {
            Log.e(TAG, "the keyId in the Private Key Model does not match the recipientKeyId in encryptedModel, aborted");
            return null;
        }
        if (!isEcdheMode) {
            if (!remotePublicKeyModel.getKeyId().equals(encryptionModel.getSenderKeyId())) {
                Log.e(TAG, "the keyId in the remote Public Key Model does not match the senderKeyId in encryptedModel, aborted");
                return null;
            }
        }

        // derive the encryption key
        byte[] encryptionKey = getEncryptionKeyHkdf(
                encryptionModel.getDeriveAlgorithm(),
                HKDF_NAME.AES_KEY,
                sharedSecret,
                base64Decoding(encryptionModel.getDeriveSaltBase64()));
        if (encryptionKey == null) {
            Log.e(TAG, "could not derive the encryption key, aborted");
            return null;
        }
        // encryptionTransformation
        String encryptionAlgorithm = encryptionModel.getEncryptionAlgorithm();
        String transformation = "";
        if (encryptionAlgorithm.equals(ENCRYPTION_ALGORITHM.AES_CBC_PKCS5PADDING.toString())) {
            transformation = "AES/CBC/PKCS5PADDING";
        } else if (encryptionAlgorithm.equals(ENCRYPTION_ALGORITHM.AES_GCM_NOPADDING.toString())) {
            transformation = "AES/GCM/NOPADDING";
        } else {
            // at this point no valid encryptionAlgorithm was found
            Log.e(TAG, "no valid encryptionAlgorithm found, aborted");
            return null;
        }
        byte[] decryptedData = decryptAesInternal(
                encryptionAlgorithm,
                transformation,
                encryptionKey,
                base64Decoding(encryptionModel.getIvBase64()),
                base64Decoding(encryptionModel.getCiphertextBase64())
        );
        if (decryptedData == null) {
            Log.e(TAG, "error during decryption, aborted");
            return null;
        }
        return decryptedData;
    }

    public static enum KEY_PARAMETER {
        P_256, P_521
    }

    public static enum KEY_TYPE {
        EC, RSA
    }

    /**
     * single steps
     * These steps are for demonstration only and do have no exception management
     */




    /**
     * internal methods
     */


    public static KeyPair generateEcKeyPairInternal(KEY_PARAMETER key_parameter) {
        int keyLength;
        if (key_parameter == KEY_PARAMETER.P_256) {
            keyLength = 256;
        } else if (key_parameter == KEY_PARAMETER.P_521) {
            keyLength = 521;
        } else {
            Log.d(TAG, "unsupported key parameter, aborted");
            return null;
        }
        return generateEcKeyPair(keyLength);
    }

    public static KeyPair generateEcKeyPair(int keyLength) {
        // check for allowed key lengths
        if ((keyLength != 256) && (keyLength != 384) && (keyLength != 521)) {
            Log.d(TAG, "Key length has to be 256, 384 or 521, aborted");
            return null;
        }
        KeyPair kp;
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(keyLength);
            kp = kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "Error: " + e.getMessage());
            return null;
        }
        Log.d(TAG, "EC key pair generated with length " + keyLength);
        return kp;
    }

    public static PrivateKey getPrivateKeyFromEncoded(byte[] encodedPrivateKey) {
        if (encodedPrivateKey == null) {
            Log.d(TAG, "encoded Private Key is NULL, aborted");
            return null;
        }
        KeyFactory kf = null;
        PrivateKey privateKey;
        try {
            kf = KeyFactory.getInstance("EC");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
            privateKey = kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            Log.e(TAG, "Error: " + e.getMessage());
            return null;
        }
        Log.d(TAG, "Private Key from encoded generated");
        return privateKey;
    }

    public static PublicKey getPublicKeyFromEncoded(byte[] encodedPublicKey) {
        if (encodedPublicKey == null) {
            Log.d(TAG, "encoded Public Key is NULL, aborted");
            return null;
        }
        KeyFactory kf = null;
        PublicKey publicKey;
        try {
            kf = KeyFactory.getInstance("EC");
            X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(encodedPublicKey);
            publicKey = kf.generatePublic(pkSpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            Log.e(TAG, "Error: " + e.getMessage());
            return null;
        }
        Log.d(TAG, "Public Key from encoded generated");
        return publicKey;
    }

    /**
     * JSON converter
     */

    public static String privateKeyModelToJson(PrivateKeyModel privateKeyModel) {
        return new GsonBuilder().setPrettyPrinting().create().toJson(privateKeyModel, PrivateKeyModel.class);
    }

    public static PrivateKeyModel privateKeyModelFromJson(String jsonString) {
        Gson gson = new Gson();
        return gson.fromJson(jsonString, PrivateKeyModel.class);
    }

    public static String publicKeyModelToJson(PublicKeyModel publicKeyModel) {
        return new GsonBuilder().setPrettyPrinting().create().toJson(publicKeyModel, PublicKeyModel.class);
    }

    public static PublicKeyModel publicKeyModelFromJson(String jsonString) {
        Gson gson = new Gson();
        return gson.fromJson(jsonString, PublicKeyModel.class);
    }

    public static String encryptionModelToJson(EncryptionModel encryptionModel) {
        return new GsonBuilder().setPrettyPrinting().create().toJson(encryptionModel, EncryptionModel.class);
    }

    // todo change model to new class EncryptionModel
    public static EncryptionModel encryptionModelFromJson(String jsonString) {
        Gson gson = new Gson();
        return gson.fromJson(jsonString, EncryptionModel.class);
    }


    public static byte[] getEcdhSharedSecret(PrivateKey privateKey, PublicKey remotePublicKey) {
        if (privateKey == null) {
            Log.d(TAG, "Private Key is NULL, aborted");
            return null;
        }
        if (remotePublicKey == null) {
            Log.d(TAG, "remote Public Key is NULL, aborted");
            return null;
        }
        KeyAgreement ka = null;
        try {
            ka = KeyAgreement.getInstance("ECDH");
            ka.init(privateKey);
            ka.doPhase(remotePublicKey, true);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            Log.e(TAG, "Error: " + e.getMessage());
            return null;
        }
        Log.d(TAG, "ECDH shared secret generated");
        return ka.generateSecret();
    }

    public static enum HKDF_ALGORITHM {
        HMAC_SHA256, HMAC_SHA512
    }

    public static enum HKDF_NAME {
        AES_KEY
    }

    public static byte[][] deriveEncryptionKeyHkdf(HKDF_ALGORITHM hkdf_algorithm, HKDF_NAME hkdf_name, byte[] sharedSecret) {
        // HKDF algorithm
        HKDF hkdf = null;
        if (hkdf_algorithm.equals(HKDF_ALGORITHM.HMAC_SHA256)) {
            hkdf = HKDF.fromHmacSha256();
        } else if (hkdf_algorithm.equals(HKDF_ALGORITHM.HMAC_SHA512)) {
            hkdf = HKDF.fromHmacSha512();
        } else {
            // at this pint no valid deriveAlgorithm was found
            Log.e(TAG, "no valid HKDF algorithm found, aborted");
            return null;
        }
        if (sharedSecret == null) {
            Log.d(TAG, "shared secret is NULL, aborted");
        }
        byte[][] result = new byte[2][];
        // generate a random salt
        byte[] randomSalt32Byte = generateRandomNumber(32);
        byte[] pseudoRandomKey;
        pseudoRandomKey = hkdf.extract(randomSalt32Byte, sharedSecret);
        // create expanded bytes for e.g. AES secret key
        result[0] = hkdf.expand(pseudoRandomKey, hkdf_name.toString().getBytes(StandardCharsets.UTF_8), 32);
        result[1] = randomSalt32Byte;
        return result;
    }

    public static byte[] getEncryptionKeyHkdf(String hkdfAlgorithm, HKDF_NAME hkdf_name, byte[] sharedSecret, byte[] salt) {
        // HKDF algorithm
        HKDF hkdf = null;
        if (hkdfAlgorithm.equals(HKDF_ALGORITHM.HMAC_SHA256.toString())) {
            hkdf = HKDF.fromHmacSha256();
        } else if (hkdfAlgorithm.equals(HKDF_ALGORITHM.HMAC_SHA512.toString())) {
            hkdf = HKDF.fromHmacSha512();
        } else {
            // at this pint no valid deriveAlgorithm was found
            Log.e(TAG, "no valid HKDF algorithm found, aborted");
            return null;
        }
        if (sharedSecret == null) {
            Log.d(TAG, "shared secret is NULL, aborted");
        }
        // generate a random salt
        byte[] pseudoRandomKey;
        pseudoRandomKey = hkdf.extract(salt, sharedSecret);
        // create expanded bytes for e.g. AES secret key
        return hkdf.expand(pseudoRandomKey, hkdf_name.toString().getBytes(StandardCharsets.UTF_8), 32);
    }

    public static byte[] getEncryptionKeyHkdf(String hkdfAlgorithm, String hkdf_name, byte[] sharedSecret, byte[] salt) {
        // HKDF algorithm
        HKDF hkdf = null;
        if (hkdfAlgorithm.equals(HKDF_ALGORITHM.HMAC_SHA256.toString())) {
            hkdf = HKDF.fromHmacSha256();
        } else if (hkdfAlgorithm.equals(HKDF_ALGORITHM.HMAC_SHA512.toString())) {
            hkdf = HKDF.fromHmacSha512();
        } else {
            // at this pint no valid deriveAlgorithm was found
            Log.e(TAG, "no valid HKDF algorithm found, aborted");
            return null;
        }
        String hkdfName;
        if (hkdf_name.equals(HKDF_NAME.AES_KEY.toString())) {
            hkdfName = HKDF_NAME.AES_KEY.toString();
        } else {
            // at this pint no valid hkdf_name was found
            Log.e(TAG, "no valid HKDF name found, aborted");
            return null;
        }

        if (sharedSecret == null) {
            Log.d(TAG, "shared secret is NULL, aborted");
        }
        // generate a random salt
        byte[] pseudoRandomKey;
        pseudoRandomKey = hkdf.extract(salt, sharedSecret);
        // create expanded bytes for e.g. AES secret key
        return hkdf.expand(pseudoRandomKey, hkdfName.getBytes(StandardCharsets.UTF_8), 32);
    }

    public static byte[] getEncryptionKeyHkdf(HKDF_ALGORITHM hkdf_algorithm, HKDF_NAME hkdf_name, byte[] sharedSecret, byte[] salt) {
        // HKDF algorithm
        HKDF hkdf = null;
        if (hkdf_algorithm.equals(HKDF_ALGORITHM.HMAC_SHA256)) {
            hkdf = HKDF.fromHmacSha256();
        } else if (hkdf_algorithm.equals(HKDF_ALGORITHM.HMAC_SHA512)) {
            hkdf = HKDF.fromHmacSha512();
        } else {
            // at this pint no valid deriveAlgorithm was found
            Log.e(TAG, "no valid HKDF algorithm found, aborted");
            return null;
        }
        if (sharedSecret == null) {
            Log.d(TAG, "shared secret is NULL, aborted");
        }
        // generate a random salt
        byte[] pseudoRandomKey;
        pseudoRandomKey = hkdf.extract(salt, sharedSecret);
        // create expanded bytes for e.g. AES secret key
        return hkdf.expand(pseudoRandomKey, hkdf_name.toString().getBytes(StandardCharsets.UTF_8), 32);
    }

    public static enum ENCRYPTION_ALGORITHM {
        AES_CBC_PKCS5PADDING, AES_GCM_NOPADDING
    }

    public static EncryptionModel encryptAesInternal(
            String hkdfAlgorithm,
            String encryptionAlgorithm,
            String transformation,
            String senderKeyId,
            String recipientKeyId,
            byte[] deriveSalt,
            String deriveName,
            byte[] encryptionKey,
            byte[] data,
            boolean isEcdhe,
            String senderPublicKeyBase64) {

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
        String senderPublicKey = ""; // ecdh encryption
        if (isEcdhe) {
            senderPublicKey = senderPublicKeyBase64;
        }
       return new EncryptionModel(
                senderKeyId,
                recipientKeyId,
                senderPublicKey,
                base64EncodingNpe(deriveSalt),
                deriveName,
                hkdfAlgorithm,
                encryptionAlgorithm,
                base64EncodingNpe(initVector),
                base64EncodingNpe(ciphertext));
    }

    public static byte[] decryptAesInternal(String encryptionAlgorithm, String transformation, byte[] encryptionKey, byte[] initVector, byte[] ciphertext) {
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


    public static EncryptionModel encryptAesSingle(String deriveAlgorithm, String encryptionAlgorithm, String transformation, String aliasSender, String aliasRecipient, byte[] deriveSalt, String deriveName, byte[] encryptionKey, byte[] data) {
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
        return new EncryptionModel(aliasSender, aliasRecipient, "", base64EncodingNpe(deriveSalt), deriveName, deriveAlgorithm, encryptionAlgorithm, base64EncodingNpe(initVector), base64EncodingNpe(ciphertext));
    }

    public static EcdhModel encryptAes(String deriveAlgorithm, String encryptionAlgorithm, String transformation, String aliasRecipient, byte[] deriveSalt, String deriveName, byte[] encryptionKey, byte[] data) {
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

    public static String generateUuid() {
        UUID uuid = UUID.randomUUID();
        return uuid.toString();
    }

    public static byte[] generateRandomNumber(int length) {
        if (length < 1) return null;
        byte[] number = new byte[length];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(number);
        return number;
    }

    public static String base64EncodingNpe(byte[] input) {
        if (input == null) return null;
        return Base64.encodeToString(input, Base64.NO_WRAP);
    }

    public static byte[] base64Decoding(String input) {
        if (TextUtils.isEmpty(input)) return null;
        return Base64.decode(input, Base64.NO_WRAP);
    }

}
