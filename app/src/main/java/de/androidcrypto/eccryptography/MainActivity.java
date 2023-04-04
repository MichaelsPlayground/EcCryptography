package de.androidcrypto.eccryptography;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.ParseException;

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
import de.androidcrypto.eccryptography.model.EcdheModel;
import de.androidcrypto.eccryptography.model.EncryptionModel;
import de.androidcrypto.eccryptography.model.PrivateKeyModel;
import de.androidcrypto.eccryptography.model.PublicKeyModel;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainAct";

    Button btn2, btn3, btn4, btn5, btn6, btn7, btn8, btn9, btn10, btn11, btn12, btn13, btn14, btn15;
    TextView tv2;

    private static final String EC_SPEC_P256 = "p-256";
    private static final String EC_SPEC_P521 = "p-521";
    private static final String KEY_AGREEMENT_ALG = "ECDH";
    private static final String KEY_STORE_PROVIDER = "AndroidKeyStore";
    KeyPair one;
    KeyPair two;
    byte[] shareOne;
    byte[] shareTwo;
    byte[] expandedAesKeyOne;
    byte[] expandedAesKeyTwo;
    byte[] expandedIvOne, expandedIvTwo;
    byte[] expandedNonceOne, expandedNonceTwo;
    byte[] plaintext, encrypted; byte[] decrypted;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        btn2 = findViewById(R.id.btn2);
        btn3 = findViewById(R.id.btn3);
        btn4 = findViewById(R.id.btn4);
        btn5 = findViewById(R.id.btn5);
        btn6 = findViewById(R.id.btn6);
        btn7 = findViewById(R.id.btn7);
        btn8 = findViewById(R.id.btn8);
        btn9 = findViewById(R.id.btn9);
        btn10 = findViewById(R.id.btn10);
        btn11 = findViewById(R.id.btn11);
        btn12 = findViewById(R.id.btn12);
        btn13 = findViewById(R.id.btn13);
        btn14 = findViewById(R.id.btn14);
        btn15 = findViewById(R.id.btn15);
        tv2 = findViewById(R.id.tv2);

        // check for Android version
        // CODES.S = Android 31
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            btn2.setEnabled(false);
            btn3.setEnabled(false);
            btn4.setEnabled(false);
            //btn5.setEnabled(false); // manual work
            btn6.setEnabled(false);
            btn7.setEnabled(false);
            btn8.setEnabled(false);
            btn9.setEnabled(false);
        }

        btn2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.i(TAG, "btn2");
                // generate key pairs
                try {
                    // try with curve P-256
                    one = generateKeysP256("alias_one");
                    two = generateKeysP256("alias_two");
                    // try with curve P-521
                    // one = generateKeysP521("alias_one");
                    // two = generateKeysP521("alias_two");
                } catch (NoSuchAlgorithmException | NoSuchProviderException |
                         InvalidAlgorithmParameterException | ParseException e) {
                    throw new RuntimeException(e);
                }
                StringBuilder sb = new StringBuilder();
                sb.append("Generated key pair one:").append("\n");
                sb.append("Private Key: ").append("not exported from Android's keystore").append("\n");
                //sb.append("Private Key: ").append(bytesToHexNpe(one.getPrivate().getEncoded())).append("\n");
                sb.append("Public  Key: ").append(bytesToHexNpe(one.getPublic().getEncoded())).append("\n");
                sb.append("Generated key pair two:").append("\n");
                sb.append("Private Key: ").append("not exported from Android's keystore").append("\n");
                //sb.append("Private Key: ").append(bytesToHexNpe(two.getPrivate().getEncoded())).append("\n");
                sb.append("Public  Key: ").append(bytesToHexNpe(two.getPublic().getEncoded())).append("\n");
                tv2.setText(sb.toString());
                Log.d(TAG, "step 1 generate key pairs:\n" + sb.toString());
            }
        });

        btn3.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.i(TAG, "btn3");
                // shared keys
                try {
                    shareOne = sharedSecret(one.getPrivate(), two.getPublic());
                    shareTwo = sharedSecret(two.getPrivate(), one.getPublic());
                } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException e) {
                    throw new RuntimeException(e);
                } catch (NullPointerException e) {
                    tv2.setText("please generate a key pair first");
                    return;
                }
                try {
                    StringBuilder sb = new StringBuilder();
                    sb.append("shared secret one:").append("\n");
                    sb.append("shared key length: ").append(shareOne.length).append(" data: ").append(bytesToHexNpe(shareOne)).append("\n");
                    sb.append("shared secret two:").append("\n");
                    sb.append("shared key length: ").append(shareOne.length).append(" data: ").append(bytesToHexNpe(shareTwo)).append("\n");
                    tv2.setText(sb.toString());
                    Log.d(TAG, "step 2 calculate the shared secrets:\n" + sb.toString());
                } catch (NullPointerException e) {
                    tv2.setText("Error in generating the shared secret");
                }
            }
        });

        // https://gist.github.com/thackerronak/554c985c3001b16810af5fc0eb5c358f

        // hkdf: https://github.com/patrickfav/hkdf

        btn4.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.i(TAG, "btn4");
                // HKDF

                // This example creates a high-quality AES secret key and initialization vector from a shared secret calculated by a
                // key agreement protocol and encrypts with CBC block mode:
                //if no dynamic salt is available, a static salt is better than null
                byte[] staticSalt32Byte = new byte[]{(byte) 0xDA, (byte) 0xAC, 0x3E, 0x10, 0x55, (byte) 0xB5, (byte) 0xF1, 0x3E, 0x53, (byte) 0xE4, 0x70, (byte) 0xA8, 0x77, 0x79, (byte) 0x8E, 0x0A, (byte) 0x89, (byte) 0xAE, (byte) 0x96, 0x5F, 0x19, 0x5D, 0x53, 0x62, 0x58, (byte) 0x84, 0x2C, 0x09, (byte) 0xAD, 0x6E, 0x20, (byte) 0xD4};

                HKDF hkdf = HKDF.fromHmacSha256();

                //extract the "raw" data to create output with concentrated entropy
                byte[] pseudoRandomKeyOne;
                byte[] pseudoRandomKeyTwo;
                try {
                    pseudoRandomKeyOne = hkdf.extract(staticSalt32Byte, shareOne);
                    pseudoRandomKeyTwo = hkdf.extract(staticSalt32Byte, shareTwo);
                } catch (IllegalArgumentException e) {
                    tv2.setText("please generate the shared secret first");
                    return;
                }

                //create expanded bytes for e.g. AES secret key and IV
                expandedAesKeyOne = hkdf.expand(pseudoRandomKeyOne, "aes-key".getBytes(StandardCharsets.UTF_8), 32);
                expandedIvOne = hkdf.expand(pseudoRandomKeyOne, "aes-iv".getBytes(StandardCharsets.UTF_8), 16);
                expandedNonceOne = hkdf.expand(pseudoRandomKeyOne, "aes-nonce".getBytes(StandardCharsets.UTF_8), 12);

                expandedAesKeyTwo = hkdf.expand(pseudoRandomKeyTwo, "aes-key".getBytes(StandardCharsets.UTF_8), 32);
                expandedIvTwo = hkdf.expand(pseudoRandomKeyTwo, "aes-iv".getBytes(StandardCharsets.UTF_8), 16);
                expandedNonceTwo = hkdf.expand(pseudoRandomKeyTwo, "aes-nonce".getBytes(StandardCharsets.UTF_8), 12);

                StringBuilder sb = new StringBuilder();
                sb.append("HKDF one:").append("\n");
                sb.append("expandedAesKey length: ").append(expandedAesKeyOne.length).append(" data: ").append(bytesToHexNpe(expandedAesKeyOne)).append("\n");
                sb.append("expandedIv     length: ").append(expandedIvOne.length).append(" data: ").append(bytesToHexNpe(expandedIvOne)).append("\n");
                sb.append("expandedNonce  length: ").append(expandedNonceOne.length).append(" data: ").append(bytesToHexNpe(expandedNonceOne)).append("\n");
                sb.append("HKDF two:").append("\n");
                sb.append("expandedAesKey length: ").append(expandedAesKeyTwo.length).append(" data: ").append(bytesToHexNpe(expandedAesKeyTwo)).append("\n");
                sb.append("expandedIv     length: ").append(expandedIvTwo.length).append(" data: ").append(bytesToHexNpe(expandedIvTwo)).append("\n");
                sb.append("expandedNonce  length: ").append(expandedNonceTwo.length).append(" data: ").append(bytesToHexNpe(expandedNonceTwo)).append("\n");
                tv2.setText(sb.toString());
                Log.d(TAG, "step 3 derive the encryption key using HKDF from shared secrets:\n" + sb.toString());
            }
        });

        btn5.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.i(TAG, "btn 5");
                tv2.setText("");

                // manual work
                // Generate ephemeral ECDH keypair
                KeyPair kp1;
                try {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                    kpg.initialize(256);
                    //kpg.initialize(521);
                    //kpg.initialize(384);
                    kp1 = kpg.generateKeyPair();
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }

                byte[] ourPriKey1 = kp1.getPrivate().getEncoded();
                byte[] ourPubKey1 = kp1.getPublic().getEncoded();

                KeyPair kp2;
                try {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                    kpg.initialize(256);
                    kp2 = kpg.generateKeyPair();
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
                byte[] remotePriKey2 = kp2.getPrivate().getEncoded();
                byte[] remotePubKey2 = kp2.getPublic().getEncoded();

                KeyFactory kf = null;
                PublicKey remotePublicKey;
                try {
                    kf = KeyFactory.getInstance("EC");
                    X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(remotePubKey2);
                    remotePublicKey = kf.generatePublic(pkSpec);
                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    throw new RuntimeException(e);
                }
                // Perform key agreement
                KeyAgreement ka = null;
                try {
                    ka = KeyAgreement.getInstance("ECDH");
                    ka.init(kp1.getPrivate());
                    ka.doPhase(remotePublicKey, true);
                } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                    throw new RuntimeException(e);
                }
                // Read shared secret
                byte[] sharedSecret1 = ka.generateSecret();

                // shared secret 2
                KeyAgreement ka2= null;
                try {
                    ka2 = KeyAgreement.getInstance("ECDH");
                    ka2.init(kp2.getPrivate());
                    ka2.doPhase(kp1.getPublic(), true);
                } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                    throw new RuntimeException(e);
                }
                // Read shared secret
                byte[] sharedSecret2 = ka2.generateSecret();

                // HKDF only for shared secret 1
                // get the encryption key with hkdf
                byte[] randomSalt32Byte = generateRandomNumber(32);
                byte[] pseudoRandomKey;
                //HKDF hkdf = HKDF.fromHmacSha512();
                HKDF hkdf = HKDF.fromHmacSha256();
                pseudoRandomKey = hkdf.extract(randomSalt32Byte, sharedSecret1);
                //create expanded bytes for e.g. AES secret key and IV
                byte[] encryptionKey1 = hkdf.expand(pseudoRandomKey, "aes-key".getBytes(StandardCharsets.UTF_8), 32);

                StringBuilder sb = new StringBuilder();
                sb.append("Manual ECDH").append("\n");
                sb.append("PrivateKey 1: ").append(kp1.getPrivate().toString()).append(" Algorithm: ").append(kp1.getPrivate().getAlgorithm()).append("\n");
                sb.append("PublicKey  2: ").append(kp2.getPublic().toString()).append("\n");
                sb.append("Shared secret 1 length: ").append(sharedSecret1.length).append(" data: ").append(bytesToHexNpe(sharedSecret1)).append("\n");
                sb.append("Shared secret 2 length: ").append(sharedSecret2.length).append(" data: ").append(bytesToHexNpe(sharedSecret2)).append("\n");
                sb.append("encryptionKey 1 length: ").append(encryptionKey1.length).append(" data: ").append(bytesToHexNpe(encryptionKey1)).append("\n");
                tv2.setText(sb.toString());
            }
        });

        btn6.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.i(TAG, "btn6");
                // encryption / decryption
                //Example boilerplate encrypting a simple string with created key/iv
                // encryption
                plaintext = "my secret message".getBytes(StandardCharsets.UTF_8);
                SecretKey keyOne;
                try {
                    keyOne = new SecretKeySpec(expandedAesKeyOne, "AES"); //AES-256 key
                } catch (IllegalArgumentException e) {
                    tv2.setText("please run HKDF first");
                    return;
                }
                Cipher cipherOne = null;
                try {
                    cipherOne = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipherOne.init(Cipher.ENCRYPT_MODE, keyOne, new IvParameterSpec(expandedIvOne));
                    encrypted = cipherOne.doFinal(plaintext);
                } catch (NoSuchAlgorithmException | IllegalBlockSizeException |
                         BadPaddingException | NoSuchPaddingException |
                         InvalidAlgorithmParameterException | InvalidKeyException e) {
                    throw new RuntimeException(e);
                }
                // decryption
                SecretKey keyTwo;
                try {
                    keyTwo = new SecretKeySpec(expandedAesKeyTwo, "AES"); //AES-256 key
                } catch (IllegalArgumentException e) {
                    tv2.setText("please run HKDF first");
                    return;
                }
                Cipher cipherTwo = null;
                try {
                    cipherTwo = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipherTwo.init(Cipher.DECRYPT_MODE, keyTwo, new IvParameterSpec(expandedIvTwo));
                    decrypted = cipherTwo.doFinal(encrypted);
                } catch (NoSuchAlgorithmException | IllegalBlockSizeException |
                         BadPaddingException | NoSuchPaddingException |
                         InvalidAlgorithmParameterException | InvalidKeyException e) {
                    throw new RuntimeException(e);
                }
                StringBuilder sb = new StringBuilder();
                sb.append("AES/CBC/PKCS5Padding").append("\n");
                sb.append("plaintext one: ").append(new String(plaintext)).append("\n");
                sb.append("plaintext length: ").append(plaintext.length).append(" data: ").append(bytesToHexNpe(plaintext)).append("\n");
                sb.append("encrypted length: ").append(encrypted.length).append(" data: ").append(bytesToHexNpe(encrypted)).append("\n");
                sb.append("decrypted two").append("\n");
                sb.append("decrypted length: ").append(decrypted.length).append(" data: ").append(bytesToHexNpe(decrypted)).append("\n");
                sb.append("decrypted two: ").append(new String(decrypted)).append("\n");
                tv2.setText(sb.toString());
                Log.d(TAG, "step 4 encrypt and decrypt data with AES-CBC from HKDF derived keys:\n" + sb.toString());
            }
        });

        btn7.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.i(TAG, "btn 7");
                // encryption / decryption
                //Example boilerplate encrypting a simple string with created key/iv
                // encryption
                plaintext = "my secret message".getBytes(StandardCharsets.UTF_8);
                SecretKey keyOne;
                try {
                    keyOne = new SecretKeySpec(expandedAesKeyOne, "AES"); //AES-256 key
                } catch (IllegalArgumentException e) {
                    tv2.setText("please run HKDF first");
                    return;
                }
                Cipher cipherOne = null;
                try {
                    cipherOne = Cipher.getInstance("AES/GCM/NoPadding");
                    cipherOne.init(Cipher.ENCRYPT_MODE, keyOne, new GCMParameterSpec(16, expandedNonceOne));
                    encrypted = cipherOne.doFinal(plaintext);
                } catch (NoSuchAlgorithmException | IllegalBlockSizeException |
                         BadPaddingException | NoSuchPaddingException |
                         InvalidAlgorithmParameterException | InvalidKeyException e) {
                    throw new RuntimeException(e);
                }
                // decryption
                SecretKey keyTwo;
                try {
                    keyTwo = new SecretKeySpec(expandedAesKeyTwo, "AES"); //AES-256 key
                } catch (IllegalArgumentException e) {
                    tv2.setText("please run HKDF first");
                    return;
                }
                Cipher cipherTwo = null;
                try {
                    cipherTwo = Cipher.getInstance("AES/GCM/NoPadding");
                    cipherTwo.init(Cipher.DECRYPT_MODE, keyTwo, new GCMParameterSpec(16, expandedNonceTwo));
                    decrypted = cipherTwo.doFinal(encrypted);
                } catch (NoSuchAlgorithmException | IllegalBlockSizeException |
                         BadPaddingException | NoSuchPaddingException |
                         InvalidAlgorithmParameterException | InvalidKeyException e) {
                    throw new RuntimeException(e);
                } catch (IllegalArgumentException e) {

                }
                StringBuilder sb = new StringBuilder();
                sb.append("AES/GCM/NoPadding").append("\n");
                sb.append("plaintext one: ").append(new String(plaintext)).append("\n");
                sb.append("plaintext length: ").append(plaintext.length).append(" data: ").append(bytesToHexNpe(plaintext)).append("\n");
                sb.append("encrypted length: ").append(encrypted.length).append(" data: ").append(bytesToHexNpe(encrypted)).append("\n");
                sb.append("decrypted two").append("\n");
                sb.append("decrypted length: ").append(decrypted.length).append(" data: ").append(bytesToHexNpe(decrypted)).append("\n");
                sb.append("decrypted two: ").append(new String(decrypted)).append("\n");
                tv2.setText(sb.toString());
                Log.d(TAG, "step 4 encrypt and decrypt data with AES-GCM from HKDF derived keys:\n" + sb.toString());
            }
        });

        btn8.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.d(TAG, "btn8");
                StringBuilder sb = new StringBuilder();
                sb.append("ECDH encryption").append("\n");
                // step 1 generate key pairs
                String uuid1 = EcdhEncryption.generateUuid();
                sb.append("generate EC key 1 with UUID: ").append(uuid1).append("\n");
                PublicKeyModel pk1 = EcdhEncryption.generateEcKey(uuid1, PublicKeyModel.KEY_PARAMETER.P_256.toString());
                sb.append("publicKey 1:").append("\n").append(pk1.dump()).append("\n");
                String uuid2 = EcdhEncryption.generateUuid();
                sb.append("generate EC key 2 with UUID: ").append(uuid2).append("\n");
                PublicKeyModel pk2 = EcdhEncryption.generateEcKey(uuid2, PublicKeyModel.KEY_PARAMETER.P_256.toString());
                sb.append("publicKey 2:").append("\n").append(pk2.dump()).append("\n");

                String dataToEncryptString = "The quick fox";
                sb.append("=== Encryption ===").append("\n");
                sb.append("plaintext: ").append(dataToEncryptString).append("\n");
                byte[] dataToEncrypt = dataToEncryptString.getBytes(StandardCharsets.UTF_8);
                //EcdhModel ecdhCiphertext = EcdhEncryption.encryptData(uuid1, uuid2, pk2, EcdhModel.HKDF_ALGORITHM.HMAC_SHA256.toString() , EcdhModel.ENCRYPTION_ALGORITHM.AES_CBC_PKCS5PADDING.toString(), dataToEncrypt);
                EcdhModel ecdhCiphertext = EcdhEncryption.encryptData(uuid1, uuid2, pk2, EcdhModel.HKDF_ALGORITHM.HMAC_SHA512.toString() , EcdhModel.ENCRYPTION_ALGORITHM.AES_GCM_NOPADDING.toString(), dataToEncrypt);
                if (ecdhCiphertext != null) {
                    sb.append("encryptedData:").append("\n").append(ecdhCiphertext.dump()).append("\n");
                }
                sb.append("").append("\n");
                sb.append("=== Decryption ===").append("\n");

                KeyFactory kf = null;
                PublicKey senderPubKey;
                byte[] encodedSenderPublicKey = base64Decoding(pk1.getPublicKeyEncodedBase64());
                try {
                    kf = KeyFactory.getInstance("EC");
                    senderPubKey = (PublicKey) kf.generatePublic(new X509EncodedKeySpec(encodedSenderPublicKey));
                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    //throw new RuntimeException(e);
                    Log.e(TAG, "Exception: " + e.getMessage());
                    return;
                }
                byte[] decryptedData = EcdhEncryption.decryptData(ecdhCiphertext, senderPubKey);
                if (decryptedData != null) {
                    sb.append("decryptedData: ").append(new String(decryptedData)).append("\n");
                } else {
                    sb.append("Error on decryption").append("\n");
                }

                tv2.setText(sb.toString());
            }
        });

        btn9.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.d(TAG, "btn9");
                StringBuilder sb = new StringBuilder();
                sb.append("ECDHE encryption").append("\n");
                // step 1 generate key pairs
                String uuid1 = EcdheEncryption.generateUuid();
                sb.append("generate EC key 1 with UUID: ").append(uuid1).append("\n");
                PublicKeyModel pk1 = EcdheEncryption.generateEcKey(uuid1, PublicKeyModel.KEY_PARAMETER.P_256.toString());
                sb.append("publicKey 1:").append("\n").append(pk1.dump()).append("\n");
                String uuid2 = EcdheEncryption.generateUuid();
                sb.append("generate EC key 2 with UUID: ").append(uuid2).append("\n");
                PublicKeyModel pk2 = EcdheEncryption.generateEcKey(uuid2, PublicKeyModel.KEY_PARAMETER.P_256.toString());
                sb.append("publicKey 2:").append("\n").append(pk2.dump()).append("\n");

                String dataToEncryptString = "The quick fox";
                sb.append("=== Encryption ===").append("\n");
                sb.append("plaintext: ").append(dataToEncryptString).append("\n");
                byte[] dataToEncrypt = dataToEncryptString.getBytes(StandardCharsets.UTF_8);
                EcdheModel ecdheCiphertext = EcdheEncryption.encryptData(uuid1, uuid2, pk2, EcdhModel.HKDF_ALGORITHM.HMAC_SHA256.toString() , EcdhModel.ENCRYPTION_ALGORITHM.AES_CBC_PKCS5PADDING.toString(), dataToEncrypt);
                //EcdheModel ecdheCiphertext = EcdheEncryption.encryptData(uuid1, uuid2, pk2, EcdhModel.HKDF_ALGORITHM.HMAC_SHA512.toString() , EcdhModel.ENCRYPTION_ALGORITHM.AES_GCM_NOPADDING.toString(), dataToEncrypt);
                if (ecdheCiphertext != null) {
                    sb.append("encryptedData:").append("\n").append(ecdheCiphertext.dump()).append("\n");
                }
                sb.append("").append("\n");
                sb.append("=== Decryption ===").append("\n");

                KeyFactory kf = null;
                PublicKey senderPubKey;
                byte[] encodedSenderPublicKey = base64Decoding(pk1.getPublicKeyEncodedBase64());
                try {
                    kf = KeyFactory.getInstance("EC");
                    senderPubKey = (PublicKey) kf.generatePublic(new X509EncodedKeySpec(encodedSenderPublicKey));
                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    //throw new RuntimeException(e);
                    Log.e(TAG, "Exception: " + e.getMessage());
                    return;
                }
                byte[] decryptedData = EcdheEncryption.decryptData(ecdheCiphertext);
                if (decryptedData != null) {
                    sb.append("decryptedData: ").append(new String(decryptedData)).append("\n");
                } else {
                    sb.append("Error on decryption").append("\n");
                }

                tv2.setText(sb.toString());
            }
        });

        btn10.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.d(TAG, "btn10");
                tv2.setText("");
                StringBuilder sb = new StringBuilder();
                sb.append("Manual ECDH ext").append("\n");

                // generate a key pair
                KeyPair keyPair1 = EcEncryption.generateEcKeyPairInternal(EcEncryption.KEY_PARAMETER.P_256);
                sb.append("key pair 1 generated").append("\n");
                KeyPair keyPair2 = EcEncryption.generateEcKeyPairInternal(EcEncryption.KEY_PARAMETER.P_256);
                sb.append("key pair 2 generated").append("\n");
                sb.append("").append("\n");

                // generate PublicKeyModels
                String publicKey1Base64 = EcEncryption.base64EncodingNpe(keyPair1.getPublic().getEncoded());
                String keyId1 = EcEncryption.generateUuid();
                PublicKeyModel publicKeyModel1 = new PublicKeyModel(EcEncryption.KEY_TYPE.EC.toString(), EcEncryption.KEY_PARAMETER.P_256.toString(), keyId1, publicKey1Base64);
                String publicKey2Base64 = EcEncryption.base64EncodingNpe(keyPair2.getPublic().getEncoded());
                String keyId2 = EcEncryption.generateUuid();
                PublicKeyModel publicKeyModel2 = new PublicKeyModel(EcEncryption.KEY_TYPE.EC.toString(), EcEncryption.KEY_PARAMETER.P_256.toString(), keyId2, publicKey2Base64);
                sb.append("PublicKeyModel 1 generated").append("\n").append(publicKeyModel1.dump()).append("\n");
                sb.append("PublicKeyModel 2 generated").append("\n").append(publicKeyModel2.dump()).append("\n");

                // get the shared secrets
                sb.append("").append("\n");
                sb.append("get shared secrets").append("\n");
                byte[] sharedSecret1 = EcEncryption.getEcdhSharedSecret(keyPair1.getPrivate(), keyPair2.getPublic());
                byte[] sharedSecret2 = EcEncryption.getEcdhSharedSecret(keyPair2.getPrivate(), keyPair1.getPublic());
                sb.append("sharedSecret 1: ").append(EcEncryption.base64EncodingNpe(sharedSecret1)).append("\n");
                sb.append("sharedSecret 2: ").append(EcEncryption.base64EncodingNpe(sharedSecret2)).append("\n");

                // get the encryption keys
                sb.append("").append("\n");
                sb.append("get encryption keys").append("\n");
                byte[][] encryptionKeyArray1 = EcEncryption.deriveEncryptionKeyHkdf(EcEncryption.HKDF_ALGORITHM.HMAC_SHA256, EcEncryption.HKDF_NAME.AES_KEY, sharedSecret1);

                sb.append("EncryptionKey 1 generated:  ").append("\n").append(EcEncryption.base64EncodingNpe(encryptionKeyArray1[0])).append("\n");
                sb.append("EncryptionKey 1 randomSalt: ").append("\n").append(EcEncryption.base64EncodingNpe(encryptionKeyArray1[1])).append("\n");
                //sb.append("PublicKeyModel 2 generated").append("\n").append(publicKeyModel2.dump()).append("\n");
                byte[] encryptionKey2 = EcEncryption.getEncryptionKeyHkdf(EcEncryption.HKDF_ALGORITHM.HMAC_SHA256, EcEncryption.HKDF_NAME.AES_KEY, sharedSecret2, encryptionKeyArray1[1]);
                sb.append("EncryptionKey 2 generated:  ").append("\n").append(EcEncryption.base64EncodingNpe(encryptionKey2)).append("\n");

                // encrypt some data
                String plaintextString = "The quick brown fox jumps over the lazy dog";
                sb.append("").append("\n");
                sb.append("encrypt plaintext: ").append(plaintextString).append("\n");
                byte[] plaintext = plaintextString.getBytes(StandardCharsets.UTF_8);

                // public static EcdhModel encryptAes(String deriveAlgorithm, String encryptionAlgorithm, String transformation, String aliasRecipient, byte[] deriveSalt, String deriveName, byte[] encryptionKey, byte[] data) {
                EcdhModel ecdhModel1 = EcEncryption.encryptAes(
                        EcEncryption.HKDF_ALGORITHM.HMAC_SHA256.toString(),
                        EcEncryption.ENCRYPTION_ALGORITHM.AES_CBC_PKCS5PADDING.toString(),
                        "AES/CBC/PKCS5PADDING",
                        keyId2,
                        encryptionKeyArray1[1],
                        EcEncryption.HKDF_NAME.AES_KEY.toString(),
                        encryptionKeyArray1[0],
                        plaintext
                );
                sb.append("ecdhModel 1 generated").append("\n").append(ecdhModel1.dump()).append("\n");

                // decrypt the data
                sb.append("").append("\n");
                sb.append("decrypt ecdhModel 1").append("\n");

                // public static byte[] decryptAes(String encryptionAlgorithm, String transformation, String alias, byte[] encryptionKey, byte[] initVector, byte[] ciphertext) {
                byte[] decryptedData = EcEncryption.decryptAes(
                        EcEncryption.ENCRYPTION_ALGORITHM.AES_CBC_PKCS5PADDING.toString(),
                        "AES/CBC/PKCS5PADDING",
                        keyId2,
                        encryptionKey2,
                        EcEncryption.base64Decoding(ecdhModel1.getIvBase64()),
                        EcEncryption.base64Decoding(ecdhModel1.getCiphertextBase64())
                );
                sb.append("decryptedData: ").append("\n").append(new String(decryptedData, StandardCharsets.UTF_8)).append("\n");



                /*
                // manual work
                // Generate ephemeral ECDH keypair
                KeyPair kp1;
                try {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                    kpg.initialize(256);
                    //kpg.initialize(521);
                    //kpg.initialize(384);
                    kp1 = kpg.generateKeyPair();
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }

                byte[] ourPriKey1 = kp1.getPrivate().getEncoded();
                byte[] ourPubKey1 = kp1.getPublic().getEncoded();

                KeyPair kp2;
                try {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                    kpg.initialize(256);
                    kp2 = kpg.generateKeyPair();
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
                byte[] remotePriKey2 = kp2.getPrivate().getEncoded();
                byte[] remotePubKey2 = kp2.getPublic().getEncoded();

                KeyFactory kf = null;
                PublicKey remotePublicKey;
                try {
                    kf = KeyFactory.getInstance("EC");
                    X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(remotePubKey2);
                    remotePublicKey = kf.generatePublic(pkSpec);
                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    throw new RuntimeException(e);
                }
                // Perform key agreement
                KeyAgreement ka = null;
                try {
                    ka = KeyAgreement.getInstance("ECDH");
                    ka.init(kp1.getPrivate());
                    ka.doPhase(remotePublicKey, true);
                } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                    throw new RuntimeException(e);
                }
                // Read shared secret
                byte[] sharedSecret1 = ka.generateSecret();

                // shared secret 2
                KeyAgreement ka2= null;
                try {
                    ka2 = KeyAgreement.getInstance("ECDH");
                    ka2.init(kp2.getPrivate());
                    ka2.doPhase(kp1.getPublic(), true);
                } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                    throw new RuntimeException(e);
                }
                // Read shared secret
                byte[] sharedSecret2 = ka2.generateSecret();

                // HKDF only for shared secret 1
                // get the encryption key with hkdf
                byte[] randomSalt32Byte = generateRandomNumber(32);
                byte[] pseudoRandomKey;
                //HKDF hkdf = HKDF.fromHmacSha512();
                HKDF hkdf = HKDF.fromHmacSha256();
                pseudoRandomKey = hkdf.extract(randomSalt32Byte, sharedSecret1);
                //create expanded bytes for e.g. AES secret key and IV
                byte[] encryptionKey1 = hkdf.expand(pseudoRandomKey, "aes-key".getBytes(StandardCharsets.UTF_8), 32);


                sb.append("Manual ECDH").append("\n");
                sb.append("PrivateKey 1: ").append(kp1.getPrivate().toString()).append(" Algorithm: ").append(kp1.getPrivate().getAlgorithm()).append("\n");
                sb.append("PublicKey  2: ").append(kp2.getPublic().toString()).append("\n");
                sb.append("Shared secret 1 length: ").append(sharedSecret1.length).append(" data: ").append(bytesToHexNpe(sharedSecret1)).append("\n");
                sb.append("Shared secret 2 length: ").append(sharedSecret2.length).append(" data: ").append(bytesToHexNpe(sharedSecret2)).append("\n");
                sb.append("encryptionKey 1 length: ").append(encryptionKey1.length).append(" data: ").append(bytesToHexNpe(encryptionKey1)).append("\n");
                */
                tv2.setText(sb.toString());

            }
        });

        btn12.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.d(TAG, "btn12");
                tv2.setText("");
                StringBuilder sb = new StringBuilder();
                sb.append("ECDH encapsulated ext").append("\n");

                // generate keys
                PrivateKeyModel pkm1 = EcEncryption.generateEcKeyPair(EcEncryption.KEY_PARAMETER.P_256);
                PrivateKeyModel pkm2 = EcEncryption.generateEcKeyPair(EcEncryption.KEY_PARAMETER.P_256);
                sb.append("").append("\n");
                sb.append("PrivateKeyModel 1 generated").append("\n").append(pkm1.dump());
                sb.append("").append("\n");
                sb.append("PrivateKeyModel 2 generated").append("\n").append(pkm2.dump());

                // get JSON encoding
                // you can store the json string easily
                String pkm1Json = EcEncryption.privateKeyModelToJson(pkm1);
                String pkm2Json = EcEncryption.privateKeyModelToJson(pkm2);
                sb.append("").append("\n");
                sb.append("PrivateKeyModel 1 JSON").append("\n").append(pkm1Json);
                sb.append("").append("\n");
                sb.append("PrivateKeyModel 2 JSON").append("\n").append(pkm2Json);

                // json back to PrivateKeyModel just for testing
                PrivateKeyModel pkm1Re = EcEncryption.privateKeyModelFromJson(pkm1Json);
                PrivateKeyModel pkm2Re = EcEncryption.privateKeyModelFromJson(pkm2Json);
                sb.append("").append("\n").append("\n");
                sb.append("get PrivateKeyModel from Json").append("\n");
                sb.append("PKM 1 keyId: ").append(pkm1Re.getKeyId()).append("\n");
                sb.append("PKM 2 keyId: ").append(pkm2Re.getKeyId()).append("\n");

                sb.append("").append("\n").append("\n");
                sb.append("get PublicKeyModel from PrivateKeyModel").append("\n");
                PublicKeyModel publicKeyModel1 = EcEncryption.getPublicKeyModelFromPrivateKeyModel(pkm1);
                PublicKeyModel publicKeyModel2 = EcEncryption.getPublicKeyModelFromPrivateKeyModel(pkm2);
                sb.append("").append("\n");
                sb.append("PublicKeyModel 1").append("\n").append(publicKeyModel1.dump());
                sb.append("").append("\n");
                sb.append("PublicKeyModel 2").append("\n").append(publicKeyModel2.dump());

                // get JSON encoding
                // you can store the json string easily
                String pubkm1Json = EcEncryption.publicKeyModelToJson(publicKeyModel1);
                String pubkm2Json = EcEncryption.publicKeyModelToJson(publicKeyModel2);
                sb.append("").append("\n");
                sb.append("PublicKeyModel 1 JSON").append("\n").append(pubkm1Json);
                sb.append("").append("\n");
                sb.append("PublicKeyModel 2 JSON").append("\n").append(pubkm2Json);

                // json back to PrivateKeyModel just for testing
                PublicKeyModel pubkm1Re = EcEncryption.publicKeyModelFromJson(pubkm1Json);
                PublicKeyModel pubkm2Re = EcEncryption.publicKeyModelFromJson(pubkm2Json);
                sb.append("").append("\n").append("\n");
                sb.append("get PublicKeyModel from Json").append("\n");
                sb.append("PUBKM 1 keyId: ").append(pubkm1Re.getKeyId()).append("\n");
                sb.append("PUBKM 2 keyId: ").append(pubkm2Re.getKeyId()).append("\n");

                // encryption using the PrivateKeyModel1 (sender) and PublicKeyModel2 (recipient)
                String plaintextString = "The quick brown fox jumps over the lazy dog";
                sb.append("").append("\n");
                sb.append("encrypt plaintext: ").append(plaintextString).append("\n");
                sb.append("running in ECDH mode").append("\n");
                byte[] plaintext = plaintextString.getBytes(StandardCharsets.UTF_8);

                EncryptionModel encryptedData = EcEncryption.ecdhEncryption(
                        pkm1,
                        publicKeyModel2,
                        EcEncryption.HKDF_ALGORITHM.HMAC_SHA256,
                        EcEncryption.ENCRYPTION_ALGORITHM.AES_CBC_PKCS5PADDING,
                        plaintext,
                        false // only ecdh encryption
                );
                sb.append("encrypted data: ").append(encryptedData.dump()).append("\n");

                // encryptedData as JSON string
                String encryptedDataString = EcEncryption.encryptionModelToJson(encryptedData);
                sb.append("").append("\n");
                sb.append("encrypted data (JSON):").append("\n").append(encryptedDataString).append("\n");

                sb.append("").append("\n");
                sb.append("decrypt ciphertext: ").append("\n");
                byte[] decryptedData = EcEncryption.ecdhDecryption(
                        pkm2,
                        publicKeyModel1,
                        encryptedData);
                if (decryptedData == null) {
                    sb.append("error on decryption").append("\n");
                } else {
                    sb.append("decrypted data: ").append(new String(decryptedData)).append("\n");
                }


                sb.append("").append("\n");

                sb.append("running in ECDHE mode").append("\n");
                EncryptionModel encryptedDataE = EcEncryption.ecdhEncryption(
                        pkm1,
                        publicKeyModel2,
                        EcEncryption.HKDF_ALGORITHM.HMAC_SHA256,
                        EcEncryption.ENCRYPTION_ALGORITHM.AES_CBC_PKCS5PADDING,
                        plaintext,
                        true // ecdhe encryption
                );
                sb.append("encrypted data: ").append(encryptedDataE.dump()).append("\n");

                // encryptedData as JSON string
                String encryptedDataEString = EcEncryption.encryptionModelToJson(encryptedDataE);
                sb.append("").append("\n");
                sb.append("encrypted data (JSON):").append("\n").append(encryptedDataEString).append("\n");

                sb.append("").append("\n");
                sb.append("decrypt ciphertext: ").append("\n");
                byte[] decryptedDataE = EcEncryption.ecdhDecryption(
                        pkm2,
                        null, // ECDHE mode
                        encryptedDataE);
                if (decryptedDataE == null) {
                    sb.append("error on decryption").append("\n");
                } else {
                    sb.append("decrypted data: ").append(new String(decryptedDataE)).append("\n");
                }

                sb.append("").append("\n");

                tv2.setText(sb.toString());
            }
        });

        btn14.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                    Log.d(TAG, "btn14");
                    Intent intent = new Intent(MainActivity.this, EcdhActivity.class);
                    startActivity(intent);
            }
        });

        btn15.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.d(TAG, "btn15");
                Intent intent = new Intent(MainActivity.this, EcdheActivity.class);
                startActivity(intent);
            }
        });

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

    public static KeyPair generateKeysP256(String alias) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, ParseException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, KEY_STORE_PROVIDER);
        keyPairGenerator.initialize(
                new KeyGenParameterSpec.Builder(
                        alias,
                        KeyProperties.PURPOSE_AGREE_KEY)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec(EC_SPEC_P256))
                        .setUserAuthenticationRequired(false)
                        .setKeyValidityEnd(DateFormat.getDateInstance().parse("Aug 1, 2199"))
                        .build());
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair generateKeysP521(String alias) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, ParseException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, KEY_STORE_PROVIDER);
        keyPairGenerator.initialize(
                new KeyGenParameterSpec.Builder(
                        alias,
                        KeyProperties.PURPOSE_AGREE_KEY)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec(EC_SPEC_P521))
                        .setUserAuthenticationRequired(false)
                        .setKeyValidityEnd(DateFormat.getDateInstance().parse("Aug 1, 2199"))
                        .build());
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] sharedSecret(PrivateKey mine, PublicKey remote) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALG, KEY_STORE_PROVIDER);
            //Line 55 here ↓ where error occurs
            keyAgreement.init(mine);
            keyAgreement.doPhase(remote, true);
            return keyAgreement.generateSecret();
        } catch (ProviderException e) {
            Log.e(TAG, "error on generating a shared secred)");
            return null;
        }
    }

    /**
     * converts a byte array to a hex encoded string
     * @param bytes
     * @return hex encoded string
     */
    public static String bytesToHexNpe(byte[] bytes) {
        if (bytes == null) return "";
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    /**
     * section for OptionsMenu
     */

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_activity_main, menu);

        MenuItem mOpenFile = menu.findItem(R.id.action_open_file);
        mOpenFile.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Log.i(TAG, "mOpenFile");
                //Intent i = new Intent(MainActivity.this, AddEntryActivity.class);
                //startActivity(i);
                //readResult.setText("");
                //dumpFileName = "";
                //dumpExportString = "";
                //openFileFromExternalSharedStorage();
                return false;
            }
        });

        MenuItem mPlusTextSize = menu.findItem(R.id.action_plus_text_size);
        mPlusTextSize.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Log.i(TAG, "mPlusTextSize");
                /*
                //int textSizeInDp = sharedPreferences.getInt(TEXT_SIZE, defaultTextSizeInDp) + 1;
                //readResult.setTextSize(coverPixelToDP(textSizeInDp));
                System.out.println("textSizeInDp: " + textSizeInDp);
                try {
                    sharedPreferences.edit().putInt(TEXT_SIZE, textSizeInDp).apply();
                } catch (Exception e) {
                    writeToUiToast("Error on size storage: " + e.getMessage());
                    return false;
                }

                 */
                return false;
            }
        });

        MenuItem mMinusTextSize = menu.findItem(R.id.action_minus_text_size);
        mMinusTextSize.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Log.i(TAG, "mMinusTextSize");
                /*
                int textSizeInDp = sharedPreferences.getInt(TEXT_SIZE, defaultTextSizeInDp) - 1;
                if (textSizeInDp < MINIMUM_TEXT_SIZE_IN_DP) {
                    writeToUiToast("You cannot decrease text size any further");
                    return false;
                }
                readResult.setTextSize(coverPixelToDP(textSizeInDp));
                try {
                    sharedPreferences.edit().putInt(TEXT_SIZE, textSizeInDp).apply();
                } catch (Exception e) {
                    writeToUiToast("Error on size storage: " + e.getMessage());
                    return false;
                }

                 */
                return false;
            }
        });

        MenuItem mExportDumpFile = menu.findItem(R.id.action_export_dump_file);
        mExportDumpFile.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Log.i(TAG, "mExportDumpFile");
                //exportDumpFile();
                return false;
            }
        });

        MenuItem mMailDumpFile = menu.findItem(R.id.action_mail_dump_file);
        mMailDumpFile.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Log.i(TAG, "mMailDumpFile");
                //mailDumpFile();
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }

}