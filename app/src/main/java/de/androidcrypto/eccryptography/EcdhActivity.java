package de.androidcrypto.eccryptography;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.Button;

import com.google.android.material.textfield.TextInputLayout;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import de.androidcrypto.eccryptography.model.EncryptionModel;
import de.androidcrypto.eccryptography.model.PrivateKeyModel;
import de.androidcrypto.eccryptography.model.PublicKeyModel;

public class EcdhActivity extends AppCompatActivity {

    private Button ecdhStep01, ecdhStep02, ecdhStep03, ecdhStep04, ecdhStep05, ecdhStep06, ecdhStep07, ecdhStep08, ecdhStep09;

    private com.google.android.material.textfield.TextInputEditText pri1, pub1, pri2, pub2, result03, result04, input05, result05;
    private com.google.android.material.textfield.TextInputEditText result07, result08, result09;
    private com.google.android.material.textfield.TextInputLayout result02Layout, result03Layout, result04Layout, input05Layout, result05Layout, result06Layout;
    private com.google.android.material.textfield.TextInputLayout result07Layout, result08Layout, result09Layout;

    private PrivateKeyModel priKeyModelSender, priKeyModelRecipient;
    private PublicKeyModel pubKeyModelSender, pubKeyModelRedipient;
    private byte[] sharedSecretSenderSide;
    private byte[] sharedSecretRecipientSide;
    private byte[][] derivedEncryptionKeyArray;
    private byte[] derivedDecryptionKey;
    String encryptedDataJson;
    EncryptionModel encryptedDataRecipientSide;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_ecdh);

        ecdhStep01 = findViewById(R.id.ecdh01);
        ecdhStep02 = findViewById(R.id.ecdh02);
        ecdhStep03 = findViewById(R.id.ecdh03);
        ecdhStep04 = findViewById(R.id.ecdh04);
        ecdhStep05 = findViewById(R.id.ecdh05);
        ecdhStep06 = findViewById(R.id.ecdh06);
        ecdhStep07 = findViewById(R.id.ecdh07);
        ecdhStep08 = findViewById(R.id.ecdh08);
        ecdhStep09 = findViewById(R.id.ecdh09);
        pri1 = findViewById(R.id.etPri1);
        pub1 = findViewById(R.id.etPub1);
        pri2 = findViewById(R.id.etPri2);
        pub2 = findViewById(R.id.etPub2);
        result02Layout = findViewById(R.id.result02Layout);
        result03Layout = findViewById(R.id.result03Layout);
        result03 = findViewById(R.id.result03);
        result04Layout = findViewById(R.id.result04Layout);
        result04 = findViewById(R.id.result04);
        input05Layout = findViewById(R.id.input05Layout);
        input05 = findViewById(R.id.input05);
        result05Layout = findViewById(R.id.result05Layout);
        result05 = findViewById(R.id.result05);
        result06Layout = findViewById(R.id.result06Layout);
        result07Layout = findViewById(R.id.result07Layout);
        result07 = findViewById(R.id.result07);
        result08Layout = findViewById(R.id.result08Layout);
        result08 = findViewById(R.id.result08);
        result09Layout = findViewById(R.id.result09Layout);
        result09 = findViewById(R.id.result09);

        ecdhStep01.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // generate key pairs
                clearData();
                // generate keys for sender and recipient
                priKeyModelSender = EcEncryption.generateEcKeyPair(EcEncryption.KEY_PARAMETER.P_256);
                pubKeyModelSender = EcEncryption.getPublicKeyModelFromPrivateKeyModel(priKeyModelSender);
                priKeyModelRecipient = EcEncryption.generateEcKeyPair(EcEncryption.KEY_PARAMETER.P_256);
                pubKeyModelRedipient = EcEncryption.getPublicKeyModelFromPrivateKeyModel(priKeyModelRecipient);
                pri1.setText(priKeyModelSender.dump());
                // show public key in JSON encoding
                pub1.setText(EcEncryption.publicKeyModelToJson(pubKeyModelSender));
                pri2.setText(priKeyModelRecipient.dump());
                // show public key in JSON encoding
                pub2.setText(EcEncryption.publicKeyModelToJson(pubKeyModelRedipient));
                ecdhStep02.setEnabled(true);
            }
        });

        ecdhStep02.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                result02Layout.setVisibility(View.VISIBLE);
                ecdhStep03.setEnabled(true);
            }
        });

        ecdhStep03.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // calculate shared secret on sender's side
                PrivateKey privateKey = EcEncryption.getPrivateKeyFromEncoded(EcEncryption.base64Decoding(priKeyModelSender.getPrivateKeyEncodedBase64()));
                PublicKey remotePublicKey = EcEncryption.getPublicKeyFromEncoded(EcEncryption.base64Decoding(pubKeyModelRedipient.getPublicKeyEncodedBase64()));
                sharedSecretSenderSide = EcEncryption.getEcdhSharedSecret(privateKey, remotePublicKey);
                result03.setText(EcEncryption.base64EncodingNpe(sharedSecretSenderSide));
                result03Layout.setVisibility(View.VISIBLE);
                ecdhStep04.setEnabled(true);
            }
        });

        ecdhStep04.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                derivedEncryptionKeyArray = EcEncryption.deriveEncryptionKeyHkdf(EcEncryption.HKDF_ALGORITHM.HMAC_SHA256, EcEncryption.HKDF_NAME.AES_KEY, sharedSecretSenderSide);
                // [0] contains the encryption key
                // [1] contains the salt
                StringBuilder sb = new StringBuilder();
                sb.append("The encryption key was derived with these parameter").append("\n");
                sb.append("  HKDF algorithm: ").append(EcEncryption.HKDF_ALGORITHM.HMAC_SHA256.toString()).append("\n");
                sb.append("  HKDF name:      ").append(EcEncryption.HKDF_NAME.AES_KEY.toString()).append("\n");
                sb.append("  random Salt:    ").append(EcEncryption.base64EncodingNpe(derivedEncryptionKeyArray[1])).append("\n");
                sb.append("encryption key: ").append(EcEncryption.base64EncodingNpe(derivedEncryptionKeyArray[0]));
                result04.setText(sb.toString());
                result04Layout.setVisibility(View.VISIBLE);
                input05Layout.setVisibility(View.VISIBLE);
                ecdhStep05.setEnabled(true);
            }
        });

        ecdhStep05.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String plaintextString = input05.getText().toString();
                if (TextUtils.isEmpty(plaintextString)) {
                    result05.setText("You need to input some text to encrypt");
                } else {
                    byte[] plaintext = plaintextString.getBytes(StandardCharsets.UTF_8);
                    EncryptionModel encryptedData = EcEncryption.encryptAesSingle(
                            EcEncryption.HKDF_ALGORITHM.HMAC_SHA256.toString(),
                            EcEncryption.ENCRYPTION_ALGORITHM.AES_GCM_NOPADDING.toString(),
                            "AES/GCM/NOPADDING",
                            priKeyModelSender.getKeyId(),
                            pubKeyModelRedipient.getKeyId(),
                            derivedEncryptionKeyArray[1],
                            EcEncryption.HKDF_NAME.AES_KEY.toString(),
                            derivedEncryptionKeyArray[0],
                            plaintext
                    );
                    encryptedDataJson = EcEncryption.encryptionModelToJson(encryptedData);
                    result05.setText(encryptedDataJson);
                    result05Layout.setVisibility(View.VISIBLE);
                    ecdhStep06.setEnabled(true);
                }
            }
        });

        ecdhStep06.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                result06Layout.setVisibility(View.VISIBLE);
                ecdhStep07.setEnabled(true);
            }
        });

        ecdhStep07.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // calculate shared secret on recipient's side
                PrivateKey privateKey = EcEncryption.getPrivateKeyFromEncoded(EcEncryption.base64Decoding(priKeyModelRecipient.getPrivateKeyEncodedBase64()));
                PublicKey remotePublicKey = EcEncryption.getPublicKeyFromEncoded(EcEncryption.base64Decoding(pubKeyModelSender.getPublicKeyEncodedBase64()));
                sharedSecretRecipientSide = EcEncryption.getEcdhSharedSecret(privateKey, remotePublicKey);
                result07.setText(EcEncryption.base64EncodingNpe(sharedSecretRecipientSide));
                result07Layout.setVisibility(View.VISIBLE);
                ecdhStep08.setEnabled(true);
            }
        });

        ecdhStep08.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // get the decryption key
                // we do have the encryptedDataJson available
                encryptedDataRecipientSide = EcEncryption.encryptionModelFromJson(encryptedDataJson);
                derivedDecryptionKey = EcEncryption.getEncryptionKeyHkdf(
                        encryptedDataRecipientSide.getDeriveAlgorithm(),
                        encryptedDataRecipientSide.getDeriveName(),
                        sharedSecretRecipientSide,
                        EcEncryption.base64Decoding(encryptedDataRecipientSide.getDeriveSaltBase64())
                        );
                StringBuilder sb = new StringBuilder();
                sb.append("The encryption key was derived with these parameter").append("\n");
                sb.append("  HKDF algorithm: ").append(encryptedDataRecipientSide.getDeriveAlgorithm()).append("\n");
                sb.append("  HKDF name:      ").append(encryptedDataRecipientSide.getDeriveName()).append("\n");
                sb.append("  random Salt:    ").append(encryptedDataRecipientSide.getDeriveSaltBase64()).append("\n");
                sb.append("decryption key: ").append(EcEncryption.base64EncodingNpe(derivedDecryptionKey));
                result08.setText(sb.toString());
                result08Layout.setVisibility(View.VISIBLE);
                ecdhStep09.setEnabled(true);
            }
        });

        ecdhStep09.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // decrypt the data
                // we do need the encryptedDataRecipientSide and the decryptionKey
                StringBuilder sb = new StringBuilder();
                sb.append("Decryption using these parameter").append("\n");
                // encryptionTransformation
                String encryptionAlgorithm = encryptedDataRecipientSide.getEncryptionAlgorithm();
                String transformation = "";
                if (encryptionAlgorithm.equals(EcEncryption.ENCRYPTION_ALGORITHM.AES_CBC_PKCS5PADDING.toString())) {
                    transformation = "AES/CBC/PKCS5PADDING";
                    sb.append("  algorithm: ").append("AES CBC mode").append("\n");
                } else if (encryptionAlgorithm.equals(EcEncryption.ENCRYPTION_ALGORITHM.AES_GCM_NOPADDING.toString())) {
                    transformation = "AES/GCM/NOPADDING";
                    sb.append("  algorithm: ").append("AES GCM mode").append("\n");
                } else {
                    // at this point no valid encryptionAlgorithm was found
                    return;
                }
                sb.append("  InitVector: ").append(encryptedDataRecipientSide.getIvBase64()).append("\n");
                byte[] decryptedData = EcEncryption.decryptAesInternal(
                        encryptionAlgorithm,
                        transformation,
                        derivedDecryptionKey,
                        EcEncryption.base64Decoding(encryptedDataRecipientSide.getIvBase64()),
                        EcEncryption.base64Decoding(encryptedDataRecipientSide.getCiphertextBase64())
                );
                if (decryptedData != null) {
                    sb.append("decrypted data:").append("\n").append(new String(decryptedData, StandardCharsets.UTF_8));
                } else {
                    sb.append("decrypted data:").append("\n").append("ERROR during decryption, sorry.");
                }
                result09.setText(sb.toString());
                result09Layout.setVisibility(View.VISIBLE);
            }
        });

    }



    private void clearData() {
        pri1.setText("");
        pub1.setText("");
        pri2.setText("");
        pub2.setText("");
        ecdhStep02.setEnabled(false);
        result02Layout.setVisibility(View.GONE);
        //result02Layout.setEnabled(false);
        ecdhStep03.setEnabled(false);
        result02Layout.setVisibility(View.GONE);
        result03.setText("");
        result03Layout.setVisibility(View.GONE);
        ecdhStep04.setEnabled(false);
        result04.setText("");
        result04Layout.setVisibility(View.GONE);
        ecdhStep05.setEnabled(false);
        input05.setText("The quick brown fox jumps over the lazy dog");
        input05Layout.setVisibility(View.GONE);
        result05Layout.setVisibility(View.GONE);
        result05.setText("");
        ecdhStep06.setEnabled(false);
        result06Layout.setVisibility(View.GONE);
        ecdhStep07.setEnabled(false);
        result07Layout.setVisibility(View.GONE);
        result07.setText("");
        ecdhStep08.setEnabled(false);
        result08Layout.setVisibility(View.GONE);
        result08.setText("");
    }

}