package de.androidcrypto.eccryptography;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.text.TextUtils;
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

    private Button ecdhStep01, ecdhStep02, ecdhStep03, ecdhStep04, ecdhStep05, ecdhStep06, ecdhStep07;

    private com.google.android.material.textfield.TextInputEditText pri1, pub1, pri2, pub2, result03, result04, input05, result05;
    private com.google.android.material.textfield.TextInputEditText result07;
    private com.google.android.material.textfield.TextInputLayout result02Layout, result03Layout, result04Layout, input05Layout, result05Layout, result06Layout;
    private com.google.android.material.textfield.TextInputLayout result07Layout;

    private PrivateKeyModel priKeyModel1, priKeyModel2;
    private PublicKeyModel pubKeyModel1, pubKeyModel2;
    private byte[] sharedSecretSenderSide;
    private byte[] sharedSecretRecipientSide;
    private byte[][] derivedEncryptionKeyArray;

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

        ecdhStep01.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // generate key pairs
                clearData();
                // generate keyPair 1
                priKeyModel1 = EcEncryption.generateEcKeyPair(EcEncryption.KEY_PARAMETER.P_256);
                pubKeyModel1 = EcEncryption.getPublicKeyModelFromPrivateKeyModel(priKeyModel1);
                priKeyModel2 = EcEncryption.generateEcKeyPair(EcEncryption.KEY_PARAMETER.P_256);
                pubKeyModel2 = EcEncryption.getPublicKeyModelFromPrivateKeyModel(priKeyModel2);
                pri1.setText(priKeyModel1.dump());
                // show public key in JSON encoding
                pub1.setText(EcEncryption.publicKeyModelToJson(pubKeyModel1));
                pri2.setText(priKeyModel2.dump());
                // show public key in JSON encoding
                pub2.setText(EcEncryption.publicKeyModelToJson(pubKeyModel2));
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
                PrivateKey privateKey = EcEncryption.getPrivateKeyFromEncoded(EcEncryption.base64Decoding(priKeyModel1.getPrivateKeyEncodedBase64()));
                PublicKey remotePublicKey = EcEncryption.getPublicKeyFromEncoded(EcEncryption.base64Decoding(pubKeyModel2.getPublicKeyEncodedBase64()));
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
                            priKeyModel1.getKeyId(),
                            pubKeyModel2.getKeyId(),
                            derivedEncryptionKeyArray[1],
                            EcEncryption.HKDF_NAME.AES_KEY.toString(),
                            derivedEncryptionKeyArray[0],
                            plaintext
                    );
                    String encryptedDataJson = EcEncryption.encryptionModelToJson(encryptedData);
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

    }

}