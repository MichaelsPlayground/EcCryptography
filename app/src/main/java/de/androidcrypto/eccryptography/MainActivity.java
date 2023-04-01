package de.androidcrypto.eccryptography;

import android.content.Intent;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.text.DateFormat;
import java.text.ParseException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    private final String TAG = "MainAct";

    Button btn1, btn2, btn3, btn4, btn5, btn6, btn7;
    TextView tv1, tv2;
    EditText et1;

    private static final String EC_SPEC = "p-256";
    private static final String KEY_PAIR_NAME = "abcdefgh";
    private static final String MAC_ALG = "HMACSHA256";
    private static final String INFO_TAG = "ECDH p-256 AES-256-GCM-SIV\0";
    private static final String KEY_AGREEMENT_ALG = "ECDH";
    private static final String KEY_STORE_PROVIDER = "AndroidKeyStore";
    KeyPair one;
    KeyPair two;
    byte[] shareOne;
    byte[] shareTwo;
    byte[] expandedAesKeyOne;
    byte[] expandedAesKeyTwo;
    byte[] expandedIvOne;
    byte[] expandedIvTwo;
    byte[] plaintext, encrypted; byte[] decrypted;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        btn1 = findViewById(R.id.btn1);
        btn2 = findViewById(R.id.btn2);
        btn3 = findViewById(R.id.btn3);
        btn4 = findViewById(R.id.btn4);
        btn5 = findViewById(R.id.btn5);
        btn6 = findViewById(R.id.btn6);
        btn7 = findViewById(R.id.btn7);
        tv1 = findViewById(R.id.tv1);
        tv2 = findViewById(R.id.tv2);
        et1 = findViewById(R.id.et1);

        btn1.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.i(TAG, "btn1 back to main menu");
                Intent intent = new Intent(MainActivity.this, MainActivity.class);
                startActivity(intent);
                finish();
            }
        });

        btn2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.i(TAG, "btn2");
                // generate key pairs
                try {
                    one = generateKeys("alias_one");
                    two = generateKeys("alias_two");
                } catch (NoSuchAlgorithmException | NoSuchProviderException |
                         InvalidAlgorithmParameterException | ParseException e) {
                    throw new RuntimeException(e);
                }
                StringBuilder sb = new StringBuilder();
                sb.append("Generated key pair one").append("\n");
                sb.append("Private Key: ").append(bytesToHexNpe(one.getPrivate().getEncoded())).append("\n");
                sb.append("Public  Key: ").append(bytesToHexNpe(one.getPublic().getEncoded())).append("\n");
                sb.append("Generated key pair two").append("\n");
                sb.append("Private Key: ").append(bytesToHexNpe(two.getPrivate().getEncoded())).append("\n");
                sb.append("Public  Key: ").append(bytesToHexNpe(two.getPublic().getEncoded())).append("\n");
                tv2.setText(sb.toString());
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
                }
                StringBuilder sb = new StringBuilder();
                sb.append("shared secret one").append("\n");
                sb.append("shared key length: ").append(shareOne.length).append(" data: ").append(bytesToHexNpe(shareOne)).append("\n");
                sb.append("shared secret two").append("\n");
                sb.append("shared key length: ").append(shareOne.length).append(" data: ").append(bytesToHexNpe(shareTwo)).append("\n");
                tv2.setText(sb.toString());
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
                byte[] pseudoRandomKeyOne = hkdf.extract(staticSalt32Byte, shareOne);
                byte[] pseudoRandomKeyTwo = hkdf.extract(staticSalt32Byte, shareTwo);

                //create expanded bytes for e.g. AES secret key and IV
                expandedAesKeyOne = hkdf.expand(pseudoRandomKeyOne, "aes-key".getBytes(StandardCharsets.UTF_8), 32);
                expandedIvOne = hkdf.expand(pseudoRandomKeyOne, "aes-iv".getBytes(StandardCharsets.UTF_8), 16);

                expandedAesKeyTwo = hkdf.expand(pseudoRandomKeyTwo, "aes-key".getBytes(StandardCharsets.UTF_8), 32);
                expandedIvTwo = hkdf.expand(pseudoRandomKeyTwo, "aes-iv".getBytes(StandardCharsets.UTF_8), 16);

                StringBuilder sb = new StringBuilder();
                sb.append("HKDF one").append("\n");
                sb.append("expandedAesKey length: ").append(expandedAesKeyOne.length).append(" data: ").append(bytesToHexNpe(expandedAesKeyOne)).append("\n");
                sb.append("expandedIv     length: ").append(expandedIvOne.length).append(" data: ").append(bytesToHexNpe(expandedIvOne)).append("\n");
                sb.append("HKDF two").append("\n");
                sb.append("expandedAesKey length: ").append(expandedAesKeyTwo.length).append(" data: ").append(bytesToHexNpe(expandedAesKeyTwo)).append("\n");
                sb.append("expandedIv     length: ").append(expandedIvTwo.length).append(" data: ").append(bytesToHexNpe(expandedIvTwo)).append("\n");
                tv2.setText(sb.toString());
            }
        });

        btn5.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.i(TAG, "btn5");
                // encryption / decryption
                //Example boilerplate encrypting a simple string with created key/iv
                // encryption
                plaintext = "my secret message".getBytes(StandardCharsets.UTF_8);
                SecretKey keyOne = new SecretKeySpec(expandedAesKeyOne, "AES"); //AES-128 key
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
                SecretKey keyTwo = new SecretKeySpec(expandedAesKeyTwo, "AES"); //AES-128 key
                Cipher cipherTwo = null;
                try {
                    cipherTwo = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipherTwo.init(Cipher.DECRYPT_MODE, keyOne, new IvParameterSpec(expandedIvTwo));
                    decrypted = cipherTwo.doFinal(encrypted);
                } catch (NoSuchAlgorithmException | IllegalBlockSizeException |
                         BadPaddingException | NoSuchPaddingException |
                         InvalidAlgorithmParameterException | InvalidKeyException e) {
                    throw new RuntimeException(e);
                }
                StringBuilder sb = new StringBuilder();
                sb.append("encrypted one").append("\n");
                sb.append("plaintext one: ").append(new String(plaintext)).append("\n");
                sb.append("plaintext length: ").append(plaintext.length).append(" data: ").append(bytesToHexNpe(plaintext)).append("\n");
                sb.append("encrypted length: ").append(encrypted.length).append(" data: ").append(bytesToHexNpe(encrypted)).append("\n");
                sb.append("decrypted two").append("\n");
                sb.append("decrypted length: ").append(decrypted.length).append(" data: ").append(bytesToHexNpe(decrypted)).append("\n");
                sb.append("decrypted two: ").append(new String(decrypted)).append("\n");
                tv2.setText(sb.toString());

            }
        });

        btn6.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.i(TAG, "btn 6");

            }
        });

        btn7.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.i(TAG, "btn 7");

            }
        });
    }

    public static KeyPair generateKeys(String alias) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, ParseException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, KEY_STORE_PROVIDER);
        keyPairGenerator.initialize(
                new KeyGenParameterSpec.Builder(
                        alias,
                        KeyProperties.PURPOSE_AGREE_KEY)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec(EC_SPEC))
                        .setUserAuthenticationRequired(false)
                        .setKeyValidityEnd(DateFormat.getDateInstance().parse("Aug 1, 2199"))
                        .build());
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] sharedSecret(PrivateKey mine, PublicKey remote) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALG, KEY_STORE_PROVIDER);
        //Line 55 here ↓ where error occurs
        keyAgreement.init(mine);
        keyAgreement.doPhase(remote, true);
        return keyAgreement.generateSecret();
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