package de.androidcrypto.eccryptography.model;

public class EcdhModel {

    private final String keyId; // key from other party = recipient
    private final String deriveSaltBase64; // the salt used for HKDF derivation in Base64 encoding
    private final String deriveName; // the name used for HKDF derivation in Base64 encoding
    // todo HKDF algorithm HKDF hkdf = HKDF.fromHmacSha256();

    private final String encryptionAlgorithm; // "AES-CBC-PKCS7PADDING" or "AES-GCM-NOPADDING"
    private final String ivBase64; // the init vector (or nonce) in Base64 encoding
    private final String ciphertextBase64; // the encrypted data

    public EcdhModel(String keyId, String deriveSaltBase64, String deriveName, String encryptionAlgorithm, String ivBase64, String ciphertextBase64) {
        this.keyId = keyId;
        this.deriveSaltBase64 = deriveSaltBase64;
        this.deriveName = deriveName;
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.ivBase64 = ivBase64;
        this.ciphertextBase64 = ciphertextBase64;
    }

    public static enum ENCRYPTION_ALGORITHM {
        AES_CBC_PKCS5PADDING, AES_GCM_NOPADDING
    }

    public String getKeyId() {
        return keyId;
    }

    public String getDeriveSaltBase64() {
        return deriveSaltBase64;
    }

    public String getDeriveName() {
        return deriveName;
    }

    public String getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public String getIvBase64() {
        return ivBase64;
    }

    public String getCiphertextBase64() {
        return ciphertextBase64;
    }

    public String dump() {
        StringBuilder sb = new StringBuilder();
        sb.append("ECDH encrypted data").append("\n");
        sb.append("keyId: ").append(keyId).append("\n");
        sb.append("deriveSaltBase64: ").append(deriveSaltBase64).append("\n");
        sb.append("deriveName: ").append(deriveName).append("\n");
        sb.append("encryptionAlgorithm: ").append(encryptionAlgorithm).append("\n");
        sb.append("initVectorBase64: ").append(ivBase64).append("\n");
        sb.append("ciphertext: ").append(ciphertextBase64).append("\n");
        return sb.toString();
    }
}
