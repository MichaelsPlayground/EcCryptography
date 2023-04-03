package de.androidcrypto.eccryptography.model;

public class PrivateKeyModel {

    private final String keyType; // "EC", "RSA"
    private final String keyParameter; // "P-256", "P-521", "2048"
    private final String keyId; // a name like an alias or UUID
    private final String privateKeyEncodedBase64; // the encoded public key in Base64 encoding
    private final String publicKeyEncodedBase64; // the encoded public key in Base64 encoding

    public PrivateKeyModel(String keyType, String keyParameter, String keyId, String privateKeyEncodedBase64, String publicKeyEncodedBase64) {
        this.keyType = keyType;
        this.keyParameter = keyParameter;
        this.keyId = keyId;
        this.privateKeyEncodedBase64 = privateKeyEncodedBase64;
        this.publicKeyEncodedBase64 = publicKeyEncodedBase64;
    }

    public static enum KEY_TYPE {
        EC, RSA
    }

    public static enum KEY_PARAMETER {
        P_256, P_521
    }

    public String getKeyType() {
        return keyType;
    }

    public String getKeyParameter() {
        return keyParameter;
    }

    public String getKeyId() {
        return keyId;
    }

    public String getPrivateKeyEncodedBase64() {
        return privateKeyEncodedBase64;
    }

    public String getPublicKeyEncodedBase64() {
        return publicKeyEncodedBase64;
    }

    public String dump() {
        StringBuilder sb = new StringBuilder();
        sb.append("PrivateKey").append("\n");
        sb.append("key type: ").append(keyType).append("\n");
        sb.append("key parameter: ").append(keyParameter).append("\n");
        sb.append("keyId: ").append(keyId).append("\n");
        sb.append("privateKeyBase64: ").append(privateKeyEncodedBase64).append("\n");
        sb.append("publicKeyBase64: ").append(publicKeyEncodedBase64).append("\n");
        return sb.toString();
    }
}
