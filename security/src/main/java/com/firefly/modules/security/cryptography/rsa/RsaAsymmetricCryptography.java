package com.firefly.modules.security.cryptography.rsa;

import com.firefly.modules.security.cryptography.interfaces.AsymmetricCryptography;
import com.firefly.modules.security.cryptography.interfaces.CryptographyException;
import com.firefly.modules.security.cryptography.interfaces.KeyPair;
import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author Jiawei Chan
 * @date 2019-01-09
 */
public class RsaAsymmetricCryptography implements AsymmetricCryptography<byte[], byte[]> {
    private static final String RSA_ALGORITHM = "RSA";
    private static final int KEY_LENGTH = 1024;
    private static final String SHA256_WITH_RSA_ALGORITHM = "SHA256withRSA";
    private static final String NO_RSA_ALGORITHM_MESSAGE =
            String.format("No provider which implements the %s algorithm is found", RSA_ALGORITHM);
    private static final String NO_SHA256_WITH_RSA_ALGORITHM_MESSAGE =
            String.format("No provider which implements the %s algorithm is found", SHA256_WITH_RSA_ALGORITHM);

    @Override
    public KeyPair<byte[], byte[]> generateKeyPair() throws CryptographyException {
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(NO_RSA_ALGORITHM_MESSAGE, e);
        }

        keyPairGenerator.initialize(KEY_LENGTH);
        java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();

        return new KeyPair<>(keyPair.getPublic().getEncoded(), keyPair.getPrivate().getEncoded());
    }

    @Override
    public byte[] encryptWithPublicKey(byte[] plainText, byte[] publicKey) throws CryptographyException {
        Key key = fromBytes(publicKey, false);
        return processText(plainText, key, Cipher.ENCRYPT_MODE);
    }

    @Override
    public byte[] encryptWithPrivateKey(byte[] plainText, byte[] privateKey) throws CryptographyException {
        Key key = fromBytes(privateKey, true);
        return processText(plainText, key, Cipher.ENCRYPT_MODE);
    }

    @Override
    public byte[] decryptWithPublicKey(byte[] cipherText, byte[] publicKey) throws CryptographyException {
        Key key = fromBytes(publicKey, false);
        return processText(cipherText, key, Cipher.DECRYPT_MODE);
    }

    @Override
    public byte[] decryptWithPrivateKey(byte[] cipherText, byte[] privateKey) throws CryptographyException {
        Key key = fromBytes(privateKey, true);
        return processText(cipherText, key, Cipher.DECRYPT_MODE);
    }

    private Key fromBytes(byte[] bytesKey, boolean isPrivate) throws CryptographyException {
        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(NO_RSA_ALGORITHM_MESSAGE, e);
        }

        Key key;
        try {
            if (isPrivate) {
                key = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(bytesKey));
            } else {
                key = keyFactory.generatePublic(new X509EncodedKeySpec(bytesKey));
            }
        } catch (InvalidKeySpecException e) {
            throw new CryptographyException(String.format("Fails to get key from %s", HexBin.encode(bytesKey)), e);
        }

        return key;
    }

    private byte[] processText(byte[] text, Key key, int mode) throws CryptographyException {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(RSA_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(NO_RSA_ALGORITHM_MESSAGE, e);
        } catch (NoSuchPaddingException e) {
            throw new CryptographyException(String.format("Getting cipher of %s goes wrong", RSA_ALGORITHM), e);
        }

        try {
            cipher.init(mode, key);
            return cipher.doFinal(text);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptographyException("An exception happens when encrypt plain text or decrypt cipher text", e);
        }
    }

    @Override
    public byte[] sign(byte[] message, byte[] privateKey) throws CryptographyException {
        Signature signature;
        try {
            signature = Signature.getInstance(SHA256_WITH_RSA_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(NO_SHA256_WITH_RSA_ALGORITHM_MESSAGE, e);
        }


        PrivateKey key = (PrivateKey) fromBytes(privateKey, true);
        try {
            signature.initSign(key);
        } catch (InvalidKeyException e) {
            throw new CryptographyException(
                    String.format("Fails to initialize for signing with key %s", HexBin.encode(privateKey)), e);
        }

        try {
            signature.update(message);
            return signature.sign();
        } catch (SignatureException e) {
            throw new CryptographyException("An exception happens when sign message", e);
        }
    }

    @Override
    public boolean verify(byte[] message, byte[] messageDigest, byte[] publicKey) throws CryptographyException {
        Signature signature;
        try {
            signature = Signature.getInstance(SHA256_WITH_RSA_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(NO_SHA256_WITH_RSA_ALGORITHM_MESSAGE, e);
        }

        PublicKey key = (PublicKey) fromBytes(publicKey, false);
        try {
            signature.initVerify(key);
        } catch (InvalidKeyException e) {
            throw new CryptographyException(
                    String.format("Fails to initialize for verification with key %s", HexBin.encode(publicKey)), e);
        }

        try {
            signature.update(message);
            return signature.verify(messageDigest);
        } catch (SignatureException e) {
            throw new CryptographyException("An exception happens when verify message against digest", e);
        }
    }
}
