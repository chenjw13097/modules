package com.firefly.modules.security.crypto.interfaces;

/**
 * @author Jiawei Chan
 * @date 2019-01-09
 */
public interface Crypto<P, V> {
    KeyPair<P, V> generateKeyPair() throws CryptoException;

    byte[] encryptWithPublicKey(byte[] plainText, P publicKey) throws CryptoException;

    byte[] encryptWithPrivateKey(byte[] plainText, V privateKey) throws CryptoException;

    byte[] decryptWithPublicKey(byte[] cipherText, P publicKey) throws CryptoException;

    byte[] decryptWithPrivateKey(byte[] cipherText, V privateKey) throws CryptoException;

    byte[] sign(byte[] message, V privateKey) throws CryptoException;

    boolean verify(byte[] message, byte[] messageDigest, P publicKey) throws CryptoException;
}
