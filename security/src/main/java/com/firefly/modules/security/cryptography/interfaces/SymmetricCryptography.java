package com.firefly.modules.security.cryptography.interfaces;

/**
 * @author Jiawei Chan
 * @date 2019-01-10
 */
public interface SymmetricCryptography<K> {
    K generateKey() throws CryptographyException;

    byte[] encrypt(byte[] plainText, K key) throws CryptographyException;

    byte[] decrypt(byte[] cipherText, K key) throws CryptographyException;
}
