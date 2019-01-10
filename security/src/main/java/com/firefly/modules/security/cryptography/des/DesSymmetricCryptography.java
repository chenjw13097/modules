package com.firefly.modules.security.cryptography.des;

import com.firefly.modules.security.cryptography.interfaces.CryptographyException;
import com.firefly.modules.security.cryptography.interfaces.SymmetricCryptography;
import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * @author Jiawei Chan
 * @date 2019-01-10
 */
public class DesSymmetricCryptography implements SymmetricCryptography<byte[]> {
    private static final String DES_ALGORITHM = "DES";
    private static final String NO_DES_ALGORITHM_MESSAGE =
            String.format("No provider which implements the %s algorithm is found", DES_ALGORITHM);

    @Override
    public byte[] generateKey() throws CryptographyException {
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance(DES_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(NO_DES_ALGORITHM_MESSAGE, e);
        }

        keyGenerator.init(56);
        SecretKey generateKey = keyGenerator.generateKey();

        return generateKey.getEncoded();
    }

    @Override
    public byte[] encrypt(byte[] plainText, byte[] key) throws CryptographyException {
        return processText(adjustLength(plainText, true), key, Cipher.ENCRYPT_MODE);
    }

    @Override
    public byte[] decrypt(byte[] cipherText, byte[] key) throws CryptographyException {
        return adjustLength(processText(cipherText, key, Cipher.DECRYPT_MODE), false);
    }

    private byte[] processText(byte[] text, byte[] key, int mode) throws CryptographyException {
        SecretKeyFactory secretKeyFactory;
        try {
            secretKeyFactory = SecretKeyFactory.getInstance(DES_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(NO_DES_ALGORITHM_MESSAGE, e);
        }

        SecretKey secretKey;
        try {
            DESKeySpec desKeySpec = new DESKeySpec(key);
            secretKey = secretKeyFactory.generateSecret(desKeySpec);
        } catch (InvalidKeyException | InvalidKeySpecException e) {
            throw new CryptographyException(String.format("Fails to get key from %s", HexBin.encode(key)), e);
        }

        Cipher cipher;
        try {
            cipher = Cipher.getInstance(DES_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException(NO_DES_ALGORITHM_MESSAGE, e);
        } catch (NoSuchPaddingException e) {
            throw new CryptographyException(String.format("Getting cipher of %s goes wrong", DES_ALGORITHM), e);
        }

        try {
            cipher.init(mode, secretKey);
            return cipher.doFinal(text);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptographyException("An exception happens when encrypt plain text or decrypt cipher text", e);
        }
    }

    private byte[] adjustLength(byte[] data, boolean fill) {
        int dataLength = data.length;
        if (dataLength > Integer.MAX_VALUE - 8) {
            throw new IllegalArgumentException("Data to be processed is too big");
        }

        if (fill) {
            int fillNumber = 8 - dataLength % 8;

            byte[] addend = new byte[fillNumber];
            addend[fillNumber - 1] = (byte) fillNumber;

            byte[] output = new byte[dataLength + fillNumber];
            System.arraycopy(data, 0, output, 0, dataLength);
            System.arraycopy(addend, 0, output, dataLength, fillNumber);
            return output;
        } else {
            int fillNumber = data[dataLength - 1];

            byte[] output = new byte[dataLength - fillNumber];
            System.arraycopy(data, 0, output, 0, output.length);
            return output;
        }
    }
}
