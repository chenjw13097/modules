package com.firefly.modules.security.cryptography.rsa;

import com.firefly.modules.security.cryptography.interfaces.AsymmetricCryptography;
import com.firefly.modules.security.cryptography.interfaces.CryptographyException;
import com.firefly.modules.security.cryptography.interfaces.KeyPair;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

/**
 * @author Jiawei Chan
 * @date 2019-01-09
 */
public class RsaAsymmetricCryptographyTest {
    private static AsymmetricCryptography<byte[], byte[]> asymmetricCryptography;
    private static byte[] publicKey;
    private static byte[] privateKey;

    @Before
    public void setUp() throws Exception {
        asymmetricCryptography = new RsaAsymmetricCryptography();
        KeyPair<byte[], byte[]> keyPair = asymmetricCryptography.generateKeyPair();
        publicKey = keyPair.getPublicKey();
        privateKey = keyPair.getPrivateKey();
    }

    @After
    public void tearDown() {
        privateKey = null;
        publicKey = null;
        asymmetricCryptography = null;
    }

    @Test
    public void testEncryptWithPublicKey() throws CryptographyException {
        byte[] plainTextSend = "123!&kjWdfYYL?".getBytes(StandardCharsets.UTF_8);


        byte[] cipherText = asymmetricCryptography.encryptWithPublicKey(plainTextSend, publicKey);
        byte[] plainTextReceive = asymmetricCryptography.decryptWithPrivateKey(cipherText, privateKey);

        Assert.assertEquals(Base64.encode(plainTextSend), Base64.encode(plainTextReceive));
    }

    @Test
    public void testEncryptWithPrivateKey() throws CryptographyException {
        byte[] plainTextSend = "3!&jWdfYYL?".getBytes(StandardCharsets.UTF_8);

        byte[] cipherText = asymmetricCryptography.encryptWithPrivateKey(plainTextSend, privateKey);
        byte[] plainTextReceive = asymmetricCryptography.decryptWithPublicKey(cipherText, publicKey);

        Assert.assertEquals(Base64.encode(plainTextSend), Base64.encode(plainTextReceive));
    }

    @Test
    public void testSignAndVerify() throws CryptographyException {
        byte[] message = "fj123!&kWfY".getBytes(StandardCharsets.UTF_8);

        byte[] messageDigest = asymmetricCryptography.sign(message, privateKey);
        boolean verify = asymmetricCryptography.verify(message, messageDigest, publicKey);

        Assert.assertTrue(verify);
    }
}