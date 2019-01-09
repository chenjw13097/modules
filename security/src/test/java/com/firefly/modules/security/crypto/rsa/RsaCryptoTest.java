package com.firefly.modules.security.crypto.rsa;

import com.firefly.modules.security.crypto.interfaces.Crypto;
import com.firefly.modules.security.crypto.interfaces.CryptoException;
import com.firefly.modules.security.crypto.interfaces.KeyPair;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.UnsupportedEncodingException;

/**
 * @author Jiawei Chan
 * @date 2019-01-09
 */
public class RsaCryptoTest {
    private static Crypto<byte[], byte[]> crypto;
    private static byte[] publicKey;
    private static byte[] privateKey;

    @Before
    public void setUp() throws Exception {
        crypto = new RsaCrypto();
        KeyPair<byte[], byte[]> keyPair = crypto.generateKeyPair();
        publicKey = keyPair.getPublicKey();
        privateKey = keyPair.getPrivateKey();
    }

    @After
    public void tearDown() {
        privateKey = null;
        publicKey = null;
        crypto = null;
    }

    @Test
    public void encryptWithPublicKey() throws CryptoException, UnsupportedEncodingException {
        byte[] plainTextSend = "123!&kjWdfYYL?".getBytes("UTF-8");

        byte[] cipherText = crypto.encryptWithPublicKey(plainTextSend, publicKey);
        byte[] plainTextReceive = crypto.decryptWithPrivateKey(cipherText, privateKey);

        Assert.assertEquals(Base64.encode(plainTextSend), Base64.encode(plainTextReceive));
    }

    @Test
    public void encryptWithPrivateKey() throws CryptoException, UnsupportedEncodingException {
        byte[] plainTextSend = "3!&jWdfYYL?".getBytes("UTF-8");

        byte[] cipherText = crypto.encryptWithPrivateKey(plainTextSend, privateKey);
        byte[] plainTextReceive = crypto.decryptWithPublicKey(cipherText, publicKey);

        Assert.assertEquals(Base64.encode(plainTextSend), Base64.encode(plainTextReceive));
    }

    @Test
    public void signAndVerify() throws CryptoException, UnsupportedEncodingException {
        byte[] message = "fj123!&kWfY".getBytes("UTF-8");

        byte[] messageDigest = crypto.sign(message, privateKey);
        boolean verify = crypto.verify(message, messageDigest, publicKey);

        Assert.assertTrue(verify);
    }
}