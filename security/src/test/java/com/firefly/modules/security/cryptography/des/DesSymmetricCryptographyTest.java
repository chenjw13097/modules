package com.firefly.modules.security.cryptography.des;

import com.firefly.modules.security.cryptography.interfaces.CryptographyException;
import com.firefly.modules.security.cryptography.interfaces.SymmetricCryptography;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

/**
 * @author Jiawei Chan
 * @date 2019-01-10
 */
public class DesSymmetricCryptographyTest {
    private static SymmetricCryptography<byte[]> symmetricCryptography;
    private static byte[] key;

    @Before
    public void setUp() throws Exception {
        symmetricCryptography = new DesSymmetricCryptography();
        key = symmetricCryptography.generateKey();
    }

    @After
    public void tearDown() {
        key = null;
        symmetricCryptography = null;
    }

    @Test
    public void testEncrypt() throws CryptographyException {
        byte[] plainTextSend = "123!&kjWdfYYL?".getBytes(StandardCharsets.UTF_8);

        byte[] cipherText = symmetricCryptography.encrypt(plainTextSend, key);
        byte[] plainTextReceive = symmetricCryptography.decrypt(cipherText, key);

        Assert.assertEquals(Base64.encode(plainTextSend), Base64.encode(plainTextReceive));
    }
}