package com.firefly.modules.security.cryptography.tool;

import com.firefly.modules.security.cryptography.des.DesSymmetricCryptography;
import com.firefly.modules.security.cryptography.interfaces.AsymmetricCryptography;
import com.firefly.modules.security.cryptography.interfaces.CryptographyException;
import com.firefly.modules.security.cryptography.interfaces.KeyPair;
import com.firefly.modules.security.cryptography.interfaces.SymmetricCryptography;
import com.firefly.modules.security.cryptography.rsa.RsaAsymmetricCryptography;
import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;

import java.io.*;
import java.math.BigInteger;

/**
 * @author Jiawei Chan
 * @date 2019-01-14
 */
public class FileEncoder {
    private static AsymmetricCryptography<byte[], byte[]> asymmetricCryptography = new RsaAsymmetricCryptography();
    private static SymmetricCryptography<byte[]> symmetricCryptography = new DesSymmetricCryptography();

    public static void main(String[] args) throws IOException, CryptographyException {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        String operate;

        do {
            System.out.println("Chose an operation. Generates a key pair(1), encrypts a file(2) or decrypts a file(3):");
            operate = bufferedReader.readLine();
        } while (!"1".equals(operate) && !"2".equals(operate) && !"3".equals(operate));

        if ("1".equals(operate)) {
            generateKeyPair(bufferedReader);
        } else if ("2".equals(operate)) {
            encryptFiles(bufferedReader);
        } else {
            decryptFiles(bufferedReader);
        }
    }

    private static void generateKeyPair(BufferedReader bufferedReader) throws IOException, CryptographyException {
        System.out.println("Absolute path of file to save generated key pair:");
        BufferedWriter bufferedWriter = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(new File(bufferedReader.readLine()))));

        KeyPair<byte[], byte[]> keyPair = asymmetricCryptography.generateKeyPair();
        String publicKey = HexBin.encode(keyPair.getPublicKey());
        String privateKey = HexBin.encode(keyPair.getPrivateKey());

        bufferedWriter.write("public:" + publicKey);
        bufferedWriter.newLine();
        bufferedWriter.write("private:" + privateKey);
        bufferedWriter.flush();

        bufferedWriter.close();
    }

    private static void encryptFiles(BufferedReader bufferedReader) throws IOException, CryptographyException {
        System.out.println("Absolute path of source file:");
        String source = bufferedReader.readLine();

        System.out.println("Absolute path of target file:");
        String target = bufferedReader.readLine();

        System.out.println("Public key:");
        String publicKey = bufferedReader.readLine();

        encryptFile(new File(source), new File(target), HexBin.decode(publicKey));
    }

    private static void decryptFiles(BufferedReader bufferedReader) throws IOException, CryptographyException {
        System.out.println("Absolute path of source file:");
        String source = bufferedReader.readLine();

        System.out.println("Absolute path of target file:");
        String target = bufferedReader.readLine();

        System.out.println("Private key:");
        String privateKey = bufferedReader.readLine();

        decryptFile(new File(source), new File(target), HexBin.decode(privateKey));
    }

    private static void encryptFile(File source, File target, byte[] publicKey) throws IOException, CryptographyException {
        byte[] plainDesKey = symmetricCryptography.generateKey();
        byte[] cipherDesKey = asymmetricCryptography.encryptWithPublicKey(plainDesKey, publicKey);

        InputStream inputStream = new FileInputStream(source);
        OutputStream outputStream = new FileOutputStream(target);

        outputStream.write(toBytes(cipherDesKey.length));
        outputStream.write(cipherDesKey);

        byte[] bytes = new byte[2048];
        int readLen;
        do {
            readLen = inputStream.read(bytes);
            if (readLen != -1) {
                byte[] tmp = new byte[readLen];
                System.arraycopy(bytes, 0, tmp, 0, readLen);
                byte[] encrypt = symmetricCryptography.encrypt(tmp, plainDesKey);
                outputStream.write(toBytes(encrypt.length));
                outputStream.write(encrypt);
            }
        } while (readLen != -1);

        outputStream.close();
        inputStream.close();
    }

    private static byte[] toBytes(int length) {
        byte[] lengthInBytes = new byte[4];
        lengthInBytes[0] = (byte) ((length >> 8 >> 8 >> 8) & 0xff);
        lengthInBytes[1] = (byte) ((length >> 8 >> 8) & 0xff);
        lengthInBytes[2] = (byte) ((length >> 8) & 0xff);
        lengthInBytes[3] = (byte) ((length) & 0xff);
        return lengthInBytes;
    }

    private static void decryptFile(File source, File target, byte[] privateKey) throws IOException, CryptographyException {
        InputStream inputStream = new FileInputStream(source);
        OutputStream outputStream = new FileOutputStream(target);

        int cipherDesKeyLength = readLength(inputStream);
        byte[] cipherDesKey = new byte[cipherDesKeyLength];
        if (inputStream.read(cipherDesKey) != cipherDesKeyLength) {
            throw new IOException("Reading des key fails");
        }

        byte[] plainDesKey = asymmetricCryptography.decryptWithPrivateKey(cipherDesKey, privateKey);

        int fragmentLength;
        do {
            fragmentLength = readLength(inputStream);
            if (fragmentLength != -1) {
                byte[] fragment = new byte[fragmentLength];
                if (inputStream.read(fragment) != fragmentLength) {
                    throw new IOException("Reading data fails");
                }
                outputStream.write(symmetricCryptography.decrypt(fragment, plainDesKey));
            }
        } while (fragmentLength != -1);

        outputStream.close();
        inputStream.close();
    }

    private static int readLength(InputStream inputStream) throws IOException {
        byte[] bytes = new byte[4];
        if (inputStream.read(bytes) == 4) {
            return new BigInteger(1, bytes).intValue();
        }
        return -1;
    }
}
