package com.firefly.modules.tool.snappy;

import org.xerial.snappy.Snappy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * @author Jiawei Chan
 * @date 2019-01-25
 */
public class User {
    public static void main(String[] args) throws IOException {
        String input = "Hello snappy-java! Snappy-java is a JNI-based wrapper of Snappy, a fast compresser/decompresser.";

        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
        System.out.println("before compressed, bytes: " + inputBytes.length);
        byte[] compressed = Snappy.compress(inputBytes);
        System.out.println("after compressed, bytes: " + compressed.length);

        byte[] uncompressed = Snappy.uncompress(compressed);
        System.out.println("after uncompressed bytes: " + uncompressed.length);

        String result = new String(uncompressed, StandardCharsets.UTF_8);
        System.out.println(result.equals(input));
    }
}
