package com.shiguangshe.crypto;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Base64 编码/解码工具类
 * 注意：Base64 不是加密，只是编码，任何人都能解码
 */
public class Base64Utils {

    private static final String CHARSET = "UTF-8";

    // =====================================================
    // 1. 字符串编码/解码
    // =====================================================

    /**
     * 字符串编码
     * @param plainText 明文
     * @return String
     */
    public static String encode(String plainText) {
        return Base64.getEncoder().encodeToString(plainText.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 字符串解码
     * @param base64Text base64 字符串
     * @return String
     */
    public static String decode(String base64Text) {
        return new String(Base64.getDecoder().decode(base64Text), StandardCharsets.UTF_8);
    }

    /**
     * URL 安全版本（替换 +/ 为 -_）
     * @param plainText 明文
     * @return String
     */
    public static String encodeUrlSafe(String plainText) {
        return Base64.getUrlEncoder().encodeToString(plainText.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * URL 安全版本解码
     * @param base64Text base64 字符串
     * @return String
     */
    public static String decodeUrlSafe(String base64Text) {
        return new String(Base64.getUrlDecoder().decode(base64Text), StandardCharsets.UTF_8);
    }

    // =====================================================
    // 2. 文件编码/解码
    // =====================================================

    /**
     * 把文件内容编码成 Base64 字符串
     * @param file 待编码文件
     * @return String
     */
    public static String encodeFile(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int len;
            while ((len = fis.read(buffer)) != -1) {
                bos.write(buffer, 0, len);
            }
            return Base64.getEncoder().encodeToString(bos.toByteArray());
        }
    }

    /**
     * 把 Base64 字符串解码写入文件
     * @param base64Text Base64 字符串
     * @param dest 目标文件
     */
    public static void decodeToFile(String base64Text, File dest) throws IOException {
        byte[] data = Base64.getDecoder().decode(base64Text);
        try (FileOutputStream fos = new FileOutputStream(dest)) {
            fos.write(data);
        }
    }

    /**
     * 二进制文件转 Base64 文本文件
     * @param src 源文件
     * @param destText 目标文本文件
     */
    public static void encodeFileToTextFile(File src, File destText) throws IOException {
        String base64 = encodeFile(src);
        try (FileWriter fw = new FileWriter(destText, StandardCharsets.UTF_8)) {
            fw.write(base64);
        }
    }
}
