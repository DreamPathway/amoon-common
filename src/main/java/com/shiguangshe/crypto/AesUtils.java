package com.shiguangshe.crypto;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AES 对称加密工具类
 * - 字符串加解密（随机 IV）
 * - 文件加解密
 * - 密钥持久化到文件
 */
public class AesUtils {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 128;   // 128 / 192 / 256
    private static final int IV_SIZE = 16;     // AES 固定 16 字节
    private static final String CHARSET = "UTF-8";

    // =====================================================
    // 1. 密钥生成 / 持久化
    // =====================================================

    /**
     * 生成 AES 密钥
     * @return SecretKey
     */
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(KEY_SIZE, new SecureRandom());
        return keyGen.generateKey();
    }

    /**
     * 保存密钥到文件
     * @param key 待保存的密钥
     * @param file 保存密钥的文件
     */
    public static void saveKey(SecretKey key, File file) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(key.getEncoded());
        }
    }

    /**
     * 从文件读取密钥
     * @param file 密钥文件
     * @return SecretKey
     */
    public static SecretKey loadKey(File file) throws IOException {
        byte[] keyBytes = readAllBytes(file);
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    /**
     * 密钥转 Base64 字符串（方便配置存储）
     * @param key 密钥
     * @return String
     */
    public static String keyToBase64(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Base64 字符串还原密钥
     * @param base64Key Base64 字符串
     * @return SecretKey
     */
    public static SecretKey keyFromBase64(String base64Key) {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    // =====================================================
    // 2. 字符串加解密（随机 IV，IV 拼在密文前面）
    // =====================================================

    /**
     * 加密字符串
     * @param plainText 待加密的字符串
     * @param key 密钥
     * @return Base64 编码的加密字符串
     */
    public static String encrypt(String plainText, SecretKey key) throws Exception {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] encrypted = cipher.doFinal(plainText.getBytes(CHARSET));

        // IV + 密文
        byte[] combined = new byte[IV_SIZE + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, IV_SIZE);
        System.arraycopy(encrypted, 0, combined, IV_SIZE, encrypted.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     * 解密字符串
     * @param cipherText 待解密的字符串
     * @param key 密钥
     * @return 解密后的明文字符串
     */
    public static String decrypt(String cipherText, SecretKey key) throws Exception {
        byte[] combined = Base64.getDecoder().decode(cipherText);
        if (combined.length < IV_SIZE) {
            throw new IllegalArgumentException("密文长度不合法");
        }
        byte[] iv = new byte[IV_SIZE];
        byte[] encrypted = new byte[combined.length - IV_SIZE];
        System.arraycopy(combined, 0, iv, 0, IV_SIZE);
        System.arraycopy(combined, IV_SIZE, encrypted, 0, encrypted.length);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return new String(cipher.doFinal(encrypted), CHARSET);
    }

    // =====================================================
    // 3. 文件加解密
    // =====================================================

    /**
     * 加密文件
     * @param src 待加密的文件
     * @param dest 加密后的文件
     * @param key 密钥
     */
    public static void encryptFile(File src, File dest, SecretKey key) throws Exception {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        try (FileOutputStream fos = new FileOutputStream(dest)) {
            // 先把 IV 写进文件头
            fos.write(iv);

            try (FileInputStream fis = new FileInputStream(src);
                 CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
                byte[] buffer = new byte[8192];
                int len;
                while ((len = fis.read(buffer)) != -1) {
                    cos.write(buffer, 0, len);
                }
            }
        }
    }

    /**
     * 解密文件
     * @param src 待解密的文件
     * @param dest 解密后的文件
     * @param key 密钥
     */
    public static void decryptFile(File src, File dest, SecretKey key) throws Exception {
        try (FileInputStream fis = new FileInputStream(src)) {
            // 先读 IV
            byte[] iv = new byte[IV_SIZE];
            int read = fis.read(iv);
            if (read != IV_SIZE) {
                throw new IllegalArgumentException("文件头 IV 读取失败");
            }

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

            try (CipherInputStream cis = new CipherInputStream(fis, cipher);
                 FileOutputStream fos = new FileOutputStream(dest)) {
                byte[] buffer = new byte[8192];
                int len;
                while ((len = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, len);
                }
            }
        }
    }

    // =====================================================
    // 工具方法
    // =====================================================

    /**
     * 读取文件所有字节
     * @param file 文件
     * @return 文件字节数组
     */
    private static byte[] readAllBytes(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int len;
            while ((len = fis.read(buffer)) != -1) {
                bos.write(buffer, 0, len);
            }
            return bos.toByteArray();
        }
    }

    // =====================================================
    // 测试
    // =====================================================

    /**
     * 测试
     * @param args 参数
     * @throws Exception 如果测试过程中发生错误
     */
//    public static void main(String[] args) throws Exception {
//        SecretKey key = generateKey();
//        System.out.println("密钥(Base64): " + keyToBase64(key));
//
//        String text = "Hello, AES 加解密!";
//        String enc = encrypt(text, key);
//        System.out.println("加密: " + enc);
//        System.out.println("解密: " + decrypt(enc, key));
//    }
}
