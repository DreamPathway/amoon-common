package com.shiguangshe.crypto;

import com.shiguangshe.crypto.constant.CryptoConstant;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * DES 对称加密工具类（仅用于老系统兼容，新项目请用 AES）
 */
public class DesUtils {

    private static final String ALGORITHM = CryptoConstant.DES_ALGORITHM;
    private static final String TRANSFORMATION = CryptoConstant.DES_TRANSFORMATION;
    private static final int KEY_SIZE = CryptoConstant.DES_KEY_SIZE;
    private static final int IV_SIZE = CryptoConstant.DES_IV_SIZE;   // DES IV 固定 8 字节
    private static final String CHARSET = CryptoConstant.CHARSET;

    // =====================================================
    // 1. 密钥生成 / 持久化
    // =====================================================

    /**
     * 生成 DES 密钥
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
     * 从文件加载密钥
     * @param file 文件
     * @return SecretKey
     */
    public static SecretKey loadKey(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[CryptoConstant.BUFFER_SIZE];
            int len;
            while ((len = fis.read(buffer)) != -1) bos.write(buffer, 0, len);
            return new SecretKeySpec(bos.toByteArray(), ALGORITHM);
        }
    }

    /**
     * 密钥转 Base64 字符串（方便配置存储）
     * @param key 密钥
     * @return Base64 字符串
     */
    public static String keyToBase64(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Base64 字符串生成密钥
     * @param base64Key Base64 字符串
     * @return SecretKey
     */
    public static SecretKey keyFromBase64(String base64Key) {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        if (!CryptoConstant.isValidDesKeyLength(keyBytes)) {
            throw new IllegalArgumentException(CryptoConstant.ERR_DES_KEY_LENGTH_INVALID);
        }
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    // =====================================================
    // 2. 字符串加解密
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

        byte[] combined = new byte[IV_SIZE + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, IV_SIZE);
        System.arraycopy(encrypted, 0, combined, IV_SIZE, encrypted.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     * 解密字符串
     * @param cipherText Base64 编码的加密字符串
     * @param key 密钥
     * @return 解密后的明文字符串
     */
    public static String decrypt(String cipherText, SecretKey key) throws Exception {
        byte[] combined = Base64.getDecoder().decode(cipherText);
        if (combined.length < IV_SIZE) {
            throw new IllegalArgumentException(CryptoConstant.ERR_CIPHER_TEXT_INVALID);
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
            fos.write(iv);
            try (FileInputStream fis = new FileInputStream(src);
                 CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
                byte[] buffer = new byte[CryptoConstant.BUFFER_SIZE];
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
            byte[] iv = new byte[IV_SIZE];
            if (fis.read(iv) != IV_SIZE) {
                throw new IllegalArgumentException(CryptoConstant.ERR_IV_READ_FAILED);
            }
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

            try (CipherInputStream cis = new CipherInputStream(fis, cipher);
                 FileOutputStream fos = new FileOutputStream(dest)) {
                byte[] buffer = new byte[CryptoConstant.BUFFER_SIZE];
                int len;
                while ((len = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, len);
                }
            }
        }
    }
}
