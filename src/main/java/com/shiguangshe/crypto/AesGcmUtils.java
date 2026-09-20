package com.shiguangshe.crypto;

import com.shiguangshe.crypto.constant.CryptoConstant;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AES-GCM 认证加密工具类（推荐新项目使用）
 * 相比 CBC：
 * - 自带完整性校验（认证标签），密文被篡改会解密失败
 * - 无需单独 PKCS5 填充
 * - IV/Nonce 推荐 12 字节，每次加密随机生成
 * 格式：IV(12 字节) + 密文(含 16 字节认证标签)，Base64 输出
 */
public class AesGcmUtils {

    private static final String ALGORITHM = CryptoConstant.AES_ALGORITHM;
    private static final String TRANSFORMATION = CryptoConstant.AES_TRANSFORMATION_GCM;
    private static final int KEY_SIZE = CryptoConstant.AES_KEY_SIZE;
    private static final int IV_SIZE = CryptoConstant.AES_GCM_IV_SIZE;   // 12
    private static final int TAG_LENGTH = CryptoConstant.AES_GCM_TAG_LENGTH; // 128
    private static final String CHARSET = CryptoConstant.CHARSET;

    // =====================================================
    // 1. 密钥生成 / 持久化
    // =====================================================

    /**
     * 生成 AES-GCM 密钥
     * @return SecretKey
     */
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(KEY_SIZE, new SecureRandom());
        return keyGen.generateKey();
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
     * Base64 字符串还原密钥（带长度校验）
     * @param base64Key Base64 字符串
     * @return SecretKey
     */
    public static SecretKey keyFromBase64(String base64Key) {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        if (!CryptoConstant.isValidAesKeyLength(keyBytes)) {
            throw new IllegalArgumentException(CryptoConstant.ERR_AES_KEY_LENGTH_INVALID);
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
     * @return Base64 编码的加密字符串（IV + 密文 + 认证标签）
     */
    public static String encrypt(String plainText, SecretKey key) throws Exception {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(CHARSET));

        // IV + 密文（含认证标签）
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
     * @throws javax.crypto.AEADBadTagException 密文被篡改或密钥错误
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
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
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
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

        try (FileOutputStream fos = new FileOutputStream(dest)) {
            // 先把 IV 写进文件头
            fos.write(iv);

            try (FileInputStream fis = new FileInputStream(src)) {
                byte[] buffer = new byte[CryptoConstant.BUFFER_SIZE];
                byte[] output;
                int len;
                while ((len = fis.read(buffer)) != -1) {
                    output = cipher.update(buffer, 0, len);
                    if (output != null) fos.write(output);
                }
                // doFinal 会输出认证标签
                output = cipher.doFinal();
                if (output != null) fos.write(output);
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
            if (fis.read(iv) != IV_SIZE) {
                throw new IllegalArgumentException(CryptoConstant.ERR_IV_READ_FAILED);
            }

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

            try (FileOutputStream fos = new FileOutputStream(dest)) {
                byte[] buffer = new byte[CryptoConstant.BUFFER_SIZE];
                byte[] output;
                int len;
                while ((len = fis.read(buffer)) != -1) {
                    output = cipher.update(buffer, 0, len);
                    if (output != null) fos.write(output);
                }
                // doFinal 会校验认证标签，失败抛 AEADBadTagException
                output = cipher.doFinal();
                if (output != null) fos.write(output);
            }
        }
    }
}
