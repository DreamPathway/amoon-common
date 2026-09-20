package com.shiguangshe.crypto;

import com.shiguangshe.crypto.constant.CryptoConstant;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * 摘要（Hash）工具类
 * - MD5 / SHA-256 / SHA-512：单向不可逆，用于完整性校验
 * - HMAC-SHA256：带密钥的摘要，用于防篡改校验
 * 注意：
 * - 摘要不能"解密"，只能比对
 * - 不要用 MD5/SHA 存储密码，密码请用 {@link PasswordUtils}
 */
public class DigestUtils {

    private static final String CHARSET = CryptoConstant.CHARSET;

    // =====================================================
    // 1. 普通摘要（无密钥）
    // =====================================================

    /**
     * MD5 摘要（32 位十六进制小写）
     * @param plainText 明文
     * @return 十六进制字符串
     */
    public static String md5(String plainText) throws Exception {
        return digest(CryptoConstant.MD5, plainText);
    }

    /**
     * SHA-256 摘要（64 位十六进制小写）
     * @param plainText 明文
     * @return 十六进制字符串
     */
    public static String sha256(String plainText) throws Exception {
        return digest(CryptoConstant.SHA_256, plainText);
    }

    /**
     * SHA-512 摘要（128 位十六进制小写）
     * @param plainText 明文
     * @return 十六进制字符串
     */
    public static String sha512(String plainText) throws Exception {
        return digest(CryptoConstant.SHA_512, plainText);
    }

    /**
     * 通用摘要方法
     * @param algorithm 算法名，如 MD5、SHA-256、SHA-512
     * @param plainText 明文
     * @return 十六进制字符串
     */
    public static String digest(String algorithm, String plainText) throws Exception {
        if (algorithm == null || algorithm.isEmpty()) {
            throw new IllegalArgumentException(CryptoConstant.ERR_DIGEST_ALGORITHM_INVALID);
        }
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        byte[] bytes = messageDigest.digest(plainText.getBytes(CHARSET));
        return toHex(bytes);
    }

    // =====================================================
    // 2. HMAC 摘要（带密钥）
    // =====================================================

    /**
     * HMAC-SHA256 摘要
     * @param plainText 明文
     * @param secretKey 密钥
     * @return 十六进制字符串
     */
    public static String hmacSha256(String plainText, String secretKey) throws Exception {
        if (secretKey == null || secretKey.isEmpty()) {
            throw new IllegalArgumentException(CryptoConstant.ERR_HMAC_KEY_EMPTY);
        }
        Mac mac = Mac.getInstance(CryptoConstant.HMAC_SHA_256);
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(CHARSET), CryptoConstant.HMAC_SHA_256);
        mac.init(keySpec);
        byte[] bytes = mac.doFinal(plainText.getBytes(CHARSET));
        return toHex(bytes);
    }

    /**
     * 校验明文摘要是否与预期一致（防时序攻击，使用常量时间比较）
     * @param plainText    明文
     * @param algorithm    算法名
     * @param expectedHex  预期的十六进制摘要
     * @return 是否匹配
     */
    public static boolean verifyDigest(String plainText, String algorithm, String expectedHex) throws Exception {
        String actualHex = digest(algorithm, plainText);
        return constantTimeEquals(actualHex, expectedHex);
    }

    // =====================================================
    // 工具方法
    // =====================================================

    /**
     * 字节数组转十六进制字符串（小写）
     * @param bytes 字节数组
     * @return 十六进制字符串
     */
    public static String toHex(byte[] bytes) {
        if (bytes == null) return null;
        char[] chars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            chars[i * 2] = CryptoConstant.HEX_CHARS[v >>> 4];
            chars[i * 2 + 1] = CryptoConstant.HEX_CHARS[v & 0x0F];
        }
        return new String(chars);
    }

    /**
     * 常量时间字符串比较，避免时序攻击
     */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        if (aBytes.length != bBytes.length) return false;
        int result = 0;
        for (int i = 0; i < aBytes.length; i++) {
            result |= aBytes[i] ^ bBytes[i];
        }
        return result == 0;
    }
}
