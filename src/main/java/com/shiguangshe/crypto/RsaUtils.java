package com.shiguangshe.crypto;

import com.shiguangshe.crypto.constant.CryptoConstant;

import javax.crypto.Cipher;
import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * RSA 非对称加密工具类
 * - 公钥加密 / 私钥解密
 * - 私钥加密 / 公钥解密（签名场景,正式签名请用 Signature）
 * - 文件加解密（大文件需注意 RSA 块长度限制）
 * - 密钥对持久化
 * - 数字签名 / 验签
 */
public class RsaUtils {

    private static final String ALGORITHM = CryptoConstant.RSA_ALGORITHM;
    private static final String TRANSFORMATION = CryptoConstant.RSA_TRANSFORMATION;
    private static final int KEY_SIZE = CryptoConstant.RSA_KEY_SIZE;
    private static final String CHARSET = CryptoConstant.CHARSET;

    // =====================================================
    // 1. 密钥对生成
    // =====================================================

    /**
     * 生成密钥对（默认 2048 位）
     * @return KeyPair
     */
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(KEY_SIZE, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    /**
     * 生成指定长度的 RSA 密钥对
     * @param keySize 密钥长度
     * @return KeyPair
     */
    public static KeyPair generateKeyPair(int keySize) throws Exception {
        if (!CryptoConstant.isValidRsaKeyLength(keySize)) {
            throw new IllegalArgumentException(CryptoConstant.ERR_RSA_KEY_LENGTH_INVALID);
        }
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(keySize, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    // =====================================================
    // 2. 密钥对持久化
    // =====================================================

    /**
     * 保存公钥到文件
     * @param publicKey 公钥
     * @param file 文件
     */
    public static void savePublicKey(PublicKey publicKey, File file) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(publicKey.getEncoded());
        }
    }

    /**
     * 保存私钥到文件
     * @param privateKey 私钥
     * @param file 文件
     */
    public static void savePrivateKey(PrivateKey privateKey, File file) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(privateKey.getEncoded());
        }
    }

    /**
     * 从文件加载公钥
     * @param file 文件
     * @return PublicKey
     */
    public static PublicKey loadPublicKey(File file) throws Exception {
        byte[] keyBytes = readAllBytes(file);
        return KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    /**
     * 从文件加载私钥
     * @param file 文件
     * @return PrivateKey
     */
    public static PrivateKey loadPrivateKey(File file) throws Exception {
        byte[] keyBytes = readAllBytes(file);
        return KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    // =====================================================
    // 3. 密钥 <-> Base64 字符串
    // =====================================================
    /**
     * 公钥转 Base64 字符串
     * @param publicKey 公钥
     * @return String
     */
    public static String publicKeyToBase64(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     * 私钥转 Base64 字符串
     * @param privateKey 私钥
     * @return String
     */
    public static String privateKeyToBase64(PrivateKey privateKey) {
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    /**
     * 从 Base64 字符串加载公钥
     * @param base64 Base64 字符串
     * @return PublicKey
     */
    public static PublicKey publicKeyFromBase64(String base64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        return KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    /**
     * 从 Base64 字符串加载私钥
     * @param base64 Base64 字符串
     * @return PrivateKey
     */
    public static PrivateKey privateKeyFromBase64(String base64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        return KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    // =====================================================
    // 4. 字符串加解密
    // =====================================================

    /**
     * 公钥加密
     * @param plainText 明文
     * @param publicKey 公钥
     * @return String
     */
    public static String encryptByPublicKey(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(CHARSET));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * 私钥解密
     * @param cipherText 密文
     * @param privateKey 私钥
     * @return String
     */
    public static String decryptByPrivateKey(String cipherText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(decrypted, CHARSET);
    }

    /**
     * 私钥加密
     * @param plainText 明文
     * @param privateKey 私钥
     * @return String
     */
    public static String encryptByPrivateKey(String plainText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(CHARSET));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * 公钥解密
     * @param cipherText 密文
     * @param publicKey 公钥
     * @return String
     */
    public static String decryptByPublicKey(String cipherText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(decrypted, CHARSET);
    }

    // =====================================================
    // 5. 文件加解密（分块处理，避免 RSA 长度限制）
    // =====================================================
    // 分块大小从 CryptoConstant 读取，避免硬编码
    // 默认 2048 位密钥：2048 / 8 - 11 = 245 字节

    /**
     * 公钥加密文件 （默认 2048 位分块）
     * @param src 源文件
     * @param dest 目标文件
     * @param publicKey 公钥
     */
    public static void encryptFileByPublicKey(File src, File dest, PublicKey publicKey) throws Exception {
        encryptFileByPublicKey(src, dest, publicKey, KEY_SIZE);
    }

    /**
     * 公钥加密文件 （支持自定义密钥长度）
     * @param src 源文件
     * @param dest 目标文件
     * @param publicKey 公钥
     * @param keySize 密钥长度（位），如 1024、2048、4096
     */
    public static void encryptFileByPublicKey(File src, File dest, PublicKey publicKey, int keySize) throws Exception {
        if (!CryptoConstant.isValidRsaKeyLength(keySize)) {
            throw new IllegalArgumentException(CryptoConstant.ERR_RSA_KEY_LENGTH_INVALID);
        }

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        int maxBlock = CryptoConstant.rsaMaxEncryptBlock(keySize);

        try (FileInputStream fis = new FileInputStream(src);
             DataOutputStream dos = new DataOutputStream(new FileOutputStream(dest))) {
            byte[] buffer = new byte[maxBlock];
            int len;
            while ((len = fis.read(buffer)) != -1) {
                byte[] out = cipher.doFinal(buffer, 0, len);
                dos.writeInt(out.length);
                dos.write(out);
            }
        }
    }

    /**
     * 私钥解密文件
     * @param src 源文件
     * @param dest 目标文件
     * @param privateKey 私钥
     */
    public static void decryptFileByPrivateKey(File src, File dest, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        try (DataInputStream dis = new DataInputStream(new FileInputStream(src));
             FileOutputStream fos = new FileOutputStream(dest)) {

            while (true) {
                int blockLen;
                try {
                    blockLen = dis.readInt();
                } catch (EOFException e) {
                    break; // 读完
                }
                byte[] block = new byte[blockLen];
                dis.readFully(block);
                byte[] out = cipher.doFinal(block);
                fos.write(out);
            }
        }
    }

    // =====================================================
    // 6. 数字签名（推荐做法）
    // =====================================================
    // RSA 直接加密用于"签名"并不规范，正式场景请用 Signature

    /**
     * 用私钥对数据签名（SHA256withRSA）
     * @param data 数据
     * @param privateKey 私钥
     * @return 签名的 Base64 字符串
     */
    public static String sign(String data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(CryptoConstant.RSA_SIGN_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(data.getBytes(CHARSET));
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    /**
     * 用公钥验签
     * @param data 数据
     * @param signBase64 签名的 Base64 字符串
     * @param publicKey 公钥
     * @return boolean 是否验签通过
     */
    public static boolean verify(String data, String signBase64, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance(CryptoConstant.RSA_SIGN_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(data.getBytes(CHARSET));
        return signature.verify(Base64.getDecoder().decode(signBase64));
    }

    // =====================================================
    // 工具方法
    // =====================================================

    /**
     * 读取文件所有字节
     * @param file 文件
     * @return byte[]
     */
    private static byte[] readAllBytes(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[CryptoConstant.BUFFER_SIZE];
            int len;
            while ((len = fis.read(buffer)) != -1) {
                bos.write(buffer, 0, len);
            }
            return bos.toByteArray();
        }
    }
}
