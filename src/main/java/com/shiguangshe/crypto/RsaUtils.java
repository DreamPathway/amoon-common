package com.shiguangshe.crypto;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * RSA 非对称加密工具类
 * - 公钥加密 / 私钥解密
 * - 私钥加密 / 公钥解密（签名场景）
 * - 文件加解密（大文件需注意 RSA 块长度限制）
 * - 密钥对持久化
 */
public class RsaUtils {

    private static final String ALGORITHM = "RSA";
    private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final int KEY_SIZE = 2048;
    private static final String CHARSET = "UTF-8";

    // =====================================================
    // 1. 密钥对生成 / 持久化
    // =====================================================

    /**
     * 生成密钥对
     * @return KeyPair
     */
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(KEY_SIZE, new SecureRandom());
        return keyGen.generateKeyPair();
    }

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
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance(ALGORITHM).generatePublic(spec);
    }

    /**
     * 从文件加载私钥
     * @param file 文件
     * @return PrivateKey
     */
    public static PrivateKey loadPrivateKey(File file) throws Exception {
        byte[] keyBytes = readAllBytes(file);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance(ALGORITHM).generatePrivate(spec);
    }

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
     * 从 Base64 字符串加载私钥
     * @param base64 Base64 字符串
     * @return PrivateKey
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
    // 2. 字符串加解密
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
    // 3. 文件加解密（分块处理，避免 RSA 长度限制）
    // =====================================================

    /**
     * 公钥加密文件
     * @param src 源文件
     * @param dest 目标文件
     * @param publicKey 公钥
     */
    public static void encryptFileByPublicKey(File src, File dest, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // RSA 单块最大加密字节数 = keySize/8 - 11
        int maxBlock = KEY_SIZE / 8 - 11;

        try (FileInputStream fis = new FileInputStream(src);
             FileOutputStream fos = new FileOutputStream(dest);
             DataOutputStream dos = new DataOutputStream(fos)) {

            byte[] buffer = new byte[maxBlock];
            int len;
            while ((len = fis.read(buffer)) != -1) {
                byte[] out = cipher.doFinal(buffer, 0, len);
                dos.writeInt(out.length);  // 写块长度，解密时用
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

//    public static void main(String[] args) throws Exception {
//        KeyPair keyPair = generateKeyPair();
//
//        String text = "Hello, RSA!";
//        String enc = encryptByPublicKey(text, keyPair.getPublic());
//        System.out.println("加密: " + enc);
//        System.out.println("解密: " + decryptByPrivateKey(enc, keyPair.getPrivate()));
//    }
}
