package com.shiguangshe.crypto.constant;

/**
 * 加解密常量统一管理
 * 集中定义算法名、模式、填充、密钥长度、IV 长度、分块大小、字符集等
 */
public final class CryptoConstant {

    private CryptoConstant() {
        // 工具类禁止实例化
    }

    // =====================================================
    // 通用
    // =====================================================

    /** 默认字符集 */
    public static final String CHARSET = "UTF-8";

    /** 流式加解密缓冲区大小（字节） */
    public static final int BUFFER_SIZE = 8192;

    // =====================================================
    // 错误提示
    // =====================================================

    public static final String ERR_IV_READ_FAILED = "文件头 IV 读取失败";
    public static final String ERR_CIPHER_TEXT_INVALID = "密文长度不合法";
    public static final String ERR_PASSWORD_EMPTY = "密码不能为空";

    /** AES 密钥长度非法 */
    public static final String ERR_AES_KEY_LENGTH_INVALID = "AES 密钥长度不合法";

    /** 摘要算法名非法 */
    public static final String ERR_DIGEST_ALGORITHM_INVALID = "摘要算法名不能为空";

    /** HMAC 密钥不能为空 */
    public static final String ERR_HMAC_KEY_EMPTY = "HMAC 密钥不能为空";

    /** GCM 认证标签校验失败 */
    public static final String ERR_GCM_TAG_MISMATCH = "GCM 认证标签校验失败，数据可能被篡改";

    /** RSA 密钥长度非法 */
    public static final String ERR_RSA_KEY_LENGTH_INVALID = "RSA 密钥长度不合法";

    /** DES 密钥长度非法 */
    public static final String ERR_DES_KEY_LENGTH_INVALID = "DES 密钥长度不合法";

    // =====================================================
    // AES
    // =====================================================

    public static final String AES_ALGORITHM = "AES";

    /** CBC 模式 + PKCS5 填充 */
    public static final String AES_TRANSFORMATION_CBC = "AES/CBC/PKCS5Padding";

    /** GCM 模式（更安全，推荐新项目使用） */
    public static final String AES_TRANSFORMATION_GCM = "AES/GCM/NoPadding";

    /** AES 默认密钥长度（位） */
    public static final int AES_KEY_SIZE = 128;

    /** AES 密钥长度可选值 */
    public static final int AES_KEY_SIZE_192 = 192;
    public static final int AES_KEY_SIZE_256 = 256;

    /** AES 合法密钥字节数（128/192/256 位对应的字节数） */
    public static final int AES_KEY_BYTES_128 = 16;
    public static final int AES_KEY_BYTES_192 = 24;
    public static final int AES_KEY_BYTES_256 = 32;

    /**
     * 校验 AES 密钥字节长度是否合法
     * @param keyBytes 密钥字节数组
     * @return 是否合法
     */
    public static boolean isValidAesKeyLength(byte[] keyBytes) {
        if (keyBytes == null) return false;
        int len = keyBytes.length;
        return len == AES_KEY_BYTES_128
                || len == AES_KEY_BYTES_192
                || len == AES_KEY_BYTES_256;
    }

    /** AES IV 长度（字节） */
    public static final int AES_IV_SIZE = 16;

    /** AES GCM 推荐 IV/Nonce 长度（字节） */
    public static final int AES_GCM_IV_SIZE = 12;

    /** AES GCM 认证标签长度（位） */
    public static final int AES_GCM_TAG_LENGTH = 128;

    // =====================================================
    // DES
    // =====================================================

    public static final String DES_ALGORITHM = "DES";
    public static final String DES_TRANSFORMATION = "DES/CBC/PKCS5Padding";
    public static final int DES_KEY_SIZE = 56;
    public static final int DES_IV_SIZE = 8;

    /** DES 合法密钥字节数 */
    public static final int DES_KEY_BYTES = 8;

    /**
     * 校验 DES 密钥字节长度是否合法
     * @param keyBytes 密钥字节数组
     * @return 是否合法
     */
    public static boolean isValidDesKeyLength(byte[] keyBytes) {
        return keyBytes != null && keyBytes.length == DES_KEY_BYTES;
    }

    // =====================================================
    // RSA
    // =====================================================

    public static final String RSA_ALGORITHM = "RSA";
    public static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    /** RSA 默认密钥长度（位） */
    public static final int RSA_KEY_SIZE = 2048;

    public static final int RSA_KEY_SIZE_1024 = 1024;
    public static final int RSA_KEY_SIZE_4096 = 4096;

    /**
     * 校验 RSA 密钥长度是否合法
     * @param keySize 密钥长度（位）
     * @return 是否合法
     */
    public static boolean isValidRsaKeyLength(int keySize) {
        return keySize == RSA_KEY_SIZE_1024
                || keySize == RSA_KEY_SIZE
                || keySize == RSA_KEY_SIZE_4096;
    }

    /** RSA 签名算法 */
    public static final String RSA_SIGN_ALGORITHM = "SHA256withRSA";

    /**
     * RSA PKCS1Padding 单块最大加密字节数（默认 2048 位密钥）
     * 公式：密钥长度(位) / 8 - 11
     */
    public static final int RSA_MAX_ENCRYPT_BLOCK = RSA_KEY_SIZE / 8 - 11;

    /**
     * 根据密钥长度动态计算 RSA 单块最大加密字节数
     * @param keySize 密钥长度（位），如 1024、2048、4096
     * @return 单块最大加密字节数
     */
    public static int rsaMaxEncryptBlock(int keySize) {
        return keySize / 8 - 11;
    }

    /**
     * RSA 单块最大解密字节数（等于密钥长度 / 8）
     * @param keySize 密钥长度（位）
     * @return 单块最大解密字节数
     */
    public static int rsaMaxDecryptBlock(int keySize) {
        return keySize / 8;
    }

    // =====================================================
    // 摘要（Hash）
    // =====================================================

    public static final String MD5 = "MD5";
    public static final String SHA_256 = "SHA-256";
    public static final String SHA_512 = "SHA-512";
    public static final String HMAC_SHA_256 = "HmacSHA256";

    /** 十六进制字符表 */
    public static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    // =====================================================
    // bcrypt
    // =====================================================

    /** bcrypt cost 因子，默认 10。越大越慢越安全，推荐 10~12 */
    public static final int BCRYPT_COST = 12;
}