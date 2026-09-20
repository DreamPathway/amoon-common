package com.shiguangshe.crypto;


import org.mindrot.jbcrypt.BCrypt;

/**
 * 密码存储工具类（基于 bcrypt）
 * 特点：
 * - 自动加盐，无需手动管理 salt
 * - 慢哈希，抗 GPU / 彩虹表暴力破解
 * - 每次加密结果不同（因为盐随机），但都能验证通过
 * 注意：bcrypt 是单向哈希，不能"解密"，只能 verify
 */
public class PasswordUtils {

    /** bcrypt cost 因子，默认 10。越大越慢越安全，推荐 10~12 */
    private static final int COST = 12;

    /**
     * 对明文密码进行哈希
     * @param plainPassword 明文密码
     * @return bcrypt 哈希字符串（含盐，可直接存数据库）
     */
    public static String hash(String plainPassword) {
        if (plainPassword == null || plainPassword.isEmpty()) {
            throw new IllegalArgumentException("密码不能为空");
        }
        return BCrypt.hashpw(plainPassword, BCrypt.gensalt(COST));
    }

    /**
     * 校验明文密码和数据库中的哈希是否匹配
     * @param plainPassword  用户输入的明文
     * @param hashedPassword 数据库里存的 bcrypt 哈希
     * @return boolean 表示密码正确
     */
    public static boolean verify(String plainPassword, String hashedPassword) {
        if (plainPassword == null || hashedPassword == null || hashedPassword.isEmpty()) {
            return false;
        }
        try {
            return BCrypt.checkpw(plainPassword, hashedPassword);
        } catch (Exception e) {
            // 哈希格式非法等异常
            return false;
        }
    }

    // =====================================================
    // 测试
    // =====================================================

//    public static void main(String[] args) {
//        String password = "MyP@ssw0rd!";
//
//        // 两次 hash 结果不同，因为盐随机
//        String hash1 = hash(password);
//        String hash2 = hash(password);
//        System.out.println("hash1: " + hash1);
//        System.out.println("hash2: " + hash2);
//
//        // 但验证都能通过
//        System.out.println("verify 正确密码: " + verify(password, hash1));   // true
//        System.out.println("verify 错误密码: " + verify("wrong", hash1));    // false
//    }
}
