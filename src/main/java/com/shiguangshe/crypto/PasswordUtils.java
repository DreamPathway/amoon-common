package com.shiguangshe.crypto;

import com.shiguangshe.crypto.constant.CryptoConstant;
import org.mindrot.jbcrypt.BCrypt;

/**
 * 密码存储工具类（基于 bcrypt）
 * 特点：
 * - 自动加盐，无需手动管理 salt
 * - 慢哈希，抗 GPU / 彩虹表暴力破解
 * - 单向哈希，不能"解密"，只能 verify
 * - 每次加密结果不同（因为盐随机），但都能验证通过
 */
public class PasswordUtils {

    /**
     * 对明文密码进行哈希
     * @param plainPassword 明文密码
     * @return bcrypt 哈希字符串（含盐，可直接存数据库）
     */
    public static String hash(String plainPassword) {
        if (plainPassword == null || plainPassword.isEmpty()) {
            throw new IllegalArgumentException(CryptoConstant.ERR_PASSWORD_EMPTY);
        }
        return BCrypt.hashpw(plainPassword, BCrypt.gensalt(CryptoConstant.BCRYPT_COST));
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
}
