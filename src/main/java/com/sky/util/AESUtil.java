package com.sky.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;

/**
 * @program SelfIssueRsaDoubleCertificate
 * @description: AES工具类
 * @author: daile
 * @create: 2019/02/19 20:58
 */
public class AESUtil {
    //算法名称
    public static final String KEY_ALGORITHM = "AES";
    //算法名称/加密模式/填充方式
    public static final String CIPHER_ALGORITHM = "AES/CBC/PKCS7Padding";

    public static Key init(byte[] keyBytes) {
        // 如果密钥不足16位，那么就补足. 这个if 中的内容很重要
        int base = 16;
        if (keyBytes.length < base) {
            System.out.println("密钥不足16位");
            int groups = keyBytes.length / base + (keyBytes.length % base != 0 ? 1 : 0);
            byte[] temp = new byte[groups * base];
            Arrays.fill(temp, (byte) 0);
            System.arraycopy(keyBytes, 0, temp, 0, keyBytes.length);
            keyBytes = temp;

        }
        // 初始化
        Security.addProvider(new BouncyCastleProvider());
        // 转化成JAV的密钥格式
        Key key = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
        // 初始化cipher
        return key;

    }

    /**
     * BC aes 加密 byte[] 到 byte[]
     *
     * @param data
     * @param keybytes
     * @param iv
     * @return
     * @throws Exception
     */
    public static byte[] AESBCEncrypt(byte[] data, byte[] keybytes, byte[] iv) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Key key = init(keybytes);
        // 实例化Cipher对象，它用于完成实际的加密操作
        // 初始化Cipher对象，设置为加密模式
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        //加密操作
        byte[] results = cipher.doFinal(data);
        return results;
    }

    /**
     * BC aes 解密 byte[] 到 byte[]
     *
     * @param data
     * @param keybytes
     * @param iv
     * @return
     * @throws Exception
     */
    public static byte[] AESBCDecrypt(byte[] data, byte[] keybytes, byte[] iv) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Key key = init(keybytes);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM, "BC");
        //初始化Cipher对象，设置为解密模式
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        // 执行解密操作
        return cipher.doFinal(data);
    }


    /**
     * 生成AES秘钥 128 192 256
     *
     * @param bitNum
     * @return
     */
    public static SecretKey generateAESKey(int bitNum) {
        KeyGenerator kg;
        try {
            kg = KeyGenerator.getInstance("AES");
            kg.init(bitNum);
            SecretKey symmKey = kg.generateKey();
            return symmKey;
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }
}
