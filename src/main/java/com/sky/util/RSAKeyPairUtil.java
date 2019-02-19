package com.sky.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;

/**
 * @program SelfIssueRsaDoubleCertificate
 * @description: 产生RSA密钥对两种方式
 * @author: daile
 * @create: 2019/02/19 21:06
 */
public class RSAKeyPairUtil {
    public static KeyPair createKeyPair() {
        try {
            KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
            pairGen.initialize(1024, new SecureRandom());
            return pairGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    public static KeyPair createKeyPairBC() {
        Security.addProvider(new BouncyCastleProvider());
        try {
            KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA", "BC");
            pairGen.initialize(1024, new SecureRandom());
            return pairGen.generateKeyPair();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }
}
