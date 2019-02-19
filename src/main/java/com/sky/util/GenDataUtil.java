package com.sky.util;

import com.sky.CertificateResponse;
import com.sky.EnvelopedKeyPairData;
import com.sky.util.AESUtil;
import com.sky.util.RSAEncryptUtil;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.DEROctetString;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

/**
 * @program SelfIssueRsaDoubleCertificate
 * @description:
 * @author: daile
 * @create: 2019/02/19 20:54
 */
public class GenDataUtil {
    public static CertificateResponse getCertificateResponse(PublicKey signedPubKey, PrivateKey encPriKey, X509Certificate encCert) throws Exception {

        //生成对称秘钥和初始向量
        String ivStr = "0BAB08DEFEAB6F17";
        SecretKey symmKey = AESUtil.generateAESKey(128);

        //对称密钥加密私钥
        byte[] encPriKeySrcByts = encPriKey.getEncoded();
        byte[] encPriKeyepdByts = AESUtil.AESBCEncrypt(encPriKeySrcByts, symmKey.getEncoded(), ivStr.getBytes());

        //公钥加密对称秘钥
//        ASN1OctetString enSymmKeyData = new DEROctetString(
        byte[] enSymmKeyData = RSAEncryptUtil.encrypt((RSAPublicKey) signedPubKey,
                symmKey.getEncoded());

        //构造证书响应
        CertificateResponse response = new CertificateResponse();

        response.setEncCertificate(new DEROctetString(Base64.encodeBase64(encCert.getEncoded())));

        EnvelopedKeyPairData enveloped = new EnvelopedKeyPairData();

        //设置加密的对称秘钥
        enveloped.setEncryptedSymmKeyData(new DEROctetString(Base64.encodeBase64(enSymmKeyData)));

        //设置保护的私钥
        enveloped.setEncryptedKeyPairData(new DEROctetString(Base64.encodeBase64(encPriKeyepdByts)));
        //设置iv向量
        enveloped.setSymmetricIV(new DEROctetString(Base64.encodeBase64(ivStr.getBytes())));

        //设置算法标识
        enveloped.setSymmetricCipherOID(new DEROctetString(Base64.encodeBase64("2.16.840.1.101.3.4.1.2".getBytes())));
        response.setEncKeyPair(enveloped);
        return response;
    }
}
