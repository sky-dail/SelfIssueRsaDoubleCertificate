package com.sky;

import com.sky.util.FileUtil;
import com.sky.util.GenDataUtil;
import com.sky.util.PemUtil;
import com.sky.util.RSAKeyPairUtil;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * @program SelfIssueRsaDoubleCertificate
 * @description: 签发RSA双证书
 * @author: daile
 * @create: 2019/02/19 21:02
 */
public class IssueCert {
    /**
     * @param request
     *            证书请求文件
     * @param upCert
     *            ca的证书
     * @return
     * @throws Exception
     */
    @SuppressWarnings("deprecation")
    public static X509Certificate createSignCertificate(PKCS10CertificationRequest request, X509Certificate upCert, PrivateKey priKey, String certFilePath, boolean signMode)
            throws Exception {

        // 签名算法标识符
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
        // 摘要算法标识符
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        // 签发者名称
        org.bouncycastle.asn1.x500.X500Name issuer = null;
        if(signMode) {
            issuer = new org.bouncycastle.asn1.x500.X500Name(
                    upCert.getSubjectX500Principal().getName());
        }else {
            issuer = request.getSubject();
        }
        // 序列号
        BigInteger serial = new BigInteger(32, new SecureRandom());
        // 有效日期
        Date from = new Date();
        Date to = new Date(System.currentTimeMillis() + (365 * 80 * 86400000L));
        // 摘要计算器
        // DigestCalculator digCalc = new BcDigestCalculatorProvider()
        // .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
        // 证书成成器
        X509v3CertificateBuilder certgen = new X509v3CertificateBuilder(issuer, serial, from, to, request.getSubject(),
                request.getSubjectPublicKeyInfo());

        //设置keyUsage扩展项
        certgen.addExtension(X509Extensions.KeyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature));

        // CA端进行签名, 才有具有法律效力
        ContentSigner signer = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(PrivateKeyFactory
                .createKey(priKey.getEncoded()));

        // 生成BC结构的证书
        Security.addProvider(new BouncyCastleProvider());
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(certgen.build(signer));

        FileUtil.createParentFilePath(certFilePath);
        PemUtil.PemWriter(certificate.getEncoded(), "CERTIFICATE", certFilePath);
        // 最终生成的是java.security的证书
        return certificate;
    }

    /**
     *
     * @param upCert
     * @param signedCert
     * @param upCertpriKey
     * @param encOutFilePath
     * @return
     * @throws Exception
     */
    @SuppressWarnings("deprecation")
    public static X509Certificate createEncCertificate(X509Certificate upCert, X509Certificate signedCert, PrivateKey upCertpriKey, String encOutFilePath)
            throws Exception {

        KeyPair keyPair = RSAKeyPairUtil.createKeyPair();
        PublicKey encPubKey = keyPair.getPublic();
        PrivateKey encPriKey = keyPair.getPrivate();
        PemUtil.PemWriter(encPriKey.getEncoded(),"PRIVATEKEY","C:/Users/as/Desktop/ENCPrivateKey.pem");
        // 签名算法标识符
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
        // 摘要算法标识符
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        // 签发者名称
        org.bouncycastle.asn1.x500.X500Name issuer = new org.bouncycastle.asn1.x500.X500Name(
                upCert.getSubjectX500Principal().getName());

        //公钥信息
        SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfo.getInstance(encPubKey.getEncoded());

        // 序列号
        BigInteger serial = new BigInteger(32, new SecureRandom());

        // 有效日期
        Date from = new Date();
        Date to = new Date(System.currentTimeMillis() + (365 * 80 * 86400000L));

        //所有者信息
        Principal subjectDn = signedCert.getSubjectDN();
        org.bouncycastle.asn1.x500.X500Name subject = new org.bouncycastle.asn1.x500.X500Name(subjectDn.getName());

        // 证书成成器
        X509v3CertificateBuilder certgen = new X509v3CertificateBuilder(issuer, serial, from, to, subject,
                pubKeyInfo);

        //设置keyUsage扩展项
        certgen.addExtension(X509Extensions.KeyUsage, true,
                new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.dataEncipherment));

        // CA端进行签名, 才有具有法律效力
        ContentSigner signer = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(PrivateKeyFactory
                .createKey(upCertpriKey.getEncoded()));

        // 生成BC结构的证书
        Security.addProvider(new BouncyCastleProvider());
        System.out.println(new String(Base64.encodeBase64(certgen.build(signer).getEncoded())));
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(certgen.build(signer));

        //生成证书响应格式
        CertificateResponse certResponse = GenDataUtil.getCertificateResponse(signedCert.getPublicKey(),
                encPriKey, certificate);

        //进行封装持久化，输出enc文件
        FileUtil.createParentFilePath(encOutFilePath);
        PemUtil.PemWriter(certResponse.getEncoded(), "ENC", encOutFilePath);
        PemUtil.PemWriter(certificate.getEncoded(), "CERTIFICATE", "C:/Users/as/Desktop/encyptedEncCert.cer");

        return certificate;
    }
}
