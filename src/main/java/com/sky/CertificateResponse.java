package com.sky;

import org.bouncycastle.asn1.*;

/**
 * @program SelfIssueRsaDoubleCertificate
 * @description:  证书响应格式
 * @author: daile
 * @create: 2019/02/19 20:52
 */
public class CertificateResponse extends ASN1Object {
    //X509 证书（加密证书）
    private ASN1OctetString encCertificate;
    //被加密的加密私钥
    private EnvelopedKeyPairData  encKeyPair;

    public ASN1OctetString getEncCertificate() {
        return encCertificate;
    }

    public void setEncCertificate(ASN1OctetString encCertificate) {
        this.encCertificate = encCertificate;
    }

    public EnvelopedKeyPairData  getEncKeyPair() {
        return encKeyPair;
    }

    public void setEncKeyPair(EnvelopedKeyPairData  encKeyPair) {
        this.encKeyPair = encKeyPair;
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Object#toASN1Primitive()
     */
    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector encodableVector = new ASN1EncodableVector();
        encodableVector.add(encCertificate);
        encodableVector.add(encKeyPair);
        return new DERSequence(encodableVector);
    }

}
