package com.sky;

import org.bouncycastle.asn1.*;

/**
 * @program SelfIssueRsaDoubleCertificate
 * @description: 封包格式
 * @author: daile
 * @create: 2019/02/19 20:53
 */
public class EnvelopedKeyPairData extends ASN1Object {
    //签名密钥对的公钥保护的对称密钥密文
    private ASN1OctetString encryptedSymmKeyData;
    //使用对称密钥保护的加密证书密钥对
    private ASN1OctetString encryptedKeyPairData;
    //对称加密的IV值
    private ASN1OctetString symmetricIV;
    //所使用的对称算法 OID
    private ASN1OctetString symmetricCipherOID;

    public ASN1OctetString getEncryptedSymmKeyData() {
        return encryptedSymmKeyData;
    }

    public void setEncryptedSymmKeyData(ASN1OctetString encryptedSymmKeyData) {
        this.encryptedSymmKeyData = encryptedSymmKeyData;
    }

    public ASN1OctetString getEncryptedKeyPairData() {
        return encryptedKeyPairData;
    }

    public void setEncryptedKeyPairData(ASN1OctetString encryptedKeyPairData) {
        this.encryptedKeyPairData = encryptedKeyPairData;
    }

    public ASN1OctetString getSymmetricIV() {
        return symmetricIV;
    }

    public void setSymmetricIV(ASN1OctetString symmetricIV) {
        this.symmetricIV = symmetricIV;
    }

    public ASN1OctetString getSymmetricCipherOID() {
        return symmetricCipherOID;
    }

    public void setSymmetricCipherOID(ASN1OctetString symmetricCipherOID) {
        this.symmetricCipherOID = symmetricCipherOID;
    }

    @Override
    public String toString() {
        return "EnvelopedKeyPairData  [encryptedSymmKeyData=" + encryptedSymmKeyData + ", encryptedKeyPairData="
                + encryptedKeyPairData + ", symmetricIV=" + symmetricIV + ", symmetricCipherOID=" + symmetricCipherOID
                + "]";
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector encodableVector = new ASN1EncodableVector();
        encodableVector.add(encryptedSymmKeyData);
        encodableVector.add(encryptedKeyPairData);
        encodableVector.add(symmetricIV);
        encodableVector.add(symmetricCipherOID);

        return new DERSequence(encodableVector);
    }
}
