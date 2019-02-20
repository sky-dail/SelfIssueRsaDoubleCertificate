# SelfIssueRsaDoubleCertificate
- 服务端自生成P10请求，根据请求生成根证书
- 根据根证书生成RSA签名证书，RSA加密证书

- 封包（将私钥以及加密证书封装成指定格式）
~~~
/**
 * EnvelopedKeyPairData ::= SEQUENCE {
 *     encryptedSymmKeyData     OctetString, //签名密钥对的公钥保护的对称密钥密文
 *     encryptedKeyPairData     OctetString, //使用对称密钥保护的加密证书密钥对
 *     symmetricIV              OctetString, //对称加密的IV值
 *     symmetricCipherOID       OctetString  //所使用的对称算法 OID
 *     }
 *
 * CertificateResponse ::= SEQUENCE {
 *     encCertificate       Certificate,  //X509 证书（加密证书）
 *     encKeyPair           EnvelopedKeyPairData,  //被加密的加密私钥
 *     }
 */
~~~
