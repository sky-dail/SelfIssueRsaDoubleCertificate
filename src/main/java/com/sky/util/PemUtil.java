package com.sky.util;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import sun.misc.BASE64Decoder;
import sun.security.pkcs10.PKCS10;
import sun.security.x509.X509CertImpl;

import java.io.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * @program SelfIssueRsaDoubleCertificate
 * @description: pem格式工具类
 * @author: daile
 * @create: 2019/02/19 21:04
 */
public class PemUtil {
    private static final int LINE_LENGTH = 64;

    public static void PemWriter(byte[] data,String type,String path){
        String encode= Base64.encodeBase64String(data);
        StringBuffer result= new StringBuffer();
        result.append("-----BEGIN " + type + "-----" );
        for(int i=0;i<encode.length();i++){
            if(i%LINE_LENGTH!=0){
                result.append(encode.charAt(i));
            }else{
                result.append('\n');
                result.append(encode.charAt(i));
            }
        }
        result.append('\n');
        result.append("-----END "+type+"-----"+'\n');

        File file=new File(path);
        try {
            PrintWriter writer=new PrintWriter(new FileOutputStream(file.getAbsolutePath()));
            writer.write(result.toString());
            writer.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static PrivateKey pvKeyReader(String path){
        try{
            BufferedReader br=new BufferedReader(new FileReader(path));
            String s=br.readLine();
            StringBuffer pvkey=new StringBuffer();
            s=br.readLine();
            while(s.charAt(0)!='-'){
                pvkey.append(s+'\r');
                s=br.readLine();
            }
            BASE64Decoder base64Decoder=new BASE64Decoder();
            byte keybyte[]=base64Decoder.decodeBuffer(pvkey.toString());
            KeyFactory keyFactory=KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec=new PKCS8EncodedKeySpec(keybyte);
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static X509Certificate CertReader(String path){
        try{
            BufferedReader br=new BufferedReader(new FileReader(path));
            String s=br.readLine();
            StringBuffer cert=new StringBuffer();
            s=br.readLine();
            while(s.charAt(0)!='-'){
                cert.append(s+'\r');
                s=br.readLine();
            }
            BASE64Decoder base64Decoder=new BASE64Decoder();
            byte certbyte[]=base64Decoder.decodeBuffer(cert.toString());
            return new X509CertImpl(certbyte);
        } catch (IOException | CertificateException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static Certificate CertBCReader(String path){
        try{
            BufferedReader br=new BufferedReader(new FileReader(path));
            String s=br.readLine();
            StringBuffer cert=new StringBuffer();
            s=br.readLine();
            while(s.charAt(0)!='-'){
                cert.append(s+'\r');
                s=br.readLine();
            }
            BASE64Decoder base64Decoder=new BASE64Decoder();
            byte certbyte[]=base64Decoder.decodeBuffer(cert.toString());
            X509CertificateHolder holder=new X509CertificateHolder(certbyte);
            return holder.toASN1Structure();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * @param path
     *            pem文件地址
     * @return
     * @throws Exception
     *
     *             从pem中获取证书请求信息
     */
    public static PKCS10CertificationRequest getRequestFromFileBC(String path) throws Exception {
        PEMParser pp = new PEMParser(new FileReader(path));
        PKCS10CertificationRequest request = (PKCS10CertificationRequest) pp.readObject();
        return request;
    }

    /**
     * @param path
     *            pem文件地址
     * @return
     * @throws Exception
     *
     *             从pem中获取证书请求信息
     */
    public static PKCS10 getRequestFromFile(String path) {
        try{
            BufferedReader br=new BufferedReader(new FileReader(path));
            String s=br.readLine();
            StringBuffer cert=new StringBuffer();
            s=br.readLine();
            while(s.charAt(0)!='-'){
                cert.append(s+'\r');
                s=br.readLine();
            }
            BASE64Decoder base64Decoder=new BASE64Decoder();
            byte[] certbyte = base64Decoder.decodeBuffer(cert.toString());
            PKCS10 pkcs10= new PKCS10(certbyte);
            return pkcs10;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;

    }
}
