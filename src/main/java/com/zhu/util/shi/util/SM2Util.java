package com.zhu.util.shi.util;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * SM2的工具类
 */
public class SM2Util {
    /**
     * 默认USERID
     */
    public static String USER_ID = "1234567812345678";
    private static Logger log = LoggerFactory.getLogger(SM2Util.class);
    /**
     * SM2加密算法
     * @param publicKeyStr     公钥
     * @param data          明文数据
     * @return
     */
    public static String encrypt(String publicKeyStr, String data){
        Security.addProvider(new BouncyCastleProvider());
        PublicKey publicKey = null;
        try {
            log.info("开始转换字符串公钥，公钥值：{},数据值:{}",publicKeyStr,data);
            byte[] keyBytes =  Base64.decodeBase64(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            publicKey = keyFactory.generatePublic(keySpec);
            log.info("转换后的公钥：{}",publicKey);
        } catch (Exception e) {
            log.error("SM2字符串公钥转换异常：{}",e.getMessage());
            e.printStackTrace();
        }
        log.info("SM2开始加密数据");
        ECPublicKeyParameters ecPublicKeyParameters = null;
        if (publicKey instanceof BCECPublicKey) {
            BCECPublicKey bcecPublicKey = (BCECPublicKey) publicKey;
            ECParameterSpec ecParameterSpec = bcecPublicKey.getParameters();
            ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(),
                    ecParameterSpec.getG(), ecParameterSpec.getN());
            ecPublicKeyParameters = new ECPublicKeyParameters(bcecPublicKey.getQ(), ecDomainParameters);
        }
        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(true, new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom()));
        byte[] arrayOfBytes = null;
        try {
            byte[] in = data.getBytes("utf-8");
            arrayOfBytes = sm2Engine.processBlock(in,0, in.length);
        } catch (Exception e) {
            log.error("SM2加密时出现异常:",e.getMessage());
            System.out.println("SM2加密时出现异常:");
        }
        return  Base64.encodeBase64String(arrayOfBytes);
    }

    /**
     * SM2解密算法
     * @param privateKeyStr        私钥
     * @param cipherData        密文数据
     * @return
     */
    public static String decrypt(String privateKeyStr, String cipherData){
        Security.addProvider(new BouncyCastleProvider());
        PrivateKey privateKey = null;
        try {
            log.info("开始转换字符串私钥钥，私钥值：{},数据值:{}",privateKeyStr,cipherData);
            byte[] keyBytes = Base64.decodeBase64(privateKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            privateKey = keyFactory.generatePrivate(keySpec);
            log.info("转换后的私钥：{}",privateKey);
        }catch (Exception e){
            log.error("SM2字符串私钥转换异常：{}",e.getMessage());
            e.printStackTrace();
        }

        BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) privateKey;
        ECParameterSpec ecParameterSpec = bcecPrivateKey.getParameters();
        ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(),
                ecParameterSpec.getG(), ecParameterSpec.getN());
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(bcecPrivateKey.getD(),
                ecDomainParameters);
        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(false, ecPrivateKeyParameters);
        String result = null;

        byte[] arrayOfBytes = null;
        try {
            byte[] in = Base64.decodeBase64(cipherData);
            arrayOfBytes = sm2Engine.processBlock(in,0, in.length);
            result=new String(arrayOfBytes, "utf-8");
        } catch (Exception e) {
            System.out.println("SM2解密时出现异常");
        }
        return result;
    }

    /**
     * SM2算法生成密钥对
     * @return 密钥对信息
     */
    public static KeyPair generateSm2KeyPair() {
        try {
            final ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
            // 获取一个椭圆曲线类型的密钥对生成器
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
            SecureRandom random = new SecureRandom();
            // 使用SM2的算法区域初始化密钥生成器
            kpg.initialize(sm2Spec, random);
            // 获取密钥对
            KeyPair keyPair = kpg.generateKeyPair();
            return keyPair;
        } catch (Exception e) {
            log.error("generate sm2 key pair failed:{}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * 签名   格式是R+S
     * @param privateKey
     * @param dataHex
     * @return
     * @throws Exception
     */
    public static  String SM2Sign(String privateKey,String dataHex) throws Exception {
        // 私钥Hex格式转字节数组
        byte[] privatekey = Hex.decode(privateKey);
        // 待签数据Hex格式转字节数组
        byte[] sourceData = Hex.decode(dataHex);
        BigInteger userD = new  BigInteger(1,privatekey);
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
        ECPoint userKey = ecSpec.getG().multiply(userD);

        SM3Digest sm3Digest = new SM3Digest();
        byte [] z = sm2GetZ(USER_ID.getBytes(), userKey);
        sm3Digest.update(z, 0, z.length);
        sm3Digest.update(sourceData,0,sourceData.length);
        byte [] md = new byte[32];
        sm3Digest.doFinal(md, 0);
        BigInteger e = new BigInteger(1, md);
        BigInteger k = null;
        ECPoint kp = null;
        BigInteger r = null;
        BigInteger s = null;
        BigInteger R = null;
        BigInteger S = null;
        BigInteger n = ecSpec.getN();
        do {
            do {
                // 正式环境
                KeyPair keypair = generateSm2KeyPair();
                // 获取私钥和公钥的参数
                ECPrivateKey ecPrivateKey = (ECPrivateKey) keypair.getPrivate();
                ECPublicKey ecPublicKey = (ECPublicKey) keypair.getPublic();
                k = ecPrivateKey.getD();
                kp = ecPublicKey.getQ();
                r = e.add(kp.getXCoord().toBigInteger());
                r = r.mod(n);
            } while (r.equals(BigInteger.ZERO) || r.add(k).equals(n)||r.toString(16).length()!=64);
            BigInteger da_1 = userD.add(BigInteger.ONE);
            da_1 = da_1.modInverse(n);
            s = r.multiply(userD);
            s = k.subtract(s).mod(n);
            s = da_1.multiply(s).mod(n);
        } while (s.equals(BigInteger.ZERO)||(s.toString(16).length()!=64));

        R = r;
        S = s;
//        ASN1Integer d_r = new ASN1Integer(R);
//        ASN1Integer d_s = new ASN1Integer(S);
//        ASN1EncodableVector v2 = new ASN1EncodableVector();
//        v2.add(d_r);
//        v2.add(d_s);
//        DERSequence sign = new DERSequence(v2);
//        String result = Hex.toHexString(sign.getEncoded());
        return R.toString(16)+S.toString(16);
    }

    /**
     * 根据公钥、曲线参数计算Z
     * @param userId
     * @param userKey
     * @return
     */
    public static byte[] sm2GetZ(byte[] userId, ECPoint userKey) {
        SM3Digest sm3 = new SM3Digest();
        // 获取 SM2 曲线参数
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
        // 提取曲线参数
        ECCurve curve = ecSpec.getCurve();
        int len = userId.length * 8;
        sm3.update((byte) (len >> 8 & 0xFF));
        sm3.update((byte) (len & 0xFF));
        sm3.update(userId, 0, userId.length);

        byte[] p = curve.getA().getEncoded();
        sm3.update(p, 0, p.length);

        p = curve.getB().getEncoded();
        sm3.update(p, 0, p.length);

        p = ecSpec.getG().getXCoord().getEncoded();
        sm3.update(p, 0, p.length);

        p =  ecSpec.getG().getYCoord().getEncoded();
        sm3.update(p, 0, p.length);

        p = userKey.normalize().getXCoord().getEncoded();
        sm3.update(p, 0, p.length);

        p = userKey.normalize().getYCoord().getEncoded();
        sm3.update(p, 0, p.length);

        byte[] md = new byte[sm3.getDigestSize()];
        sm3.doFinal(md, 0);
        return md;
    }

    /**
     * 使用SM2 SM3杂凑验签
     * @param publicKey 公钥
     * @param hexData  待签数据
     * @param signHex 签名
     * @return
     * @throws Exception
     */
    public static boolean verifySM2(String publicKey, String hexData, String signHex) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // 解码公钥
        byte[] keyBytes = Hex.decode("04" + publicKey);
        ECPoint ecPoint = ECNamedCurveTable.getParameterSpec("sm2p256v1").getCurve().decodePoint(keyBytes);

        // 计算 Z 值
        SM3Digest sm3Digest = new SM3Digest();
        byte[] z = sm2GetZ(USER_ID.getBytes(), ecPoint);

        // 计算消息摘要
        byte[] sourceData = Hex.decode(hexData);
        sm3Digest.update(z, 0, z.length);
        sm3Digest.update(sourceData, 0, sourceData.length);
        byte[] md = new byte[32];
        sm3Digest.doFinal(md, 0);

        // 解析签名
        ASN1Primitive derObj = ASN1Primitive.fromByteArray(Hex.decode(SM2SignHardToSoft(signHex)));
        ASN1Sequence sequence = (ASN1Sequence) derObj;
        BigInteger r = ((ASN1Integer) sequence.getObjectAt(0)).getValue();
        BigInteger s = ((ASN1Integer) sequence.getObjectAt(1)).getValue();

        // 计算 t 和 R
        BigInteger t = r.add(s).mod(ECNamedCurveTable.getParameterSpec("sm2p256v1").getN());
        ECPoint x1y1 = ecPoint.multiply(t);
        BigInteger e1 = new BigInteger(1, md);


        ECPoint pointG = ECNamedCurveTable.getParameterSpec("sm2p256v1").getG().multiply(s);
        x1y1 = x1y1.add(pointG);

        BigInteger R = e1.add(x1y1.normalize().getXCoord().toBigInteger()).mod(ECNamedCurveTable.getParameterSpec("sm2p256v1").getN());
        return r.equals(R);
    }

    /**
     * SM2签名Hard转soft
     * @param hardSign
     * @return
     */
    public static String SM2SignHardToSoft(String hardSign) {
        byte[] bytes = Hex.decode(hardSign);
        byte[] r = new byte[bytes.length / 2];
        byte[] s = new byte[bytes.length / 2];
        System.arraycopy(bytes, 0, r, 0, bytes.length / 2);
        System.arraycopy(bytes, bytes.length / 2, s, 0, bytes.length / 2);
        ASN1Integer d_r = new ASN1Integer(byteConvertInteger(r));
        ASN1Integer d_s = new ASN1Integer(byteConvertInteger(s));
        ASN1EncodableVector v2 = new ASN1EncodableVector();
        v2.add(d_r);
        v2.add(d_s);
        DERSequence sign = new DERSequence(v2);

        String result = null;
        try {
            result = Hex.toHexString(sign.getEncoded());
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
        //SM2加密机转软加密编码格式
        return result;
    }
    /**
     * 换字节流（字节数组）型数据转大数字
     *
     * @param b
     * @return
     */
    public static BigInteger byteConvertInteger(byte[] b) {
        if (b[0] < 0) {
            byte[] temp = new byte[b.length + 1];
            temp[0] = 0;
            System.arraycopy(b, 0, temp, 1, b.length);
            return new BigInteger(temp);
        }
        return new BigInteger(b);
    }

    public static String utf8ToHex(String input) {
        byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
        StringBuilder hexString = new StringBuilder();

        for (byte b : bytes) {
            String hex = Integer.toHexString(b & 0xFF);
            if (hex.length() == 1) {
                hexString.append('0'); // 保证每个字节都是两位
            }
            hexString.append(hex);
        }

        return hexString.toString();
    }

    public static void main(String[] args) throws Exception{
        String text = "这是一段明文";
        String dataHex = utf8ToHex(text);
        String publicKey = "2497a4a3afaede06537455dea0a26e071aead87bb49ea2a19e5550c7cb421f55d399363649d876f4f0e443dbf9f79726e374d10b021576b1c6e44ba217204ac2";
        String privateKey = "4f7d3642bfdcf5612a3546372fb4626d70beb855200b43c645d6e80bf53fa442";

        String sign = SM2Sign(privateKey, dataHex);
        System.out.println(sign);
        //验签硬加密的串
//        String signYJ = "6e67313ee3c92fff83458741ccb0130a9b700fde4797e51224a76210e033f932aa2828b6e55c745acb36c4b446a7793e194fc318343707f336b47fe7554ebcdd";
        boolean verify = verifySM2(publicKey, dataHex, sign);
        System.err.println("验签结果" + verify);
    }

}
