package cn.com.agree.cipher.sm2;

import cn.com.agree.cipher.sm3.SM3Util;
import cn.com.agree.cipher.utils.ByteUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.io.*;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

/**
 * SM2工具类
 *
 * @author zaile
 */
public class SM2Util implements SM2Const {


    /**
     * 公钥加密
     *
     * @param input        加密原文
     * @param publicKeyStr 字符串公钥
     * @return
     */
    public static String encrypt(String input, String publicKeyStr) {
        SM2 sm = new SM2();
        ECPoint publicKey = SM2Util.getPubKeyFromHexString(publicKeyStr);
        byte[] data = sm.encrypt(input, publicKey);
        return ByteUtil.byteToHex(data);
    }

    /**
     * 私钥解密
     *
     * @param input         密文数据
     * @param privateKeyStr 解密私钥字符串
     * @return
     */
    public static String decrypt(String input, String privateKeyStr) {
        SM2 sm = new SM2();
        BigInteger privateKey = new BigInteger(privateKeyStr, 16);
        byte[] encryptData = ByteUtil.hexToByte(input);
        return sm.decrypt(encryptData, privateKey);
    }


    /**
     * 签名
     *
     * @param M             签名信息
     * @param privateKeyStr 私钥字符串
     * @return
     * @throws IOException
     */
    public static String sign(String M, String privateKeyStr) throws IOException {
        BigInteger privateKey = new BigInteger(privateKeyStr, 16);
        ECPoint pubKeyByPriKey = SM2Util.generatePubKeyByPriKey(privateKey);
        SM2 sm = new SM2();
        String signStr = ByteUtils.toHexString(sm.signWithEncode(M, new SM2KeyPair(pubKeyByPriKey, privateKey)));
        return signStr;
    }

    public static String sign(String M, String privateKeyStr, String publicKeyStr) throws IOException {
        BigInteger privateKey = new BigInteger(privateKeyStr, 16);
        ECPoint pubKeyByPriKey = SM2Util.getPubKeyFromHexString(publicKeyStr);
        SM2 sm = new SM2();
        String signStr = ByteUtils.toHexString(sm.signWithEncode(M, new SM2KeyPair(pubKeyByPriKey, privateKey)));
        return signStr;
    }

    /**
     * 签名
     *
     * @param M             签名信息
     * @param IDA           签名方唯一标识
     * @param privateKeyStr 私钥字符串
     * @return
     * @throws IOException
     */
    public static String sign(String M, byte[] IDA, String privateKeyStr) throws IOException {
        BigInteger privateKey = new BigInteger(privateKeyStr, 16);
        ECPoint pubKeyByPriKey = SM2Util.generatePubKeyByPriKey(privateKey);
        SM2 sm = new SM2();
        String signStr = ByteUtils.toHexString(sm.signWithEncode(M, IDA, new SM2KeyPair(pubKeyByPriKey, privateKey)));
        return signStr;
    }

    /**
     * 验签
     *
     * @param M                标准签名信息
     * @param encodedSignature 签名
     * @param publicKeyStr     公钥字符串
     */
    public static boolean checkSign(String M, String encodedSignature, String publicKeyStr) throws IOException {
        SM2 sm = new SM2();
        ECPoint pubKey = SM2Util.getPubKeyFromHexString(publicKeyStr);
        return sm.verifyWithEncoded(M, encodedSignature, pubKey);
    }

    /**
     * 验签
     *
     * @param M                标准签名信息
     * @param IDA              签名方唯一标识
     * @param encodedSignature 签名
     * @param publicKeyStr     公钥字符串
     * @return
     * @throws IOException
     */
    public static boolean checkSign(String M, byte[] IDA, String encodedSignature, String publicKeyStr) throws IOException {
        SM2 sm = new SM2();
        ECPoint pubKey = SM2Util.getPubKeyFromHexString(publicKeyStr);
        boolean verifyResult = sm.verifyWithEncoded(M, IDA, encodedSignature, pubKey);
        return verifyResult;
    }


    /**
     * 判断字节数组是否全0
     *
     * @param buffer
     * @return
     */
    public static boolean allZero(byte[] buffer) {
        for (int i = 0; i < buffer.length; i++) {
            if (buffer[i] != 0)
                return false;
        }
        return true;
    }

    /**
     * 生成密钥对
     *
     * @return
     */
    public static SM2KeyPair generateKeyPair() {

        BigInteger d = random(N.subtract(new BigInteger("1")));

        SM2KeyPair keyPair = new SM2KeyPair(G.multiply(d).normalize(), d);

        if (checkPublicKey(keyPair.getPublicKey())) {
            return keyPair;
        } else {
            return null;
        }
    }

    /**
     * 根据私钥生成公钥
     *
     * @param priKey 使用的私钥
     * @return
     */
    public static ECPoint generatePubKeyByPriKey(BigInteger priKey) {
        SM2KeyPair keyPair = new SM2KeyPair(G.multiply(priKey).normalize(), priKey);

        if (checkPublicKey(keyPair.getPublicKey())) {
            return keyPair.getPublicKey();
        } else {
            return null;
        }
    }


    /**
     * 检查公私钥是否匹配
     *
     * @param priKey 私钥
     * @param pubkey 公钥
     * @return
     */
    public static boolean isKeyMatch(BigInteger priKey, ECPoint pubkey) {
        ECPoint ecPoint = generatePubKeyByPriKey(priKey);
        return ecPoint.equals(pubkey);
    }

    /**
     * 根据hexstring获取公钥
     *
     * @param hexString
     * @return
     */
    public static ECPoint getPubKeyFromHexString(String hexString) {
        ECPoint pubKey = getCandidatePubKeyFromHexString(hexString);
        if (checkPublicKey(pubKey)) {
            return pubKey;
        }
        throw new IllegalArgumentException("Illegal PublicKey: " + hexString);
    }


    /**
     * 随机数生成器
     *
     * @param max
     * @return
     */
    public static BigInteger random(BigInteger max) {
        BigInteger r = new BigInteger(256, random);
        // int count = 1;
        while (r.compareTo(max) >= 0) {
            r = new BigInteger(128, random);
            // count++;
        }
        // System.out.println("count: " + count);
        return r;
    }

    /**
     * 判断是否在范围内
     *
     * @param param
     * @param min
     * @param max
     * @return
     */
    public static boolean between(BigInteger param, BigInteger min, BigInteger max) {
        if (param.compareTo(min) >= 0 && param.compareTo(max) < 0) {
            return true;
        } else {
            return false;
        }
    }


    /**
     * 检查公钥合法性
     *
     * @param hexString
     * @return
     */
    public static boolean checkPubKeyIllegal(String hexString) {
        char[] chars = hexString.toUpperCase().toCharArray();
        if (chars.length == 130) {
            if (chars[0] == '0' && chars[1] == '4') {
                for (int i = 2; i < chars.length; i++) {
                    char c = chars[i];
                    if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
                        continue;
                    } else {
                        return false;
                    }
                }
                ECPoint ecPoint = getCandidatePubKeyFromHexString(hexString);
                return checkPublicKey(ecPoint);
//                return true;
            }
        }
        return false;
    }

    /**
     * sm3摘要
     *
     * @param params
     * @return
     */
    public static byte[] sm3hash(byte[]... params) {
        byte[] res = null;
        res = SM3Util.sm3DigistAsBytes(join(params));
        return res;
    }

    /**
     * 字节数组拼接
     *
     * @param params
     * @return
     */
    public static byte[] join(byte[]... params) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] res = null;
        try {
            for (int i = 0; i < params.length; i++) {
                baos.write(params[i]);
            }
            res = baos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return res;
    }


    /**
     * 取得用户标识字节数组
     *
     * @param IDA
     * @param aPublicKey
     * @return
     */
    public static byte[] ZA(byte[] IDA, ECPoint aPublicKey) {
        byte[] idaBytes = IDA;
        int entlenA = idaBytes.length * 8;
        byte[] ENTLA = new byte[]{(byte) (entlenA >> 8 & 0xFF), (byte) (entlenA & 0xFF)};
        byte[] ZA = sm3hash(ENTLA, idaBytes, A.getEncoded(), B.getEncoded(), GX.getEncoded(), GY.getEncoded(),
                aPublicKey.getXCoord().getEncoded(),
                aPublicKey.getYCoord().getEncoded());
        return ZA;
    }

    /**
     * 密钥派生函数
     *
     * @param Z
     * @param klen 生成klen字节数长度的密钥
     * @return
     */
    public static byte[] KDF(byte[] Z, int klen) {
        int ct = 1;
        int end = (int) Math.ceil(klen * 1.0 / 32);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            for (int i = 1; i < end; i++) {
                baos.write(sm3hash(Z, SM3Util.toByteArray(ct)));
                ct++;
            }
            byte[] last = sm3hash(Z, SM3Util.toByteArray(ct));
            if (klen % 32 == 0) {
                baos.write(last);
            } else
                baos.write(last, 0, klen % 32);
            return baos.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * bigInteger转成16进制
     *
     * @param bigInteger
     * @return
     */
    public static String bigIntegerToHex(BigInteger bigInteger) {
        return bigIntegerToHex(bigInteger, 64);
    }

    /**
     * bigInteger转成16进制
     *
     * @param bigInteger
     * @param length
     * @return
     */
    public static String bigIntegerToHex(BigInteger bigInteger, int length) {
        byte[] bytes = new byte[length];
        byte[] hexBytes = bigInteger.toString(16).getBytes();
        for (int i = 0; i < length; i++) {
            int position = hexBytes.length - i - 1;
            if (position < 0) {
                bytes[length - i - 1] = '0';
            } else {
                bytes[length - i - 1] = hexBytes[position];
            }
        }
        return new String(bytes);
    }

    /**
     * 生成字符串密钥对，以privateKey+","+publicKey格式返回，私钥和公钥以英文逗号分隔
     *
     * @return
     */
    public static String createKey() {
        SM2KeyPair key = SM2Util.generateKeyPair();
        String privateKey = key.getPrivateKey().toString(16).toUpperCase();
        String publicKey = ByteUtil.byteToHex(key.getPublicKey().getEncoded(false));
        return privateKey + "," + publicKey;
    }


    /**
     * 导出公钥到本地
     *
     * @param publicKey
     * @param path
     */
    public static void exportPublicKey(ECPoint publicKey, String path) {
        File file = new File(path);
        try {
            if (!file.exists())
                file.createNewFile();
            byte buffer[] = publicKey.getEncoded(false);
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(buffer);
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 从本地导入公钥
     *
     * @param path
     * @return
     */
    public static ECPoint importPublicKey(String path) {
        File file = new File(path);
        try {
            if (!file.exists())
                return null;
            FileInputStream fis = new FileInputStream(file);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            byte buffer[] = new byte[16];
            int size;
            while ((size = fis.read(buffer)) != -1) {
                baos.write(buffer, 0, size);
            }
            fis.close();
            return curve.decodePoint(baos.toByteArray());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 导出私钥到本地
     *
     * @param privateKey
     * @param path
     */
    public static void exportPrivateKey(BigInteger privateKey, String path) {
        File file = new File(path);
        try {
            if (!file.exists())
                file.createNewFile();
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(file));
            oos.writeObject(privateKey);
            oos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 从本地导入私钥
     *
     * @param path
     * @return
     */
    public static BigInteger importPrivateKey(String path) {
        File file = new File(path);
        try {
            if (!file.exists())
                return null;
            FileInputStream fis = new FileInputStream(file);
            ObjectInputStream ois = new ObjectInputStream(fis);
            BigInteger res = (BigInteger) (ois.readObject());
            ois.close();
            fis.close();
            return res;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;

    }


    /**
     * 根据私钥字符获取公钥字符串
     *
     * @param privateKeyStr 私钥字符串
     * @return
     */
    public static String getPublicKeyStr(String privateKeyStr) {
        ECPoint pubKeyByPriKey = SM2Util.generatePubKeyByPriKey(new BigInteger(privateKeyStr, 16));
        String pubKeyString = ByteUtil.byteToHex(pubKeyByPriKey.getEncoded(false));
        return pubKeyString;
    }

    /**
     * 应用公钥格式校验
     *
     * @param publicKeyStr
     * @return
     */
    public static boolean checkPublicKey(String publicKeyStr) {
        return SM2Util.checkPubKeyIllegal(publicKeyStr);
    }


    /**
     * 获取候选公钥
     *
     * @param hexString
     * @return
     */
    private static ECPoint getCandidatePubKeyFromHexString(String hexString) {
        BigInteger xPoint = new BigInteger(hexString.substring(0, 64), 16);
        BigInteger yPoint = new BigInteger(hexString.substring(64), 16);
        return curve.createPoint(xPoint, yPoint);
    }

    /**
     * 判断生成的公钥是否合法
     *
     * @param publicKey
     * @return
     */
    private static boolean checkPublicKey(ECPoint publicKey) {
        if (!publicKey.isInfinity()) {

            BigInteger x = publicKey.getXCoord().toBigInteger();
            BigInteger y = publicKey.getYCoord().toBigInteger();

            if (between(x, new BigInteger("0"), P) && between(y, new BigInteger("0"), P)) {
                BigInteger xResult = x.pow(3).add(a.multiply(x)).add(b).mod(P);
                BigInteger yResult = y.pow(2).mod(P);

                if (yResult.equals(xResult) && publicKey.multiply(N).isInfinity()) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * SM2算法生成密钥对
     *
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
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        //生成密钥对
        String key = createKey();
        String privateKeyStr = key.split(",")[0];
        String publicKeyStr = key.split(",")[1];
        System.out.println("公钥：" + publicKeyStr);

        System.out.println("私钥：" + privateKeyStr);


        //加密
        System.out.println("========加解密测试=======");
        String message = "密文原文";
        String seceretyMessage = encrypt(message, publicKeyStr);
        System.out.println("加密后：" + seceretyMessage);

        message = decrypt(seceretyMessage, privateKeyStr);
        System.out.println("解密后：" + message);

        SM2 sm2 = new SM2();
        byte[] dd = sm2.encrypt(message, SM2Util.getPubKeyFromHexString(publicKeyStr));

        System.out.println("加密后2：" + ByteUtil.byteToHex(dd));
        String dd2 = sm2.decrypt(dd, new BigInteger(privateKeyStr, 16));
        System.out.println("解密后2=" + dd2);


        //加解签
//    	公钥：04CEBC7A659510AF193DC1B5820F6E4AA6A4EA3162779069710206041974C1DE2EEDF129417036043E3897854C749D04E0FC97F2AFDDC7073EA40000CF4CF16F1C
//    	私钥：8048c52c39a89e29837eed20a0c5abf5c940c8d60834439982f4a9fdf38c181c
        System.out.println("========加解签测试=======");

        try {
            String msg = sign("ddd", "f4e08d945183fc9fa6425561e4799efa8facfe0b715cb93c2db8a8142aad6f24");//,"0446fdfdd70d9a9c3c80fbbbf790abdaa954ce62b3642390923f706acced5b5db0864f6873397b94ab48d1d0bf05bcfa5b4c2e032de4f25556f72e2ed9ebe69bfc");
//			String msg = sign("ddd", "e4b752f27421e5228f572c840ae9b9f016e3ce9e33fa17d163ee61869c664954");//"0487DF13B9FDB99097D58F3CC65AD9DE70624704C2EC540A08268A14158A961FCCE1C5795B49BF16B1958AF92A70118BBADF03D67C38B09869A4E7A3F99CD1DD29");

            System.out.println("签名=" + msg);
            boolean flag = checkSign("ddd", msg, "0446fdfdd70d9a9c3c80fbbbf790abdaa954ce62b3642390923f706acced5b5db0864f6873397b94ab48d1d0bf05bcfa5b4c2e032de4f25556f72e2ed9ebe69bfc");
//    	    boolean flag = checkSign("ddd", msg, "0487DF13B9FDB99097D58F3CC65AD9DE70624704C2EC540A08268A14158A961FCCE1C5795B49BF16B1958AF92A70118BBADF03D67C38B09869A4E7A3F99CD1DD29");
            System.out.println("验签=" + flag);

        } catch (IOException e) {
            // TODO 自动生成的 catch 块
            e.printStackTrace();
        }


    }


}
    
