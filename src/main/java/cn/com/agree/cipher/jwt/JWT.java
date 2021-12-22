package cn.com.agree.cipher.jwt;

import cn.com.agree.cipher.exception.JWTException;
import cn.com.agree.cipher.jwe.AAD;
import cn.com.agree.cipher.sm2.SM2CertEncryptionUtil;
import cn.com.agree.cipher.sm2.SM2KeyPair;
import cn.com.agree.cipher.sm2.SM2Util;
import cn.com.agree.cipher.sm3.SM3Util;
import cn.com.agree.cipher.sm4.SM4Util;
import cn.com.agree.cipher.utils.ByteUtil;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.impl.io.InstanceLocator;
import io.jsonwebtoken.io.*;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;
import io.jsonwebtoken.lang.Strings;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.HashMap;
import java.util.Map;


/**
 * JWT工具类
 * <p>
 * 签发：JWS、JWE
 */
public class JWT {

    /**
     * 签JWT
     *
     * @param privateKeyStr 十六进制私钥，签发者的私钥
     * @param claims        签入的字段内容
     */
    public static String signJWT(String kid, String privateKeyStr, Map<String, Object> claims) throws IOException {
        //头部
        Map<String, Object> header = new HashMap<>();
        header.put("alg", "SM2");
        header.put("typ", "JWT");
        header.put("kid", kid);
        Encoder<byte[], String> base64UrlEncoder = Encoders.BASE64URL;
        String base64UrlEncodedHeader = base64UrlEncode(header, "Unable to serialize header to json.", base64UrlEncoder);

        //负载为JWE的报文体
        if (claims == null) {
            claims = new HashMap<String, Object>();
        }

        byte[] bytes = toJson(claims);
        String base64UrlEncodedBody = base64UrlEncoder.encode(bytes);
        String jwt = base64UrlEncodedHeader + JwtParser.SEPARATOR_CHAR + base64UrlEncodedBody;
        //签名
        String base64UrlSignature = SM2Util.sign(jwt, privateKeyStr);
        jwt += JwtParser.SEPARATOR_CHAR + base64UrlSignature;
        return jwt;
    }

    /**
     * 验证JWT
     *
     * @param jwt          jwt
     * @param publicKeyStr 公钥字符串， 发送方的公钥
     */
    public static Map<String, ?> checkJWT(String jwt, String publicKeyStr) throws JWTException {
        boolean flag = false;
        String encodedSignature = null;
        StringBuilder sb = new StringBuilder(128);
        int delimiterCount = 0;
        String base64UrlEncodedHeader = null;
        String base64UrlEncodedBody = null;
        String base64UrlSignature = null;

        String M = null;
        for (char c : jwt.toCharArray()) {
            if (c == JwtParser.SEPARATOR_CHAR) {
                CharSequence tokenSeq = Strings.clean(sb);
                String token = tokenSeq != null ? tokenSeq.toString() : null;

                if (delimiterCount == 0) {
                    base64UrlEncodedHeader = token;
                } else if (delimiterCount == 1) {
                    base64UrlEncodedBody = token;
                }
                delimiterCount++;
                sb.setLength(0);
            } else {
                sb.append(c);
            }
        }

        if (delimiterCount != 2) {
            String msg = "JWT strings must contain exactly 2 period characters. Found: " + delimiterCount;
            throw new MalformedJwtException(msg);
        }

        if (sb.length() > 0) {
            base64UrlSignature = sb.toString();
        }

        if (base64UrlEncodedHeader == null) {
            throw new MalformedJwtException("JWT string '" + jwt + "' is missing a header.");
        }

        if (base64UrlEncodedBody == null) {
            throw new MalformedJwtException("JWT string '" + jwt + "' is missing a playload.");
        }

        if (base64UrlSignature == null) {
            throw new MalformedJwtException("JWT string '" + jwt + "' is missing a signature.");
        }

        //校验签名
        try {
            M = base64UrlEncodedHeader + JwtParser.SEPARATOR_CHAR + base64UrlEncodedBody;
            encodedSignature = base64UrlSignature;
            flag = SM2Util.checkSign(M, encodedSignature, publicKeyStr);
            if (flag) {
                String payload = new String(Decoders.BASE64URL.decode(base64UrlEncodedBody));
                return readValue(payload);
            }
        } catch (IOException e) {
            throw new JWTException("fail to check jwt", e);
        }
        return null;
    }

    /**
     * 签JWS
     *
     * @param kid           应用ID
     * @param privateKeyStr 十六进制私钥，签发者的私钥
     * @param plainText     请求报文体，若为get请求或报文体为空时，则传null
     * @return
     * @throws IOException
     */
    public static String signJWS(String kid, String privateKeyStr, String plainText) throws IOException {
        //头部
        Map<String, Object> header = new HashMap<>();
        header.put("alg", "SM2");
        header.put("typ", "JWT");
        header.put("kid", kid);
        Encoder<byte[], String> base64UrlEncoder = Encoders.BASE64URL;
        String base64UrlEncodedHeader = base64UrlEncode(header, "Unable to serialize header to json.", base64UrlEncoder);

        String base64UrlEncodedBody = "";
        String base64UrlSignature = "";
        HashMap<String, Object> claims = new HashMap<String, Object>();
        byte[] bytes = toJson(claims);
        base64UrlEncodedBody = base64UrlEncoder.encode(bytes);

        String jwt = base64UrlEncodedHeader + JwtParser.SEPARATOR_CHAR + base64UrlEncodedBody;
        if (plainText == null || plainText.equals("")) {
            //无报文体为空负载签名
            base64UrlSignature = base64UrlEncoder.encode(SM2Util.sign(jwt, privateKeyStr).getBytes());
        } else {
            // 报文体作为负载签名
            base64UrlSignature = base64UrlEncoder.encode(SM2Util.sign(base64UrlEncodedHeader + JwtParser.SEPARATOR_CHAR + plainText, privateKeyStr).getBytes());
        }
        jwt = jwt + JwtParser.SEPARATOR_CHAR + base64UrlSignature;
        return jwt;
    }

    /**
     * 验证JWS
     *
     * @param jwt          jwt 需校验的请求头x-jws-signature
     * @param publicKeyStr 公钥字符串， 发送方的公钥
     * @param plainText    请求报文体，若为get请求或报文体为空时，则传null,若报文进行了jwe加密，验证前需先将jwe进行解密获取原文报文体
     * @return
     */
    public static boolean checkJWS(String jwt, String publicKeyStr, String plainText) throws JWTException {
        Decoder<String, byte[]> base64UrlDecoder = Decoders.BASE64URL;
        boolean flag = false;
        String encodedSignature = null;
        StringBuilder sb = new StringBuilder(128);
        int delimiterCount = 0;
        String base64UrlEncodedHeader = null;
        String base64UrlEncodedBody = null;
        String base64UrlSignature = null;

        String M = null;
        for (char c : jwt.toCharArray()) {
            if (c == JwtParser.SEPARATOR_CHAR) {
                CharSequence tokenSeq = Strings.clean(sb);
                String token = tokenSeq != null ? tokenSeq.toString() : null;

                if (delimiterCount == 0) {
                    base64UrlEncodedHeader = token;
                } else if (delimiterCount == 1) {
                    base64UrlEncodedBody = token;
                }
                delimiterCount++;
                sb.setLength(0);
            } else {
                sb.append(c);
            }
        }

        if (delimiterCount != 2) {
            String msg = "JWT strings must contain exactly 2 period characters. Found: " + delimiterCount;
            throw new MalformedJwtException(msg);
        }

        if (sb.length() > 0) {
            base64UrlSignature = sb.toString();
        }

        if (base64UrlEncodedHeader == null) {
            throw new MalformedJwtException("JWT string '" + jwt + "' is missing a header.");
        }

        if (base64UrlEncodedBody == null) {
            throw new MalformedJwtException("JWT string '" + jwt + "' is missing a playload.");
        }

        if (base64UrlSignature == null) {
            throw new MalformedJwtException("JWT string '" + jwt + "' is missing a signature.");
        }

        //校验签名
        try {
            if (plainText != null && !plainText.equals("")) {
                M = base64UrlEncodedHeader + JwtParser.SEPARATOR_CHAR + plainText;
            } else {
                M = base64UrlEncodedHeader + JwtParser.SEPARATOR_CHAR + base64UrlEncodedBody;
            }
            encodedSignature = new String(base64UrlDecoder.decode(base64UrlSignature));
            flag = SM2Util.checkSign(M, encodedSignature, publicKeyStr);
        } catch (IOException e) {
            throw new JWTException("fail to check JWS", e);
        }
        return flag;
    }

    public static boolean checkJWSWithB64Cert(String jwt, String b64Cert, String plainText) throws JWTException {
        Decoder<String, byte[]> base64UrlDecoder = Decoders.BASE64URL;
        boolean flag = false;
        String encodedSignature = null;
        StringBuilder sb = new StringBuilder(128);
        int delimiterCount = 0;
        String base64UrlEncodedHeader = null;
        String base64UrlEncodedBody = null;
        String base64UrlSignature = null;

        String M = null;
        for (char c : jwt.toCharArray()) {
            if (c == JwtParser.SEPARATOR_CHAR) {
                CharSequence tokenSeq = Strings.clean(sb);
                String token = tokenSeq != null ? tokenSeq.toString() : null;

                if (delimiterCount == 0) {
                    base64UrlEncodedHeader = token;
                } else if (delimiterCount == 1) {
                    base64UrlEncodedBody = token;
                }
                delimiterCount++;
                sb.setLength(0);
            } else {
                sb.append(c);
            }
        }

        if (delimiterCount != 2) {
            String msg = "JWT strings must contain exactly 2 period characters. Found: " + delimiterCount;
            throw new MalformedJwtException(msg);
        }

        if (sb.length() > 0) {
            base64UrlSignature = sb.toString();
        }

        if (base64UrlEncodedHeader == null) {
            throw new MalformedJwtException("JWT string '" + jwt + "' is missing a header.");
        }

        if (base64UrlEncodedBody == null) {
            throw new MalformedJwtException("JWT string '" + jwt + "' is missing a playload.");
        }

        if (base64UrlSignature == null) {
            throw new MalformedJwtException("JWT string '" + jwt + "' is missing a signature.");
        }

        //校验签名
        try {
            if (plainText != null && !plainText.equals("")) {
                M = base64UrlEncodedHeader + JwtParser.SEPARATOR_CHAR + plainText;
            } else {
                M = base64UrlEncodedHeader + JwtParser.SEPARATOR_CHAR + base64UrlEncodedBody;
            }
            flag = SM2CertEncryptionUtil.checkSignWithB64Cert(M, base64UrlDecoder.decode(base64UrlSignature), b64Cert);
        } catch (IOException e) {
            throw new JWTException("fail to check JWS", e);
        }
        return flag;
    }

    /**
     * 获取JWS请求头
     *
     * @param jwt
     * @return
     */
    public static Map<String, ?> getJWSHeader(String jwt) {
        StringBuilder sb = new StringBuilder(128);
        String base64UrlEncodedHeader = null;

        for (char c : jwt.toCharArray()) {
            if (c == JwtParser.SEPARATOR_CHAR) {
                CharSequence tokenSeq = Strings.clean(sb);
                String token = tokenSeq != null ? tokenSeq.toString() : null;
                base64UrlEncodedHeader = token;
                break;
            } else {
                sb.append(c);
            }
        }

        if (base64UrlEncodedHeader == null) {
            throw new MalformedJwtException("JWT string '" + jwt + "' is missing a header.");
        }

        String header = new String(Decoders.BASE64URL.decode(base64UrlEncodedHeader));
        return readValue(header);
    }


    /**
     * SM4算法CBC模式加密报文内容
     *
     * @param kid          指明使用证书哪个签名id的公私钥，告诉接收方应该使用这个值来标识用于验证JWS/JWE的证书。
     * @param publicKeyStr SM2算法公钥加密SM4算法加密内容的动态对称密钥
     * @param plainText    需要加密的明文报文体
     * @return
     * @throws IOException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */
    public static String signJWE(String kid, String publicKeyStr, String plainText) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        /**
         * 参考 RFC 7516 (JWE), section Appendix B
         */
        Encoder<byte[], String> base64UrlEncoder = Encoders.BASE64URL;
        // 头部
        Map<String, Object> header = new HashMap<>();
        // type：一般是 jwt
        // alg：算法名称，和JWS相同，该算法用于加密稍后用于加密内容的实际密钥
        // enc：算法名称，用上一步生成的密钥加密内容的算法。
        header.put("alg", "SM2");
        header.put("typ", "JWT");
        header.put("kid", kid);
        header.put("enc", "SM4");
        String base64UrlEncodedHeader = base64UrlEncode(header, "Unable to serialize header to json.", base64UrlEncoder);
        //随机生成128位密钥，用于SM4加密密钥
        String sm4EncKey = ByteUtil.byteToHex(SM4Util.generateKey());
        //随机生成128位密钥，用于HMAC-SM3加密密钥
        String hmacKey = ByteUtil.byteToHex(SM4Util.generateKey());
        // 将SM4密钥和HMAC密钥拼接(HMAC在前)，然后使用公钥SM2算法对拼接后的结果加密
        String encryptedKey = SM2Util.encrypt(hmacKey + sm4EncKey, publicKeyStr);
        String base64EncryptedKey = base64UrlEncoder.encode(encryptedKey.getBytes());
        // 生成iv（Initialization Vector）
        String iv = ByteUtil.byteToHex(SM4Util.generateSM4IV(128));
        String base64Iv = base64UrlEncoder.encode(iv.getBytes());
        // 加密原始报文
        byte[] cipherTextByte = SM4Util.encrypt_Cbc_Padding(ByteUtil.hexStringToBytes(sm4EncKey), ByteUtil.hexStringToBytes(iv), plainText.getBytes("UTF-8"));
        String cipherText = ByteUtil.byteToHex(cipherTextByte);
        String base64Ciphertext = base64UrlEncoder.encode(cipherText.getBytes());

        // 生成Additional Authentication Data，生成方式：ASCII(BASE64URL(UTF8(JWE Protected Header)))
        byte[] aadBytes = AAD.compute(base64UrlEncodedHeader);
        // 计算AAD length (AL)
        byte[] alBytes = AAD.computeLength(aadBytes);
        /**
         * 使用 HMAC-SM3 算法计算HMAC值，计算流程
         *  1、 将 AAD, IV, Ciphertext, AADLength 进行连接
         *  2、 使用 HMAC-SM3 计算第1步中的连接值
         * 参考 RFC 7516 (JWE), section Appendix B.5、B.6
         */
        byte[] concatBytes = ByteUtil.concatenate(aadBytes, ByteUtil.hexToByte(iv), ByteUtil.hexToByte(cipherText), alBytes);
        byte[] hmacBytes = SM3Util.hmacAsBytes(concatBytes, ByteUtil.hexToByte(hmacKey));
        // 截断 HMAC 值生成消息认证标签（Authentication Tag），取前128位
        byte[] tagBytes = ByteUtils.subArray(hmacBytes, 0, 16);
        String base64Tag = base64UrlEncoder.encode(tagBytes);
        // 使用 JWE Compact 序列化方式
        String jwe = base64UrlEncodedHeader + JwtParser.SEPARATOR_CHAR
                + base64EncryptedKey + JwtParser.SEPARATOR_CHAR
                + base64Iv + JwtParser.SEPARATOR_CHAR
                + base64Ciphertext + JwtParser.SEPARATOR_CHAR
                + base64Tag;
        return jwe;
    }


    public static String signJWEWithB64Cert(String appId, String publicKeyStr, String plainText)
            throws IOException, NoSuchAlgorithmException, NoSuchProviderException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException, InvalidCipherTextException {
        /**
         * 参考 RFC 7516 (JWE), section Appendix B
         */
        Encoder<byte[], String> base64UrlEncoder = Encoders.BASE64URL;
        // 头部
        Map<String, Object> header = new HashMap<>();
        // type：一般是 jwt
        // alg：算法名称，和JWS相同，该算法用于加密稍后用于加密内容的实际密钥
        // enc：算法名称，用上一步生成的密钥加密内容的算法。
        header.put("alg", "SM2");
        header.put("typ", "JWT");
        header.put("kid", appId);
        header.put("enc", "SM4");
        String base64UrlEncodedHeader = base64UrlEncode(header, "Unable to serialize header to json.", base64UrlEncoder);
        //随机生成128位密钥，用于SM4加密密钥
        String sm4EncKey = ByteUtil.byteToHex(SM4Util.generateKey());
        //随机生成128位密钥，用于HMAC-SM3加密密钥
        String hmacKey = ByteUtil.byteToHex(SM4Util.generateKey());
        // 将SM4密钥和HMAC密钥拼接(HMAC在前)，然后使用公钥SM2算法对拼接后的结果加密
        String base64EncryptedKey = base64UrlEncoder.encode(
                ByteUtil.byteToHex(SM2CertEncryptionUtil.encryptWithb4Cert((hmacKey + sm4EncKey), publicKeyStr)).getBytes());
        System.out.println("base64EncryptedKey:" + base64EncryptedKey);

        // 生成iv（Initialization Vector）
        String iv = ByteUtil.byteToHex(SM4Util.generateSM4IV(128));
        System.out.println("iv:" + iv);

        String base64Iv = base64UrlEncoder.encode(iv.getBytes());
        System.out.println("base64Iv:" + base64Iv);

        // 加密原始报文
        byte [] cipherTextByte = SM4Util.encrypt_Cbc_Padding( ByteUtil.hexStringToBytes(sm4EncKey),  ByteUtil.hexStringToBytes(iv), plainText.getBytes("UTF-8"));
        String cipherText = ByteUtil.byteToHex(cipherTextByte);
        System.out.println("cipherText:" + cipherText);

        String base64Ciphertext = base64UrlEncoder.encode(cipherText.getBytes());
        System.out.println("base64Ciphertext:" + base64Ciphertext);

        // 生成Additional Authentication Data，生成方式：ASCII(BASE64URL(UTF8(JWE Protected Header)))
        byte[] aadBytes = AAD.compute(base64UrlEncodedHeader);
        // 计算AAD length (AL)
        byte[] alBytes = AAD.computeLength(aadBytes);
        /**
         * 使用 HMAC-SM3 算法计算HMAC值，计算流程
         *  1、 将 AAD, IV, Ciphertext, AADLength 进行连接
         *  2、 使用 HMAC-SM3 计算第1步中的连接值
         * 参考 RFC 7516 (JWE), section Appendix B.5、B.6
         */
        byte[] concatBytes = ByteUtil.concatenate(aadBytes, ByteUtil.hexToByte(iv), ByteUtil.hexToByte(cipherText), alBytes);
        byte[] hmacBytes = SM3Util.sm3DigistAsBytes(concatBytes);
        // 截断 HMAC 值生成消息认证标签（Authentication Tag），取前128位
        byte[] tagBytes = ByteUtils.subArray(hmacBytes, 0, 16);
        String base64Tag = base64UrlEncoder.encode(tagBytes);
        // 使用 JWE Compact 序列化方式
        String jwe = base64UrlEncodedHeader + JwtParser.SEPARATOR_CHAR
                + base64EncryptedKey + JwtParser.SEPARATOR_CHAR
                + base64Iv + JwtParser.SEPARATOR_CHAR
                + base64Ciphertext + JwtParser.SEPARATOR_CHAR
                + base64Tag;
        return jwe;
    }

    /**
     * 验证JWE并返回明文报文
     *
     * @param jwe           JWE报文体
     * @param privateKeyStr SM2算法私钥， 自身的私钥
     * @return
     */
    public static String decryptJWE(String jwe, String privateKeyStr) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
            NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, UnsupportedEncodingException {
        StringBuilder sb = new StringBuilder(128);
        int delimiterCount = 0;
        String base64UrlEncodedHeader = null;
        String base64EncryptedKey = null;
        String base64Iv = null;
        String base64Ciphertext = null;
        String base64Tag = null;
        for (char c : jwe.toCharArray()) {
            if (c == JwtParser.SEPARATOR_CHAR) {
                CharSequence tokenSeq = Strings.clean(sb);
                String token = tokenSeq != null ? tokenSeq.toString() : null;

                if (delimiterCount == 0) {
                    base64UrlEncodedHeader = token;
                } else if (delimiterCount == 1) {
                    base64EncryptedKey = token;
                } else if (delimiterCount == 2) {
                    base64Iv = token;
                } else if (delimiterCount == 3) {
                    base64Ciphertext = token;
                }
                delimiterCount++;
                sb.setLength(0);
            } else {
                sb.append(c);
            }
        }

        if (delimiterCount != 4) {
            String msg = "JWE strings must contain exactly 4 period characters. Found: " + delimiterCount;
            throw new MalformedJwtException(msg);
        }

        if (sb.length() > 0) {
            base64Tag = sb.toString();
        }

        if (base64UrlEncodedHeader == null) {
            throw new MalformedJwtException("JWE string '" + jwe + "' is missing a header.");
        }

        if (base64EncryptedKey == null) {
            throw new MalformedJwtException("JWE string '" + jwe + "' is missing a encryptedKey.");
        }

        if (base64Iv == null) {
            throw new MalformedJwtException("JWE string '" + jwe + "' is missing a iv.");
        }

        if (base64Ciphertext == null) {
            throw new MalformedJwtException("JWE string '" + jwe + "' is missing a ciphertext.");
        }

        if (base64Tag == null) {
            throw new MalformedJwtException("JWE string '" + jwe + "' is missing a tag.");
        }

        Decoder<String, byte[]> base64UrlDecoder = Decoders.BASE64URL;
        Encoder<byte[], String> base64UrlEncoder = Encoders.BASE64URL;
        // 验签
        // 解码密钥密文
        String encryptedKey = new String(base64UrlDecoder.decode(base64EncryptedKey));
        // 使用私钥对密钥密文进行解密
        String secretKey = SM2Util.decrypt(encryptedKey, privateKeyStr);
        // 该密钥为256位，其中前128位是HMAC的密钥，后128位是SM4密钥
        byte[] cekBytes = ByteUtil.hexToByte(secretKey);
        if (cekBytes.length != 32) {
            throw new MalformedJwtException("JWE string's encryption key must contain exactly 256 bits.");
        }
        // 128位的HMAC-SM3加密密钥
        String hmacKey = ByteUtil.byteToHex(ByteUtils.subArray(cekBytes, 0, 16));
        // 128位的SM4加密密钥
        String sm4EncKey = ByteUtil.byteToHex(ByteUtils.subArray(cekBytes, 16));
        //iv
        String iv = new String(base64UrlDecoder.decode(base64Iv));
        //秘文
        String cipherText = new String(base64UrlDecoder.decode(base64Ciphertext));
        // 生成Additional Authentication Data，生成方式：ASCII(BASE64URL(UTF8(JWE Protected Header)))
        byte[] aadBytes = AAD.compute(base64UrlEncodedHeader);
        // 计算AAD length (AL)
        byte[] alBytes = AAD.computeLength(aadBytes);
        /**
         * 使用 HMAC-SM3 算法计算HMAC值，计算流程
         *  1、 将 AAD, IV, Ciphertext, AADLength 进行连接
         *  2、 使用 HMAC-SM3 计算第1步中的连接值
         * 参考 RFC 7516 (JWE), section Appendix B.5、B.6
         */
        byte[] concatBytes = ByteUtil.concatenate(aadBytes, ByteUtil.hexToByte(iv), ByteUtil.hexToByte(cipherText), alBytes);
        byte[] hmacBytes = SM3Util.hmacAsBytes(concatBytes, ByteUtil.hexToByte(hmacKey));
        // 截断 HMAC 值生成消息认证标签（Authentication Tag），取前128位
        byte[] tagBytes = ByteUtils.subArray(hmacBytes, 0, 16);
        if (!base64UrlEncoder.encode(tagBytes).equals(base64Tag)) {
            throw new MalformedJwtException("JWE tag '" + base64Tag + "' is error.");
        }

        // 解密加密数据得到原始报文
        byte[] plainTextByte = SM4Util.decrypt_Cbc_Padding(ByteUtil.hexStringToBytes(sm4EncKey), ByteUtil.hexStringToBytes(iv), ByteUtil.hexToByte(cipherText));
        String plainText = new String(plainTextByte, "UTF-8");
        return plainText;
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

    protected static Map<String, ?> readValue(String val) {
        try {
            InstanceLocator<Deserializer<Map<String, ?>>> locator =
                    Classes.newInstance("io.jsonwebtoken.impl.io.RuntimeClasspathDeserializerLocator");
            Deserializer<Map<String, ?>> deserializer = locator.getInstance();
            byte[] bytes = val.getBytes(Strings.UTF_8);
            return deserializer.deserialize(bytes);
        } catch (DeserializationException e) {
            throw new MalformedJwtException("Unable to read JSON value: " + val, e);
        }
    }


    @SuppressWarnings("rawtypes")
    protected static String base64UrlEncode(Object o, String errMsg, Encoder<byte[], String> base64UrlEncoder) {
        Assert.isInstanceOf(Map.class, o, "object argument must be a map.");
        Map m = (Map) o;
        byte[] bytes;
        try {
            bytes = toJson(m);
        } catch (SerializationException e) {
            throw new IllegalStateException(errMsg, e);
        }

        return base64UrlEncoder.encode(bytes);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    protected static byte[] toJson(Object object) throws SerializationException {
        Assert.isInstanceOf(Map.class, object, "object argument must be a map.");
        Map m = (Map) object;
        InstanceLocator<Serializer<Map<String, ?>>> locator =
                Classes.newInstance("io.jsonwebtoken.impl.io.RuntimeClasspathSerializerLocator");
        Serializer<Map<String, ?>> serializer = locator.getInstance();
        return serializer.serialize(m);
    }


    public static String signJWSWithPlatFormPrivateKey(String kid, String privateKeyStr, String plainText) throws IOException, CryptoException {
        //头部
        Map<String, Object> header = new HashMap<>();
        header.put("alg", "SM2");
        header.put("typ", "JWT");
        header.put("kid", kid);
        Encoder<byte[], String> base64UrlEncoder = Encoders.BASE64URL;
        String base64UrlEncodedHeader = base64UrlEncode(header, "Unable to serialize header to json.", base64UrlEncoder);

        String base64UrlEncodedBody = "";
        String base64UrlSignature = "";
        HashMap<String, Object> claims = new HashMap<String, Object>();
        byte[] bytes = toJson(claims);
        base64UrlEncodedBody = base64UrlEncoder.encode(bytes);

        String jwt = base64UrlEncodedHeader + JwtParser.SEPARATOR_CHAR + base64UrlEncodedBody;
        if (plainText == null || plainText.equals("")) {
            //无报文体为空负载签名
            base64UrlSignature = base64UrlEncoder.encode(
                    SM2CertEncryptionUtil.signWithPlatfromPrivateKey(jwt, privateKeyStr));
        } else {
            // 报文体作为负载签名
            base64UrlSignature = base64UrlEncoder.encode(
                    SM2CertEncryptionUtil.signWithPlatfromPrivateKey(base64UrlEncodedHeader + JwtParser.SEPARATOR_CHAR + plainText,
                            privateKeyStr));
        }
        jwt = jwt + JwtParser.SEPARATOR_CHAR + base64UrlSignature;
        return jwt;
    }

    public static String decryptJWEWithPlatFormPrivateKey(String jwe, String privateKeyStr)
            throws IOException, InvalidCipherTextException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException {
        StringBuilder sb = new StringBuilder(128);
        int delimiterCount = 0;
        String base64UrlEncodedHeader = null;
        String base64EncryptedKey = null;
        String base64Iv = null;
        String base64Ciphertext = null;
        String base64Tag = null;
        for (char c : jwe.toCharArray()) {
            if (c == JwtParser.SEPARATOR_CHAR) {
                CharSequence tokenSeq = Strings.clean(sb);
                String token = tokenSeq != null ? tokenSeq.toString() : null;
                if (delimiterCount == 0) {
                    base64UrlEncodedHeader = token;
                } else if (delimiterCount == 1) {
                    base64EncryptedKey = token;
                } else if (delimiterCount == 2) {
                    base64Iv = token;
                } else if (delimiterCount == 3) {
                    base64Ciphertext = token;
                }
                delimiterCount++;
                sb.setLength(0);
            } else {
                sb.append(c);
            }
        }

        if (delimiterCount != 4) {
            String msg = "JWE strings must contain exactly 4 period characters. Found: " + delimiterCount;
            throw new MalformedJwtException(msg);
        }

        if (sb.length() > 0) {
            base64Tag = sb.toString();
        }

        if (base64UrlEncodedHeader == null) {
            throw new MalformedJwtException("JWE string '" + jwe + "' is missing a header.");
        }

        if (base64EncryptedKey == null) {
            throw new MalformedJwtException("JWE string '" + jwe + "' is missing a encryptedKey.");
        }

        if (base64Iv == null) {
            throw new MalformedJwtException("JWE string '" + jwe + "' is missing a iv.");
        }

        if (base64Ciphertext == null) {
            throw new MalformedJwtException("JWE string '" + jwe + "' is missing a ciphertext.");
        }

        if (base64Tag == null) {
            throw new MalformedJwtException("JWE string '" + jwe + "' is missing a tag.");
        }

        Decoder<String, byte[]> base64UrlDecoder = Decoders.BASE64URL;
        Encoder<byte[], String> base64UrlEncoder = Encoders.BASE64URL;
        // 验签
        // 解码密钥密文
        byte[] encryptedKeyByte = base64UrlDecoder.decode(base64EncryptedKey);
        byte[] encryptedKeyByte2 = ByteUtil.hexToByte(new String(encryptedKeyByte));

        // 使用私钥对密钥密文进行解密
        String secretKey =new String(SM2CertEncryptionUtil.decryptWithPlatfromPrivateKey(encryptedKeyByte2, privateKeyStr));
        // 该密钥为256位，其中前128位是HMAC的密钥，后128位是SM4密钥
        byte[] cekBytes = ByteUtil.hexToByte(secretKey);
        if (cekBytes.length != 32) {
            throw new MalformedJwtException("JWE string's encryption key must contain exactly 256 bits.");
        }
        // 128位的HMAC-SM3加密密钥
        String hmacKey = ByteUtil.byteToHex(ByteUtils.subArray(cekBytes, 0, 16));
        // 128位的SM4加密密钥
        String sm4EncKey = ByteUtil.byteToHex(ByteUtils.subArray(cekBytes, 16));
        System.out.println("sm4EncKey:" + sm4EncKey);
        //iv
        String iv = new String(base64UrlDecoder.decode(base64Iv));
        System.out.println("iv:" + iv);
        //秘文
        String cipherText = new String(base64UrlDecoder.decode(base64Ciphertext));
        System.out.println("cipherText:" + cipherText);

        // 生成Additional Authentication Data，生成方式：ASCII(BASE64URL(UTF8(JWE Protected Header)))
        byte[] aadBytes = AAD.compute(base64UrlEncodedHeader);
        // 计算AAD length (AL)
        byte[] alBytes = AAD.computeLength(aadBytes);
        /**
         * 使用 HMAC-SM3 算法计算HMAC值，计算流程
         *  1、 将 AAD, IV, Ciphertext, AADLength 进行连接
         *  2、 使用 HMAC-SM3 计算第1步中的连接值
         * 参考 RFC 7516 (JWE), section Appendix B.5、B.6
         */
        byte[] concatBytes = ByteUtil.concatenate(aadBytes, ByteUtil.hexToByte(iv), ByteUtil.hexToByte(cipherText), alBytes);
        byte[] hmacBytes = SM3Util.sm3DigistAsBytes(concatBytes);
        // 截断 HMAC 值生成消息认证标签（Authentication Tag），取前128位
        byte[] tagBytes = ByteUtils.subArray(hmacBytes, 0, 16);
        if (!base64UrlEncoder.encode(tagBytes).equals(base64Tag)) {
            throw new MalformedJwtException("JWE tag '" + base64Tag + "' is error.");
        }

        // 解密加密数据得到原始报文
        byte [] plainTextByte = SM4Util.decrypt_Cbc_Padding(
                ByteUtil.hexStringToBytes(sm4EncKey),
                ByteUtil.hexStringToBytes(iv),
                ByteUtil.hexToByte(cipherText));
        String plainText = new String(plainTextByte, "UTF-8");
        return plainText;
    }

}
