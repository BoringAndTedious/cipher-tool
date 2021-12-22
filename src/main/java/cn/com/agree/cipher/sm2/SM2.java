package cn.com.agree.cipher.sm2;

import org.bouncycastle.crypto.signers.DSAEncoding;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * SM2公钥加密算法实现 包括 -签名,验签 -密钥交换 -公钥加密,私钥解密
 * 
 * @author zaile
 *
 */
public class SM2 implements SM2Const {
	
	private final DSAEncoding encoding = StandardDSAEncoding.INSTANCE;
	
    /**
     * 公钥加密
     *
     * @param input     加密原文
     * @param publicKey 公钥
     * @return
     */
    public byte[] encrypt(String input, ECPoint publicKey) {

        byte[] inputBuffer = input.getBytes();
        byte[] C1Buffer;
        ECPoint kpb;
        byte[] t;
        do {
            /* 1 产生随机数k，k属于[1, N-1] */
            BigInteger k = SM2Util.random(N);

            /* 2 计算椭圆曲线点C1 = [k]G = (x1, y1) */
            ECPoint C1 = G.multiply(k);
            C1Buffer = C1.getEncoded(false);

            /*
             * 3 计算椭圆曲线点 S = [h]Pb
             */
            BigInteger h = ECC_BC_SPEC.getH();
            if (h != null) {
                ECPoint S = publicKey.multiply(h);
                if (S.isInfinity())
                    throw new IllegalStateException();
            }

            /* 4 计算 [k]PB = (x2, y2) */
            kpb = publicKey.multiply(k).normalize();

            /* 5 计算 t = KDF(x2||y2, klen) */
            byte[] kpbBytes = kpb.getEncoded(false);
            t = SM2Util.KDF(kpbBytes, inputBuffer.length);
            // DerivationFunction kdf = new KDF1BytesGenerator(new
            // ShortenedDigest(new SHA256Digest(), DIGEST_LENGTH));
            //
            // t = new byte[inputBuffer.length];
            // kdf.init(new ISO18033KDFParameters(kpbBytes));
            // kdf.generateBytes(t, 0, t.length);
        } while (SM2Util.allZero(t));

        /* 6 计算C2=M^t */
        byte[] C2 = new byte[inputBuffer.length];
        for (int i = 0; i < inputBuffer.length; i++) {
            C2[i] = (byte) (inputBuffer[i] ^ t[i]);
        }

        /* 7 计算C3 = Hash(x2 || M || y2) */
        byte[] C3 = SM2Util.sm3hash(kpb.getXCoord().toBigInteger().toByteArray(), inputBuffer,
                kpb.getYCoord().toBigInteger().toByteArray());

        /* 8 输出密文 C=C1 || C2 || C3 */

        byte[] encryptResult = new byte[C1Buffer.length + C2.length + C3.length];

        System.arraycopy(C1Buffer, 0, encryptResult, 0, C1Buffer.length);
        System.arraycopy(C2, 0, encryptResult, C1Buffer.length, C2.length);
        System.arraycopy(C3, 0, encryptResult, C1Buffer.length + C2.length, C3.length);

        return encryptResult;
    }

    /**
     * 私钥解密
     *
     * @param encryptData 密文数据字节数组
     * @param privateKey  解密私钥
     * @return
     */
    public String decrypt(byte[] encryptData, BigInteger privateKey) {
        byte[] C1Byte = new byte[65];
        System.arraycopy(encryptData, 0, C1Byte, 0, C1Byte.length);

        ECPoint C1 = curve.decodePoint(C1Byte).normalize();

        /*
         * 计算椭圆曲线点 S = [h]C1 是否为无穷点
         */
        BigInteger h = ECC_BC_SPEC.getH();
        if (h != null) {
            ECPoint S = C1.multiply(h);
            if (S.isInfinity())
                throw new IllegalStateException();
        }
        /* 计算[dB]C1 = (x2, y2) */
        ECPoint dBC1 = C1.multiply(privateKey).normalize();

        /* 计算t = KDF(x2 || y2, klen) */
        byte[] dBC1Bytes = dBC1.getEncoded(false);
        int klen = encryptData.length - 65 - DIGEST_LENGTH;
        byte[] t = SM2Util.KDF(dBC1Bytes, klen);
        // DerivationFunction kdf = new KDF1BytesGenerator(new
        // ShortenedDigest(new SHA256Digest(), DIGEST_LENGTH));
        // if (debug)
        // System.out.println("klen = " + klen);
        // kdf.init(new ISO18033KDFParameters(dBC1Bytes));
        // kdf.generateBytes(t, 0, t.length);

        if (SM2Util.allZero(t)) {
            System.err.println("all zero");
            throw new IllegalStateException();
        }

        /* 5 计算M'=C2^t */
        byte[] M = new byte[klen];
        for (int i = 0; i < M.length; i++) {
            M[i] = (byte) (encryptData[C1Byte.length + i] ^ t[i]);
        }

        /* 6 计算 u = Hash(x2 || M' || y2) 判断 u == C3是否成立 */
        byte[] C3 = new byte[DIGEST_LENGTH];

        System.arraycopy(encryptData, encryptData.length - DIGEST_LENGTH, C3, 0, DIGEST_LENGTH);
        byte[] u = SM2Util.sm3hash(dBC1.getXCoord().toBigInteger().toByteArray(), M,
                dBC1.getYCoord().toBigInteger().toByteArray());
        if (Arrays.equals(u, C3)) {
            try {
                return new String(M, "UTF8");
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    /**
     * 签名
     *
     * @param M       签名信息
     * @param keyPair 签名方密钥对
     * @return 签名
     */
    public Signature sign(String M, SM2KeyPair keyPair) {
        return sign(M, "1234567812345678".getBytes(), keyPair);
    }
    
    /**
     * 签名
     *
     * @param M       签名信息
     * @param IDA     签名方唯一标识
     * @param keyPair 签名方密钥对
     * @return 签名
     */
    public Signature sign(String M, byte[] IDA, SM2KeyPair keyPair) {
    	ECPoint publicKey = keyPair.getPublicKey();
    	BigInteger privateKey = keyPair.getPrivateKey();
        return sign(M, IDA, publicKey, privateKey);
    }
    
    /**
     * 签名
     *
     * @param M       签名信息
     * @param IDA     签名方唯一标识
     * @param publicKey 公钥
     * @param privateKey 私钥
     * @return 签名
     */
    /**
     * @param M
     * @param IDA
   
     * @return
     */
    public Signature sign(String M, byte[] IDA, ECPoint publicKey, BigInteger privateKey) {
        byte[] ZA = SM2Util.ZA(IDA, publicKey);
        byte[] M_ = SM2Util.join(ZA, M.getBytes());
        BigInteger e = new BigInteger(1, SM2Util.sm3hash(M_));
        // BigInteger k = new BigInteger(
        // "6CB28D99 385C175C 94F94E93 4817663F C176D925 DD72B727 260DBAAE
        // 1FB2F96F".replace(" ", ""), 16);
        BigInteger k;
        BigInteger r;
        do {
            k = SM2Util.random(N);
            ECPoint p1 = G.multiply(k).normalize();
            BigInteger x1 = p1.getXCoord().toBigInteger();
            r = e.add(x1);
            r = r.mod(N);
        } while (r.equals(BigInteger.ZERO) || r.add(k).equals(N));

        BigInteger s = (privateKey.add(BigInteger.ONE).modInverse(N))
                .multiply((k.subtract(r.multiply(privateKey))).mod(N)).mod(N);

        return new Signature(r, s);
    }
    
    /**
     * 签名
     *
     * @param M       签名信息
     * @param keyPair 签名方密钥对
     * @return 签名
     */
    public byte[] signWithEncode(String M, SM2KeyPair keyPair) throws IOException {
        return signWithEncode(M, "1234567812345678".getBytes(), keyPair);
    }
    

    /**
     * 签名
     *
     * @param M       签名信息
     * @param IDA     签名方唯一标识
     * @param keyPair 签名方密钥对
     * @return 签名
     */
    public byte[] signWithEncode(String M, byte[] IDA, SM2KeyPair keyPair) throws IOException {
        Signature signature = sign(M, IDA, keyPair);
        return encoding.encode(N, signature.r, signature.s);
    }
    
    /**
     * 验签
     *
     * @param M          签名信息
     * @param signature  签名
     * @param aPublicKey 签名方公钥
     * @return true or false
     */
    public boolean verify(String M, Signature signature, ECPoint aPublicKey) {
        return verify(M, signature, "1234567812345678".getBytes(), aPublicKey);
    }

    /**
     * 验签
     *
     * @param M          签名信息
     * @param signature  签名
     * @param IDA        签名方唯一标识
     * @param aPublicKey 签名方公钥
     * @return true or false
     */
    public boolean verify(String M, Signature signature, byte[] IDA, ECPoint aPublicKey) {
        if (!SM2Util.between(signature.r, BigInteger.ONE, N))
            return false;
        if (!SM2Util.between(signature.s, BigInteger.ONE, N))
            return false;

        byte[] M_ = SM2Util.join(SM2Util.ZA(IDA, aPublicKey), M.getBytes());
        BigInteger e = new BigInteger(1, SM2Util.sm3hash(M_));
        BigInteger t = signature.r.add(signature.s).mod(N);

        if (t.equals(BigInteger.ZERO))
            return false;

        ECPoint p1 = G.multiply(signature.s).normalize();
        ECPoint p2 = aPublicKey.multiply(t).normalize();
        BigInteger x1 = p1.add(p2).normalize().getXCoord().toBigInteger();
        BigInteger R = e.add(x1).mod(N);
        if (R.equals(signature.r)){
        	return true;
        }
        return false;
    }
    
    /**
     * 验签
     *
     * @param M                标准签名信息
     * @param encodedSignature 签名
     * @param aPublicKey       签名方公钥
     * @return true or false
     */
    public boolean verifyWithEncoded(String M, String encodedSignature, ECPoint aPublicKey) throws IOException {
        return verifyWithEncoded(M, "1234567812345678".getBytes(), encodedSignature, aPublicKey);
    }

    /**
     * 验签
     *
     * @param M                标准签名信息
     * @param IDA        签名方唯一标识
     * @param encodedSignature 签名
     * @param aPublicKey       签名方公钥
     * @return true or false
     */
    public boolean verifyWithEncoded(String M, byte[] IDA, String encodedSignature, ECPoint aPublicKey) throws IOException {
        BigInteger[] sign = encoding.decode(N, ByteUtils.fromHexString(encodedSignature));
        Signature signature = new Signature(sign[0], sign[1]);
        return verify(M, signature, IDA, aPublicKey);
    }
    

    
    public static void main(String[] args) {
		SM2 sm = new SM2();
		try {
			String signStr = ByteUtils.toHexString(sm.signWithEncode("name=tom&age=10", new SM2KeyPair(SM2Util.getPubKeyFromHexString("0446fdfdd70d9a9c3c80fbbbf790abdaa954ce62b3642390923f706acced5b5db0864f6873397b94ab48d1d0bf05bcfa5b4c2e032de4f25556f72e2ed9ebe69bfc"),
					new BigInteger("f4e08d945183fc9fa6425561e4799efa8facfe0b715cb93c2db8a8142aad6f24",16)))).toUpperCase();
			
			
			boolean verifyWithEncoded = sm.verifyWithEncoded("name=tom&age=10", signStr, SM2Util.getPubKeyFromHexString("0446fdfdd70d9a9c3c80fbbbf790abdaa954ce62b3642390923f706acced5b5db0864f6873397b94ab48d1d0bf05bcfa5b4c2e032de4f25556f72e2ed9ebe69bfc"));
			System.out.print(verifyWithEncoded);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}