package cn.com.agree.cipher.sm3;

import cn.com.agree.cipher.bc.BouncyCastleProviderSingleton;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;


public class SM3Util {

	static {
		Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
		System.out.println(provider);
		if (provider == null){
			System.out.println("SM3Util add BC provider");
			BouncyCastleProvider bcp = BouncyCastleProviderSingleton.getInstance();
			Security.addProvider(bcp);
			// 配置HMAC-SM3算法
			new SM3.Mappings().configure(bcp);
		} else {
			if (provider instanceof BouncyCastleProvider) {
				// 配置HMAC-SM3算法
				new SM3.Mappings().configure((BouncyCastleProvider) provider);
			}
		}
	}

    public static String sm3DigistAsString(String content) {
        return ByteUtils.toHexString(sm3DigistAsBytes(content)).toUpperCase();
    }

    public static byte[] sm3DigistAsBytes(String content) {
        return sm3DigistAsBytes(content.getBytes());
    }

    public static String sm3DigistAsString(byte[] contentBuffer) {
        return ByteUtils.toHexString(sm3DigistAsBytes(contentBuffer)).toUpperCase();
    }

    public static byte[] sm3DigistAsBytes(byte[] contentBuffer) {
        SM3 sm3 = new SM3();
        sm3.update(contentBuffer, 0, contentBuffer.length);
        byte[] out = new byte[SM3.DIGEST_LENGTH];
        sm3.doFinal(out);
        return out;
    }

    public static String sm3DigistAsString(InputStream inputStream) throws IOException {
        return ByteUtils.toHexString(sm3DigistAsBytes(inputStream)).toUpperCase();
    }

    public static byte[] sm3DigistAsBytes(InputStream inputStream) throws IOException {
        int length = 0;
        byte[] buffer = new byte[8192];
        SM3 sm3 = new SM3();
        while ((length = inputStream.read(buffer)) != -1) {
            sm3.update(buffer, 0, length);
        }
        byte[] out = new byte[SM3.DIGEST_LENGTH];
        sm3.doFinal(out);
        return out;
    }

	/**
	 * 使用HMAC-SM3生成256位认证消息
	 * @Param: content 原始消息
	 * @Param: secretKey 密钥
	 * @Date: 2019/12/12 11:20
	 * @return: byte[] 认证消息
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws NoSuchProviderException
	 */
	public static String hmacAsString(String content, String secretKey)
		throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
		return ByteUtils.toHexString(hmacAsBytes(content, secretKey));
	}
    
    /**
     * 使用HMAC-SM3生成256位认证消息
     * @Param: content 原始消息
	 * @Param: secretKey 密钥
     * @Date: 2019/12/12 11:20
     * @return: byte[] 认证消息
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws NoSuchProviderException
	 */
	public static byte[] hmacAsBytes(String content, String secretKey)
		throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
		return hmacAsBytes(content.getBytes(), secretKey.getBytes());
	}

	/**
	 * 使用HMAC-SM3生成256位认证消息
	 * @Param: contentBuffer 原始消息
	 * @Param: secretKeyBytes 密钥
	 * @Date: 2019/12/12 11:20
	 * @return: byte[] 认证消息
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws NoSuchProviderException
	 */
	public static byte[] hmacAsBytes(byte[] contentBuffer, byte[] secretKeyBytes)
		throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException {
		String hmacName = "HMAC-SM3";
		SecretKey key = new SecretKeySpec(secretKeyBytes, hmacName);
		Mac mac = Mac.getInstance(hmacName, "BC");
		mac.init(key);
		mac.reset();
		mac.update(contentBuffer, 0, contentBuffer.length);
		return mac.doFinal();
	}

    public static byte[] toByteArray(int i) {
        byte[] byteArray = new byte[4];
        byteArray[0] = (byte) (i >>> 24);
        byteArray[1] = (byte) ((i & 0xFFFFFF) >>> 16);
        byteArray[2] = (byte) ((i & 0xFFFF) >>> 8);
        byteArray[3] = (byte) (i & 0xFF);
        return byteArray;
    }
	public static void main(String[] args) throws Exception {
		byte[] keyBytes = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
		byte[] message = Hex.decode("4869205468657265");
		byte[] out,out1;

		// SM3
		MessageDigest sm3 = MessageDigest.getInstance("SM3", "BC");
		out1 = sm3.digest(message);
		System.out.println(Hex.toHexString(out1));

		// HMAC-SM3
		String hmacName = "HMAC-SM3";
		SecretKey key = new SecretKeySpec(keyBytes, hmacName);
		Mac mac = Mac.getInstance(hmacName, "BC");
		mac.init(key);
		mac.reset();
		mac.update(message, 0, message.length);
		out = mac.doFinal();
		System.out.println(Hex.toHexString(out));

		/*System.out.println("-------列出加密服务提供者-----");
		Provider[] pro = Security.getProviders();
		for (Provider p : pro) {
			System.out.println("Provider:" + p.getName() + " - version:" + p.getVersion());
			System.out.println(p.getInfo());
		}
		System.out.println("");
		System.out.println("-------列出系统支持的消息摘要算法：");
		for (String ss : Security.getAlgorithms("Mac")) {
			System.out.println(ss);
		}
		System.out.println("-------列出系统支持的生成公钥和私钥对的算法：");
		for (String ss : Security.getAlgorithms("KeyPairGenerator")) {
			System.out.println(ss);
		}*/
	}
}
