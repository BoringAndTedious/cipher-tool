package cn.com.agree.cipher.sm4;

/**
 * Created by $(USER) on $(DATE)
 */

import cn.com.agree.cipher.bc.BouncyCastleProviderSingleton;
import cn.com.agree.cipher.utils.ByteUtil;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.macs.CBCBlockCipherMac;
import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SM4Util {

	static {
		// Security.addProvider(new BouncyCastleProvider());
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(BouncyCastleProviderSingleton.getInstance());
		}
	}


	public static final String ALGORITHM_NAME = "SM4";
	public static final int DEFAULT_KEY_SIZE = 128;

	public static final String ALGORITHM_NAME_ECB_PADDING = "SM4/ECB/PKCS5Padding";
	public static final String ALGORITHM_NAME_ECB_NOPADDING = "SM4/ECB/NoPadding";
	public static final String ALGORITHM_NAME_CBC_PADDING = "SM4/CBC/PKCS5Padding";
	public static final String ALGORITHM_NAME_CBC_NOPADDING = "SM4/CBC/NoPadding";

	public static byte[] encrypt_Ecb_Padding(byte[] key, byte[] data)
		throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
		NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = generateEcbCipher(ALGORITHM_NAME_ECB_PADDING, Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(data);
	}

	public static byte[] decrypt_Ecb_Padding(byte[] key, byte[] cipherText)
		throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
		NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		Cipher cipher = generateEcbCipher(ALGORITHM_NAME_ECB_PADDING, Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(cipherText);
	}

	public static byte[] encrypt_Ecb_NoPadding(byte[] key, byte[] data)
		throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
		NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = generateEcbCipher(ALGORITHM_NAME_ECB_NOPADDING, Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(data);
	}

	public static byte[] decrypt_Ecb_NoPadding(byte[] key, byte[] cipherText)
		throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
		NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		Cipher cipher = generateEcbCipher(ALGORITHM_NAME_ECB_NOPADDING, Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(cipherText);
	}

	public static byte[] encrypt_Cbc_Padding(byte[] key, byte[] iv, byte[] data)
		throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
		NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
		InvalidAlgorithmParameterException {
		Cipher cipher = generateCbcCipher(ALGORITHM_NAME_CBC_PADDING, Cipher.ENCRYPT_MODE, key, iv);
		return cipher.doFinal(data);
	}

	public static byte[] decrypt_Cbc_Padding(byte[] key, byte[] iv, byte[] cipherText)
		throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
		NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
		InvalidAlgorithmParameterException {
		Cipher cipher = generateCbcCipher(ALGORITHM_NAME_CBC_PADDING, Cipher.DECRYPT_MODE, key, iv);
		return cipher.doFinal(cipherText);
	}

	public static byte[] encrypt_Cbc_NoPadding(byte[] key, byte[] iv, byte[] data)
		throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
		NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
		InvalidAlgorithmParameterException {
		Cipher cipher = generateCbcCipher(ALGORITHM_NAME_CBC_NOPADDING, Cipher.ENCRYPT_MODE, key, iv);
		return cipher.doFinal(data);
	}

	public static byte[] decrypt_Cbc_NoPadding(byte[] key, byte[] iv, byte[] cipherText)
		throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
		NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
		InvalidAlgorithmParameterException {
		Cipher cipher = generateCbcCipher(ALGORITHM_NAME_CBC_NOPADDING, Cipher.DECRYPT_MODE, key, iv);
		return cipher.doFinal(cipherText);
	}

	public static byte[] doCMac(byte[] key, byte[] data) throws NoSuchProviderException, NoSuchAlgorithmException,
		InvalidKeyException {
		Key keyObj = new SecretKeySpec(key, ALGORITHM_NAME);
		return doMac("SM4-CMAC", keyObj, data);
	}

	public static byte[] doGMac(byte[] key, byte[] iv, int tagLength, byte[] data) {
		org.bouncycastle.crypto.Mac mac = new GMac(new GCMBlockCipher(new SM4Engine()), tagLength * 8);
		return doMac(mac, key, iv, data);
	}

	/**
	 * 默认使用PKCS7Padding/PKCS5Padding填充的CBCMAC
	 *
	 * @param key
	 * @param iv
	 * @param data
	 * @return
	 */
	public static byte[] doCBCMac(byte[] key, byte[] iv, byte[] data) {
		SM4Engine engine = new SM4Engine();
		org.bouncycastle.crypto.Mac mac = new CBCBlockCipherMac(engine, engine.getBlockSize() * 8, new PKCS7Padding());
		return doMac(mac, key, iv, data);
	}

	/**
	 * @param key
	 * @param iv
	 * @param padding 可以传null，传null表示NoPadding，由调用方保证数据必须是BlockSize的整数倍
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static byte[] doCBCMac(byte[] key, byte[] iv, BlockCipherPadding padding, byte[] data) throws Exception {
		SM4Engine engine = new SM4Engine();
		if (padding == null) {
			if (data.length % engine.getBlockSize() != 0) {
				throw new Exception("if no padding, data length must be multiple of SM4 BlockSize");
			}
		}
		org.bouncycastle.crypto.Mac mac = new CBCBlockCipherMac(engine, engine.getBlockSize() * 8, padding);
		return doMac(mac, key, iv, data);
	}


	private static byte[] doMac(org.bouncycastle.crypto.Mac mac, byte[] key, byte[] iv, byte[] data) {
		CipherParameters cipherParameters = new KeyParameter(key);
		mac.init(new ParametersWithIV(cipherParameters, iv));
		mac.update(data, 0, data.length);
		byte[] result = new byte[mac.getMacSize()];
		mac.doFinal(result, 0);
		return result;
	}

	private static byte[] doMac(String algorithmName, Key key, byte[] data) throws NoSuchProviderException,
		NoSuchAlgorithmException, InvalidKeyException {
		Mac mac = Mac.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
		mac.init(key);
		mac.update(data);
		return mac.doFinal();
	}

	private static Cipher generateEcbCipher(String algorithmName, int mode, byte[] key)
		throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
		InvalidKeyException {
		Cipher cipher = Cipher.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
		Key sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
		cipher.init(mode, sm4Key);
		return cipher;
	}

	private static Cipher generateCbcCipher(String algorithmName, int mode, byte[] key, byte[] iv)
		throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
		NoSuchProviderException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
		Key sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
		cipher.init(mode, sm4Key, ivParameterSpec);
		return cipher;
	}

	/**
	 * 生成128位密钥
	 *
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public static byte[] generateKey() throws NoSuchAlgorithmException, NoSuchProviderException {
		return generateKey(DEFAULT_KEY_SIZE);
	}

	/**
	 * 生成指定位数密钥
	 *
	 * @param keySize
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public static byte[] generateKey(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
		kg.init(keySize, new SecureRandom());
		return kg.generateKey().getEncoded();
	}

	/**
	 * 生成指定长度的iv, CBC模式需要
	 *
	 * @param keySize
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public static byte[] generateSM4IV(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
		kg.init(keySize, new SecureRandom());
		return kg.generateKey().getEncoded();
	}


	public static String encryptData_ECB(String plainText, String secretKey) {
		try {
			SM4_Context ctx = new SM4_Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_ENCRYPT;

			byte[] keyBytes;
			keyBytes = ByteUtil.hexStringToBytes(secretKey);
			SM4 sm4 = new SM4();
			sm4.sm4_setkey_enc(ctx, keyBytes);
			byte[] encrypted = sm4.sm4_crypt_ecb(ctx, plainText.getBytes("UTF-8"));
			return ByteUtil.byteToHex(encrypted);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static String decryptData_ECB(String cipherText, String secretKey) {
		try {
			byte[] encrypted = ByteUtil.hexToByte(cipherText);
			cipherText = Base64.encodeBase64String(encrypted);
			;
			//cipherText = new BASE64Encoder().encode(encrypted);
			if (cipherText != null && cipherText.trim().length() > 0) {
				Pattern p = Pattern.compile("\\s*|\t|\r|\n");
				Matcher m = p.matcher(cipherText);
				cipherText = m.replaceAll("");
			}

			SM4_Context ctx = new SM4_Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_DECRYPT;

			byte[] keyBytes;
			keyBytes = ByteUtil.hexStringToBytes(secretKey);

			SM4 sm4 = new SM4();
			sm4.sm4_setkey_dec(ctx, keyBytes);
			byte[] decrypted = sm4.sm4_crypt_ecb(ctx, Base64.decodeBase64(cipherText));
			//byte[] decrypted = sm4.sm4_crypt_ecb(ctx, new BASE64Decoder().decodeBuffer(cipherText));
			return new String(decrypted, "UTF-8");
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}


	public static String encryptData_CBC(String plainText, String secretKey, String iv) {
		try {
			SM4_Context ctx = new SM4_Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_ENCRYPT;

			byte[] keyBytes;
			byte[] ivBytes;

			keyBytes = ByteUtil.hexStringToBytes(secretKey);
			ivBytes = ByteUtil.hexStringToBytes(iv);


			SM4 sm4 = new SM4();
			sm4.sm4_setkey_enc(ctx, keyBytes);
			byte[] encrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, plainText.getBytes("UTF-8"));
			return ByteUtil.byteToHex(encrypted);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static String decryptData_CBC(String cipherText, String secretKey, String iv) {
		try {
			byte[] encrypted = ByteUtil.hexToByte(cipherText);
			cipherText = Base64.encodeBase64String(encrypted);
			;
			//cipherText = new BASE64Encoder().encode(encrypted);
			if (cipherText != null && cipherText.trim().length() > 0) {
				Pattern p = Pattern.compile("\\s*|\t|\r|\n");
				Matcher m = p.matcher(cipherText);
				cipherText = m.replaceAll("");
			}
			SM4_Context ctx = new SM4_Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_DECRYPT;

			byte[] keyBytes;
			byte[] ivBytes;
			keyBytes = ByteUtil.hexStringToBytes(secretKey);
			ivBytes = ByteUtil.hexStringToBytes(iv);

			SM4 sm4 = new SM4();
			sm4.sm4_setkey_dec(ctx, keyBytes);
			//byte[] decrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, new BASE64Decoder().decodeBuffer(cipherText));
			byte[] decrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, Base64.decodeBase64(cipherText));
            /*String text = new String(decrypted, "UTF-8");
            return text.substring(0,text.length()-1);*/
			return new String(decrypted, "UTF-8");
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

}
