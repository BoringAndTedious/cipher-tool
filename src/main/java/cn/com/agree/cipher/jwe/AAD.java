package cn.com.agree.cipher.jwe;

import cn.com.agree.cipher.utils.ByteUtil;
import cn.com.agree.cipher.utils.IntegerOverflowException;
import io.jsonwebtoken.impl.io.InstanceLocator;
import io.jsonwebtoken.io.Encoder;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.io.SerializationException;
import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.lang.Classes;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Map;

/**
 * Additional authenticated data (AAD).
 * <p>See RFC 7518 (JWA), section 5.1, point 14.
 * @ClassName AAD
 * @Author lqw
 * @Date 2019/12/13 9:47
 * @Version 1.0
 */
public class AAD {

	/**
	 * Computes the Additional Authenticated Data (AAD) for the specified
	 * JWE header.
	 *
	 * @param jweHeader The JWE header. Must not be {@code null}.
	 *
	 * @return The AAD.
	 */
	public static byte[] compute(final Map<String, Object> jweHeader) {
		Encoder<byte[], String> base64UrlEncoder = Encoders.BASE64URL;
		return compute(base64UrlEncode(jweHeader, base64UrlEncoder));
	}

	/**
	 * Computes the Additional Authenticated Data (AAD) for the specified
	 * BASE64URL-encoded JWE header.
	 *
	 * @param encodedJWEHeader The BASE64URL-encoded JWE header. Must not
	 *                         be {@code null}.
	 *
	 * @return The AAD.
	 */
	public static byte[] compute(final String encodedJWEHeader) {

		return encodedJWEHeader.getBytes(Charset.forName("ASCII"));
	}
	/**
	 * Computes the bit length of the specified Additional Authenticated
	 * Data (AAD). Used in AES/CBC/PKCS5Padding/HMAC-SHA2 encryption.
	 *
	 * @param aad The Additional Authenticated Data (AAD). Must not be
	 *            {@code null}.
	 *
	 * @return The computed AAD bit length, as a 64 bit big-endian
	 *         representation (8 byte array).
	 *
	 * @throws IntegerOverflowException On a integer overflow.
	 */
	public static byte[] computeLength(final byte[] aad)
		throws IntegerOverflowException {

		final int bitLength = ByteUtil.safeBitLength(aad);
		return ByteBuffer.allocate(8).putLong(bitLength).array();
	}
	/**
	 * Base64url-encode the specified JWE Header.
	 * @Param: o
	 * @Param errMsg
	 * @Param base64UrlEncoder
	 * @Date: 2019/12/13 9:57
	 * @return: java.lang.String
	 */
	private static String base64UrlEncode(final Map<String, Object> jweHeader, Encoder<byte[], String> base64UrlEncoder) {
		byte[] bytes;
		try {
			InstanceLocator<Serializer<Map<String,?>>> locator =
				Classes.newInstance("io.jsonwebtoken.impl.io.RuntimeClasspathSerializerLocator");
			Serializer<Map<String, ?>> serializer = locator.getInstance();
			bytes = serializer.serialize(jweHeader);
		} catch (SerializationException e) {
			throw new IllegalStateException("Unable to serialize header to json.", e);
		}

		return base64UrlEncoder.encode(bytes);
	}

}
