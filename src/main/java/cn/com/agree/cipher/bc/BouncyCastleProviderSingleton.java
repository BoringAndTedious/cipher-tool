package cn.com.agree.cipher.bc;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * BouncyCastle JCA provider singleton, intended to prevent memory leaks by
 * ensuring a single instance is loaded at all times. Application code that
 * needs a BouncyCastle JCA provider should use the {@link #getInstance()}
 * method to obtain an instance.
 *
 * @ClassName BouncyCastleProviderSingleton
 * @Author lqw
 * @Date 2019/12/13 10:22
 * @Version 1.0
 */
public final class BouncyCastleProviderSingleton {

	/**
	 * The BouncyCastle provider, lazily instantiated.
	 */
	private static volatile BouncyCastleProvider bouncyCastleProvider;

	/**
	 * Prevents external instantiation.
	 */
	private BouncyCastleProviderSingleton() {}

	/**
	 * Returns a BouncyCastle JCA provider instance.
	 *
	 * @return The BouncyCastle JCA provider instance.
	 */
	public static BouncyCastleProvider getInstance() {
		if (bouncyCastleProvider == null) {
			synchronized (BouncyCastleProviderSingleton.class) {
				if (bouncyCastleProvider == null) {
					bouncyCastleProvider = new BouncyCastleProvider();
				}
			}
		}
		return bouncyCastleProvider;
	}
}
