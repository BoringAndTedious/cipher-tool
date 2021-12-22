package cn.com.agree.cipher.sm2;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * 国密办文件中推荐的椭圆曲线相关参数
 * 
 * @author zaile
 *
 */
public interface SM2Const {
	
	BigInteger N = new BigInteger(
            "FFFFFFFE" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "7203DF6B" + "21C6052B" + "53BBF409" + "39D54123", 16);
    BigInteger P = new BigInteger(
            "FFFFFFFE" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "00000000" + "FFFFFFFF" + "FFFFFFFF", 16);
    BigInteger a = new BigInteger(
            "FFFFFFFE" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "00000000" + "FFFFFFFF" + "FFFFFFFC", 16);
    BigInteger b = new BigInteger(
            "28E9FA9E" + "9D9F5E34" + "4D5A9E4B" + "CF6509A7" + "F39789F5" + "15AB8F92" + "DDBCBD41" + "4D940E93", 16);
    BigInteger gx = new BigInteger(
            "32C4AE2C" + "1F198119" + "5F990446" + "6A39C994" + "8FE30BBF" + "F2660BE1" + "715A4589" + "334C74C7", 16);
    BigInteger gy = new BigInteger(
            "BC3736A2" + "F4F6779C" + "59BDCEE3" + "6B692153" + "D0A9877C" + "C62A4740" + "02DF32E5" + "2139F0A0", 16);

    @SuppressWarnings("deprecation")
	ECCurve.Fp curve = new ECCurve.Fp(P, // q
            a, // A
            b); // B

    ECFieldElement A = curve.getA();
    ECFieldElement B = curve.getB();

    ECPoint G = curve.createPoint(gx, gy);

    ECFieldElement GX = G.getAffineXCoord();
    ECFieldElement GY = G.getAffineYCoord();

    ECDomainParameters ECC_BC_SPEC = new ECDomainParameters(curve, G, N);

    SecureRandom random = new SecureRandom();

    int W = (int) Math.ceil(N.bitLength() * 1.0 / 2) - 1;
    BigInteger _2W = new BigInteger("2").pow(W);
    int DIGEST_LENGTH = 32;
}
