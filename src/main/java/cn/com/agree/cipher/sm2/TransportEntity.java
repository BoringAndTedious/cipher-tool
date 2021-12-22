package cn.com.agree.cipher.sm2;

import org.bouncycastle.math.ec.ECPoint;

/**
 * 传输实体类
 *
 * @author zaile
 */
public class TransportEntity {
    final byte[] R; //R点
    final byte[] S; //验证S
    final byte[] Z; //用户标识
    final byte[] K; //公钥

    public TransportEntity(byte[] r, byte[] s, byte[] z, ECPoint pKey) {
        R = r;
        S = s;
        Z = z;
        K = pKey.getEncoded(false);
    }
}
