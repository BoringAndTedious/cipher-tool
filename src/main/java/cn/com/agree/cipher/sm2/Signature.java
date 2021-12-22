package cn.com.agree.cipher.sm2;

import java.math.BigInteger;

/**
 * 签名
 * @author zaiel
 *
 */
public class Signature {
    BigInteger r;
    BigInteger s;

    public Signature(BigInteger r, BigInteger s) {
        this.r = r;
        this.s = s;
    }

    public BigInteger getR() {
        return r;
    }

    public void setR(BigInteger r) {
        this.r = r;
    }

    public BigInteger getS() {
        return s;
    }

    public void setS(BigInteger s) {
        this.s = s;
    }

    /* 
     * 转成大写
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
//        return r.toString(16) + "," + s.toString(16);
        return SM2Util.bigIntegerToHex(r).toUpperCase() + SM2Util.bigIntegerToHex(s).toUpperCase();
    }
}