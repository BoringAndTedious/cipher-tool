package cn.com.agree.cipher.sm2;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @author zaile
 */
public class SM2CertEncryptionUtil {
    public static byte[] encryptWithb4Cert(String oriData, String b64Cert) throws InvalidCipherTextException, IOException {
        X509CertificateHolder certHolder = new X509CertificateHolder(Base64.decode(b64Cert));
        CipherParameters pubKeyParameters = new ParametersWithRandom(parseEcPublicKey(certHolder), new SecureRandom());
        SM2Engine sm2Engine = new SM2Engine(new SM3Digest(), SM2Engine.Mode.C1C3C2);
        sm2Engine.init(true, pubKeyParameters);
        byte[] oriDataByte = oriData.getBytes();
        return sm2Engine.processBlock(oriDataByte, 0, oriDataByte.length);
    }

    private static ECPublicKeyParameters parseEcPublicKey(X509CertificateHolder cert) {
        SubjectPublicKeyInfo keyInfo = cert.getSubjectPublicKeyInfo();
        byte[] pubKeyData = keyInfo.getPublicKeyData().getBytes();
        X9ECParameters gmParams = GMNamedCurves.getByOID(GMObjectIdentifiers.sm2p256v1);
        ECDomainParameters gmDomainParams = new ECDomainParameters(gmParams.getCurve(), gmParams.getG(), gmParams.getN(), gmParams.getH(), gmParams.getSeed());
        X9ECPoint x9Point = new X9ECPoint(gmParams.getCurve(), pubKeyData);
        ECPoint pubKeyPoint = x9Point.getPoint();
        return new ECPublicKeyParameters(pubKeyPoint, gmDomainParams);
    }

    public static byte[] signWithPlatfromPrivateKey(String oriData, String p8) throws IOException, CryptoException {
        ASN1Primitive asn1Primitive = new ASN1InputStream(Base64.decode(p8.getBytes())).readObject();
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(asn1Primitive);
        ECPrivateKeyParameters ecPrivateKeyParameters = parseEcPrivateKey(privateKeyInfo);
        SM2Signer signer = new SM2Signer();
        signer.init(true, ecPrivateKeyParameters);
        byte[] oriDataByte = oriData.getBytes();
        signer.update(oriDataByte, 0, oriDataByte.length);
        return signer.generateSignature();
    }

    public static boolean checkSignWithB64Cert(String oriData, byte[] signData, String b64Cert) throws IOException {
        X509CertificateHolder certHolder = new X509CertificateHolder(Base64.decode(b64Cert));
        CipherParameters pubKeyParameters = parseEcPublicKey(certHolder);
        SM2Signer signer = new SM2Signer();
        signer.init(false, pubKeyParameters);
        byte[] oriDataByte = oriData.getBytes();
        signer.update(oriDataByte, 0, oriDataByte.length);
        return signer.verifySignature(signData);
    }

    private static ECPrivateKeyParameters parseEcPrivateKey(PrivateKeyInfo privKeyInfo) {
        ECPrivateKey ec = null;
        try {
            ec = ECPrivateKey.getInstance(privKeyInfo.parsePrivateKey());
        } catch (IOException e) {
            e.printStackTrace();
        }
        BigInteger d = ec.getKey();
        X9ECParameters gmParams = GMNamedCurves.getByOID(GMObjectIdentifiers.sm2p256v1);
        ECDomainParameters gmDomainParams = new ECDomainParameters(gmParams.getCurve(),
                gmParams.getG(), gmParams.getN(), gmParams.getH(), gmParams.getSeed());
        return new ECPrivateKeyParameters(d, gmDomainParams);
    }
    public static byte[] decryptWithPlatfromPrivateKey(byte[] encData,String p8) throws IOException, InvalidCipherTextException {
        ASN1Primitive asn1Primitive = new ASN1InputStream(Base64.decode(p8.getBytes())).readObject();
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(asn1Primitive);
        ECPrivateKeyParameters ecPrivateKeyParameters = parseEcPrivateKey(privateKeyInfo);
        SM2Engine sm2Engine = new SM2Engine(new SM3Digest(), SM2Engine.Mode.C1C3C2);
        sm2Engine.init(false, ecPrivateKeyParameters);
        return sm2Engine.processBlock(encData, 0, encData.length);
    }
}
