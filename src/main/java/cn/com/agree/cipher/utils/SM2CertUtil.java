package cn.com.agree.cipher.utils;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import sun.misc.BASE64Decoder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * @author zaile
 * 获取证书公钥
 */
@Slf4j
public class SM2CertUtil {
    /**
     * 获取 PKCS7 证书链公钥
     *
     * @param b64Cert
     * @return
     */
    public static String getPKCS7CertPublicKey(String b64Cert) {
        Security.removeProvider("BC");
        Security.addProvider(new BouncyCastleProvider());
        StringBuffer stringBuffer = new StringBuffer();
        stringBuffer.append("-----BEGIN PKCS7-----\n");
        String cerCont = new String(Base64.decode(b64Cert)) + "\n";
        stringBuffer.append(cerCont);
        stringBuffer.append("-----END PKCS7-----");
        String result = stringBuffer.toString();
        //创建X509工厂类
        CertificateFactory cf = null;
        //创建证书对象
        String publicKeyString = "";
        try {
            cf = CertificateFactory.getInstance("X.509", "BC");
            // p7b包含单证书
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(result.getBytes()));
            //p7b包含国密双证  下面方法解析
           // Collection<X509Certificate> certs = (Collection<X509Certificate>) cf.generateCertificate(new ByteArrayInputStream(result.getBytes()));
            PublicKey puk = cert.getPublicKey();
            publicKeyString = new String(Base64.encode(extractData(puk)));
            System.out.println("PublicKey:"+publicKeyString);
            System.out.println("cert:"+cert.toString());
        } catch (Exception e) {
            e.printStackTrace();
            log.error("读取公钥失败！！！！");
        }
        return publicKeyString;
    }
    public static String getCertPublicKey(String b64Cert) {
        Security.removeProvider("BC");
        Security.addProvider(new BouncyCastleProvider());
        StringBuffer stringBuffer = new StringBuffer();
        stringBuffer.append("-----BEGIN CERTIFICATE-----\n");
        String cerCont = b64Cert + "\n";
        stringBuffer.append(cerCont);
        stringBuffer.append("-----END CERTIFICATE-----");
        String result = stringBuffer.toString();
        //创建X509工厂类
        CertificateFactory cf = null;
        //创建证书对象
        String publicKeyString = "";
        try {
            cf = CertificateFactory.getInstance("X.509", "BC");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(result.getBytes()));
            PublicKey puk = cert.getPublicKey();
            publicKeyString = new String(Base64.encode(extractData(puk)));
            System.out.println("PublicKey:"+publicKeyString);
            System.out.println("cert:"+cert.toString());
        } catch (Exception e) {
            e.printStackTrace();
            log.error("读取公钥失败！！！！");
        }
        return publicKeyString;
    }

    /**
     * PKCS7 证书链提取证书
     *
     * @param b64Cert
     * @return
     */
    public static String getKCS7CertStrCert(String b64Cert) {
        Security.removeProvider("BC");
        Security.addProvider(new BouncyCastleProvider());
        StringBuffer stringBuffer = new StringBuffer();
        stringBuffer.append("-----BEGIN PKCS7-----\n");
        String cerCont = new String(Base64.decode(b64Cert)) + "\n";
        stringBuffer.append(cerCont);
        stringBuffer.append("-----END PKCS7-----");
        String result = stringBuffer.toString();
        //创建X509工厂类
        CertificateFactory cf = null;
        //创建证书对象
        String certContent = "";
        try {
            cf = CertificateFactory.getInstance("X.509", "BC");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(result.getBytes()));
            certContent = Base64.toBase64String(cert.getEncoded());
            System.out.println(certContent);

        } catch (Exception e) {
            e.printStackTrace();
            log.error("读取证书失败！！！！");
        }
        return certContent;
    }


    public static void main(String[] args) throws Exception {
        String result = "TUlJQzFBWUpLb1pJaHZjTkFRY0NvSUlDeFRDQ0FzRUNBUUV4QURBTEJna3Foa2lHOXcwQkJ3R2dnZ0twTUlJQ3BUQ0NBa3FnQXdJQkFnSUZFRVdFQVdrd0RBWUlLb0VjejFVQmczVUZBREJjTVFzd0NRWURWUVFHRXdKRFRqRXdNQzRHQTFVRUNnd25RMmhwYm1FZ1JtbHVZVzVqYVdGc0lFTmxjblJwWm1sallYUnBiMjRnUVhWMGFHOXlhWFI1TVJzd0dRWURWUVFEREJKRFJrTkJJRlJGVTFRZ1UwMHlJRTlEUVRFd0hoY05NakV3T0RBMU1UWXdNREF3V2hjTk1qTXdPREExTVRZd01EQXdXakJlTVFzd0NRWURWUVFHRXdKRFRqRVhNQlVHQTFVRUNnd09RMFpEUVNCVFRUSWdUME16UVRFeEZEQVNCZ05WQkFzTUMwVnVkR1Z5Y0hKcGMyVnpNU0F3SGdZRFZRUUREQmRDWVc1cklHOW1JRk5vWVc1blNHRnBRREE0TURjd01UQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxQkhNOVZBWUl0QTBJQUJJNGM4RzZHbUo1Q0Q4RFBuYjl6alFjRm9Rcy9tUVp1L3VmYTJ6cXVBOWxqeU9qWStyOUZqZ0ZuWnFIVFVDbUpVUzFzU3luV3F2aUd6ZHVQU1RES3ZLYWpnZlF3Z2ZFd0h3WURWUjBqQkJnd0ZvQVVhLzRZMm85Q09xYTRiYk11aUlNNk5LTEJNT0V3U0FZRFZSMGdCRUV3UHpBOUJnaGdnUnlHN3lvQkFUQXhNQzhHQ0NzR0FRVUZCd0lCRmlOb2RIUndPaTh2ZDNkM0xtTm1ZMkV1WTI5dExtTnVMM1Z6TDNWekxURTBMbWgwYlRBNUJnTlZIUjhFTWpBd01DNmdMS0FxaGlob2RIUndPaTh2ZFdOeWJDNWpabU5oTG1OdmJTNWpiaTlUVFRJdlkzSnNNalUxT1RVdVkzSnNNQXNHQTFVZER3UUVBd0lENkRBZEJnTlZIUTRFRmdRVTVrNEtvSFkwZ2tYVmR3SXI5ekdVOUhCVEc4WXdIUVlEVlIwbEJCWXdGQVlJS3dZQkJRVUhBd0lHQ0NzR0FRVUZCd01FTUF3R0NDcUJITTlWQVlOMUJRQURSd0F3UkFJZ1FYNjRjWDNjSk42ZUsybDFGOTQ2Z2RGY0VkWFJLVU9pM044WWV6bXRnMzRDSUMwcTJWNWdmcTdEV1ltdTVwME5OdkNxMWFOYXloN2o1dFFCRnl3ZHVEMmJNUUE9";
        getPKCS7CertPublicKey(result);
    }

    /**
     * PublicKey 获取字节publicKey
     *
     * @param publicKey
     * @return
     * @throws IOException
     */
    public static byte[] extractData(PublicKey publicKey) throws IOException {
        final SubjectPublicKeyInfo subjectPublicKeyInfo =
                SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        final byte[] encodedBytes = subjectPublicKeyInfo.getPublicKeyData().getBytes();
        final byte[] publicKeyData = new byte[encodedBytes.length - 1];

        System.arraycopy(encodedBytes, 1, publicKeyData, 0, encodedBytes.length - 1);

        return publicKeyData;
    }

    /**
     * 根据私钥字符串获取16进制私钥
     *
     * @param privateKey
     * @throws Exception
     */
    public static String getPrivateKey(String privateKey) throws Exception {
        BASE64Decoder decode = new BASE64Decoder();
        byte[] b = decode.decodeBuffer(privateKey);
        byte[] privatekey_bytes = privateKey(b);
        System.out.println("privateKey:" + ByteUtil.bytesToHex(privatekey_bytes));
        return ByteUtil.bytesToHex(privatekey_bytes);
    }

    /**
     * 私钥转ASN1Sequence 获取私钥
     *
     * @param privatekey
     * @return
     * @throws Exception
     */
    public static byte[] privateKey(byte[] privatekey) throws Exception {
        ASN1Sequence seq = ASN1Sequence.getInstance(privatekey);

        ASN1Encodable asn1Encodable = seq.getObjectAt(2);
        DEROctetString eEROctetString = (DEROctetString) asn1Encodable;

        DLSequence dLSequence = (DLSequence) ASN1Sequence
                .fromByteArray(eEROctetString.getOctets());
        asn1Encodable = dLSequence.getObjectAt(1);
        eEROctetString = (DEROctetString) asn1Encodable;
        return eEROctetString.getOctets();
    }

}
