# cipher-tool
## 国密SM2签发证书及进行JWT过程

## openssl生成国密私钥和p10

1. 安装 openssl-3.0.0-beta1.tar.gz

   > [下载地址](https://github.com/openssl/openssl/releases/tag/openssl-3.0.0-beta1)

2. 查看openssl版本  openssl version

   > 低版本可能不支持 sm3WithSM2Sign算法

3. 检查修改openssl配置文件openssl.cnf ，修改[ req ] default_md  = sm3

   ```shell
   [ req ]
   default_bits            = 2048
   default_md              = sm3
   default_keyfile         = privkey.pem
   distinguished_name      = req_distinguished_name
   attributes              = req_attributes
   ```

4. 执行命令生成SM2私钥：

   ```shell
   openssl ecparam -genkey -name SM2  -out sm2Private.key 
   ```

5. 执行命令生成p10:

   ```shell
   openssl req  -key sm2Private.key  -new -out sm2P10.req -subj '/CN=Bank of ShangHai/OU=Enterprises/O=CFCA SM2 OC3A1/C=CN'
   ```

   > **-key 引用第4步生成的SM2私钥文件**
   > **-subj 为userDn:  cn:主题名称；ou：部门；o：组织；c：国家。**
   
6. 查看p10文件：

   ```shell
   cat sm2P10.req
   ```
   
   >   P10 格式
   >
   > ```shell
   > -----BEGIN CERTIFICATE REQUEST-----
   > MIIBBzCBrwIBADBMMQ4wDAYDVQQDDAVBR1JFRTEUMBIGA1UECwwLRW50ZXJwcmlz
   > ZXMxFzAVBgNVBAoMDkNGQ0EgU00yIE9DM0ExMQswCQYDVQQGEwJDTjBaMBQGCCqB
   > HM9VAYItBggqgRzPVQGCLQNCAAQknsWuFWQra+jbYILKZWngh0diqUbbRW8SjpMg
   > zJrlqYjtEgxL5j+e9NafDQ5Pbg731k6TmLGTPbg+mkPjudsUoAAwCgYIKoEcz1UB
   > g3UDRwAwRAIgdNO/NzyvyijuayD6hmXXMyLWAl6cFwRiGo3g7RAJnwoCIBlR7OZs
   > YekVddODBh4eCXWWfHlQxC1yHZ4E1VHdyvbY
   > -----END CERTIFICATE REQUEST-----
   > ```
   >
   > 
   
   
   
7. 查看私钥文件

   ```shell
   cat sm2Private.key 
   ```

   >   私钥样式
   >
   > ```shell
   > -----BEGIN SM2 PARAMETERS-----
   > BggqgRzPVQGCLQ==
   > -----END SM2 PARAMETERS-----
   > -----BEGIN PRIVATE KEY-----
   > MIGIAgEAMBQGCCqBHM9VAYItBggqgRzPVQGCLQRtMGsCAQEEIDs3/YQsngBc93r/
   > 8xmin/9h31Ap6SluVy/LeCMvA/MzoUQDQgAEJJ7FrhVkK2vo22CCymVp4IdHYqlG
   > 20VvEo6TIMya5amI7RIMS+Y/nvTWnw0OT24O99ZOk5ixkz24PppD47nbFA==
   > -----END PRIVATE KEY-----
   > ```

   ​      `BggqgRzPVQGCLQ==` 是椭圆曲线的关键参数，对应`secp256k1`标识。

   ​	  用`secp256k1`生成私钥每次私钥是不同的，但`EC PARAMETERS`都是相同的。

   ​     只有用不同的name指定不同曲线`EC PARAMETERS`才会不同。

   ​     因为私钥可以生成公钥，要用到曲线，所以要将曲线的标识写到密钥文件里。

   8. 根据p10签发证书：

   p7b证书样式：

   ```shell
   -----BEGIN PKCS7-----
   MIIC1AYJKoZIhvcNAQcCoIICxTCCAsECAQExADALBgkqhkiG9w0BBwGgggKpMIICpTCCAkqgAwIBAgIFEEWEAWkwDAYIKoEcz1UBg3UFADBcMQswCQYDVQQGEwJDTjEwMC4GA1UECgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRswGQYDVQQDDBJDRkNBIFRFU1QgU00yIE9DQTEwHhcNMjEwODA1MTYwMDAwWhcNMjMwODA1MTYwMDAwWjBeMQswCQYDVQQGEwJDTjEXMBUGA1UECgwOQ0ZDQSBTTTIgT0MzQTExFDASBgNVBAsMC0VudGVycHJpc2VzMSAwHgYDVQQDDBdCYW5rIG9mIFNoYW5nSGFpQDA4MDcwMTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABI4c8G6GmJ5CD8DPnb9zjQcFoQs/mQZu/ufa2zquA9ljyOjY+r9FjgFnZqHTUCmJUS1sSynWqviGzduPSTDKvKajgfQwgfEwHwYDVR0jBBgwFoAUa/4Y2o9COqa4bbMuiIM6NKLBMOEwSAYDVR0gBEEwPzA9BghggRyG7yoBATAxMC8GCCsGAQUFBwIBFiNodHRwOi8vd3d3LmNmY2EuY29tLmNuL3VzL3VzLTE0Lmh0bTA5BgNVHR8EMjAwMC6gLKAqhihodHRwOi8vdWNybC5jZmNhLmNvbS5jbi9TTTIvY3JsMjU1OTUuY3JsMAsGA1UdDwQEAwID6DAdBgNVHQ4EFgQU5k4KoHY0gkXVdwIr9zGU9HBTG8YwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMAwGCCqBHM9VAYN1BQADRwAwRAIgQX64cX3cJN6eK2l1F946gdFcEdXRKUOi3N8Yezmtg34CIC0q2V5gfq7DWYmu5p0NNvCq1aNayh7j5tQBFywduD2bMQA=
   -----END PKCS7-----
   ```

     cer证书样式：

   >   ```shell
   >   -----BEGIN CERTIFICATE-----
   >   MIICpTCCAkqgAwIBAgIFEEWEAWkwDAYIKoEcz1UBg3UFADBcMQswCQYDVQQGEwJDTjEwMC4GA1UECgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRswGQYDVQQDDBJDRkNBIFRFU1QgU00yIE9DQTEwHhcNMjEwODA1MTYwMDAwWhcNMjMwODA1MTYwMDAwWjBeMQswCQYDVQQGEwJDTjEXMBUGA1UECgwOQ0ZDQSBTTTIgT0MzQTExFDASBgNVBAsMC0VudGVycHJpc2VzMSAwHgYDVQQDDBdCYW5rIG9mIFNoYW5nSGFpQDA4MDcwMTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABI4c8G6GmJ5CD8DPnb9zjQcFoQs/mQZu/ufa2zquA9ljyOjY+r9FjgFnZqHTUCmJUS1sSynWqviGzduPSTDKvKajgfQwgfEwHwYDVR0jBBgwFoAUa/4Y2o9COqa4bbMuiIM6NKLBMOEwSAYDVR0gBEEwPzA9BghggRyG7yoBATAxMC8GCCsGAQUFBwIBFiNodHRwOi8vd3d3LmNmY2EuY29tLmNuL3VzL3VzLTE0Lmh0bTA5BgNVHR8EMjAwMC6gLKAqhihodHRwOi8vdWNybC5jZmNhLmNvbS5jbi9TTTIvY3JsMjU1OTUuY3JsMAsGA1UdDwQEAwID6DAdBgNVHQ4EFgQU5k4KoHY0gkXVdwIr9zGU9HBTG8YwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMAwGCCqBHM9VAYN1BQADRwAwRAIgQX64cX3cJN6eK2l1F946gdFcEdXRKUOi3N8Yezmtg34CIC0q2V5gfq7DWYmu5p0NNvCq1aNayh7j5tQBFywduD2b
   >   -----END CERTIFICATE-----
   >   ```

8. 针对证书的一些操作：

   pom.xml引入

   ```xml
           <dependency>
               <groupId>org.bouncycastle</groupId>
               <artifactId>bcprov-jdk15on</artifactId>
               <version>1.65</version>
               <scope>compile</scope>
           </dependency>
           <dependency>
               <groupId>org.bouncycastle</groupId>
               <artifactId>bcpkix-jdk15on</artifactId>
               <version>1.61</version>
           </dependency>
   ```

   根据p10提取userDn

   ```java
   import org.apache.commons.io.IOUtils;
   import org.bouncycastle.asn1.x500.X500Name;
   import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
   import org.bouncycastle.openssl.PEMParser;
   import org.bouncycastle.pkcs.PKCS10CertificationRequest;
   import java.io.*;
   import java.nio.charset.StandardCharsets;
   import java.security.Security;
   import java.util.logging.Logger;
   public class CSRInfoDecoder {
       private static Logger LOG = Logger.getLogger(CSRInfoDecoder.class.getName());
       
       private static final String csrPEM = "-----BEGIN CERTIFICATE REQUEST-----\n" +
               "MIIBEzCBugIBADBXMRkwFwYDVQQDDBBCYW5rIG9mIFNoYW5nSGFpMRQwEgYDVQQL\n" +
               "DAtFbnRlcnByaXNlczEXMBUGA1UECgwOQ0ZDQSBTTTIgT0MzQTExCzAJBgNVBAYT\n" +
               "AkNOMFowFAYIKoEcz1UBgi0GCCqBHM9VAYItA0IABAiVp9P6u52W/2i8r9bGvmSR\n" +
               "P62lHyByJZU2VvpxNnqpCudvwXGIP/l94RvYZ8IfmIjw5fLMfIsa9KrtSQAV23Wg\n" +
               "ADAKBggqgRzPVQGDdQNIADBFAiA1dITLNwkAyz/DXo5wXmus1JYQVU+RwN9rqAme\n" +
               "6QTfpgIhAPQDGmZg14u++tuomhOSaSXYC8xITBfSyUnHcdcXQJm1\n" +
               "-----END CERTIFICATE REQUEST-----";
   
       public static void main(String[] args) {
           InputStream stream = new ByteArrayInputStream(csrPEM.getBytes(StandardCharsets.UTF_8));
   
           CSRInfoDecoder m = new CSRInfoDecoder();
           m.readCertificateSigningRequest(stream);
       }
   
       public String readCertificateSigningRequest(InputStream csrStream) {
   
           PKCS10CertificationRequest csr = convertPemToPKCS10CertificationRequest(csrStream);
           String compname = null;
   
           if (csr == null) {
           } else {
               X500Name x500Name = csr.getSubject();
               compname = x500Name.toString();
               System.out.println("userDn is: " + x500Name + "\n");
            }
   
           return compname;
       }
   
   
       private PKCS10CertificationRequest convertPemToPKCS10CertificationRequest(InputStream pem) {
           Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
           PKCS10CertificationRequest csr = null;
           ByteArrayInputStream pemStream = null;
   
           pemStream = (ByteArrayInputStream) pem;
   
           Reader pemReader = new BufferedReader(new InputStreamReader(pemStream));
           PEMParser pemParser = null;
           try {
               pemParser = new PEMParser(pemReader);
               Object parsedObj = pemParser.readObject();
               System.out.println("PemParser returned: " + parsedObj);
               if (parsedObj instanceof PKCS10CertificationRequest) {
                   csr = (PKCS10CertificationRequest) parsedObj;
               }
           } catch (IOException ex) {
           } finally {
               if (pemParser != null) {
                   IOUtils.closeQuietly(pemParser);
               }
           }
           return csr;
       }
   }
   ```

   SM2证书工具类：

   ```java
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
   
   ```

   解析证书：

   ```java
      // p7b格式的证书链文件
           String b64P7bCert = "TUlJQzFBWUpLb1pJaHZjTkFRY0NvSUlDeFRDQ0FzRUNBUUV4QURBTEJna3Foa2lHOXcwQkJ3R2dnZ0twTUlJQ3BUQ0NBa3FnQXdJQkFnSUZFRVdFQVdrd0RBWUlLb0VjejFVQmczVUZBREJjTVFzd0NRWURWUVFHRXdKRFRqRXdNQzRHQTFVRUNnd25RMmhwYm1FZ1JtbHVZVzVqYVdGc0lFTmxjblJwWm1sallYUnBiMjRnUVhWMGFHOXlhWFI1TVJzd0dRWURWUVFEREJKRFJrTkJJRlJGVTFRZ1UwMHlJRTlEUVRFd0hoY05NakV3T0RBMU1UWXdNREF3V2hjTk1qTXdPREExTVRZd01EQXdXakJlTVFzd0NRWURWUVFHRXdKRFRqRVhNQlVHQTFVRUNnd09RMFpEUVNCVFRUSWdUME16UVRFeEZEQVNCZ05WQkFzTUMwVnVkR1Z5Y0hKcGMyVnpNU0F3SGdZRFZRUUREQmRDWVc1cklHOW1JRk5vWVc1blNHRnBRREE0TURjd01UQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxQkhNOVZBWUl0QTBJQUJJNGM4RzZHbUo1Q0Q4RFBuYjl6alFjRm9Rcy9tUVp1L3VmYTJ6cXVBOWxqeU9qWStyOUZqZ0ZuWnFIVFVDbUpVUzFzU3luV3F2aUd6ZHVQU1RES3ZLYWpnZlF3Z2ZFd0h3WURWUjBqQkJnd0ZvQVVhLzRZMm85Q09xYTRiYk11aUlNNk5LTEJNT0V3U0FZRFZSMGdCRUV3UHpBOUJnaGdnUnlHN3lvQkFUQXhNQzhHQ0NzR0FRVUZCd0lCRmlOb2RIUndPaTh2ZDNkM0xtTm1ZMkV1WTI5dExtTnVMM1Z6TDNWekxURTBMbWgwYlRBNUJnTlZIUjhFTWpBd01DNmdMS0FxaGlob2RIUndPaTh2ZFdOeWJDNWpabU5oTG1OdmJTNWpiaTlUVFRJdlkzSnNNalUxT1RVdVkzSnNNQXNHQTFVZER3UUVBd0lENkRBZEJnTlZIUTRFRmdRVTVrNEtvSFkwZ2tYVmR3SXI5ekdVOUhCVEc4WXdIUVlEVlIwbEJCWXdGQVlJS3dZQkJRVUhBd0lHQ0NzR0FRVUZCd01FTUF3R0NDcUJITTlWQVlOMUJRQURSd0F3UkFJZ1FYNjRjWDNjSk42ZUsybDFGOTQ2Z2RGY0VkWFJLVU9pM044WWV6bXRnMzRDSUMwcTJWNWdmcTdEV1ltdTVwME5OdkNxMWFOYXloN2o1dFFCRnl3ZHVEMmJNUUE9";
   
   //cer证书内容
           String cert = "MIICpTCCAkqgAwIBAgIFEEWEAWkwDAYIKoEcz1UBg3UFADBcMQswCQYDVQQGEwJDTjEwMC4GA1UECgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRswGQYDVQQDDBJDRkNBIFRFU1QgU00yIE9DQTEwHhcNMjEwODA1MTYwMDAwWhcNMjMwODA1MTYwMDAwWjBeMQswCQYDVQQGEwJDTjEXMBUGA1UECgwOQ0ZDQSBTTTIgT0MzQTExFDASBgNVBAsMC0VudGVycHJpc2VzMSAwHgYDVQQDDBdCYW5rIG9mIFNoYW5nSGFpQDA4MDcwMTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABI4c8G6GmJ5CD8DPnb9zjQcFoQs/mQZu/ufa2zquA9ljyOjY+r9FjgFnZqHTUCmJUS1sSynWqviGzduPSTDKvKajgfQwgfEwHwYDVR0jBBgwFoAUa/4Y2o9COqa4bbMuiIM6NKLBMOEwSAYDVR0gBEEwPzA9BghggRyG7yoBATAxMC8GCCsGAQUFBwIBFiNodHRwOi8vd3d3LmNmY2EuY29tLmNuL3VzL3VzLTE0Lmh0bTA5BgNVHR8EMjAwMC6gLKAqhihodHRwOi8vdWNybC5jZmNhLmNvbS5jbi9TTTIvY3JsMjU1OTUuY3JsMAsGA1UdDwQEAwID6DAdBgNVHQ4EFgQU5k4KoHY0gkXVdwIr9zGU9HBTG8YwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMAwGCCqBHM9VAYN1BQADRwAwRAIgQX64cX3cJN6eK2l1F946gdFcEdXRKUOi3N8Yezmtg34CIC0q2V5gfq7DWYmu5p0NNvCq1aNayh7j5tQBFywduD2b";
           //如果是单证书可以直接获取公钥
           String pubKey = SM2CertUtil.getPKCS7CertPublicKey(b64P7bCert);
           System.out.println(pubKey);
           //单证书内容   p7b提取cer格式
           String certStr = SM2CertUtil.getKCS7CertStrCert(b64P7bCert);
           System.out.println(certStr);
           //cer证书公钥
           String pubKey1 = SM2CertUtil.getCertPublicKey(b64Cert);
           System.out.println(pubKey1);
   ```

   公钥样式：

   ```java
   jhzwboaYnkIPwM+dv3ONBwWhCz+ZBm7+59rbOq4D2WPI6Nj6v0WOAWdmodNQKYlRLWxLKdaq+IbN249JMMq8pg==
   ```

   获取16进制公私钥对：

   ```java
     /**
            * 私钥原始文件：
            * -----BEGIN SM2 PARAMETERS-----
            * BggqgRzPVQGCLQ==
            * -----END SM2 PARAMETERS-----
            * -----BEGIN PRIVATE KEY-----
            * MIGIAgEAMBQGCCqBHM9VAYItBggqgRzPVQGCLQRtMGsCAQEEINUyZHhFJieSqP4c
            * VOIVTuaApCPhHlXj/PL0xZSAG73ZoUQDQgAEjhzwboaYnkIPwM+dv3ONBwWhCz+Z
            * Bm7+59rbOq4D2WPI6Nj6v0WOAWdmodNQKYlRLWxLKdaq+IbN249JMMq8pg==
            * -----END PRIVATE KEY-----
            */
           String privateKey = "MIGIAgEAMBQGCCqBHM9VAYItBggqgRzPVQGCLQRtMGsCAQEEINUyZHhFJieSqP4c\n" +
                   "VOIVTuaApCPhHlXj/PL0xZSAG73ZoUQDQgAEjhzwboaYnkIPwM+dv3ONBwWhCz+Z\n" +
                   "Bm7+59rbOq4D2WPI6Nj6v0WOAWdmodNQKYlRLWxLKdaq+IbN249JMMq8pg==";
           //当前公钥为证书提取出来的公钥
           String publicKey = "jhzwboaYnkIPwM+dv3ONBwWhCz+ZBm7+59rbOq4D2WPI6Nj6v0WOAWdmodNQKYlRLWxLKdaq+IbN249JMMq8pg==";
           String priKey = SM2CertUtil.getPrivateKey(privateKey);
           System.out.println("priKey:" + priKey);
           System.out.println("publicKey:" + ByteUtil.bytesToHex(Base64.decode(publicKey)));
   ```

   16进制公私钥对样式：

   ```shell
   priKey:d532647845262792a8fe1c54e2154ee680a423e11e55e3fcf2f4c594801bbdd9
   publicKey:8e1cf06e86989e420fc0cf9dbf738d0705a10b3f99066efee7dadb3aae03d963c8e8d8fabf458e016766a1d3502989512d6c4b29d6aaf886cddb8f4930cabca6
   ```

   128位公钥，前64位为x轴，后64位为y轴 根据xy获取ECPoint对象进行SM2加密

   也可用证书原文获取ECPoint进行加密

   ```java
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
   ```

9. JWE组成：

   1 头部用于描述关于该JWT的最基本的信息，例如其类型以及签名所用的算法等。

   2 生成一个随机的Content Encryption Key （CEK）。

   3 使用RSAES-OAEP 加密算法，用公钥加密CEK，生成JWE Encrypted Key。

   4 生成JWE初始化向量。

   5 使用AES GCM加密算法对明文部分进行加密生成密文Ciphertext,算法会随之生成一个128位的认证标记Authentication Tag。

   

   对五个部分分别进行base64编码。

