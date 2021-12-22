package cn.com.agree.cipher;

import cn.com.agree.cipher.jwt.JWT;
import cn.com.agree.cipher.sm2.SM2Util;
import cn.com.agree.cipher.utils.ByteUtil;
import cn.com.agree.cipher.utils.CSRInfoDecoder;
import cn.com.agree.cipher.utils.SM2CertUtil;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Test;
import sun.awt.SunHints;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

class CipherApplicationTests {

    /**
     * 根据p10获取userDn
     */
    @Test
    void getUserDn() {
        String p10 = "-----BEGIN CERTIFICATE REQUEST-----\n" +
                "MIIBBzCBrwIBADBMMQ4wDAYDVQQDDAVBR1JFRTEUMBIGA1UECwwLRW50ZXJwcmlz\n" +
                "ZXMxFzAVBgNVBAoMDkNGQ0EgU00yIE9DM0ExMQswCQYDVQQGEwJDTjBaMBQGCCqB\n" +
                "HM9VAYItBggqgRzPVQGCLQNCAAQknsWuFWQra+jbYILKZWngh0diqUbbRW8SjpMg\n" +
                "zJrlqYjtEgxL5j+e9NafDQ5Pbg731k6TmLGTPbg+mkPjudsUoAAwCgYIKoEcz1UB\n" +
                "g3UDRwAwRAIgdNO/NzyvyijuayD6hmXXMyLWAl6cFwRiGo3g7RAJnwoCIBlR7OZs\n" +
                "YekVddODBh4eCXWWfHlQxC1yHZ4E1VHdyvbY\n" +
                "-----END CERTIFICATE REQUEST-----";
        InputStream stream = new ByteArrayInputStream(p10.getBytes(StandardCharsets.UTF_8));
        CSRInfoDecoder.readCertificateSigningRequest(stream);
    }

    /**
     * 生成SM2公私钥对
     */
    @Test
    void generateSm2KeyPair(){
        KeyPair keyPair =  SM2Util.generateSm2KeyPair();
        assert keyPair != null;
        System.out.println("privateKey:"+new String(Base64.encode(keyPair.getPrivate().getEncoded())));
        System.out.println("publicKey:"+new String(Base64.encode(keyPair.getPublic().getEncoded())));
    }
    /**
     * 解析证书
     */
    @Test
    void resolveCert() {
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
        String pubKey1 = SM2CertUtil.getCertPublicKey(cert);
        System.out.println(pubKey1);

    }

    /**
     * 16进制公私钥
     */
    @Test
    void hexKeyPair() throws Exception {
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

    }

    /**
     * 根据16进制公私钥对进行JWT
     * @throws Exception
     */
    @Test
    void hexKeyPairJWTTest() throws Exception {
        /**
         * 当前公私钥对为 hexKeyPair() 方法返回的公私钥对
         */
        String publicKey = "8e1cf06e86989e420fc0cf9dbf738d0705a10b3f99066efee7dadb3aae03d963c8e8d8fabf458e016766a1d3502989512d6c4b29d6aaf886cddb8f4930cabca6";
        String privateKey = "d532647845262792a8fe1c54e2154ee680a423e11e55e3fcf2f4c594801bbdd9";

        //测试签JWE
        String jwe = JWT.signJWE("6829ccfd-a838-4b4f-a282-724a0342b999", publicKey, "测试签JWE");
        System.out.println("签jwe= " + jwe);

        //测试解报体
        String plainText = JWT.decryptJWE(jwe, privateKey);
        System.out.println("解出报文体= " + plainText);

//		签名
        String jws = JWT.signJWS("6829ccfd-a838-4b4f-a282-724a0342b999", privateKey, "测试签名");
        System.out.println("签jws= " + jws);
//		验证签名
        boolean flag = JWT.checkJWS(jws,
                publicKey,
                "测试签名");
        System.out.println("验证= " + flag);

        //签名，包含playload
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("consentId", "consentId_001");
        String authorizeJWT = JWT.signJWT("6829ccfd-a838-4b4f-a282-724a0342b999", privateKey, claims);
        System.out.println("签authorizeJWT=" + authorizeJWT);
        System.out.println();
        //解签
        Map<String, ?> result = JWT.checkJWT(authorizeJWT, publicKey);

        System.out.println(result.get("consentId"));

    }

    /**
     * 根据证书原文 及私钥原文进行JWT
     * @throws Exception
     */
    @Test
    public void certJWTTest() throws Exception {
        String body = "{\"code\": \"E00200010005\",\"message\": \"调用权限不足\", \"errors\": [{\"errorCode\": \"ISV_INVALID_PARAM\", \"errorMessage\": \"开发者上送参数无效\"}]}";
        String appId = "2021080691440300708461136T000001";
        /**
         * 签发证书原文 SM2CertUtil.getKCS7CertStrCert(b64P7bCert) 获取的证书内容
         */
        String b64Cert = "MIICvDCCAaSgAwIBAgIMGzEAAAAAAB7gNDutMA0GCSqGSIb3DQEBCwUAMCgxCzAJBgNVBAYTAkNOMRkwFwYDVQQDDBBTdWJDQV9SU0FfMTkwNzEwMB4XDTIxMDczMTE2MDAwMFoXDTIxMDgzMTE1NTk1OVowXjELMAkGA1UEBhMCQ04xFzAVBgNVBAoMDkNGQ0EgU00yIE9DM0ExMRQwEgYDVQQLDAtFbnRlcnByaXNlczEgMB4GA1UEAwwXQmFuayBvZiBTaGFuZ0hhaUAwODA3MDEwWjAUBggqgRzPVQGCLQYIKoEcz1UBgi0DQgAEjhzwboaYnkIPwM+dv3ONBwWhCz+ZBm7+59rbOq4D2WPI6Nj6v0WOAWdmodNQKYlRLWxLKdaq+IbN249JMMq8pqN6MHgwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgDAMBEGCWCGSAGG+EIBAQQEAwIAQDAfBgNVHSMEGDAWgBSu3wQLd6LJWYgTI3KOdbDMiEirXzAdBgNVHQ4EFgQU5k4KoHY0gkXVdwIr9zGU9HBTG8YwDQYJKoZIhvcNAQELBQADggEBAGWD/OBQGv7G3sfgK3cxDW80ZhrT6h0pIJkCeK2TsM406NKvcIM36CTfY5bYDnf23gzwxu3AsESR3qtXxMv3zQWoJw983/AYI/EnhGGCitPKkcHAztZy6nOOn6FALUwmOmtRegKyKf/bibHyXCCH46vyPkfXkQ8KP8VBGg1BjXQ3nPIvGd3IrcE6qTIxitLcDOnpV/LRiLASb2uj+YRhpAzpmjEOjBJRfw56JRmhn/ERt6NmOIpeagMDh8Lk4yTKd71n+75Ys+2Kl4TDt30G6EDTAimWpnimx5M0c5U9Kbmk584melPqRUW9uTCLEZE172n3BGzeDKXyAptbsZuH53c=";
        /**
         * 私钥原文
         */
        String privateKey = "MIGIAgEAMBQGCCqBHM9VAYItBggqgRzPVQGCLQRtMGsCAQEEINUyZHhFJieSqP4cVOIVTuaApCPhHlXj/PL0xZSAG73ZoUQDQgAEjhzwboaYnkIPwM+dv3ONBwWhCz+ZBm7+59rbOq4D2WPI6Nj6v0WOAWdmodNQKYlRLWxLKdaq+IbN249JMMq8pg==";


        String jwe = JWT.signJWEWithB64Cert(appId, b64Cert, body);
        System.out.println("jwe:" + jwe);
        String jws = JWT.signJWSWithPlatFormPrivateKey(appId, privateKey, jwe);
        System.out.println("jws:" + jws);
        Boolean isCheck = JWT.checkJWSWithB64Cert(jws, b64Cert, jwe);
        System.out.println("isCheck:" + (isCheck ? "true" : "false"));
        String orginBody = JWT.decryptJWEWithPlatFormPrivateKey(jwe, privateKey);
        System.out.println("orginBody:" + orginBody);
    }
}
