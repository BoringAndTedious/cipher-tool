package cn.com.agree.cipher;

import cn.com.agree.cipher.jwt.JWT;
import org.junit.Test;

/**
 * 私钥原始文件 及证书加解密加验签
 */
public class JWTCertTest {
    @Test
    public void test() throws Exception {
        String body = "{\"code\": \"E00200010005\",\"message\": \"调用权限不足\", \"errors\": [{\"errorCode\": \"ISV_INVALID_PARAM\", \"errorMessage\": \"开发者上送参数无效\"}]}";
        String appId = "2021080691440300708461136T000001";
        String b64Cert = "MIICvDCCAaSgAwIBAgIMGzEAAAAAAB7gNDutMA0GCSqGSIb3DQEBCwUAMCgxCzAJBgNVBAYTAkNOMRkwFwYDVQQDDBBTdWJDQV9SU0FfMTkwNzEwMB4XDTIxMDczMTE2MDAwMFoXDTIxMDgzMTE1NTk1OVowXjELMAkGA1UEBhMCQ04xFzAVBgNVBAoMDkNGQ0EgU00yIE9DM0ExMRQwEgYDVQQLDAtFbnRlcnByaXNlczEgMB4GA1UEAwwXQmFuayBvZiBTaGFuZ0hhaUAwODA3MDEwWjAUBggqgRzPVQGCLQYIKoEcz1UBgi0DQgAEjhzwboaYnkIPwM+dv3ONBwWhCz+ZBm7+59rbOq4D2WPI6Nj6v0WOAWdmodNQKYlRLWxLKdaq+IbN249JMMq8pqN6MHgwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgDAMBEGCWCGSAGG+EIBAQQEAwIAQDAfBgNVHSMEGDAWgBSu3wQLd6LJWYgTI3KOdbDMiEirXzAdBgNVHQ4EFgQU5k4KoHY0gkXVdwIr9zGU9HBTG8YwDQYJKoZIhvcNAQELBQADggEBAGWD/OBQGv7G3sfgK3cxDW80ZhrT6h0pIJkCeK2TsM406NKvcIM36CTfY5bYDnf23gzwxu3AsESR3qtXxMv3zQWoJw983/AYI/EnhGGCitPKkcHAztZy6nOOn6FALUwmOmtRegKyKf/bibHyXCCH46vyPkfXkQ8KP8VBGg1BjXQ3nPIvGd3IrcE6qTIxitLcDOnpV/LRiLASb2uj+YRhpAzpmjEOjBJRfw56JRmhn/ERt6NmOIpeagMDh8Lk4yTKd71n+75Ys+2Kl4TDt30G6EDTAimWpnimx5M0c5U9Kbmk584melPqRUW9uTCLEZE172n3BGzeDKXyAptbsZuH53c=";
        String platformPrivateKey = "MIGIAgEAMBQGCCqBHM9VAYItBggqgRzPVQGCLQRtMGsCAQEEINUyZHhFJieSqP4cVOIVTuaApCPhHlXj/PL0xZSAG73ZoUQDQgAEjhzwboaYnkIPwM+dv3ONBwWhCz+ZBm7+59rbOq4D2WPI6Nj6v0WOAWdmodNQKYlRLWxLKdaq+IbN249JMMq8pg==";
        String privateKey = "";
        String publicKey = "";

        String jwe = JWT.signJWEWithB64Cert(appId, b64Cert, body);
        System.out.println("jwe:" + jwe);
        String jws = JWT.signJWSWithPlatFormPrivateKey(appId, platformPrivateKey, jwe);
        System.out.println("jws:" + jws);
        Boolean isCheck = JWT.checkJWSWithB64Cert(jws, b64Cert, jwe);
        System.out.println("isCheck:" + (isCheck ? "true" : "false"));
        String orginBody = JWT.decryptJWEWithPlatFormPrivateKey(jwe, platformPrivateKey);
        System.out.println("orginBody:" + orginBody);
    }


}