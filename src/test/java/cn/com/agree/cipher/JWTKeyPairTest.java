package cn.com.agree.cipher;

import cn.com.agree.cipher.jwt.JWT;
import cn.com.agree.cipher.sm2.SM2Util;

import java.util.HashMap;
import java.util.Map;

public class JWTKeyPairTest {
    static String publicKey = "8e1cf06e86989e420fc0cf9dbf738d0705a10b3f99066efee7dadb3aae03d963c8e8d8fabf458e016766a1d3502989512d6c4b29d6aaf886cddb8f4930cabca6";
    static String privateKey = "d532647845262792a8fe1c54e2154ee680a423e11e55e3fcf2f4c594801bbdd9";
    static String publicKey1 = "bfaef7a9d0b0d25cec6a05b971a4621f2e9f5a70224848550156f67e775c159ad8c9a419d9b028d64db055756445a9503c120b742cab73a18b4098caa18e8a1e";
    static String privateKey1 = "8d4e366d957aeb9fc63cabe22977eca52b71590a721b326c289709cb25db59c9";
    public static void main(String[] args) throws Exception {
        System.out.println(SM2Util.checkPublicKey(publicKey));;
        test();
    }

    public static void test() throws Exception {

        //测试签JWE
        String jwe = JWT.signJWE("6829ccfd-a838-4b4f-a282-724a0342b999", publicKey, "测试签JWE");
        System.out.println("签jwe= " + jwe);

        //测试解报体
        String plainText = JWT.decryptJWE(jwe, privateKey);
        System.out.println("解出报文体= " + plainText);

//		签名
        String jws = JWT.signJWS("6829ccfd-a838-4b4f-a282-724a0342b999", privateKey1, "测试签名");
        System.out.println("签jws= " + jws);
//		验证签名
        boolean flag = JWT.checkJWS(jws,
                publicKey1,
                "测试签名");
        System.out.println("验证= " + flag);

        //签名，包含playload
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("consentId", "consentId_001");
        String authorizeJWT = JWT.signJWT("6829ccfd-a838-4b4f-a282-724a0342b999", privateKey1, claims);
        System.out.println("签authorizeJWT=" + authorizeJWT);
        System.out.println();
        //解签
        Map<String, ?> result = JWT.checkJWT(authorizeJWT, publicKey1);

        System.out.println(result.get("consentId"));
    }

}
