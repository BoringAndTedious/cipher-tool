package cn.com.agree.cipher.utils;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.encoders.Base64;
import sun.misc.BASE64Decoder;

public class KeyPairHelper {
    public static void main(String[] args) throws Exception {
        String publickey_sm2 = "v673qdCw0lzsagW5caRiHy6fWnAiSEhVAVb2fndcFZrYyaQZ2bAo1k2wVXVkRalQPBILdCyrc6GLQJjKoY6KHg==";
        String publickey1_sm2 = "jhzwboaYnkIPwM+dv3ONBwWhCz+ZBm7+59rbOq4D2WPI6Nj6v0WOAWdmodNQKYlRLWxLKdaq+IbN249JMMq8pg==";
        System.out.println("publicKey:"+ bytesToHex(Base64.decode(publickey1_sm2)));

        String prikey = "MIGIAgEAMBQGCCqBHM9VAYItBggqgRzPVQGCLQRtMGsCAQEEINUyZHhFJieSqP4c\n" +
                "VOIVTuaApCPhHlXj/PL0xZSAG73ZoUQDQgAEjhzwboaYnkIPwM+dv3ONBwWhCz+Z\n" +
                "Bm7+59rbOq4D2WPI6Nj6v0WOAWdmodNQKYlRLWxLKdaq+IbN249JMMq8pg==";
        getPrivateKey(prikey);
    }

    private static void getPrivateKey(String privateKey) throws Exception {
        BASE64Decoder decode = new BASE64Decoder();
        byte[] b = decode.decodeBuffer(privateKey);
        byte[] privatekey_bytes = privateKey(b);
        System.out.println("privateKey:" + bytesToHex(privatekey_bytes));
    }

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

    private static void getPublicKey(String str) throws Exception {
        BASE64Decoder decode = new BASE64Decoder();
        byte[] b = decode.decodeBuffer(str);
        byte[] publickey_bytes = publicKey(b);
        System.out.println("publicKey:" + bytesToHex(publickey_bytes));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuffer sb = new StringBuffer();
        for(int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if(hex.length() < 2){
                sb.append(0);
            }
            sb.append(hex);
        }
        return sb.toString();
    }

    private static byte[] publicKey(byte[] pubkey) throws Exception {
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo
                .getInstance(pubkey);

        DERBitString publicKeyData = subjectPublicKeyInfo.getPublicKeyData();
        byte[] publicKey = publicKeyData.getEncoded();
        byte[] encodedPublicKey = publicKey;
        byte[] ecP = new byte[64];
        System.arraycopy(encodedPublicKey, 4, ecP, 0, ecP.length);

        byte[] certPKX = new byte[32];
        byte[] certPKY = new byte[32];
        System.arraycopy(ecP, 0, certPKX, 0, 32);
        System.arraycopy(ecP, 32, certPKY, 0, 32);
        System.out.println(new String(Base64.encode(ecP)));
        return ecP;
    }
}
