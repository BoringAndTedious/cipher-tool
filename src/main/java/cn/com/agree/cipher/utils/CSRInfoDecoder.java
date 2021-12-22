package cn.com.agree.cipher.utils;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.*;
import java.security.Security;

/**
 * @author zaile
 */
@Slf4j
public class CSRInfoDecoder {


    public static String readCertificateSigningRequest(InputStream csrStream) {

        PKCS10CertificationRequest csr = convertPemToPKCS10CertificationRequest(csrStream);

        String userDn = null;

        if (csr == null) {
        } else {
            X500Name x500Name = csr.getSubject();
            userDn = x500Name.toString();
            log.info("userDn is: " + x500Name + "\n");

        }
        return userDn;
    }


    private static String getX500Field(String asn1ObjectIdentifier, X500Name x500Name) {
        RDN[] rdnArray = x500Name.getRDNs(new ASN1ObjectIdentifier(asn1ObjectIdentifier));

        String retVal = null;
        for (RDN item : rdnArray) {
            retVal = item.getFirst().getValue().toString();
        }
        return retVal;
    }

    private static PKCS10CertificationRequest convertPemToPKCS10CertificationRequest(InputStream pem) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        PKCS10CertificationRequest csr = null;
        ByteArrayInputStream pemStream = null;

        pemStream = (ByteArrayInputStream) pem;

        Reader pemReader = new BufferedReader(new InputStreamReader(pemStream));
        PEMParser pemParser = null;
        try {
            pemParser = new PEMParser(pemReader);
            Object parsedObj = pemParser.readObject();
            log.info("PemParser returned: " + parsedObj);
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