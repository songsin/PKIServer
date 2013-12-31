package org.cryptable.pki.server.model.profile;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.cryptable.pki.server.model.profile.impl.ProfilesJAXB;
import org.junit.Before;
import org.junit.Test;

import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 00:27
 */
public class ProfilesKeyUsageTest {

    static private Profiles profiles;
    private CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();

    @Before
    public void setup() throws JAXBException, IOException, ProfileException {
        if (profiles == null)
            profiles = new ProfilesJAXB(getClass().getResourceAsStream("/KeyUsage.xml"));
    }

    /**
     * Test a normal key Usage situation with no overrule.
     *
     * <Key_Usage>
     *   <Signature>No Overrule</Signature>
     *   <Non_Repudiation>No Overrule</Non_Repudiation>
     *   <Key_Encipherment>No Overrule</Key_Encipherment>
     *   <Data_Encipherment>No Overrule</Data_Encipherment>
     *   <Key_Agreement>No Overrule</Key_Agreement>
     *   <CRL_Signature>No Overrule</CRL_Signature>
     *   <Encipherment_Only>No Overrule</Encipherment_Only>
     *   <Decipherment_Only>No Overrule</Decipherment_Only>
     *   <Key_Certificate_Signature>No Overrule</Key_Certificate_Signature>
     * </Key_Usage>
     */
    @Test
    public void testCertificateKeyUsageValid() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(2);
        Extension extension = new Extension(Extension.keyUsage,
            true,
            new DEROctetString(new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment)));
        Extensions extensions = new Extensions(extension);

        CertTemplate certTemplate = certTemplateBuilder
            .setExtensions(extensions)
            .build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);
        Result result = results.get(0);
        Extension ext = (Extension) result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertEquals(Extension.keyUsage, ext.getExtnId());
        assertTrue(ext.isCritical());

        KeyUsage keyUsage = KeyUsage.getInstance(ext.getParsedValue());

        assertTrue(keyUsage.hasUsages(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment));

    }

    /**
     * Test a normal key Usage situation with no overrule.
     *
     * <Key_Usage>
     *   <Signature>Enable</Signature>
     *   <Non_Repudiation>Enable</Non_Repudiation>
     *   <Data_Encipherment>Enable</Data_Encipherment>
     *   <Key_Agreement>Enable</Key_Agreement>
     *   <Encipherment_Only>Enable</Encipherment_Only>
     *   <Decipherment_Only>Enable</Decipherment_Only>
     *   <Key_Certificate_Signature>Enable</Key_Certificate_Signature>
     * </Key_Usage>
     */
    @Test
    public void testCertificateKeyUsageOverruled() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(1);
        Extension extension = new Extension(Extension.keyUsage,
            true,
            new DEROctetString(new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment)));
        Extensions extensions = new Extensions(extension);

        CertTemplate certTemplate = certTemplateBuilder
            .setExtensions(extensions)
            .build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);
        Result result = results.get(0);
        Extension ext = (Extension) result.getValue();

        assertEquals(Result.Decisions.OVERRULED, result.getDecision());
        assertEquals(Extension.keyUsage, ext.getExtnId());
        assertTrue(ext.isCritical());

        KeyUsage keyUsage = KeyUsage.getInstance(ext.getParsedValue());

        System.out.println(keyUsage.toString());
        System.out.println(Integer.valueOf(KeyUsage.digitalSignature | KeyUsage.nonRepudiation
            | KeyUsage.dataEncipherment | KeyUsage.keyAgreement
            | KeyUsage.encipherOnly | KeyUsage.decipherOnly
            | KeyUsage.keyCertSign).toString());
        assertTrue(keyUsage.hasUsages(KeyUsage.digitalSignature | KeyUsage.nonRepudiation
            | KeyUsage.dataEncipherment | KeyUsage.keyAgreement
            | KeyUsage.encipherOnly | KeyUsage.decipherOnly
            | KeyUsage.keyCertSign));

    }

}
