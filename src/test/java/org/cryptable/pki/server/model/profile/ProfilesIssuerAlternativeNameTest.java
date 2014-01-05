package org.cryptable.pki.server.model.profile;

import com.sun.jndi.url.dns.dnsURLContext;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.cryptable.pki.server.model.profile.impl.ProfilesJAXB;
import org.cryptable.pki.util.GeneratePKI;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.xml.bind.JAXBException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.UUID;

import static junit.framework.Assert.assertNotNull;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 00:27
 */
public class ProfilesIssuerAlternativeNameTest {

    static private Profiles profiles;
    static private GeneratePKI generatePKI;
    private CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();

    @BeforeClass
    static public void init() throws CertificateException, CertIOException, NoSuchAlgorithmException, OperatorCreationException, CRLException, NoSuchProviderException, InvalidKeySpecException {
        Security.addProvider(new BouncyCastleProvider());
        generatePKI = new GeneratePKI();
        generatePKI.createPKI();
    }

    @Before
    public void setup() throws JAXBException, IOException, ProfileException, CertificateEncodingException, NoSuchAlgorithmException {
        X509CertificateHolder x509CertificateHolder = new JcaX509CertificateHolder(generatePKI.getCaCert());
        if (profiles == null)
            profiles = new ProfilesJAXB(getClass().getResourceAsStream("/IssuerAlternativeName.xml"), x509CertificateHolder.toASN1Structure());
    }

    /**
     * Test the normal subject alternative name
     *
     * <Algorithm>SHA-1</Algorithm>
     */
    @Test
    public void testCertificateIssuerAlternaiveNameValid() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(1);
        Extension ext;
        Result result = null;


        GeneralNamesBuilder generalNamesBuilder = new GeneralNamesBuilder();
        // rfc822Name                      [1]     IA5String,
        generalNamesBuilder.addName(new GeneralName(GeneralName.rfc822Name, "ca@cryptable.org"));
        // dNSName                         [2]     IA5String,
        generalNamesBuilder.addName(new GeneralName(GeneralName.dNSName, "cryptable.org"));
        // directoryName                   [4]     Name,
        generalNamesBuilder.addName(new GeneralName(GeneralName.directoryName, "cn=alternative,o=cryptable"));
        // uniformResourceIdentifier       [6]     IA5String,
        generalNamesBuilder.addName(new GeneralName(GeneralName.uniformResourceIdentifier, "https://www.cryptable.org"));
        // iPAddress                       [7]     OCTET STRING,
        generalNamesBuilder.addName(new GeneralName(GeneralName.iPAddress, "10.2.3.4"));

        Extension extension = new Extension(Extension.issuerAlternativeName, false, new DEROctetString(generalNamesBuilder.build()));
        Extensions extensions = new Extensions(extension);

        CertTemplate certTemplate = certTemplateBuilder.setExtensions(extensions).build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);

        for (Result res : results) {
            if (((Extension)res.getValue()).getExtnId().equals(Extension.issuerAlternativeName)) {
                result = res;
                break;
            }
        }

        // Subject Key Identifier found
        assertNotNull(result);

        ext = (Extension)result.getValue();

        assertEquals(Extension.issuerAlternativeName, ((Extension) result.getValue()).getExtnId());
        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertFalse(ext.isCritical());

        // Verify the extension is not changed
        GeneralNames generalNames = GeneralNames.getInstance(ext.getParsedValue());
        assertEquals(generalNames.getNames().length, 5);
        boolean ipAddressOK = false;
        boolean eMailsOK = false;
        boolean domainNameOK = false;
        boolean dNameOK = false;
        boolean urlOK = false;
        for (GeneralName generalName : generalNames.getNames()) {
            if (generalName.getTagNo() == GeneralName.iPAddress) {
                byte[] ipAddress = DEROctetString.getInstance(generalName.getName()).getOctets();
                int ip1 = ipAddress[0] & 0xFF;
                int ip2 = ipAddress[1] & 0xFF;
                int ip3 = ipAddress[2] & 0xFF;
                int ip4 = ipAddress[3] & 0xFF;
                String ip = ip1 + "." + ip2 + "." + ip3 + "." +ip4;
                assertTrue(ip.equals("10.2.3.4"));
                ipAddressOK = true;
            }
            if (generalName.getTagNo() == GeneralName.rfc822Name) {
                String rfc822Name = DERIA5String.getInstance(generalName.getName()).getString();
                assertEquals("ca@cryptable.org", rfc822Name);
                eMailsOK = true;
            }
            if (generalName.getTagNo() == GeneralName.directoryName) {
                X500Name directoryName = X500Name.getInstance(generalName.getName());
                assertEquals(new X500Name("cn=alternative,o=cryptable"), directoryName);
                dNameOK = true;
            }
            if (generalName.getTagNo() == GeneralName.dNSName) {
                String dNSName = DERIA5String.getInstance(generalName.getName()).getString();
                assertEquals("cryptable.org", dNSName);
                domainNameOK = true;
            }
            if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                String uniformResourceIdentifier = DERIA5String.getInstance(generalName.getName()).getString();
                assertEquals("https://www.cryptable.org", uniformResourceIdentifier);
                urlOK = true;
            }
        }
        assertTrue(ipAddressOK || eMailsOK || dNameOK || domainNameOK || urlOK);
    }

    /**
     * Test the normal subject alternative name
     *
     * <Algorithm>SHA-1</Algorithm>
     */
    @Test
    public void testCertificateIssuerAlternaiveNameOverruled() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(2);
        Extension ext;
        Result result = null;


        GeneralNamesBuilder generalNamesBuilder = new GeneralNamesBuilder();
        generalNamesBuilder.addName(new GeneralName(GeneralName.iPAddress, "10.2.3.4"));
        generalNamesBuilder.addName(new GeneralName(GeneralName.rfc822Name, "ca@cryptable.org"));
        generalNamesBuilder.addName(new GeneralName(GeneralName.directoryName, "cn=alternative,o=cryptable"));
        generalNamesBuilder.addName(new GeneralName(GeneralName.dNSName, "cryptable.org"));
        generalNamesBuilder.addName(new GeneralName(GeneralName.uniformResourceIdentifier, "https://www.cryptable.org"));

        Extension extension = new Extension(Extension.issuerAlternativeName, false, new DEROctetString(generalNamesBuilder.build()));
        Extensions extensions = new Extensions(extension);

        CertTemplate certTemplate = certTemplateBuilder.setExtensions(extensions).build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);

        for (Result res : results) {
            if (((Extension)res.getValue()).getExtnId().equals(Extension.issuerAlternativeName)) {
                result = res;
                break;
            }
        }

        // Subject Key Identifier found
        assertNotNull(result);

        ext = (Extension)result.getValue();
        assertEquals(Extension.issuerAlternativeName, ((Extension) result.getValue()).getExtnId());
        assertEquals(Result.Decisions.OVERRULED, result.getDecision());
        assertFalse(ext.isCritical());

        // Verify the extension is not changed
        // System.out.print(ASN1Dump.dumpAsString(ext.getParsedValue()));
        GeneralNames generalNames = GeneralNames.getInstance(ext.getParsedValue());
        assertEquals(generalNames.getNames().length, 4);
        boolean ipAddressOK = false;
        boolean eMailsOK = false;
        boolean dNameOK = false;
        boolean urlOK = false;
        for (GeneralName generalName : generalNames.getNames()) {
            if (generalName.getTagNo() == GeneralName.iPAddress) {
                byte[] ipAddress = DEROctetString.getInstance(generalName.getName()).getOctets();
                int ip1 = ipAddress[0] & 0xFF;
                int ip2 = ipAddress[1] & 0xFF;
                int ip3 = ipAddress[2] & 0xFF;
                int ip4 = ipAddress[3] & 0xFF;
                String ip = ip1 + "." + ip2 + "." + ip3 + "." +ip4;
                assertTrue(ip.equals("10.2.3.4"));
                ipAddressOK = true;
            }
            if (generalName.getTagNo() == GeneralName.rfc822Name) {
                String rfc822Name = DERIA5String.getInstance(generalName.getName()).getString();
                assertEquals("ca@cryptable.org", rfc822Name);
                eMailsOK = true;
            }
            if (generalName.getTagNo() == GeneralName.directoryName) {
                X500Name directoryName = X500Name.getInstance(generalName.getName());
                assertEquals(new X500Name("cn=alternative,o=cryptable"), directoryName);
                dNameOK = true;
            }
            if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                String uniformResourceIdentifier = DERIA5String.getInstance(generalName.getName()).getString();
                assertEquals("https://www.cryptable.org", uniformResourceIdentifier);
                urlOK = true;
            }
        }
        assertTrue(ipAddressOK || eMailsOK || dNameOK || urlOK);
    }

    /**
     * Test the normal subject alternative name
     *
     * <Algorithm>SHA-1</Algorithm>
     */
    @Test
    public void testCertificateIssuerAlternaiveNameEmpty() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(3);
        Extension ext;
        Result result = null;


        GeneralNamesBuilder generalNamesBuilder = new GeneralNamesBuilder();
        // rfc822Name                      [1]     IA5String,
        generalNamesBuilder.addName(new GeneralName(GeneralName.rfc822Name, "ca@cryptable.org"));
        // dNSName                         [2]     IA5String,
        generalNamesBuilder.addName(new GeneralName(GeneralName.dNSName, "cryptable.org"));
        // directoryName                   [4]     Name,
        generalNamesBuilder.addName(new GeneralName(GeneralName.directoryName, "cn=alternative,o=cryptable"));
        // uniformResourceIdentifier       [6]     IA5String,
        generalNamesBuilder.addName(new GeneralName(GeneralName.uniformResourceIdentifier, "https://www.cryptable.org"));
        // iPAddress                       [7]     OCTET STRING,
        generalNamesBuilder.addName(new GeneralName(GeneralName.iPAddress, "10.2.3.4"));

        Extension extension = new Extension(Extension.issuerAlternativeName, false, new DEROctetString(generalNamesBuilder.build()));
        Extensions extensions = new Extensions(extension);

        CertTemplate certTemplate = certTemplateBuilder.setExtensions(extensions).build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);

        for (Result res : results) {
            if (((Extension)res.getValue()).getExtnId().equals(Extension.issuerAlternativeName)) {
                result = res;
                break;
            }
        }

        // Subject Key Identifier found
        assertNotNull(result);

        ext = (Extension)result.getValue();
        assertEquals(Extension.issuerAlternativeName, ((Extension) result.getValue()).getExtnId());
        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertFalse(ext.isCritical());

        // Verify the extension is not changed
        // System.out.print(ASN1Dump.dumpAsString(ext.getParsedValue()));
        GeneralNames generalNames = GeneralNames.getInstance(ext.getParsedValue());
        assertEquals(generalNames.getNames().length, 5);
        boolean ipAddressOK = false;
        boolean eMailsOK = false;
        boolean domainNameOK = false;
        boolean dNameOK = false;
        boolean urlOK = false;
        for (GeneralName generalName : generalNames.getNames()) {
            if (generalName.getTagNo() == GeneralName.iPAddress) {
                byte[] ipAddress = DEROctetString.getInstance(generalName.getName()).getOctets();
                int ip1 = ipAddress[0] & 0xFF;
                int ip2 = ipAddress[1] & 0xFF;
                int ip3 = ipAddress[2] & 0xFF;
                int ip4 = ipAddress[3] & 0xFF;
                String ip = ip1 + "." + ip2 + "." + ip3 + "." +ip4;
                assertTrue(ip.equals("10.2.3.4"));
                ipAddressOK = true;
            }
            if (generalName.getTagNo() == GeneralName.rfc822Name) {
                String rfc822Name = DERIA5String.getInstance(generalName.getName()).getString();
                assertEquals("ca@cryptable.org", rfc822Name);
                eMailsOK = true;
            }
            if (generalName.getTagNo() == GeneralName.dNSName) {
                String dNSName = DERIA5String.getInstance(generalName.getName()).getString();
                assertEquals("cryptable.org", dNSName);
                domainNameOK = true;
            }
            if (generalName.getTagNo() == GeneralName.directoryName) {
                X500Name directoryName = X500Name.getInstance(generalName.getName());
                assertEquals(new X500Name("cn=alternative,o=cryptable"), directoryName);
                dNameOK = true;
            }
            if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                String uniformResourceIdentifier = DERIA5String.getInstance(generalName.getName()).getString();
                assertEquals("https://www.cryptable.org", uniformResourceIdentifier);
                urlOK = true;
            }
        }
        assertTrue(ipAddressOK || eMailsOK || dNameOK || domainNameOK || urlOK);
    }

}
