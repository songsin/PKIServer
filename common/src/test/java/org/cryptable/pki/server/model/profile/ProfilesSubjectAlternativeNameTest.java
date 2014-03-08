package org.cryptable.pki.server.model.profile;

import junit.framework.Assert;
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
public class ProfilesSubjectAlternativeNameTest {

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
            profiles = new ProfilesJAXB(getClass().getResourceAsStream("/SubjectAlternativeName.xml"), x509CertificateHolder.toASN1Structure());
    }

    private void referenceCertificates() throws IOException {
        // Reference check to a real certificate (non) Bouncycastle
        File file = new File(getClass().getResource("/SubjectAlternativeName_GUID.der").getFile());
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int)file.length()];
        fis.read(data);
        fis.close();
        Certificate certificate = Certificate.getInstance(data);
        Extension ext2 = certificate.getTBSCertificate().getExtensions().getExtension(Extension.subjectAlternativeName);
        System.out.println("Certificate:");
        System.out.print(ASN1Dump.dumpAsString(ext2.getExtnValue(), true));
        ASN1OctetString oct = ext2.getExtnValue();
        ASN1InputStream extIn = new ASN1InputStream(new ByteArrayInputStream(oct.getOctets()));
        GeneralNames decodedGenName = GeneralNames.getInstance(extIn.readObject());
        System.out.println("Subject Alternative name:");
        System.out.print(ASN1Dump.dumpAsString(decodedGenName, true));
    }

    /**
     * Test the normal subject alternative name
     *
     * <Algorithm>SHA-1</Algorithm>
     */
    @Test
    public void testCertificateSubjectAlternaiveNameValid() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(2);
        Extension ext;
        Result result = null;


        GeneralNamesBuilder generalNamesBuilder = new GeneralNamesBuilder();
        // otherName                       [0]     OtherName,
        ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
        asn1EncodableVector.add(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"));
        asn1EncodableVector.add(new DERUTF8String("cn=david, o=cryptable"));
        generalNamesBuilder.addName(new GeneralName(GeneralName.otherName, new DERSequence(asn1EncodableVector)));
        // rfc822Name                      [1]     IA5String,
        generalNamesBuilder.addName(new GeneralName(GeneralName.rfc822Name, "david.tillemans@cryptable.org"));
        // dNSName                         [2]     IA5String,
        generalNamesBuilder.addName(new GeneralName(GeneralName.dNSName, "www.cryptable.org"));
        // directoryName                   [4]     Name,
        generalNamesBuilder.addName(new GeneralName(GeneralName.directoryName, "cn=david, o=cryptable"));
        // uniformResourceIdentifier       [6]     IA5String,
        generalNamesBuilder.addName(new GeneralName(GeneralName.uniformResourceIdentifier, "http://www.cryptable.org"));
        // iPAddress                       [7]     OCTET STRING,
        generalNamesBuilder.addName(new GeneralName(GeneralName.iPAddress, "1.2.3.4"));

        Extension extension = new Extension(Extension.subjectAlternativeName, false, new DEROctetString(generalNamesBuilder.build()));
        Extensions extensions = new Extensions(extension);

        CertTemplate certTemplate = certTemplateBuilder.setExtensions(extensions).build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);

        for (Result res : results) {
            if (((Extension)res.getValue()).getExtnId().equals(Extension.subjectAlternativeName)) {
                result = res;
                break;
            }
        }

        // Subject Key Identifier found
        assertNotNull(result);

        ext = (Extension)result.getValue();
        assertEquals(Extension.subjectAlternativeName, ((Extension) result.getValue()).getExtnId());
        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertFalse(ext.isCritical());

        // Verify the extension is not changed
        // System.out.print(ASN1Dump.dumpAsString(ext.getParsedValue()));
        GeneralNames generalNames = GeneralNames.getInstance(ext.getParsedValue());
        assertEquals(generalNames.getNames().length, 6);
        for (GeneralName generalName : generalNames.getNames()) {
            if (generalName.getTagNo() == GeneralName.otherName) {
                assertTrue(generalName.getName().equals(new DERSequence(asn1EncodableVector)));
            }
            if (generalName.getTagNo() == GeneralName.iPAddress) {
                byte[] ipAddress = DEROctetString.getInstance(generalName.getName()).getOctets();
                int ip1 = ipAddress[0] & 0xFF;
                int ip2 = ipAddress[1] & 0xFF;
                int ip3 = ipAddress[2] & 0xFF;
                int ip4 = ipAddress[3] & 0xFF;
                String ip = ip1 + "." + ip2 + "." + ip3 + "." +ip4;
                assertTrue(ip.equals("1.2.3.4"));
            }
            if (generalName.getTagNo() == GeneralName.rfc822Name) {
                String rfc822Name = DERIA5String.getInstance(generalName.getName()).getString();
                assertEquals("david.tillemans@cryptable.org", rfc822Name);
            }
            if (generalName.getTagNo() == GeneralName.directoryName) {
                X500Name directoryName = X500Name.getInstance(generalName.getName());
                assertEquals(new X500Name("cn=david, o=cryptable"), directoryName);
            }
            if (generalName.getTagNo() == GeneralName.dNSName) {
                String dNSName = DERIA5String.getInstance(generalName.getName()).getString();
                assertEquals("www.cryptable.org", dNSName);
            }
            if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                String uniformResourceIdentifier = DERIA5String.getInstance(generalName.getName()).getString();
                assertEquals("http://www.cryptable.org", uniformResourceIdentifier);
            }
        }
    }

    /**
     * Test the normal subject alternative name
     *
     * <Algorithm>SHA-1</Algorithm>
     */
    @Test
    public void testCertificateSubjectAlternaiveNameOverruled() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(1);
        Extension ext;
        Result result = null;


        GeneralNamesBuilder generalNamesBuilder = new GeneralNamesBuilder();

        // Domain controller GUID
        ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
        asn1EncodableVector.add(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.25.1"));
        UUID uuid = UUID.fromString("020002b6-7f41-456b-9b8f-2f50862b60c0");
        ByteBuffer byteBuffer = ByteBuffer.wrap(new byte[16]);
        byteBuffer.putLong(uuid.getMostSignificantBits()).putLong(uuid.getLeastSignificantBits());
        asn1EncodableVector.add(new DEROctetString(byteBuffer.array()));

        // otherName                       [0]     OtherName,
        generalNamesBuilder.addName(new GeneralName(GeneralName.otherName, new DERSequence(asn1EncodableVector)));
        // rfc822Name                      [1]     IA5String,
        generalNamesBuilder.addName(new GeneralName(GeneralName.rfc822Name, "david.tillemans@cryptable.org"));
        // dNSName                         [2]     IA5String,
        generalNamesBuilder.addName(new GeneralName(GeneralName.dNSName, "www.cryptable.org"));
        // directoryName                   [4]     Name,
        generalNamesBuilder.addName(new GeneralName(GeneralName.directoryName, "cn=david, o=cryptable"));
        // uniformResourceIdentifier       [6]     IA5String,
        generalNamesBuilder.addName(new GeneralName(GeneralName.uniformResourceIdentifier, "http://www.cryptable.org"));
        // iPAddress                       [7]     OCTET STRING,
        generalNamesBuilder.addName(new GeneralName(GeneralName.iPAddress, "1.2.3.4"));

        Extension extension = new Extension(Extension.subjectAlternativeName, false, new DEROctetString(generalNamesBuilder.build()));
        Extensions extensions = new Extensions(extension);

        CertTemplate certTemplate = certTemplateBuilder.setExtensions(extensions).build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);

        for (Result res : results) {
            if (((Extension)res.getValue()).getExtnId().equals(Extension.subjectAlternativeName)) {
                result = res;
                break;
            }
        }

        // Subject Key Identifier found
        assertNotNull(result);

        ext = (Extension)result.getValue();
        assertEquals(Extension.subjectAlternativeName, ((Extension) result.getValue()).getExtnId());
        assertEquals(Result.Decisions.OVERRULED, result.getDecision());
        assertFalse(ext.isCritical());

        // Verify the extension is not changed
        // System.out.print(ASN1Dump.dumpAsString(ext.getParsedValue()));
        GeneralNames generalNames = GeneralNames.getInstance(ext.getParsedValue());
        assertEquals(generalNames.getNames().length, 4);
        for (GeneralName generalName : generalNames.getNames()) {
            if (generalName.getTagNo() == GeneralName.otherName) {
                assertTrue(generalName.getName().equals(new DERSequence(asn1EncodableVector)));
            }
            if (generalName.getTagNo() == GeneralName.iPAddress) {
                assertTrue(false);

            }
            if (generalName.getTagNo() == GeneralName.rfc822Name) {
                String rfc822Name = DERIA5String.getInstance(generalName.getName()).getString();
                assertTrue(rfc822Name.equals("david.tillemans@cryptable.org"));
            }
            if (generalName.getTagNo() == GeneralName.directoryName) {
                assertTrue(false);
            }
            if (generalName.getTagNo() == GeneralName.dNSName) {
                String dNSName = DERIA5String.getInstance(generalName.getName()).getString();
                assertEquals("www.cryptable.org", dNSName);
            }
            if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                String uniformResourceIdentifier = DERIA5String.getInstance(generalName.getName()).getString();
                assertEquals("http://www.cryptable.org", uniformResourceIdentifier);
            }
        }
    }

    /**
     * Test the normal subject alternative name
     *
     * <Algorithm>SHA-1</Algorithm>
     */
    @Test
    public void testCertificateSubjectAlternaiveNameEmpty() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(3);
        Extension ext;
        Result result = null;


        GeneralNamesBuilder generalNamesBuilder = new GeneralNamesBuilder();

        // Domain controller GUID
        ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
        asn1EncodableVector.add(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.25.1"));
        UUID uuid = UUID.fromString("020002b6-7f41-456b-9b8f-2f50862b60c0");
        ByteBuffer byteBuffer = ByteBuffer.wrap(new byte[16]);
        byteBuffer.putLong(uuid.getMostSignificantBits()).putLong(uuid.getLeastSignificantBits());
        asn1EncodableVector.add(new DEROctetString(byteBuffer.array()));

        generalNamesBuilder.addName(new GeneralName(GeneralName.otherName, new DERSequence(asn1EncodableVector)));
        generalNamesBuilder.addName(new GeneralName(GeneralName.iPAddress, "1.2.3.4"));
        generalNamesBuilder.addName(new GeneralName(GeneralName.rfc822Name, "david.tillemans@cryptable.org"));
        generalNamesBuilder.addName(new GeneralName(GeneralName.directoryName, "cn=david, o=cryptable"));
        generalNamesBuilder.addName(new GeneralName(GeneralName.dNSName, "www.cryptable.org"));
        generalNamesBuilder.addName(new GeneralName(GeneralName.uniformResourceIdentifier, "http://www.cryptable.org"));

        Extension extension = new Extension(Extension.subjectAlternativeName, false, new DEROctetString(generalNamesBuilder.build()));
        Extensions extensions = new Extensions(extension);

        CertTemplate certTemplate = certTemplateBuilder.setExtensions(extensions).build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);

        for (Result res : results) {
            if (((Extension)res.getValue()).getExtnId().equals(Extension.subjectAlternativeName)) {
                result = res;
                break;
            }
        }

        // Subject Key Identifier found
        assertNotNull(result);

        ext = (Extension)result.getValue();
        assertEquals(Extension.subjectAlternativeName, ((Extension) result.getValue()).getExtnId());
        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertFalse(ext.isCritical());

        // Verify the extension is not changed
        // System.out.print(ASN1Dump.dumpAsString(ext.getParsedValue()));
        GeneralNames generalNames = GeneralNames.getInstance(ext.getParsedValue());
        assertEquals(generalNames.getNames().length, 6);
        for (GeneralName generalName : generalNames.getNames()) {
            if (generalName.getTagNo() == GeneralName.otherName) {
                assertTrue(generalName.getName().equals(new DERSequence(asn1EncodableVector)));
            }
            if (generalName.getTagNo() == GeneralName.iPAddress) {
                byte[] ipAddress = DEROctetString.getInstance(generalName.getName()).getOctets();
                int ip1 = ipAddress[0] & 0xFF;
                int ip2 = ipAddress[1] & 0xFF;
                int ip3 = ipAddress[2] & 0xFF;
                int ip4 = ipAddress[3] & 0xFF;
                String ip = ip1 + "." + ip2 + "." + ip3 + "." +ip4;
                assertTrue(ip.equals("1.2.3.4"));
            }
            if (generalName.getTagNo() == GeneralName.rfc822Name) {
                String rfc822Name = DERIA5String.getInstance(generalName.getName()).getString();
                assertEquals("david.tillemans@cryptable.org", rfc822Name);
            }
            if (generalName.getTagNo() == GeneralName.directoryName) {
                X500Name directoryName = X500Name.getInstance(generalName.getName());
                assertEquals(new X500Name("cn=david, o=cryptable"), directoryName);
            }
            if (generalName.getTagNo() == GeneralName.dNSName) {
                String dNSName = DERIA5String.getInstance(generalName.getName()).getString();
                assertEquals("www.cryptable.org", dNSName);
            }
            if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                String uniformResourceIdentifier = DERIA5String.getInstance(generalName.getName()).getString();
                assertEquals("http://www.cryptable.org", uniformResourceIdentifier);
            }
        }
    }
}
