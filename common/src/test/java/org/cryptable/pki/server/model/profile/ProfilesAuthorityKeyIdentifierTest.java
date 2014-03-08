package org.cryptable.pki.server.model.profile;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.cryptable.pki.server.model.profile.impl.ProfilesJAXB;
import org.cryptable.pki.util.GeneratePKI;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.xml.bind.JAXBException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

import static junit.framework.Assert.assertNotNull;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 00:27
 */
public class ProfilesAuthorityKeyIdentifierTest {

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
    public void setup() throws JAXBException, IOException, ProfileException, InvalidKeySpecException, NoSuchProviderException, NoSuchAlgorithmException, CertificateEncodingException {
        X509CertificateHolder x509CertificateHolder = new JcaX509CertificateHolder(generatePKI.getCaCert());
        if (profiles == null)
            profiles = new ProfilesJAXB(getClass().getResourceAsStream("/AuthorityKeyIdentifier.xml"), x509CertificateHolder.toASN1Structure());

   }

    /**
     * Test a normal SHA1 Subject Key Identifier. Template has no SHA1 extension
     *
     * <Subject_Key_Identifier>160 bit SHA-1</Subject_Key_Identifier>
     */
    @Test
    public void testCertificateAuthorityKeyIdentifierValid() throws ProfileException, IOException, NoSuchAlgorithmException, CertificateEncodingException {
        Profile profile = profiles.get(1);
        Extension ext = null;
        Result result = null;

        X509CertificateHolder x509CertificateHolder = new JcaX509CertificateHolder(generatePKI.getCaCert());
        Extension extension = new Extension(Extension.authorityKeyIdentifier, false,
            new DEROctetString(new AuthorityKeyIdentifier(new GeneralNames(new GeneralName(x509CertificateHolder.getIssuer())),
                x509CertificateHolder.getSerialNumber())));

        Extensions extensions = new Extensions(extension);
        CertTemplate certTemplate = certTemplateBuilder.setExtensions(extensions).build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);

        for (Result res : results) {
            if (((Extension)res.getValue()).getExtnId().equals(Extension.authorityKeyIdentifier)) {
                result = res;
            }
        }

        // Subject Key Identifier found
        assertNotNull(result);

        ext = (Extension)result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertFalse(ext.isCritical());

        // Verify the extension is not changed
        assertTrue(extension.equals(ext));

        // Reference check to a real certificate (non) Bouncycastle
//        System.out.print(ASN1Dump.dumpAsString(ext.getExtnValue(), true));

//        File file = new File(getClass().getResource("/TestCert.der").getFile());
//        FileInputStream fis = new FileInputStream(file);
//        byte[] data = new byte[(int)file.length()];
//        fis.read(data);
//        fis.close();
//        Certificate certificate = Certificate.getInstance(data);
//        Extension ext2 = certificate.getTBSCertificate().getExtensions().getExtension(Extension.subjectKeyIdentifier);
//        System.out.println("Certificate:");
//        System.out.print(ASN1Dump.dumpAsString(ext2.getExtnValue(), true));
    }

    /**
     * Test a normal SHA1 Subject Key Identifier. Template has no SHA1 extension
     *
     * <Subject_Key_Identifier>160 bit SHA-1</Subject_Key_Identifier>
     */
    @Test
    public void testCertificateAuthorityKeyIdentifierSHA() throws ProfileException, IOException, NoSuchAlgorithmException, CertificateEncodingException {
        Profile profile = profiles.get(2);
        Extension ext = null;
        Result result = null;

        X509CertificateHolder x509CertificateHolder = new JcaX509CertificateHolder(generatePKI.getCaCert());
        SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.fromExtensions(x509CertificateHolder.getExtensions());
        Extension extension = new Extension(Extension.authorityKeyIdentifier, false,
            new DEROctetString(new AuthorityKeyIdentifier(subjectKeyIdentifier.getKeyIdentifier())));

        Extensions extensions = new Extensions(extension);
        CertTemplate certTemplate = certTemplateBuilder.setExtensions(extensions).build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);

        for (Result res : results) {
            if (((Extension)res.getValue()).getExtnId().equals(Extension.authorityKeyIdentifier)) {
                result = res;
            }
        }

        // Subject Key Identifier found
        assertNotNull(result);

        ext = (Extension)result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertFalse(ext.isCritical());

        // Verify the extension is not changed
        assertTrue(extension.equals(ext));

        // System.out.print(ASN1Dump.dumpAsString(ext.getExtnValue(), true));

    }

    /**
     * Test a normal SHA1 Subject Key Identifier. No entry in the file
     *
     * <Subject_Key_Identifier>160 bit SHA-1</Subject_Key_Identifier>
     */
    @Test
    public void testCertificateAuthorityKeyIdentifierNoEntry() throws ProfileException, IOException, NoSuchAlgorithmException, CertificateEncodingException {
        Profile profile = profiles.get(3);
        Extension ext = null;
        Result result = null;

        X509CertificateHolder x509CertificateHolder = new JcaX509CertificateHolder(generatePKI.getCaCert());
        SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.fromExtensions(x509CertificateHolder.getExtensions());
        Extension extension = new Extension(Extension.authorityKeyIdentifier, false,
            new DEROctetString(new AuthorityKeyIdentifier(subjectKeyIdentifier.getKeyIdentifier())));

        Extensions extensions = new Extensions(extension);
        CertTemplate certTemplate = certTemplateBuilder.setExtensions(extensions).build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);

        for (Result res : results) {
            if (((Extension)res.getValue()).getExtnId().equals(Extension.authorityKeyIdentifier)) {
                result = res;
            }
        }

        // Subject Key Identifier found
        assertNotNull(result);

        ext = (Extension)result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertFalse(ext.isCritical());

        // Verify the extension is not changed
        assertTrue(extension.equals(ext));

        // System.out.print(ASN1Dump.dumpAsString(ext.getExtnValue(), true));

    }

    /**
     * Test a normal SHA1 Subject Key Identifier with overrule to issuer and DN.
     *
     * <Subject_Key_Identifier>160 bit SHA-1</Subject_Key_Identifier>
     */
    @Test
    public void testCertificateAuthorityKeyIdentifierOverrule() throws ProfileException, IOException, NoSuchAlgorithmException, CertificateEncodingException {
        Profile profile = profiles.get(1);
        Extension ext = null;
        Result result = null;

        X509CertificateHolder x509CertificateHolder = new JcaX509CertificateHolder(generatePKI.getCaCert());
        SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.fromExtensions(x509CertificateHolder.getExtensions());
        Extension extension = new Extension(Extension.authorityKeyIdentifier, false,
            new DEROctetString(new AuthorityKeyIdentifier(subjectKeyIdentifier.getKeyIdentifier())));

        Extensions extensions = new Extensions(extension);
        CertTemplate certTemplate = certTemplateBuilder.setExtensions(extensions).build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);

        for (Result res : results) {
            if (((Extension)res.getValue()).getExtnId().equals(Extension.authorityKeyIdentifier)) {
                result = res;
            }
        }

        // Subject Key Identifier found
        assertNotNull(result);

        ext = (Extension)result.getValue();

        assertEquals(Result.Decisions.OVERRULED, result.getDecision());
        assertFalse(ext.isCritical());

        // Verify the extension is not changed
        Extension extRef = new Extension(Extension.authorityKeyIdentifier, false,
            new DEROctetString(new AuthorityKeyIdentifier(new GeneralNames(new GeneralName(x509CertificateHolder.getIssuer())),
                x509CertificateHolder.getSerialNumber())));
        assertTrue(extRef.equals(ext));

        // System.out.print(ASN1Dump.dumpAsString(ext.getExtnValue(), true));

    }
}
