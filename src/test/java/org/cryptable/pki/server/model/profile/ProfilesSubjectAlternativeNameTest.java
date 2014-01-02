package org.cryptable.pki.server.model.profile;

import junit.framework.Assert;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.util.ASN1Dump;
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
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
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

    /**
     * Test the normal subject alternative name
     *
     * <Algorithm>SHA-1</Algorithm>
     */
    @Test
    public void testCertificateAlgorithmValidSHA1() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(1);
        Extension ext;
        Result result = null;

        GeneralNamesBuilder generalNamesBuilder = new GeneralNamesBuilder();

        generalNamesBuilder.addName(new GeneralName(GeneralName.otherName, new DERIA5String("www.google.be")));
        generalNamesBuilder.addName(new GeneralName(GeneralName.iPAddress, "10.1.1.10"));
        generalNamesBuilder.addName(new GeneralName(GeneralName.rfc822Name, "david.tillemans@cryptable.org"));
        generalNamesBuilder.addName(new GeneralName(GeneralName.directoryName, "cn=david, o=cryptable"));
        generalNamesBuilder.addName(new GeneralName(GeneralName.dNSName, "www.cryptable.org"));
        // generalNamesBuilder.addName(new GeneralName(GeneralName.ediPartyName, "EDI://cryptable:internet:google"));
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
        System.out.print(ASN1Dump.dumpAsString(ext.getParsedValue()));
        GeneralNames generalNames = GeneralNames.getInstance(ext.getParsedValue());
        assertEquals(generalNames.getNames().length, 6);
        for (GeneralName generalName : generalNames.getNames()) {
            if (generalName.getTagNo() == GeneralName.otherName) {
                assertTrue(DERIA5String.getInstance(generalName.getName()).getString().equals("www.google.be"));
            }
            if (generalName.getTagNo() == GeneralName.iPAddress) {
                assertTrue(DERIA5String.getInstance(generalName.getName()).getString().equals("10.1.1.10"));
            }
            if (generalName.getTagNo() == GeneralName.rfc822Name) {
                assertTrue(DERIA5String.getInstance(generalName.getName()).getString().equals("david.tillemans@cryptable.org"));
            }
            if (generalName.getTagNo() == GeneralName.directoryName) {
                assertTrue(DERIA5String.getInstance(generalName.getName()).getString().equals("cn=david, o=cryptable"));
            }
            if (generalName.getTagNo() == GeneralName.dNSName) {
                assertTrue(DERIA5String.getInstance(generalName.getName()).getString().equals("www.cryptable.org"));
            }
            if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                assertTrue(DERIA5String.getInstance(generalName.getName()).getString().equals("http://www.cryptable.org"));
            }
        }
        // System.out.print(ASN1Dump.dumpAsString(ext.getExtnValue(), true));
    }

}
