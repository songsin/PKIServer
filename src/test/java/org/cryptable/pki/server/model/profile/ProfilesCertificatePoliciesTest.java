package org.cryptable.pki.server.model.profile;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
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
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

import static junit.framework.Assert.assertNotNull;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertNull;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 00:27
 */
public class ProfilesCertificatePoliciesTest {

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
            profiles = new ProfilesJAXB(getClass().getResourceAsStream("/CertificatePolicies.xml"), x509CertificateHolder.toASN1Structure());

   }

    /**
     * Test a normal Certificate policy
     *
     * <Certificate_Policies Critical="Yes">
     *   <Certificate_Policy OID="1.2.3.4.1.2.3.4.1">
     *     <Qualifier ID="1.3.6.1.5.5.7.2.1">
     *       <URI>https://www.google.be</URI>
     *     </Qualifier>
     *     <Qualifier ID="1.3.6.1.5.5.7.2.2">
     *       <Organisation>Cryptable</Organisation>
     *       <Notice_Numbers>11,23,44</Notice_Numbers>
     *       <Explicit_Text>This is a test certificate</Explicit_Text>
     *     </Qualifier>
     *   </Certificate_Policy>
     *   <Certificate_Policy OID="2.3.4.2.4.5.1">
     *     <Qualifier ID="1.3.6.1.5.5.7.2.1">
     *       <URI>http://www.cryptable.org/cps.pdf</URI>
     *     </Qualifier>
     *   </Certificate_Policy>
     * </Certificate_Policies>
     */
    @Test
    public void testCertificatePoliciesValid() throws ProfileException, IOException, NoSuchAlgorithmException, CertificateEncodingException {
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
            if (((Extension)res.getValue()).getExtnId().equals(Extension.certificatePolicies)) {
                result = res;
            }
        }

        // Certificate Policies Identifier found
        assertNotNull(result);

        ext = (Extension)result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertTrue(ext.isCritical());


        File file = new File(getClass().getResource("/CertificatePolicies.der").getFile());
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int)file.length()];
        fis.read(data);
        fis.close();
        Certificate certificate = Certificate.getInstance(data);
        String policyOID1 = "1.2.3.4.1.2.3.4.1";
        String policyOID2 = "2.3.4.2.4.5.1";

        boolean bQualifier1_1 = false;
        boolean bQualifier1_2 = false;
        boolean bQualifier2_1 = false;

        CertificatePolicies certificatePoliciesRef = CertificatePolicies.fromExtensions(certificate.getTBSCertificate().getExtensions());
        CertificatePolicies certificatePoliciesTst = CertificatePolicies.getInstance(ext.getParsedValue());
        for (PolicyInformation policyInformationRef : certificatePoliciesRef.getPolicyInformation()) {
            PolicyInformation policyInformationTst = certificatePoliciesTst.getPolicyInformation(policyInformationRef.getPolicyIdentifier());
            if (policyInformationTst.getPolicyIdentifier().getId().equals(policyOID1)) {
                for (ASN1Encodable asn1EncodableRef : policyInformationRef.getPolicyQualifiers().toArray()) {
                    PolicyQualifierInfo policyQualifierInfoRef = PolicyQualifierInfo.getInstance(asn1EncodableRef);
                    for (ASN1Encodable asn1EncodableTst : policyInformationTst.getPolicyQualifiers().toArray()) {
                        PolicyQualifierInfo policyQualifierInfoTst = PolicyQualifierInfo.getInstance(asn1EncodableTst);
                        if (policyQualifierInfoRef.getPolicyQualifierId().getId().equals(policyQualifierInfoTst.getPolicyQualifierId().getId())) {
                            if  (policyQualifierInfoRef.getPolicyQualifierId().getId().equals("1.3.6.1.5.5.7.2.1") &&
                                DERIA5String.getInstance(policyQualifierInfoTst.getQualifier()).getString().equals("https://www.google.be")) {
                                bQualifier1_1 = true;
                            }
                            else if (policyQualifierInfoRef.getPolicyQualifierId().getId().equals("1.3.6.1.5.5.7.2.2")) {
                                UserNotice userNotice = UserNotice.getInstance(policyQualifierInfoTst.getQualifier());
                                if (userNotice.getExplicitText().getString().equals("This is a test certificate") &&
                                    userNotice.getNoticeRef().getOrganization().getString().equals("Cryptable")) {
                                    bQualifier1_2 = true;
                                }
                            }
                        }
                    }
                }
            }
            else if (policyInformationTst.getPolicyIdentifier().getId().equals(policyOID2)) {
                for (ASN1Encodable asn1EncodableRef : policyInformationRef.getPolicyQualifiers().toArray()) {
                    PolicyQualifierInfo policyQualifierInfoRef = PolicyQualifierInfo.getInstance(asn1EncodableRef);
                    for (ASN1Encodable asn1EncodableTst : policyInformationTst.getPolicyQualifiers().toArray()) {
                        PolicyQualifierInfo policyQualifierInfoTst = PolicyQualifierInfo.getInstance(asn1EncodableTst);
                        if (policyQualifierInfoRef.getPolicyQualifierId().getId().equals(policyQualifierInfoTst.getPolicyQualifierId().getId())) {
                            if  (policyQualifierInfoRef.getPolicyQualifierId().getId().equals("1.3.6.1.5.5.7.2.1") &&
                                DERIA5String.getInstance(policyQualifierInfoTst.getQualifier()).getString().equals("http://www.cryptable.org/cps.pdf")) {
                                bQualifier2_1 = true;
                            }
                        }
                    }
                }
            }
            else {
                assertTrue(false);
            }
        }

        assertTrue(bQualifier1_1);
        assertTrue(bQualifier1_2);
        assertTrue(bQualifier2_1);
    }

    /**
     * Test a normal 1 Certificate policy and overrule
     *
     * <Subject_Key_Identifier>160 bit SHA-1</Subject_Key_Identifier>
     */
    @Test
    public void testCertificatePoliciesOverruled() throws ProfileException, IOException, NoSuchAlgorithmException, CertificateEncodingException {
        Profile profile = profiles.get(2);
        Extension ext = null;
        Result result = null;

        List<PolicyInformation> policyInformationList = new ArrayList<PolicyInformation>();

        ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
        PolicyQualifierInfo policyQualifierInfo = null;
        Vector<Integer> noticeNumbers = new Vector<Integer>();
        noticeNumbers.add(1);
        noticeNumbers.add(2);
        noticeNumbers.add(3);
        noticeNumbers.add(4);
        noticeNumbers.add(5);
        policyQualifierInfo = new PolicyQualifierInfo(PolicyQualifierId.id_qt_unotice,
                            (new UserNotice(new NoticeReference( "Koekoek Co", noticeNumbers), "Explicit Text")).toASN1Primitive());
        asn1EncodableVector.add(policyQualifierInfo);
        policyQualifierInfo = new PolicyQualifierInfo("http://www.cryptable.org");
        asn1EncodableVector.add(policyQualifierInfo);
        PolicyInformation policyInformation = new PolicyInformation(new ASN1ObjectIdentifier("1.2.3.4.5.6.7.8.1"),
                    new DERSequence(asn1EncodableVector));
        policyInformationList.add(policyInformation);

        policyInformation = new PolicyInformation(new ASN1ObjectIdentifier("1.2.3.4.5.6.7.8.2"));
        policyInformationList.add(policyInformation);

        PolicyInformation[] policyInformations = new PolicyInformation[policyInformationList.size()];
        Extension extension = new Extension(Extension.certificatePolicies, true,
            new DEROctetString(new CertificatePolicies(policyInformationList.toArray(policyInformations))));

        Extensions extensions = new Extensions(extension);
        CertTemplate certTemplate = certTemplateBuilder.setExtensions(extensions).build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);

        for (Result res : results) {
            if (((Extension)res.getValue()).getExtnId().equals(Extension.certificatePolicies)) {
                result = res;
            }
        }

        // Certificate Policies Identifier found
        assertNotNull(result);

        ext = (Extension)result.getValue();

        assertEquals(Result.Decisions.OVERRULED, result.getDecision());
        assertFalse(ext.isCritical());


        String policyOID1 = "1.2.3.4.1.2.3.4.1";
        boolean bQualifier1_1 = false;
        boolean bQualifier1_2 = false;

        CertificatePolicies certificatePoliciesTst = CertificatePolicies.getInstance(ext.getParsedValue());
        for (PolicyInformation policyInformationTst : certificatePoliciesTst.getPolicyInformation()) {
            if (policyInformationTst.getPolicyIdentifier().getId().equals(policyOID1)) {
                for (ASN1Encodable asn1EncodableTst : policyInformationTst.getPolicyQualifiers().toArray()) {
                    PolicyQualifierInfo policyQualifierInfoTst = PolicyQualifierInfo.getInstance(asn1EncodableTst);
                    if (policyQualifierInfoTst.getPolicyQualifierId().getId().equals("1.3.6.1.5.5.7.2.1") &&
                        DERIA5String.getInstance(policyQualifierInfoTst.getQualifier()).getString().equals("https://www.google.be")) {
                        bQualifier1_1 = true;
                    } else if (policyQualifierInfoTst.getPolicyQualifierId().getId().equals("1.3.6.1.5.5.7.2.2")) {
                        UserNotice userNotice = UserNotice.getInstance(policyQualifierInfoTst.getQualifier());
                        if (userNotice.getExplicitText().getString().equals("This is a test certificate") &&
                            userNotice.getNoticeRef().getOrganization().getString().equals("Cryptable")) {
                            bQualifier1_2 = true;
                        }
                    }

                }

            }  else {
                assertTrue(false);
            }
        }

        assertTrue(bQualifier1_1);
        assertTrue(bQualifier1_2);
    }

    /**
     * Test a normal 1 Certificate policy and no overrule with empty profile settings
     *
     * <Subject_Key_Identifier>160 bit SHA-1</Subject_Key_Identifier>
     */
    @Test
    public void testCertificatePoliciesEmpty() throws ProfileException, IOException, NoSuchAlgorithmException, CertificateEncodingException {
        Profile profile = profiles.get(3);
        Extension ext = null;
        Result result = null;

        List<PolicyInformation> policyInformationList = new ArrayList<PolicyInformation>();

        ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
        PolicyQualifierInfo policyQualifierInfo = null;
        Vector<Integer> noticeNumbers = new Vector<Integer>();
        noticeNumbers.add(1);
        noticeNumbers.add(2);
        noticeNumbers.add(3);
        noticeNumbers.add(4);
        noticeNumbers.add(5);
        policyQualifierInfo = new PolicyQualifierInfo(PolicyQualifierId.id_qt_unotice,
            (new UserNotice(new NoticeReference( "Koekoek Co", noticeNumbers), "Explicit Text")).toASN1Primitive());
        asn1EncodableVector.add(policyQualifierInfo);
        policyQualifierInfo = new PolicyQualifierInfo("http://www.cryptable.org");
        asn1EncodableVector.add(policyQualifierInfo);
        PolicyInformation policyInformation = new PolicyInformation(new ASN1ObjectIdentifier("1.2.3.4.5.6.7.8.1"),
            new DERSequence(asn1EncodableVector));
        policyInformationList.add(policyInformation);

        policyInformation = new PolicyInformation(new ASN1ObjectIdentifier("1.2.3.4.5.6.7.8.2"));
        policyInformationList.add(policyInformation);

        PolicyInformation[] policyInformations = new PolicyInformation[policyInformationList.size()];
        Extension extension = new Extension(Extension.certificatePolicies, true,
            new DEROctetString(new CertificatePolicies(policyInformationList.toArray(policyInformations))));

        Extensions extensions = new Extensions(extension);
        CertTemplate certTemplate = certTemplateBuilder.setExtensions(extensions).build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);

        for (Result res : results) {
            if (((Extension)res.getValue()).getExtnId().equals(Extension.certificatePolicies)) {
                result = res;
            }
        }

        // Certificate Policies Identifier found
        assertNotNull(result);

        ext = (Extension)result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertTrue(ext.isCritical());


        String policyOID1 = "1.2.3.4.5.6.7.8.1";
        String policyOID2 = "1.2.3.4.5.6.7.8.2";
        boolean bQualifier1_1 = false;
        boolean bQualifier1_2 = false;

        CertificatePolicies certificatePoliciesTst = CertificatePolicies.getInstance(ext.getParsedValue());
        for (PolicyInformation policyInformationTst : certificatePoliciesTst.getPolicyInformation()) {
            if (policyInformationTst.getPolicyIdentifier().getId().equals(policyOID1)) {
                for (ASN1Encodable asn1EncodableTst : policyInformationTst.getPolicyQualifiers().toArray()) {
                    PolicyQualifierInfo policyQualifierInfoTst = PolicyQualifierInfo.getInstance(asn1EncodableTst);
                    if (policyQualifierInfoTst.getPolicyQualifierId().getId().equals("1.3.6.1.5.5.7.2.1") &&
                        DERIA5String.getInstance(policyQualifierInfoTst.getQualifier()).getString().equals("http://www.cryptable.org")) {
                        bQualifier1_1 = true;
                    } else if (policyQualifierInfoTst.getPolicyQualifierId().getId().equals("1.3.6.1.5.5.7.2.2")) {
                        UserNotice userNotice = UserNotice.getInstance(policyQualifierInfoTst.getQualifier());
                        if (userNotice.getExplicitText().getString().equals("Explicit Text") &&
                            userNotice.getNoticeRef().getOrganization().getString().equals("Koekoek Co")) {
                            bQualifier1_2 = true;
                        }
                    }

                }

            }
            else if (policyInformationTst.getPolicyIdentifier().getId().equals(policyOID2)) {
                assertNull(policyInformationTst.getPolicyQualifiers());
            }
            else {
                assertTrue(false);
            }
        }

        assertTrue(bQualifier1_1);
        assertTrue(bQualifier1_2);
    }

}
