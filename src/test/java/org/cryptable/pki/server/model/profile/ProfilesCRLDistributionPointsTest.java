package org.cryptable.pki.server.model.profile;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.cryptable.pki.server.model.profile.impl.ProfilesJAXB;
import org.cryptable.pki.util.GeneratePKI;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.BitSet;
import java.util.List;
import java.util.Map;

import static org.cryptable.pki.util.ASN1Utils.parseGeneralNames;
import static org.junit.Assert.*;

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 00:27
 */
public class ProfilesCRLDistributionPointsTest {

    final Logger logger = LoggerFactory.getLogger(ProfilesCRLDistributionPointsTest.class);

    static private Profiles profiles;
    private CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();

    static private GeneratePKI generatePKI;

    @BeforeClass
    static public void init() throws CertificateException, CertIOException, NoSuchAlgorithmException, OperatorCreationException, CRLException, NoSuchProviderException, InvalidKeySpecException {
        Security.addProvider(new BouncyCastleProvider());
        generatePKI = new GeneratePKI();
        generatePKI.createPKI();
    }

    @Before
    public void setup() throws JAXBException, IOException, ProfileException, NoSuchAlgorithmException, CertificateEncodingException {
        X509CertificateHolder x509CertificateHolder = new JcaX509CertificateHolder(generatePKI.getCaCert());
        if (profiles == null)
            profiles = new ProfilesJAXB(getClass().getResourceAsStream("/CRLDistributionPoints.xml"), x509CertificateHolder.toASN1Structure());
    }

    /**
     * <CRL_Distribution_Points>
     *   <Distribution_Point Name="Distribution 1">
     *     <E_Mail>ca@cryptable.org</E_Mail>
     *     <IP_Address>10.2.3.4</IP_Address>
     *     <Domain_Name>www.cryptable.org</Domain_Name>
     *     <DName>cn=ca, o=cryptable</DName>
     *     <URL>http://www.google.be</URL>
     *     <Add_Issuer_Name/>
     *     <Reason_Codes>
     *       <Key_Compromise/>
     *       <CA_Compromise/>
     *       <Affiliation_Changed/>
     *       <Superseded/>
     *       <Cessation_Of_Operation/>
     *       <Certificate_On_Hold/>
     *     </Reason_Codes>
     *   </Distribution_Point>
     * </CRL_Distribution_Points>
     */
    @Test
    public void testCRLDistributionPointValid() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(1);

        CertTemplate certTemplate = certTemplateBuilder
            .build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);
        Result result = results.get(0);
        Extension ext = (Extension) result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertEquals(Extension.cRLDistributionPoints, ext.getExtnId());
        assertFalse(ext.isCritical());

        CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(ext.getParsedValue());

        assertEquals(1, crlDistPoint.getDistributionPoints().length);
        DistributionPoint distributionPoint = crlDistPoint.getDistributionPoints()[0];
        assertNotNull(distributionPoint);
        DistributionPointName distributionPointName = distributionPoint.getDistributionPoint();
        assertEquals(DistributionPointName.FULL_NAME, distributionPointName.getType());
        GeneralNames generalNames1 = GeneralNames.getInstance(distributionPointName.getName());
        Map<Integer, String> names1 = parseGeneralNames(generalNames1);
        assertEquals("ca@cryptable.org", names1.get(GeneralName.rfc822Name));
        assertEquals("10.2.3.4", names1.get(GeneralName.iPAddress));
        assertEquals("www.cryptable.org", names1.get(GeneralName.dNSName));
        assertEquals("CN=ca,O=cryptable", names1.get(GeneralName.directoryName));
        assertEquals("http://www.google.be", names1.get(GeneralName.uniformResourceIdentifier));
        GeneralNames generalNames2 = distributionPoint.getCRLIssuer();
        Map<Integer, String> names2 = parseGeneralNames(generalNames2);
        assertEquals(1, names2.size());
        X500Name crlIssuer = JcaX500NameUtil.getSubject(generatePKI.getCaCert());
        assertEquals(crlIssuer.toString(), names2.get(GeneralName.directoryName));
        logger.info("ReasonFlags [" + distributionPoint.getReasons().intValue() + "]");

        int reasonFlags = distributionPoint.getReasons().intValue();
        assertEquals(ReasonFlags.cACompromise, (reasonFlags & ReasonFlags.cACompromise));
        assertEquals(ReasonFlags.keyCompromise, (reasonFlags & ReasonFlags.keyCompromise));
        assertEquals(ReasonFlags.affiliationChanged, (reasonFlags & ReasonFlags.affiliationChanged));
        assertEquals(ReasonFlags.superseded, (reasonFlags & ReasonFlags.superseded));
        assertEquals(ReasonFlags.cessationOfOperation, (reasonFlags & ReasonFlags.cessationOfOperation));
        assertEquals(ReasonFlags.certificateHold, (reasonFlags & ReasonFlags.certificateHold));
        assertNotEquals(ReasonFlags.aACompromise, (reasonFlags & ReasonFlags.aACompromise));
        assertNotEquals(ReasonFlags.privilegeWithdrawn, (reasonFlags & ReasonFlags.privilegeWithdrawn));
        assertNotEquals(ReasonFlags.unused, (reasonFlags & ReasonFlags.unused));
    }

    /**
     * Test a normal CRLDistributionPoints
     *
     * <CRL_Distribution_Points>
     *   <Distribution_Point Name="Distribution 1">
     *     <E_Mail>ca@cryptable.org</E_Mail>
     *     <IP_Address>10.2.3.4</IP_Address>
     *     <Domain_Name>www.cryptable.org</Domain_Name>
     *     <DName>cn=ca, o=cryptable</DName>
     *     <URL>http://www.google.be</URL>
     *     <Add_Issuer_Name/>
     *     <Reason_Codes>
     *       <Key_Compromise/>
     *       <CA_Compromise/>
     *       <Affiliation_Changed/>
     *       <Superseded/>
     *       <Cessation_Of_Operation/>
     *       <Certificate_On_Hold/>
     *     </Reason_Codes>
     *   </Distribution_Point>
     *
     *   <Distribution_Point Name="DistributionPoint 2">
     *     <Relative_DName>/O=Cryptable</Relative_DName>
     *     <Reason_Codes>
     *       <Key_Compromise/>
     *       <Affiliation_Changed/>
     *       <Certificate_On_Hold/>
     *     </Reason_Codes>
     *   </Distribution_Point>
     * </CRL_Distribution_Points>
     */
    @Test
    public void testCRLDistributionPointDouble() throws NoSuchAlgorithmException, IOException, ProfileException {
        Profile profile = profiles.get(2);

        CertTemplate certTemplate = certTemplateBuilder
            .build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);
        Result result = results.get(0);
        Extension ext = (Extension) result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertEquals(Extension.cRLDistributionPoints, ext.getExtnId());
        assertFalse(ext.isCritical());

        CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(ext.getParsedValue());

        assertEquals(2, crlDistPoint.getDistributionPoints().length);
        DistributionPoint distributionPoint1 = crlDistPoint.getDistributionPoints()[0];
        assertNotNull(distributionPoint1);
        DistributionPointName distributionPointName1 = distributionPoint1.getDistributionPoint();
        assertEquals(DistributionPointName.FULL_NAME, distributionPointName1.getType());
        GeneralNames generalNames1 = GeneralNames.getInstance(distributionPointName1.getName());
        Map<Integer, String> names1 = parseGeneralNames(generalNames1);
        assertEquals("ca@cryptable.org", names1.get(GeneralName.rfc822Name));
        assertEquals("10.2.3.4", names1.get(GeneralName.iPAddress));
        assertEquals("www.cryptable.org", names1.get(GeneralName.dNSName));
        assertEquals("CN=ca,O=cryptable", names1.get(GeneralName.directoryName));
        assertEquals("http://www.google.be", names1.get(GeneralName.uniformResourceIdentifier));
        GeneralNames generalNames2 = distributionPoint1.getCRLIssuer();
        Map<Integer, String> names2 = parseGeneralNames(generalNames2);
        assertEquals(1, names2.size());
        X500Name crlIssuer = JcaX500NameUtil.getSubject(generatePKI.getCaCert());
        assertEquals(crlIssuer.toString(), names2.get(GeneralName.directoryName));
        logger.info("ReasonFlags [" + distributionPoint1.getReasons().intValue() + "]");
        int reasonFlags = distributionPoint1.getReasons().intValue();
        assertEquals(ReasonFlags.cACompromise, (reasonFlags & ReasonFlags.cACompromise));
        assertEquals(ReasonFlags.keyCompromise, (reasonFlags & ReasonFlags.keyCompromise));
        assertEquals(ReasonFlags.affiliationChanged, (reasonFlags & ReasonFlags.affiliationChanged));
        assertEquals(ReasonFlags.superseded, (reasonFlags & ReasonFlags.superseded));
        assertEquals(ReasonFlags.cessationOfOperation, (reasonFlags & ReasonFlags.cessationOfOperation));
        assertEquals(ReasonFlags.certificateHold, (reasonFlags & ReasonFlags.certificateHold));
        assertNotEquals(ReasonFlags.aACompromise, (reasonFlags & ReasonFlags.aACompromise));
        assertNotEquals(ReasonFlags.privilegeWithdrawn, (reasonFlags & ReasonFlags.privilegeWithdrawn));
        assertNotEquals(ReasonFlags.unused, (reasonFlags & ReasonFlags.unused));

        DistributionPoint distributionPoint2 = crlDistPoint.getDistributionPoints()[1];
        assertNotNull(distributionPoint2);
        DistributionPointName distributionPointName2 = distributionPoint2.getDistributionPoint();
        assertEquals(DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER, distributionPointName2.getType());
        RDN rdn = RDN.getInstance(distributionPointName2.getName());
        logger.info("RDN oid:   " + rdn.getFirst().getType().toString());
        logger.info("RDN value: " + DERUTF8String.getInstance(rdn.getFirst().getValue()).getString());
        assertNotNull("2.5.4.10", rdn.getFirst().getType().toString());
        assertNotNull("Cryptable", DERUTF8String.getInstance(rdn.getFirst().getValue()).toString());

        logger.info("ReasonFlags [" + distributionPoint2.getReasons().intValue() + "]");
        reasonFlags = distributionPoint2.getReasons().intValue();
        assertNotEquals(ReasonFlags.cACompromise, (reasonFlags & ReasonFlags.cACompromise));
        assertEquals(ReasonFlags.keyCompromise, (reasonFlags & ReasonFlags.keyCompromise));
        assertEquals(ReasonFlags.affiliationChanged, (reasonFlags & ReasonFlags.affiliationChanged));
        assertNotEquals(ReasonFlags.superseded, (reasonFlags & ReasonFlags.superseded));
        assertNotEquals(ReasonFlags.cessationOfOperation, (reasonFlags & ReasonFlags.cessationOfOperation));
        assertEquals(ReasonFlags.certificateHold, (reasonFlags & ReasonFlags.certificateHold));
        assertNotEquals(ReasonFlags.aACompromise, (reasonFlags & ReasonFlags.aACompromise));
        assertNotEquals(ReasonFlags.privilegeWithdrawn, (reasonFlags & ReasonFlags.privilegeWithdrawn));
        assertNotEquals(ReasonFlags.unused, (reasonFlags & ReasonFlags.unused));
    }
}
