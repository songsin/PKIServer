package org.cryptable.pki.server.model.profile;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.SemanticsInformation;
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
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNull;
import static org.junit.Assert.*;

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 00:27
 */
public class ProfilesQualifiedStatementTest {

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
            profiles = new ProfilesJAXB(getClass().getResourceAsStream("/QualifiedStatement.xml"), x509CertificateHolder.toASN1Structure());
    }

    /**
     * Test a normal qualified statement situation.
     *
     * <Qualified_Statements>
     *   <Issue_Qualified_Statement/>
     *   <Liability_Limit>
     *     <Amount>10000</Amount>
     *     <Exponent>1</Exponent>
     *     <Currency_Code>978</Currency_Code>
     *   </Liability_Limit>
     *   <Retention_Period>30</Retention_Period>
     *   <Semantic_ID>11</Semantic_ID>
     *   <Registration_Agents>
     *     <DName>cn=RA1, o=Cryptable, c=be</DName>
     *     <DName>cn=RA2, o=Cryptable, c=be</DName>
     *   </Registration_Agents>
     * </Qualified_Statements>
     */
    @Test
    public void testQualifiedStatementValid() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(1);

        CertTemplate certTemplate = certTemplateBuilder
            .build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);
        Result result = results.get(0);
        Extension ext = (Extension) result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertEquals(Extension.qCStatements, ext.getExtnId());
        assertFalse(ext.isCritical());

        ASN1Sequence qcStatements = ASN1Sequence.getInstance(ext.getParsedValue());

        assertEquals(4, qcStatements.size());
        QCStatement qcStatement = QCStatement.getInstance(qcStatements.getObjectAt(0));
        assertEquals(QCStatement.id_etsi_qcs_QcCompliance, qcStatement.getStatementId());
        qcStatement = QCStatement.getInstance(qcStatements.getObjectAt(1));
        assertEquals(QCStatement.id_etsi_qcs_LimiteValue, qcStatement.getStatementId());
        MonetaryValue monetaryValue = MonetaryValue.getInstance(qcStatement.getStatementInfo());
        assertEquals(BigInteger.valueOf(10000), monetaryValue.getAmount());
        assertEquals(BigInteger.valueOf(1), monetaryValue.getExponent());
        assertEquals(978 ,monetaryValue.getCurrency().getNumeric());
        qcStatement = QCStatement.getInstance(qcStatements.getObjectAt(2));
        assertEquals(QCStatement.id_etsi_qcs_RetentionPeriod, qcStatement.getStatementId());
        ASN1Integer retentionPeriod = ASN1Integer.getInstance(qcStatement.getStatementInfo());
        assertEquals(BigInteger.valueOf(30), retentionPeriod.getValue());
        qcStatement = QCStatement.getInstance(qcStatements.getObjectAt(3));
        assertEquals(QCStatement.id_qcs_pkixQCSyntax_v2, qcStatement.getStatementId());
        SemanticsInformation semanticsInformation = SemanticsInformation.getInstance(qcStatement.getStatementInfo());
        assertEquals("1.11.3",semanticsInformation.getSemanticsIdentifier().getId());
        GeneralName[] ras = semanticsInformation.getNameRegistrationAuthorities();
        assertEquals(GeneralName.directoryName, ras[0].getTagNo());
        assertEquals("CN=RA1,O=Cryptable,C=be", X500Name.getInstance(ras[0].getName()).toString());
        assertEquals(GeneralName.directoryName, ras[1].getTagNo());
        assertEquals("CN=RA2,O=Cryptable,C=be", X500Name.getInstance(ras[1].getName()).toString());
    }

    /**
     * Test a normal basic constraints situation.
     *
     * <Certificate_Template_Name>DomainController</Certificate_Template_Name>
     */
    @Test
    public void testQualifiedStatementValidParts1() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(2);

        CertTemplate certTemplate = certTemplateBuilder
            .build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);

        Result result = results.get(0);
        Extension ext = (Extension) result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertEquals(Extension.qCStatements, ext.getExtnId());
        assertFalse(ext.isCritical());

        ASN1Sequence qcStatements = ASN1Sequence.getInstance(ext.getParsedValue());

        assertEquals(2, qcStatements.size());
        QCStatement qcStatement = QCStatement.getInstance(qcStatements.getObjectAt(0));
        assertEquals(QCStatement.id_etsi_qcs_LimiteValue, qcStatement.getStatementId());
        MonetaryValue monetaryValue = MonetaryValue.getInstance(qcStatement.getStatementInfo());
        assertEquals(BigInteger.valueOf(10000), monetaryValue.getAmount());
        assertEquals(BigInteger.valueOf(1), monetaryValue.getExponent());
        assertEquals(978 ,monetaryValue.getCurrency().getNumeric());
        qcStatement = QCStatement.getInstance(qcStatements.getObjectAt(1));
        assertEquals(QCStatement.id_qcs_pkixQCSyntax_v2, qcStatement.getStatementId());
        SemanticsInformation semanticsInformation = SemanticsInformation.getInstance(qcStatement.getStatementInfo());
        assertEquals("1.11.2",semanticsInformation.getSemanticsIdentifier().getId());
        GeneralName[] ras = semanticsInformation.getNameRegistrationAuthorities();
        assertEquals(GeneralName.directoryName, ras[0].getTagNo());
        assertEquals("CN=RA1,O=Cryptable,C=be", X500Name.getInstance(ras[0].getName()).toString());
        assertEquals(GeneralName.directoryName, ras[1].getTagNo());
        assertEquals("CN=RA2,O=Cryptable,C=be", X500Name.getInstance(ras[1].getName()).toString());
    }

    /**
     * Test a normal basic constraints situation.
     *
     * <Basic_Constraints>
     *   <Use_CA_Key>No</Use_CA_Key>
     *   <Certificate_Path_lentgh>-1</Certificate_Path_lentgh>
     * </Basic_Constraints>
     */
    @Test
    public void testQualifiedStatementValidParts2() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(3);

        CertTemplate certTemplate = certTemplateBuilder
            .build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);
        Result result = results.get(0);
        Extension ext = (Extension) result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertEquals(Extension.qCStatements, ext.getExtnId());
        assertFalse(ext.isCritical());

        ASN1Sequence qcStatements = ASN1Sequence.getInstance(ext.getParsedValue());

        assertEquals(3, qcStatements.size());
        QCStatement qcStatement = QCStatement.getInstance(qcStatements.getObjectAt(0));
        assertEquals(QCStatement.id_etsi_qcs_QcCompliance, qcStatement.getStatementId());
        qcStatement = QCStatement.getInstance(qcStatements.getObjectAt(1));
        assertEquals(QCStatement.id_etsi_qcs_RetentionPeriod, qcStatement.getStatementId());
        ASN1Integer retentionPeriod = ASN1Integer.getInstance(qcStatement.getStatementInfo());
        assertEquals(BigInteger.valueOf(30), retentionPeriod.getValue());
        qcStatement = QCStatement.getInstance(qcStatements.getObjectAt(2));
        assertEquals(QCStatement.id_qcs_pkixQCSyntax_v2, qcStatement.getStatementId());
        SemanticsInformation semanticsInformation = SemanticsInformation.getInstance(qcStatement.getStatementInfo());
        assertNull(semanticsInformation.getSemanticsIdentifier());
        GeneralName[] ras = semanticsInformation.getNameRegistrationAuthorities();
        assertEquals(GeneralName.directoryName, ras[0].getTagNo());
        assertEquals("CN=RA1,O=Cryptable,C=be", X500Name.getInstance(ras[0].getName()).toString());
        assertEquals(GeneralName.directoryName, ras[1].getTagNo());
        assertEquals("CN=RA2,O=Cryptable,C=be", X500Name.getInstance(ras[1].getName()).toString());
    }

    /**
     * Test a basic constraints issue with overrule.
     *
     * <Qualified_Statements>
     *   <Issue_Qualified_Statement/>
     *   <Liability_Limit>
     *     <Amount>10000</Amount>
     *     <Exponent>1</Exponent>
     *     <Currency_Code>978</Currency_Code>
     *   </Liability_Limit>
     *   <Retention_Period>30</Retention_Period>
     *   <Semantic_ID>11</Semantic_ID>
     *   <Registration_Agents>
     *     <DName>cn=RA1, o=Cryptable, c=be</DName>
     *     <DName>cn=RA2, o=Cryptable, c=be</DName>
     *   </Registration_Agents>
     * </Qualified_Statements>
     */
    @Test
    public void testCertificateKeyUsageOverruled() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(1);
        ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();

        asn1EncodableVector.add(new QCStatement(QCStatement.id_etsi_qcs_QcCompliance));
        GeneralName[] generalNames = new GeneralName[1];
        generalNames[0] = new GeneralName(new X500Name(BCStyle.INSTANCE, "CN=Koekoek,O=Cryptable,C=be"));
        SemanticsInformation semanticsInformationIn = new SemanticsInformation(new ASN1ObjectIdentifier("1.11.1"), generalNames);
        asn1EncodableVector.add(new QCStatement(QCStatement.id_qcs_pkixQCSyntax_v2, semanticsInformationIn));

        Extension extension = new Extension(Extension.qCStatements,
            true,
            new DEROctetString(new DERSequence(asn1EncodableVector)));

        Extensions extensions = new Extensions(extension);

        CertTemplate certTemplate = certTemplateBuilder
            .setExtensions(extensions)
            .build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);
        Result result = results.get(0);
        Extension ext = (Extension) result.getValue();

        assertEquals(Result.Decisions.OVERRULED, result.getDecision());
        assertEquals(Extension.qCStatements, ext.getExtnId());
        assertFalse(ext.isCritical());

        ASN1Sequence qcStatements = ASN1Sequence.getInstance(ext.getParsedValue());
        assertEquals(4, qcStatements.size());
        QCStatement qcStatement = QCStatement.getInstance(qcStatements.getObjectAt(0));
        assertEquals(QCStatement.id_etsi_qcs_QcCompliance, qcStatement.getStatementId());
        qcStatement = QCStatement.getInstance(qcStatements.getObjectAt(1));
        assertEquals(QCStatement.id_etsi_qcs_LimiteValue, qcStatement.getStatementId());
        MonetaryValue monetaryValue = MonetaryValue.getInstance(qcStatement.getStatementInfo());
        assertEquals(BigInteger.valueOf(10000), monetaryValue.getAmount());
        assertEquals(BigInteger.valueOf(1), monetaryValue.getExponent());
        assertEquals(978 ,monetaryValue.getCurrency().getNumeric());
        qcStatement = QCStatement.getInstance(qcStatements.getObjectAt(2));
        assertEquals(QCStatement.id_etsi_qcs_RetentionPeriod, qcStatement.getStatementId());
        ASN1Integer retentionPeriod = ASN1Integer.getInstance(qcStatement.getStatementInfo());
        assertEquals(BigInteger.valueOf(30), retentionPeriod.getValue());
        qcStatement = QCStatement.getInstance(qcStatements.getObjectAt(3));
        assertEquals(QCStatement.id_qcs_pkixQCSyntax_v2, qcStatement.getStatementId());
        SemanticsInformation semanticsInformationOut = SemanticsInformation.getInstance(qcStatement.getStatementInfo());
        assertEquals("1.11.3", semanticsInformationOut.getSemanticsIdentifier().getId());
        GeneralName[] ras = semanticsInformationOut.getNameRegistrationAuthorities();
        assertEquals(GeneralName.directoryName, ras[0].getTagNo());
        assertEquals("CN=RA1,O=Cryptable,C=be", X500Name.getInstance(ras[0].getName()).toString());
        assertEquals(GeneralName.directoryName, ras[1].getTagNo());
        assertEquals("CN=RA2,O=Cryptable,C=be", X500Name.getInstance(ras[1].getName()).toString());
    }

}
