package org.cryptable.pki.server.model.profile;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
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

import static junit.framework.Assert.assertNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 00:27
 */
public class ProfilesBasicConstraintsTest {

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
            profiles = new ProfilesJAXB(getClass().getResourceAsStream("/BasicConstraints.xml"), x509CertificateHolder.toASN1Structure());
    }

    /**
     * Test a normal basic constraints situation.
     *
     * <Basic_Constraints>
     *   <Use_CA_Key>Yes</Use_CA_Key>
     *   <Certificate_Path_lentgh>2</Certificate_Path_lentgh>
     * </Basic_Constraints>
     */
    @Test
    public void testCertificateBasicConstraintsValid() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(1);

        CertTemplate certTemplate = certTemplateBuilder
            .build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);
        Result result = results.get(0);
        Extension ext = (Extension) result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertEquals(Extension.basicConstraints, ext.getExtnId());
        assertTrue(ext.isCritical());

        BasicConstraints basicConstraints = BasicConstraints.getInstance(ext.getParsedValue());

        assertTrue(basicConstraints.isCA());
        assertEquals(BigInteger.valueOf(2), basicConstraints.getPathLenConstraint());
    }

    /**
     * Test a normal basic constraints situation.
     *
     * <Basic_Constraints>
     *   <Use_CA_Key>Yes</Use_CA_Key>
     *   <Certificate_Path_lentgh>-1</Certificate_Path_lentgh>
     * </Basic_Constraints>
     */
    @Test
    public void testCertificateBasicConstraintsNoPathLength() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(2);

        CertTemplate certTemplate = certTemplateBuilder
            .build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);
        Result result = results.get(0);
        Extension ext = (Extension) result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertEquals(Extension.basicConstraints, ext.getExtnId());
        assertTrue(ext.isCritical());

        BasicConstraints basicConstraints = BasicConstraints.getInstance(ext.getParsedValue());

        assertTrue(basicConstraints.isCA());
        assertNull(basicConstraints.getPathLenConstraint());
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
    public void testCertificateBasicConstraintsCAFalse() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(3);

        CertTemplate certTemplate = certTemplateBuilder
            .build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);
        Result result = results.get(0);
        Extension ext = (Extension) result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertEquals(Extension.basicConstraints, ext.getExtnId());
        assertTrue(ext.isCritical());

        BasicConstraints basicConstraints = BasicConstraints.getInstance(ext.getParsedValue());

        assertFalse(basicConstraints.isCA());
        assertNull(basicConstraints.getPathLenConstraint());
    }

    /**
     * Test a basic constraints issue with overrule.
     *
     * <Basic_Constraints>
     *   <Use_CA_Key>Yes</Use_CA_Key>
     *   <Certificate_Path_lentgh>2</Certificate_Path_lentgh>
     * </Basic_Constraints>
     * </Key_Usage>
     */
    @Test
    public void testCertificateKeyUsageOverruled() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(1);
        BasicConstraints basicConstraints = new BasicConstraints(false);

        Extension extension = new Extension(Extension.basicConstraints,
            true,
            new DEROctetString(new BasicConstraints(false)));
        Extensions extensions = new Extensions(extension);

        CertTemplate certTemplate = certTemplateBuilder
            .setExtensions(extensions)
            .build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);
        Result result = results.get(0);
        Extension ext = (Extension) result.getValue();

        BasicConstraints basicConstraintsOut = BasicConstraints.getInstance(ext.getParsedValue());

        assertTrue(basicConstraintsOut.isCA());
        assertEquals(BigInteger.valueOf(2), basicConstraintsOut.getPathLenConstraint());
    }

}
