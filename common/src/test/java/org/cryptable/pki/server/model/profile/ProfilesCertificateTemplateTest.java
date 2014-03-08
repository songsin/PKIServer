package org.cryptable.pki.server.model.profile;

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.microsoft.MicrosoftObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
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
import static org.junit.Assert.*;

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 00:27
 */
public class ProfilesCertificateTemplateTest {

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
            profiles = new ProfilesJAXB(getClass().getResourceAsStream("/CertificateTemplate.xml"), x509CertificateHolder.toASN1Structure());
    }

    /**
     * Test an overruled certificate template situation.
     *
     * <Certificate_Template_Name>User</Certificate_Template_Name>
     */
    @Test
    public void testCertificateBasicCertificateTemplateValid1() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(1);

        CertTemplate certTemplate = certTemplateBuilder
            .build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);
        Result result = results.get(0);
        Extension ext = (Extension) result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertEquals(MicrosoftObjectIdentifiers.microsoftCertTemplateV1, ext.getExtnId());
        assertFalse(ext.isCritical());

        String certificateTemplate = DERBMPString.getInstance(ext.getParsedValue()).getString();

        assertEquals(certificateTemplate, "User");
    }

    /**
     * Test an overruled certificate template situation.
     *
     * <Certificate_Template_Name>DomainController</Certificate_Template_Name>
     */
    @Test
    public void testCertificateBasicCertificateTemplateValid2() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(2);

        CertTemplate certTemplate = certTemplateBuilder
            .build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);
        Result result = results.get(0);
        Extension ext = (Extension) result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertEquals(MicrosoftObjectIdentifiers.microsoftCertTemplateV1, ext.getExtnId());
        assertFalse(ext.isCritical());

        String certificateTemplate = DERBMPString.getInstance(ext.getParsedValue()).getString();

        assertEquals(certificateTemplate, "DomainController");
    }

    /**
     * Test an overruled certificate template situation.
     *
     * <Certificate_Template_Name>DomainController</Certificate_Template_Name>
     */
    @Test
    public void testCertificateBasicCertificateTemplateOverruled() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(2);

        Extension extension = new Extension(MicrosoftObjectIdentifiers.microsoftCertTemplateV1,
            true,
            new DEROctetString(new DERBMPString("User")));
        Extensions extensions = new Extensions(extension);

        CertTemplate certTemplate = certTemplateBuilder
            .setExtensions(extensions)
            .build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);
        Result result = results.get(0);
        Extension ext = (Extension) result.getValue();

        assertEquals(Result.Decisions.OVERRULED, result.getDecision());
        assertEquals(MicrosoftObjectIdentifiers.microsoftCertTemplateV1, ext.getExtnId());
        assertFalse(ext.isCritical());

        String certificateTemplate = DERBMPString.getInstance(ext.getParsedValue()).getString();

        assertEquals(certificateTemplate, "DomainController");
    }

}
