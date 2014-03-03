package org.cryptable.pki.server.model.profile;

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.microsoft.MicrosoftObjectIdentifiers;
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 00:27
 */
public class ProfilesAuthorityInfoAccessTest {

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
            profiles = new ProfilesJAXB(getClass().getResourceAsStream("/AuthorityInfoAccess.xml"), x509CertificateHolder.toASN1Structure());
    }

    /**
     * Test a valid authority information access situation.
     *
     * <Authority_Info_Access>
     *   <Distribution_Point Name="AIA1">
     *     <URL>http://ocsp.cryptable.org</URL>
     *     <Access_Method>1</Access_Method>
     *   </Distribution_Point>
     *   <Distribution_Point Name="AIA2">
     *     <URL>http://www.cryptable.org/rootca.der</URL>
     *     <Access_Method>2</Access_Method>
     *   </Distribution_Point>
     * </Authority_Info_Access>
     */
    @Test
    public void testCertificateAuthorityInfoAccessValid() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(1);

        CertTemplate certTemplate = certTemplateBuilder
            .build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);
        Result result = results.get(0);
        Extension ext = (Extension) result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertEquals(Extension.authorityInfoAccess, ext.getExtnId());
        assertFalse(ext.isCritical());

        AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(ext.getParsedValue());
        AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
        assertEquals(AccessDescription.id_ad_ocsp.getId(), accessDescriptions[0].getAccessMethod().getId());
        GeneralName generalName = accessDescriptions[0].getAccessLocation();
        assertEquals(GeneralName.uniformResourceIdentifier, generalName.getTagNo());
        assertEquals("http://ocsp.cryptable.org", DERIA5String.getInstance(generalName.getName()).getString());
        assertEquals(AccessDescription.id_ad_caIssuers.getId(), accessDescriptions[1].getAccessMethod().getId());
        generalName = accessDescriptions[1].getAccessLocation();
        assertEquals(GeneralName.uniformResourceIdentifier, generalName.getTagNo());
        assertEquals("http://www.cryptable.org/rootca.der", DERIA5String.getInstance(generalName.getName()).getString());

    }

    /**
     * Test an overruled authority information access situation.
     *
     * <Authority_Info_Access>
     *   <Distribution_Point Name="AIA1">
     *     <URL>http://ocsp.cryptable.org</URL>
     *     <Access_Method>1</Access_Method>
     *   </Distribution_Point>
     *   <Distribution_Point Name="AIA2">
     *     <URL>http://www.cryptable.org/rootca.der</URL>
     *     <Access_Method>2</Access_Method>
     *   </Distribution_Point>
     * </Authority_Info_Access>
     */
    @Test
    public void testCertificateAuthorityInfoAccessOverruled() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(1);

        GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, "http://koekoek.org/ocsp");
        AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess(AccessDescription.id_ad_ocsp, generalName);

        Extension extension = new Extension(Extension.authorityInfoAccess,
            false,
            new DEROctetString(authorityInformationAccess));
        Extensions extensions = new Extensions(extension);

        CertTemplate certTemplate = certTemplateBuilder
            .build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);
        Result result = results.get(0);
        Extension ext = (Extension) result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertEquals(Extension.authorityInfoAccess, ext.getExtnId());
        assertFalse(ext.isCritical());

        authorityInformationAccess = AuthorityInformationAccess.getInstance(ext.getParsedValue());
        AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
        assertEquals(AccessDescription.id_ad_ocsp.getId(), accessDescriptions[0].getAccessMethod().getId());
        generalName = accessDescriptions[0].getAccessLocation();
        assertEquals(GeneralName.uniformResourceIdentifier, generalName.getTagNo());
        assertEquals("http://ocsp.cryptable.org", DERIA5String.getInstance(generalName.getName()).getString());
        assertEquals(AccessDescription.id_ad_caIssuers.getId(), accessDescriptions[1].getAccessMethod().getId());
        generalName = accessDescriptions[1].getAccessLocation();
        assertEquals(GeneralName.uniformResourceIdentifier, generalName.getTagNo());
        assertEquals("http://www.cryptable.org/rootca.der", DERIA5String.getInstance(generalName.getName()).getString());

    }

}
