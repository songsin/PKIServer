package org.cryptable.pki.server.model.profile;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.cryptable.pki.server.model.profile.impl.ExtendedKeyUsageJAXB;
import org.cryptable.pki.server.model.profile.impl.ProfilesJAXB;
import org.cryptable.pki.util.GeneratePKI;
import org.junit.Assert;
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
import java.util.Vector;

import static junit.framework.Assert.assertFalse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 00:27
 */
public class ProfilesExtendedKeyUsageTest {

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
            profiles = new ProfilesJAXB(getClass().getResourceAsStream("/ExtendedKeyUsage.xml"), x509CertificateHolder.toASN1Structure());
    }

    /**
     * Test a extended key Usage situation with no overrule and valid.
     *
     * <Extended_Key_Usage>
     *   <Server_Authentication>Enable</Server_Authentication>
     *   <Client_Authentication>Enable</Client_Authentication>
     *   <Code_Signing>Enable</Code_Signing>
     *   <E_Mail_Protection>Enable</E_Mail_Protection>
     *   <Time_Stamping>Enable</Time_Stamping>
     *   <IPSec_End_System>Enable</IPSec_End_System>
     *   <IPSec_Tunnel>Enable</IPSec_Tunnel>
     *   <IPSec_User>Enable</IPSec_User>
     *   <IKE_Intermediate>Enable</IKE_Intermediate>
     *   <OCSP_Signing>Enable</OCSP_Signing>
     *   <Smartcard_Logon>Enable</Smartcard_Logon>
     *   <Key_Recovery_Agent>Enable</Key_Recovery_Agent>
     *   <Drive_Encryption>Enable</Drive_Encryption>
     *   <Drive_Recovery>Enable</Drive_Recovery>
     * </Extended_Key_Usage>
     */
    @Test
    public void testCertificateExtendedKeyUsageValid() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(1);

        Vector<KeyPurposeId> keyPurposeIds = new Vector<KeyPurposeId>();
        keyPurposeIds.add(KeyPurposeId.id_kp_serverAuth);
        keyPurposeIds.add(KeyPurposeId.id_kp_clientAuth);
        keyPurposeIds.add(KeyPurposeId.id_kp_codeSigning);
        keyPurposeIds.add(KeyPurposeId.id_kp_emailProtection);
        keyPurposeIds.add(KeyPurposeId.id_kp_timeStamping);
        keyPurposeIds.add(KeyPurposeId.id_kp_ipsecEndSystem);
        keyPurposeIds.add(KeyPurposeId.id_kp_ipsecTunnel);
        keyPurposeIds.add(KeyPurposeId.id_kp_ipsecUser);
        keyPurposeIds.add(KeyPurposeId.id_kp_ipsecIKE);
        keyPurposeIds.add(KeyPurposeId.id_kp_OCSPSigning);
        keyPurposeIds.add(KeyPurposeId.id_kp_smartcardlogon);
        keyPurposeIds.add(ExtendedKeyUsageJAXB.id_kp_key_recovery_agent);
        keyPurposeIds.add(ExtendedKeyUsageJAXB.id_kp_bitlocker_drive_encryption);
        keyPurposeIds.add(ExtendedKeyUsageJAXB.id_kp_bitlocker_drive_recovery);

        KeyPurposeId[] keyPurposeIdsArray = new KeyPurposeId[keyPurposeIds.size()];
        Extension extension = new Extension(Extension.extendedKeyUsage,
            false,
            new DEROctetString(new ExtendedKeyUsage(keyPurposeIds.toArray(keyPurposeIdsArray))));
        Extensions extensions = new Extensions(extension);

        CertTemplate certTemplate = certTemplateBuilder
            .setExtensions(extensions)
            .build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);
        Result result = results.get(0);
        Extension ext = (Extension) result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertFalse(ext.isCritical());

        ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(ext.getParsedValue());

        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_clientAuth));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_codeSigning));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_emailProtection));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_timeStamping));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_ipsecEndSystem));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_ipsecTunnel));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_ipsecUser));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_ipsecIKE));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_OCSPSigning));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_smartcardlogon));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(ExtendedKeyUsageJAXB.id_kp_key_recovery_agent));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(ExtendedKeyUsageJAXB.id_kp_bitlocker_drive_encryption));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(ExtendedKeyUsageJAXB.id_kp_bitlocker_drive_recovery));

    }

    /**
     * Test a extended key Usage situation with some overrule.
     *
     * <Extended_Key_Usage>
     *   <Server_Authentication>No Overrule</Server_Authentication>
     *   <Client_Authentication>No Overrule</Client_Authentication>
     *   <Code_Signing>No Overrule</Code_Signing>
     *   <E_Mail_Protection>No Overrule</E_Mail_Protection>
     *   <Time_Stamping>No Overrule</Time_Stamping>
     *   <IPSec_End_System>No Overrule</IPSec_End_System>
     *   <IPSec_Tunnel>No Overrule</IPSec_Tunnel>
     * </Extended_Key_Usage>
     */
    @Test
    public void testCertificateExtendedKeyUsageOverruled() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(2);

        Vector<KeyPurposeId> keyPurposeIds = new Vector<KeyPurposeId>();
        keyPurposeIds.add(KeyPurposeId.id_kp_serverAuth);
        keyPurposeIds.add(KeyPurposeId.id_kp_clientAuth);
        keyPurposeIds.add(KeyPurposeId.id_kp_codeSigning);
        keyPurposeIds.add(KeyPurposeId.id_kp_emailProtection);
        keyPurposeIds.add(KeyPurposeId.id_kp_timeStamping);
        keyPurposeIds.add(KeyPurposeId.id_kp_ipsecEndSystem);
        keyPurposeIds.add(KeyPurposeId.id_kp_ipsecTunnel);
        keyPurposeIds.add(KeyPurposeId.id_kp_ipsecUser);
        keyPurposeIds.add(KeyPurposeId.id_kp_ipsecIKE);
        keyPurposeIds.add(KeyPurposeId.id_kp_OCSPSigning);
        keyPurposeIds.add(KeyPurposeId.id_kp_smartcardlogon);
        keyPurposeIds.add(ExtendedKeyUsageJAXB.id_kp_key_recovery_agent);
        keyPurposeIds.add(ExtendedKeyUsageJAXB.id_kp_bitlocker_drive_encryption);
        keyPurposeIds.add(ExtendedKeyUsageJAXB.id_kp_bitlocker_drive_recovery);

        KeyPurposeId[] keyPurposeIdsArray = new KeyPurposeId[keyPurposeIds.size()];
        Extension extension = new Extension(Extension.extendedKeyUsage,
            true,
            new DEROctetString(new ExtendedKeyUsage(keyPurposeIds.toArray(keyPurposeIdsArray))));
        Extensions extensions = new Extensions(extension);

        CertTemplate certTemplate = certTemplateBuilder
            .setExtensions(extensions)
            .build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);
        Result result = results.get(0);
        Extension ext = (Extension) result.getValue();

        assertEquals(Result.Decisions.OVERRULED, result.getDecision());
        assertFalse(ext.isCritical());

        ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(ext.getParsedValue());

        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_clientAuth));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_codeSigning));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_emailProtection));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_timeStamping));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_ipsecEndSystem));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_ipsecTunnel));
        assertFalse(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_ipsecUser));
        assertFalse(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_ipsecIKE));
        assertFalse(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_OCSPSigning));
        assertFalse(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_smartcardlogon));
        assertFalse(extendedKeyUsage.hasKeyPurposeId(ExtendedKeyUsageJAXB.id_kp_key_recovery_agent));
        assertFalse(extendedKeyUsage.hasKeyPurposeId(ExtendedKeyUsageJAXB.id_kp_bitlocker_drive_encryption));
        assertFalse(extendedKeyUsage.hasKeyPurposeId(ExtendedKeyUsageJAXB.id_kp_bitlocker_drive_recovery));
    }


    /**
     * Test a extended key Usage situation with empty settings.
     *
     */
    @Test
    public void testCertificateExtendedKeyUsageEmpty() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(3);

        Vector<KeyPurposeId> keyPurposeIds = new Vector<KeyPurposeId>();
        keyPurposeIds.add(KeyPurposeId.id_kp_serverAuth);
        keyPurposeIds.add(KeyPurposeId.id_kp_clientAuth);
        keyPurposeIds.add(KeyPurposeId.id_kp_codeSigning);
        keyPurposeIds.add(KeyPurposeId.id_kp_emailProtection);
        keyPurposeIds.add(KeyPurposeId.id_kp_timeStamping);
        keyPurposeIds.add(KeyPurposeId.id_kp_ipsecEndSystem);
        keyPurposeIds.add(KeyPurposeId.id_kp_ipsecTunnel);
        keyPurposeIds.add(KeyPurposeId.id_kp_ipsecUser);
        keyPurposeIds.add(KeyPurposeId.id_kp_ipsecIKE);
        keyPurposeIds.add(KeyPurposeId.id_kp_OCSPSigning);
        keyPurposeIds.add(KeyPurposeId.id_kp_smartcardlogon);
        keyPurposeIds.add(ExtendedKeyUsageJAXB.id_kp_key_recovery_agent);
        keyPurposeIds.add(ExtendedKeyUsageJAXB.id_kp_bitlocker_drive_encryption);
        keyPurposeIds.add(ExtendedKeyUsageJAXB.id_kp_bitlocker_drive_recovery);

        KeyPurposeId[] keyPurposeIdsArray = new KeyPurposeId[keyPurposeIds.size()];
        Extension extension = new Extension(Extension.extendedKeyUsage,
            false,
            new DEROctetString(new ExtendedKeyUsage(keyPurposeIds.toArray(keyPurposeIdsArray))));
        Extensions extensions = new Extensions(extension);

        CertTemplate certTemplate = certTemplateBuilder
            .setExtensions(extensions)
            .build();

        List<Result> results = profile.validateCertificateExtensions(certTemplate);
        Result result = results.get(0);
        Extension ext = (Extension) result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertFalse(ext.isCritical());

        ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(ext.getParsedValue());

        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_clientAuth));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_codeSigning));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_emailProtection));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_timeStamping));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_ipsecEndSystem));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_ipsecTunnel));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_ipsecUser));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_ipsecIKE));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_OCSPSigning));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_smartcardlogon));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(ExtendedKeyUsageJAXB.id_kp_key_recovery_agent));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(ExtendedKeyUsageJAXB.id_kp_bitlocker_drive_encryption));
        assertTrue(extendedKeyUsage.hasKeyPurposeId(ExtendedKeyUsageJAXB.id_kp_bitlocker_drive_recovery));

    }
}
