package org.cryptable.pki.server.model.profile;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.cryptable.pki.server.model.profile.impl.ProfilesJAXB;
import org.cryptable.pki.util.GeneratePKI;
import org.joda.time.DateTime;
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
import java.util.Date;

import static org.junit.Assert.*;

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 00:27
 */
public class ProfilesLoadTest {

    static private GeneratePKI generatePKI;

    @BeforeClass
    static public void init() throws CertificateException, CertIOException, NoSuchAlgorithmException, OperatorCreationException, CRLException, NoSuchProviderException, InvalidKeySpecException {
        Security.addProvider(new BouncyCastleProvider());
        generatePKI = new GeneratePKI();
        generatePKI.createPKI();
    }

    /**
     * Test profile construction
     */
    @Test
    public void testLoadDefaultProfile() throws JAXBException, IOException, ProfileException {

        Profiles profiles = new ProfilesJAXB();
        Profile profile = profiles.get(9);
        assertNull(profile);

    }

    @Test
    public void testLoadProfileWithFilename() throws JAXBException, IOException, ProfileException, CertificateEncodingException, NoSuchAlgorithmException {
        X509CertificateHolder x509CertificateHolder = new JcaX509CertificateHolder(generatePKI.getCaCert());
        Profiles profiles = new ProfilesJAXB(getClass().getResource("/Profiles.xml").getFile(), x509CertificateHolder.toASN1Structure());
        Profile profile = profiles.get(9);
        assertNotNull(profile);
    }

    @Test
    public void testLoadProfileWithStream() throws JAXBException, IOException, ProfileException, CertificateEncodingException, NoSuchAlgorithmException {

        X509CertificateHolder x509CertificateHolder = new JcaX509CertificateHolder(generatePKI.getCaCert());
        Profiles profiles = new ProfilesJAXB(getClass().getResourceAsStream("/Profiles.xml"), x509CertificateHolder.toASN1Structure());
        Profile profile = profiles.get(9);
        assertNotNull(profile);
    }

}
