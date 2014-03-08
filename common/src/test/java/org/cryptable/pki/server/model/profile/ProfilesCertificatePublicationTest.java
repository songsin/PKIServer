package org.cryptable.pki.server.model.profile;

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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 00:27
 */
public class ProfilesCertificatePublicationTest {

    static private Profiles profiles;
    static private GeneratePKI generatePKI;

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
            profiles = new ProfilesJAXB(getClass().getResourceAsStream("/Publication.xml"), x509CertificateHolder.toASN1Structure());
    }

    /**
     * Test the Certificate Publication delay
     *
     * <Keys>Store Private Keys</Keys>
     */
    @Test
    public void testCertificatePublicationDelayValid() throws ProfileException {
        Profile profile = profiles.get(1);

        long result = profile.certificatePublicationDelay();

        assertEquals(1200000, result);
    }

    /**
     * Test the missing Certificate Publication Delay.
     *
     */
    @Test
    public void testCertificatePublicationDelayMissing() throws ProfileException {
        Profile profile = profiles.get(2);

        long result = profile.certificatePublicationDelay();

        assertEquals(0, result);
    }

    /**
     * Test the missing Certificate Publication Delay.
     *
     */
    @Test
    public void testCertificatePublicationDelay2320() throws ProfileException {
        Profile profile = profiles.get(3);

        long result = profile.certificatePublicationDelay();

        assertEquals(((23 * 60) + 20) * 60 * 1000 , result);
    }
}
