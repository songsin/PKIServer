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

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 00:27
 */
public class ProfilesAlgorithmTest {

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
            profiles = new ProfilesJAXB(getClass().getResourceAsStream("/Algorithm.xml"), x509CertificateHolder.toASN1Structure());
    }

    /**
     * Test the Algorithm of the profile key length (SHA1).
     *
     * <Algorithm>SHA-1</Algorithm>
     */
    @Test
    public void testCertificateAlgorithmValidSHA1() throws ProfileException {
        Profile profile = profiles.get(1);

        String result = profile.getCertificateSignatureAlgorithm();

        assertEquals("SHA1WithRSAEncryption", result);
    }

    /**
     * Test the Algorithm of the profile key length (MD5).
     *
     * <Algorithm>MD5</Algorithm>
     */
    @Test
    public void testCertificateAlgorithmValidMD5() throws ProfileException {
        Profile profile = profiles.get(2);

        String result = profile.getCertificateSignatureAlgorithm();

        assertEquals("MD5WITHRSAENCRYPTION", result);
    }

    /**
     * Test the Algorithm of the profile key length (MD5).
     *
     * <Algorithm>SHA512WITHRSAENCRYPTION</Algorithm>
     */
    @Test
    public void testCertificateAlgorithmValidSHA512WITHRSAENCRYPTION() throws ProfileException {
        Profile profile = profiles.get(3);

        String result = profile.getCertificateSignatureAlgorithm();

        assertEquals("SHA512WITHRSAENCRYPTION", result);
    }

    /**
     * Test the Algorithm of the profile, missing algorithm.
     *
     */
    @Test
    public void testCertificateAlgorithmValidMissingEntry() throws ProfileException {
        Profile profile = profiles.get(4);

        String result = profile.getCertificateSignatureAlgorithm();

        assertEquals("SHA256WithRSAEncryption", result);
    }

}
