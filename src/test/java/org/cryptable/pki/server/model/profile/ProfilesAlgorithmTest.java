package org.cryptable.pki.server.model.profile;

import org.cryptable.pki.server.model.profile.impl.ProfilesJAXB;
import org.junit.Before;
import org.junit.Test;

import javax.xml.bind.JAXBException;
import java.io.IOException;

import static org.junit.Assert.assertEquals;

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 00:27
 */
public class ProfilesAlgorithmTest {

    static private Profiles profiles;

    @Before
    public void setup() throws JAXBException, IOException, ProfileException {
        if (profiles == null)
            profiles = new ProfilesJAXB(getClass().getResourceAsStream("/Algorithm.xml"));
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
