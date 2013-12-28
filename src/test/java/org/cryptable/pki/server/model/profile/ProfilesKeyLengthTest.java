package org.cryptable.pki.server.model.profile;

import org.cryptable.pki.server.model.profile.impl.ProfilesJAXB;
import org.joda.time.DateTime;
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
public class ProfilesKeyLengthTest {

    static private Profiles profiles;

    @Before
    public void setup() throws JAXBException, IOException, ProfileException {
        if (profiles == null)
            profiles = new ProfilesJAXB(getClass().getResourceAsStream("/KeyLength.xml"));
    }

    /**
     * Test the keyLengths of the profile key length.
     * <Key_Length>
     *   <Minimum_Key_Length>2048</Minimum_Key_Length>
     *   <Maximum_Key_Length>4096</Maximum_Key_Length>
     * </Key_Length>
     */
    @Test
    public void testCertificateKeyLengthValid() throws ProfileException {
        Profile profile = profiles.get(1);

        int keyLength = 2048;

        Result result = profile.validateCertificateKeyLength(keyLength);

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertEquals(Integer.valueOf(2048), result.getValue());
    }

    /**
     * Test invalid minimum key length
     */
    @Test
    public void testCertificateKeyLengthInValidMinimum() throws ProfileException {
        Profile profile = profiles.get(1);

        int keyLength = 512;

        Result result = profile.validateCertificateKeyLength(keyLength);

        assertEquals(Result.Decisions.INVALID, result.getDecision());
        assertEquals(String.valueOf("Invalid minimum key length [2048:512]"), result.getValue());
    }

    /**
     * Test invalid maximum key length
     */
    @Test
    public void testCertificateKeyLengthInValidMaximum() throws ProfileException {
        Profile profile = profiles.get(1);

        int keyLength = 8192;

        Result result = profile.validateCertificateKeyLength(keyLength);

        assertEquals(Result.Decisions.INVALID, result.getDecision());
        assertEquals(String.valueOf("Invalid maximum key length [4096:8192]"), result.getValue());
    }

    /**
     * Test minimum key length only, empty maximum test
     */
    @Test
    public void testCertificateKeyLengthValidMinimumNoMaximum() throws ProfileException {
        Profile profile = profiles.get(2);

        int keyLength = 8192;

        Result result = profile.validateCertificateKeyLength(keyLength);

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertEquals(Integer.valueOf(keyLength), result.getValue());
    }

    /**
     * Test minimum key length only, empty maximum test, but invalid keylength
     */
    @Test
    public void testCertificateKeyLengthInValidMinimumNoMaximum() throws ProfileException {
        Profile profile = profiles.get(2);

        int keyLength = 512;

        Result result = profile.validateCertificateKeyLength(keyLength);

        assertEquals(Result.Decisions.INVALID, result.getDecision());
        assertEquals(String.valueOf("Invalid minimum key length [1024:512]"), result.getValue());
    }

    /**
     * Test maximum key length only, empty minimum test
     */
    @Test
    public void testCertificateKeyLengthValidMaximumNoMinimum() throws ProfileException {
        Profile profile = profiles.get(3);

        int keyLength = 1024;

        Result result = profile.validateCertificateKeyLength(keyLength);

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertEquals(Integer.valueOf(keyLength), result.getValue());
    }

    /**
     * Test maximum key length only, empty minimum test, but invalid keylength
     */
    @Test
    public void testCertificateKeyLengthInValidMaximumNoMinimum() throws ProfileException {
        Profile profile = profiles.get(3);

        int keyLength = 8192;

        Result result = profile.validateCertificateKeyLength(keyLength);

        assertEquals(Result.Decisions.INVALID, result.getDecision());
        assertEquals(String.valueOf("Invalid maximum key length [2048:8192]"), result.getValue());
    }

}
