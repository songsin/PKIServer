package org.cryptable.pki.server.model.profile;

import org.cryptable.pki.server.model.profile.impl.ProfilesJAXB;
import org.junit.Before;
import org.junit.Test;

import javax.xml.bind.JAXBException;
import java.io.IOException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 00:27
 */
public class ProfilesStorePrivateKeyTest {

    static private Profiles profiles;

    @Before
    public void setup() throws JAXBException, IOException, ProfileException {
        if (profiles == null)
            profiles = new ProfilesJAXB(getClass().getResourceAsStream("/PrivateKey.xml"));
    }

    /**
     * Test the Private Key setting.
     *
     * <Keys>Store Private Keys</Keys>
     */
    @Test
    public void testCertificatePrivateKeyValid() throws ProfileException {
        Profile profile = profiles.get(1);

        boolean result = profile.usePrivateKeyEscrow();

        assertTrue(result);
    }

    /**
     * Test the Private Key setting.
     *
     * <Keys>Don't Store Private Keys</Keys>
     */
    @Test
    public void testCertificateDontPrivateKeyValid() throws ProfileException {
        Profile profile = profiles.get(2);

        boolean result = profile.usePrivateKeyEscrow();

        assertFalse(result);
    }

    /**
     * Test the Private Key setting.
     *
     */
    @Test
    public void testCertificatePrivateKeyMissing() throws ProfileException {
        Profile profile = profiles.get(3);

        boolean result = profile.usePrivateKeyEscrow();

        assertFalse(result);
    }


}
