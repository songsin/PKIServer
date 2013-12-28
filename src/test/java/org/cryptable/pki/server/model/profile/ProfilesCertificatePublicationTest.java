package org.cryptable.pki.server.model.profile;

import org.cryptable.pki.server.model.profile.impl.ProfilesJAXB;
import org.junit.Before;
import org.junit.Test;

import javax.xml.bind.JAXBException;
import java.io.IOException;

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

    @Before
    public void setup() throws JAXBException, IOException, ProfileException {
        if (profiles == null)
            profiles = new ProfilesJAXB(getClass().getResourceAsStream("/Publication.xml"));
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
