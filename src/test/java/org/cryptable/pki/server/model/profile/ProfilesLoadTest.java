package org.cryptable.pki.server.model.profile;

import org.cryptable.pki.server.model.profile.impl.ProfilesJAXB;
import org.joda.time.DateTime;
import org.junit.Test;

import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.util.Date;

import static org.junit.Assert.*;

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 00:27
 */
public class ProfilesLoadTest {

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
    public void testLoadProfileWithFilename() throws JAXBException, IOException, ProfileException {

        Profiles profiles = new ProfilesJAXB(getClass().getResource("/Profiles.xml").getFile());
        Profile profile = profiles.get(9);
        assertNotNull(profile);
    }

    @Test
    public void testLoadProfileWithStream() throws JAXBException, IOException, ProfileException {

        Profiles profiles = new ProfilesJAXB(getClass().getResourceAsStream("/Profiles.xml"));
        Profile profile = profiles.get(9);
        assertNotNull(profile);
    }

}
