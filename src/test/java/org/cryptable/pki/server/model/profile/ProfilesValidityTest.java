package org.cryptable.pki.server.model.profile;

import org.cryptable.pki.server.model.profile.impl.ProfilesJAXB;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.xml.bind.JAXBException;
import java.io.IOException;

import static org.junit.Assert.*;

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 00:27
 */
public class ProfilesValidityTest {

    static private Profiles profiles = null;

    @Before
    public void setup() throws JAXBException, IOException, ProfileException, ClassNotFoundException {
        if (profiles == null)
            profiles = new ProfilesJAXB(getClass().getResourceAsStream("/Validity.xml"));
    }

    /**
     * Test profile validity
     */
    @Test
    public void testCertificateValidity1() throws ProfileException, JAXBException, IOException {

        Profile profile = profiles.get(1);
        DateTime nBefore = new DateTime(2013, 1, 1, 0, 0, 0);
        DateTime nAfter = new DateTime(2015, 12, 31, 23, 59, 59);

        Result result1 = profile.validateCertificateNBefore(nBefore);
        Result result2 = profile.validateCertificateNAfter(nAfter);
        Result result3 = profile.validateCertificateValidity(nBefore, nAfter);

        assertEquals(Result.Decisions.VALID, result1.getDecision());
        assertEquals(Result.Decisions.VALID, result2.getDecision());
        assertEquals(Result.Decisions.VALID, result3.getDecision());

    }

    /**
     * Test profile validity invalid nBefore
     */
    @Test
    public void testCertificateInValidityNBefore() throws JAXBException, IOException, ProfileException {

        Profile profile = profiles.get(1);
        DateTime nBefore = new DateTime(2009, 1, 1, 0, 0, 0);
        DateTime nAfter = new DateTime(2015, 12, 31, 23, 59, 59);

        Result result1 = profile.validateCertificateNBefore(nBefore);
        Result result2 = profile.validateCertificateNAfter(nAfter);
        Result result3 = profile.validateCertificateValidity(nBefore, nAfter);

        assertEquals(Result.Decisions.INVALID, result1.getDecision());
        assertEquals(Result.Decisions.VALID, result2.getDecision());
        assertEquals(Result.Decisions.VALID, result3.getDecision());

    }

    /**
     * Test profile validity invalid nAfter
     */
    @Test
    public void testCertificateInValidityNAfter() throws JAXBException, IOException, ProfileException {

        Profile profile = profiles.get(1);
        DateTime nBefore = new DateTime(2025, 1, 1, 0, 0, 0);
        DateTime nAfter = new DateTime(2034, 12, 31, 23, 59, 59);

        Result result1 = profile.validateCertificateNBefore(nBefore);
        Result result2 = profile.validateCertificateNAfter(nAfter);
        Result result3 = profile.validateCertificateValidity(nBefore, nAfter);

        assertEquals(Result.Decisions.VALID, result1.getDecision());
        assertEquals(Result.Decisions.INVALID, result2.getDecision());
        assertEquals(Result.Decisions.VALID, result3.getDecision());

    }

    /**
     * Test profile validity invalid Minimum
     */
    @Test
    public void testCertificateInValidityMinimum() throws JAXBException, IOException, ProfileException {

        Profile profile = profiles.get(1);
        DateTime nBefore = new DateTime(2025, 1, 1, 0, 0, 0);
        DateTime nAfter = new DateTime(2025, 12, 31, 23, 59, 59);

        Result result1 = profile.validateCertificateNBefore(nBefore);
        Result result2 = profile.validateCertificateNAfter(nAfter);
        Result result3 = profile.validateCertificateValidity(nBefore, nAfter);

        assertEquals(Result.Decisions.VALID, result1.getDecision());
        assertEquals(Result.Decisions.VALID, result2.getDecision());
        assertEquals(Result.Decisions.INVALID, result3.getDecision());
        assertEquals("Invalid minimum duration [364]", result3.getValue().toString());

    }

    /**
     * Test profile validity invalid Maximum
     */
    @Test
    public void testCertificateInValidityMaximum() throws JAXBException, IOException, ProfileException {

        Profile profile = profiles.get(1);
        DateTime nBefore = new DateTime(2015, 1, 1, 0, 0, 0);
        DateTime nAfter = new DateTime(2025, 12, 31, 23, 59, 59);

        Result result1 = profile.validateCertificateNBefore(nBefore);
        Result result2 = profile.validateCertificateNAfter(nAfter);
        Result result3 = profile.validateCertificateValidity(nBefore, nAfter);

        assertEquals(Result.Decisions.VALID, result1.getDecision());
        assertEquals(Result.Decisions.VALID, result2.getDecision());
        assertEquals(Result.Decisions.INVALID, result3.getDecision());
        assertEquals("Invalid maximum duration [4017]", result3.getValue().toString());

    }

    /**
     * Test profile validity overrule nBefore and nAfter
     * <Not_Before Overrule="Yes">20130101000000</Not_Before>
     * <Not_After Overrule="Yes">20171231000000</Not_After>
     */
    @Test
    public void testCertificateValidityOverrule() throws JAXBException, IOException, ProfileException {

        Profile profile = profiles.get(4);
        DateTime nBefore = new DateTime(2015, 1, 1, 0, 0, 0);
        DateTime nAfter = new DateTime(2025, 12, 31, 23, 59, 59);

        Result result1 = profile.validateCertificateNBefore(nBefore);
        Result result2 = profile.validateCertificateNAfter(nAfter);
        Result result3 = profile.validateCertificateValidity(nBefore, nAfter);

        assertEquals(Result.Decisions.OVERRULED, result1.getDecision());
        assertEquals(new DateTime(2013, 1, 1, 0, 0, 0), result1.getValue());
        assertEquals(Result.Decisions.OVERRULED, result2.getDecision());
        assertEquals(new DateTime(2017, 12, 31, 0, 0, 0), result2.getValue());
        assertEquals(Result.Decisions.OVERRULED, result3.getDecision());

    }

    /**
     * No Minimum and Maximum dates are defined in the profile
     */
    @Test
    public void testCertificateValidityEmptyMinimumMaximum() throws JAXBException, IOException, ProfileException {

        Profile profile = profiles.get(2);
        DateTime nBefore = new DateTime(2015, 1, 1, 0, 0, 0);
        DateTime nAfter = new DateTime(2017, 12, 31, 23, 59, 59);

        Result result1 = profile.validateCertificateNBefore(nBefore);
        Result result2 = profile.validateCertificateNAfter(nAfter);
        Result result3 = profile.validateCertificateValidity(nBefore, nAfter);

        assertEquals(Result.Decisions.VALID, result1.getDecision());
        assertEquals(new DateTime(2015, 1, 1, 0, 0, 0), result1.getValue());
        assertEquals(Result.Decisions.VALID, result2.getDecision());
        assertEquals(new DateTime(2017, 12, 31, 23, 59, 59), result2.getValue());
        assertEquals(Result.Decisions.VALID, result3.getDecision());
    }

    /**
     * No NBefore and NAfter are defined in the profile
     */
    @Test
    public void testCertificateValidityEmptyNBeforeNAfter() throws JAXBException, IOException, ProfileException {

        Profile profile = profiles.get(3);
        DateTime nBefore = new DateTime(2015, 1, 1, 0, 0, 0);
        DateTime nAfter = new DateTime(2016, 12, 31, 23, 59, 59);

        Result result1 = profile.validateCertificateNBefore(nBefore);
        Result result2 = profile.validateCertificateNAfter(nAfter);
        Result result3 = profile.validateCertificateValidity(nBefore, nAfter);

        assertEquals(Result.Decisions.VALID, result1.getDecision());
        assertEquals(new DateTime(2015, 1, 1, 0, 0, 0), result1.getValue());
        assertEquals(Result.Decisions.VALID, result2.getDecision());
        assertEquals(new DateTime(2016, 12, 31, 23, 59, 59), result2.getValue());
        assertEquals(Result.Decisions.VALID, result3.getDecision());

    }

    /**
     * No NBefore and NAfter are defined in the profile invalid maximum
     */
    @Test
    public void testCertificateValidityEmptyNBeforeNAfterInvalidMaximum() throws JAXBException, IOException, ProfileException {

        Profile profile = profiles.get(3);
        DateTime nBefore = new DateTime(2015, 1, 1, 0, 0, 0);
        DateTime nAfter = new DateTime(2025, 12, 31, 23, 59, 59);

        Result result1 = profile.validateCertificateNBefore(nBefore);
        Result result2 = profile.validateCertificateNAfter(nAfter);
        Result result3 = profile.validateCertificateValidity(nBefore, nAfter);

        assertEquals(Result.Decisions.VALID, result1.getDecision());
        assertEquals(new DateTime(2015, 1, 1, 0, 0, 0), result1.getValue());
        assertEquals(Result.Decisions.VALID, result2.getDecision());
        assertEquals(new DateTime(2025, 12, 31, 23, 59, 59), result2.getValue());
        assertEquals(Result.Decisions.INVALID, result3.getDecision());

    }

}
