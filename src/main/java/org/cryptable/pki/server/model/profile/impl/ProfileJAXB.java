package org.cryptable.pki.server.model.profile.impl;

import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.cryptable.pki.server.model.profile.Profile;
import org.cryptable.pki.server.model.profile.ProfileException;
import org.cryptable.pki.server.model.profile.Result;
import org.cryptable.pki.server.persistence.profile.jaxb.JAXBDateWithOverRule;
import org.cryptable.pki.server.persistence.profile.jaxb.JAXBKeyLength;
import org.cryptable.pki.server.persistence.profile.jaxb.JAXBProfile;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.joda.time.Interval;
import org.joda.time.Period;
import org.joda.time.format.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 11:22
 */
public class ProfileJAXB implements Profile {

    final Logger logger = LoggerFactory.getLogger(ProfilesJAXB.class);

    private JAXBProfile jaxbProfile;

    public ProfileJAXB(JAXBProfile jaxbProfile) {
        this.jaxbProfile = jaxbProfile;
    }

    @Override
    public Result validateCertificateNBefore(DateTime nBefore) throws ProfileException {

        Result result = new Result(Result.Decisions.INVALID, null);

        if ((jaxbProfile.getCertificateProfile() != null) &&
            (jaxbProfile.getCertificateProfile().getCertificateValidityProfile() != null))  {
            JAXBDateWithOverRule date = jaxbProfile.getCertificateProfile().getCertificateValidityProfile().getNotBefore();

            if (date == null || (nBefore.getMillis() >= date.getDate().getMillis()) && !date.getOverrule()) {
                logger.debug("Check Not Before [null|null|" + nBefore.toString() + "]");
                result.setDecision(Result.Decisions.VALID);
                result.setValue((Object)nBefore);
            }
            else if (date.getOverrule()) {
                logger.debug("Check Not Before [" + date.getDate().toString() + "|" + date.getOverrule().toString() + "|" + nBefore.toString() + "]");
                result.setDecision(Result.Decisions.OVERRULED);
                result.setValue((Object)date.getDate());
            }
            else {
                logger.debug("Check Not Before [" + date.getDate().toString() + "|" + date.getOverrule().toString() + "|" + nBefore.toString() + "]");
                result.setDecision(Result.Decisions.INVALID);
                result.setValue(String.valueOf("Invalid Not After [" + date.toString() + ":" + nBefore.toString() + "]"));
            }
        }
        else {
            throw new ProfileException("Corrupt profile in validity section: [" + String.valueOf(jaxbProfile.getId()) + ":"
                + jaxbProfile.getName() + "]");
        }

        return result;
    }

    @Override
    public Result validateCertificateNAfter(DateTime nAfter) throws ProfileException {

        Result result = new Result(Result.Decisions.INVALID, null);

        if ((jaxbProfile.getCertificateProfile() != null) &&
            (jaxbProfile.getCertificateProfile().getCertificateValidityProfile() != null))  {
            JAXBDateWithOverRule date = jaxbProfile.getCertificateProfile().getCertificateValidityProfile().getNotAfter();

            if (date == null || (nAfter.getMillis() <= date.getDate().getMillis()) && !date.getOverrule()) {
                logger.debug("Check Not After [null|null|" + nAfter.toString() + "]");
                result.setDecision(Result.Decisions.VALID);
                result.setValue((Object)nAfter);
            }
            else if (date.getOverrule()) {
                logger.debug("Check Not After [" + date.getDate().toString() + "|" + date.getOverrule().toString() + "|" + nAfter.toString() + "]");
                result.setDecision(Result.Decisions.OVERRULED);
                result.setValue((Object)date.getDate());
            }
            else {
                logger.debug("Check Not After [" + date.getDate().toString() + "|" + date.getOverrule().toString() + "|" + nAfter.toString() + "]");
                result.setDecision(Result.Decisions.INVALID);
                result.setValue(String.valueOf("Invalid Not Before [" + date.toString() + ":" + nAfter.toString() + "]"));
            }

        }
        else {
            throw new ProfileException("Corrupt profile in validity section: [" + String.valueOf(jaxbProfile.getId()) + ":"
                + jaxbProfile.getName() + "]");
        }

        return result;
    }

    @Override
    public Result validateCertificateValidity(DateTime nBefore, DateTime nAfter) throws ProfileException {

        Result result = new Result(Result.Decisions.INVALID, null);

        if ((jaxbProfile.getCertificateProfile() != null) &&
            (jaxbProfile.getCertificateProfile().getCertificateValidityProfile() != null))  {
            JAXBDateWithOverRule dateNBefore = jaxbProfile.getCertificateProfile().getCertificateValidityProfile().getNotBefore();
            JAXBDateWithOverRule dateNAfter = jaxbProfile.getCertificateProfile().getCertificateValidityProfile().getNotAfter();

            if (dateNBefore != null && dateNAfter != null &&
                dateNBefore.getOverrule() && dateNAfter.getOverrule()) {
                logger.debug("Check Validity overruled!");

                result.setDecision(Result.Decisions.OVERRULED);
                result.setValue(null);
            }
            else {
                Integer minDays = jaxbProfile.getCertificateProfile().getCertificateValidityProfile().getMinimumDuration();
                Integer maxDays = jaxbProfile.getCertificateProfile().getCertificateValidityProfile().getMaximumDuration();
                int numDays = (new Duration(nBefore, nAfter)).toStandardDays().getDays();

                if (minDays != null && numDays < minDays) {
                    result.setDecision(Result.Decisions.INVALID);
                    result.setValue(String.valueOf("Invalid minimum duration [" + String.valueOf(numDays) + "]"));
                }
                else if (maxDays != null && numDays > maxDays) {
                    result.setDecision(Result.Decisions.INVALID);
                    result.setValue(String.valueOf("Invalid maximum duration [" + String.valueOf(numDays) + "]"));
                }
                else {
                    result.setDecision(Result.Decisions.VALID);
                    result.setValue(null);
                }
            }
        }
        else {
            throw new ProfileException("Corrupt profile in validity section: [" + String.valueOf(jaxbProfile.getId()) + ":"
                + jaxbProfile.getName() + "]");
        }

        return result;
    }

    @Override
    public Result validateCertificateKeyLength(Integer keyLength) throws ProfileException {
        Result result = new Result(Result.Decisions.INVALID, null);

        if ((jaxbProfile.getCertificateProfile() != null) &&
            (jaxbProfile.getCertificateProfile().getKeyLengthProfile() != null))  {
            JAXBKeyLength jaxbKeyLength = jaxbProfile.getCertificateProfile().getKeyLengthProfile();
            Integer minKeyLength = jaxbKeyLength.getMinimumKeyLength();
            Integer maxKeyLength = jaxbKeyLength.getMaximumKeyLength();

            logger.debug("Check keylength [" + String.valueOf(minKeyLength) + "|" + String.valueOf(maxKeyLength) + "|" + String.valueOf(keyLength) + "|");

            if (minKeyLength != null && keyLength < minKeyLength ) {
                result.setDecision(Result.Decisions.INVALID);
                result.setValue(String.valueOf("Invalid minimum key length [" + String.valueOf(minKeyLength) + ":"
                    + String.valueOf(keyLength) + "]"));
            }
            else if (maxKeyLength != null && keyLength > maxKeyLength) {
                result.setDecision(Result.Decisions.INVALID);
                result.setValue(String.valueOf("Invalid maximum key length [" + String.valueOf(maxKeyLength) + ":"
                    + String.valueOf(keyLength) + "]"));
            }
            else {
                result.setDecision(Result.Decisions.VALID);
                result.setValue(keyLength);
            }
        }
        else {
            throw new ProfileException("Corrupt profile in key length section: [" + String.valueOf(jaxbProfile.getId()) + ":"
                + jaxbProfile.getName() + "]");
        }

        return result;
    }

    @Override
    public String getCertificateSignatureAlgorithm() throws ProfileException {
        String result = "Unknown";

        if (jaxbProfile.getCertificateProfile() != null) {
            String algorithm = jaxbProfile.getCertificateProfile().getAlgorithm();
            if (algorithm == null) {
                result = "SHA256WithRSAEncryption";
            }
            else if (algorithm.equalsIgnoreCase("MD5")) {
                result = "MD5WITHRSAENCRYPTION";
            }
            else if (algorithm.equalsIgnoreCase("SHA-1")) {
                result = "SHA1WithRSAEncryption";
            }
            else {
                result = algorithm;
            }
        }
        else {
            throw new ProfileException("Corrupt profile in key length section: [" + String.valueOf(jaxbProfile.getId()) + ":"
                + jaxbProfile.getName() + "]");
        }

        return result;
    }

    @Override
    public boolean usePrivateKeyEscrow() throws ProfileException {
        boolean result = false;

        if (jaxbProfile.getCertificateProfile() != null) {
            String keys = jaxbProfile.getCertificateProfile().getKeys();

            logger.debug("Keys entry [" + String.valueOf(keys) + "]");
            if (keys != null && keys.equalsIgnoreCase("Store Private Keys")) {
                result = true;
            }
        }
        else {
            throw new ProfileException("Corrupt profile in key length section: [" + String.valueOf(jaxbProfile.getId()) + ":"
                + jaxbProfile.getName() + "]");
        }

        return result;
    }

    @Override
    public long certificatePublicationDelay() throws ProfileException {
        long result = 0;

        if (jaxbProfile.getCertificateProfile() != null) {
            PeriodFormatter periodFormatter = new PeriodFormatterBuilder()
                .printZeroAlways()
                .appendHours()
                .appendSeparator(":")
                .appendMinutes()
                .toFormatter();
            String publication = jaxbProfile.getCertificateProfile().getPublication();
            if (publication != null) {
                Period period = periodFormatter.parsePeriod(publication);
                result = period.toStandardSeconds().getSeconds() * 1000;
                logger.debug("Publication Delay entry [" + period.toString(periodFormatter) + ":" + String.valueOf(result) + "]");
            }
        }
        else {
            throw new ProfileException("Corrupt profile in key length section: [" + String.valueOf(jaxbProfile.getId()) + ":"
                + jaxbProfile.getName() + "]");
        }

        return result;
    }

    @Override
    public List<Result> validateCertificateExtensions(Extensions extensions) {
        return null;
    }
}
