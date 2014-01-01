package org.cryptable.pki.server.model.profile.impl;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.cryptable.pki.server.model.profile.Profile;
import org.cryptable.pki.server.model.profile.ProfileException;
import org.cryptable.pki.server.model.profile.Profiles;
import org.cryptable.pki.server.persistence.profile.jaxb.JAXBProfile;
import org.cryptable.pki.server.persistence.profile.jaxb.JAXBProfiles;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 11:23
 */
public class ProfilesJAXB implements Profiles {

    final Logger logger = LoggerFactory.getLogger(ProfilesJAXB.class);

    private final HashMap<Integer, Profile> profilesIDs = new HashMap<Integer, Profile>();
    private final HashMap<String, Profile> profilesNames = new HashMap<String, Profile>();

    private void init(InputStream inputStream, Certificate caCertificate) throws JAXBException, ProfileException, IOException, NoSuchAlgorithmException {
        JAXBContext jaxbContext = JAXBContext.newInstance(JAXBProfiles.class);

        Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
        JAXBProfiles jaxbProfiles = (JAXBProfiles) jaxbUnmarshaller.unmarshal(inputStream);
        if (jaxbProfiles != null)   {
            if (jaxbProfiles.getProfiles() != null) {
                List<JAXBProfile> profileList = jaxbProfiles.getProfiles();

                for (JAXBProfile jaxbProfile : profileList) {
                    if (jaxbProfile != null) {
                        ProfileJAXB profileJAXB = new ProfileJAXB(jaxbProfile, caCertificate);
                        profilesIDs.put(jaxbProfile.getId(), profileJAXB);
                        profilesNames.put(jaxbProfile.getName(), profileJAXB);
                        logger.debug("ID: [" + String.valueOf(jaxbProfile.getId()) + "] and Name: [" +
                            jaxbProfile.getName() + "]");
                    } else {
                        logger.debug("Profile null");
                    }
                }
            } else {
                logger.info("No profiles found in profile");
            }
        } else {
            logger.error("No profile found in the XML file");
            throw new ProfileException("No profile found in the XML file");
        }
    }

    public ProfilesJAXB() {
    }

    public ProfilesJAXB(InputStream inputStream, Certificate caCertificate) throws JAXBException, ProfileException, IOException, NoSuchAlgorithmException {
        init(inputStream, caCertificate);
    }

    public ProfilesJAXB(String fileName, Certificate caCertificate) throws JAXBException, IOException, ProfileException, NoSuchAlgorithmException {

        logger.debug(fileName);

        FileInputStream fis = new FileInputStream(fileName);
        init(fis, caCertificate);
        fis.close();
    }

    @Override
    public Profile get(String profileName) {
        return profilesNames.get(profileName);
    }

    @Override
    public Profile get(int profileID) {
        return profilesIDs.get(profileID);
    }
}
