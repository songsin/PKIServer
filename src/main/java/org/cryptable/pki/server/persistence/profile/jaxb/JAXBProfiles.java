package org.cryptable.pki.server.persistence.profile.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.List;

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 00:10
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name="Profiles")
public class JAXBProfiles {

    @XmlElement(name = "Profile", type = JAXBProfile.class)
    protected List<JAXBProfile> profiles = new ArrayList<JAXBProfile>();

    public List<JAXBProfile> getProfiles() {
        return profiles;
    }

    public void setProfiles(List<JAXBProfile> profiles) {
        this.profiles = profiles;
    }
}
