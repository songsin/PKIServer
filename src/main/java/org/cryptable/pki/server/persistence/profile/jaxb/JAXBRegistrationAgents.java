package org.cryptable.pki.server.persistence.profile.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import java.util.ArrayList;
import java.util.List;

/**
 * <Registration_Agents>
 *   <DName>cn=RA1, o=Cryptable, c=be</DName>
 *   <DName>cn=RA2, o=Cryptable, c=be</DName>
 * </Registration_Agents>
 *
 * Author: davidtillemans
 * Date: 3/03/14
 * Hour: 18:48
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JAXBRegistrationAgents {

    @XmlElement(name="DName")
    private List<String> dnames = new ArrayList<String>();

    public List<String> getDnames() {
        return dnames;
    }

    public void setDnames(List<String> dnames) {
        this.dnames = dnames;
    }
}
