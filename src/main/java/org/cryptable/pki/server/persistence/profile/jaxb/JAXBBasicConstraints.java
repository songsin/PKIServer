package org.cryptable.pki.server.persistence.profile.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 *
 * <Basic_Constraints>
 *   <Use_CA_Key>Yes</Use_CA_Key>
 *   <Certificate_Path_lentgh>2</Certificate_Path_lentgh>
 * </Basic_Constraints>
 *
 * Author: davidtillemans
 * Date: 29/12/13
 * Hour: 12:45
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JAXBBasicConstraints {

    @XmlElement(name = "Use_CA_Key")
    @XmlJavaTypeAdapter(BooleanYesNoAdapter.class)
    private Boolean CA;

    @XmlElement(name = "Certificate_Path_lentgh")
    private int PathLength;

    public boolean isCA() {
        return CA;
    }

    public void setCA(boolean CA) {
        this.CA = CA;
    }

    public int getPathLength() {
        return PathLength;
    }

    public void setPathLength(int pathLength) {
        PathLength = pathLength;
    }
}
