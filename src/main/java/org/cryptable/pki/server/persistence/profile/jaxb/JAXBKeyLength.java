package org.cryptable.pki.server.persistence.profile.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

/**
 *
 * <Key_Length>
 *   <Minimum_Key_Length>2048</Minimum_Key_Length>
 *   <Maximum_Key_Length>4096</Maximum_Key_Length>
 * </Key_Length>
 *
 * Author: davidtillemans
 * Date: 27/12/13
 * Hour: 23:36
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JAXBKeyLength {

    @XmlElement(name="Minimum_Key_Length")
    private Integer minimumKeyLength;

    @XmlElement(name="Maximum_Key_Length")
    private Integer maximumKeyLength;

    public Integer getMinimumKeyLength() {
        return minimumKeyLength;
    }

    public void setMinimumKeyLength(Integer minimumKeyLength) {
        this.minimumKeyLength = minimumKeyLength;
    }

    public Integer getMaximumKeyLength() {
        return maximumKeyLength;
    }

    public void setMaximumKeyLength(Integer maximumKeyLength) {
        this.maximumKeyLength = maximumKeyLength;
    }
}
