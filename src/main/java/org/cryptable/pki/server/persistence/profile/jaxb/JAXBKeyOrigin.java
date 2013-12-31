package org.cryptable.pki.server.persistence.profile.jaxb;

import javax.xml.bind.annotation.*;

/**
 * Author: davidtillemans
 * Date: 27/12/13
 * Hour: 22:33
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JAXBKeyOrigin {

    @XmlAttribute
    private String selectable;

    @XmlValue
    private String keyOrigin;

    public String getSelectable() {
        return selectable;
    }

    public void setSelectable(String selectable) {
        this.selectable = selectable;
    }

    public String getKeyOrigin() {
        return keyOrigin;
    }

    public void setKeyOrigin(String keyOrigin) {
        this.keyOrigin = keyOrigin;
    }
}
