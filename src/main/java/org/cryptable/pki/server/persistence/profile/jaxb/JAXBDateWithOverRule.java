package org.cryptable.pki.server.persistence.profile.jaxb;

import org.joda.time.DateTime;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlValue;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * Author: davidtillemans
 * Date: 27/12/13
 * Hour: 23:18
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JAXBDateWithOverRule {
    @XmlAttribute(name="Overrule")
    @XmlJavaTypeAdapter(BooleanAdapter.class)
    private Boolean overrule;

    @XmlValue
    @XmlJavaTypeAdapter(DateAdapter.class)
    private DateTime date;

    public Boolean getOverrule() {
        return overrule;
    }

    public void setOverrule(Boolean overrule) {
        this.overrule = overrule;
    }

    public DateTime getDate() {
        return date;
    }

    public void setDate(DateTime date) {
        this.date = date;
    }
}
