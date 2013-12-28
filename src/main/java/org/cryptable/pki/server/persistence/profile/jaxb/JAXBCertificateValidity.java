package org.cryptable.pki.server.persistence.profile.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

/**
 * <Validity>
 *   <Minimum_Duration>365</Minimum_Duration>
 *   <Maximum_Duration>3652</Maximum_Duration>
 *   <Not_Before Overrule="Yes">20131226220550</Not_Before>
 *   <Not_After Overrule="Yes">20171226220550</Not_After>
 * </Validity>
 *
 * Author: davidtillemans
 * Date: 27/12/13
 * Hour: 22:57
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JAXBCertificateValidity {

    @XmlElement(name="Minimum_Duration")
    protected Integer minimumDuration;

    @XmlElement(name="Maximum_Duration")
    protected Integer maximumDuration;

    @XmlElement(name="Not_Before")
    protected JAXBDateWithOverRule notBefore;

    @XmlElement(name="Not_After")
    protected JAXBDateWithOverRule notAfter;

    public Integer getMinimumDuration() {
        return minimumDuration;
    }

    public void setMinimumDuration(int minimumDuration) {
        this.minimumDuration = minimumDuration;
    }

    public Integer getMaximumDuration() {
        return maximumDuration;
    }

    public void setMaximumDuration(int maximumDuration) {
        this.maximumDuration = maximumDuration;
    }

    public JAXBDateWithOverRule getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(JAXBDateWithOverRule notBefore) {
        this.notBefore = notBefore;
    }

    public JAXBDateWithOverRule getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(JAXBDateWithOverRule notAfter) {
        this.notAfter = notAfter;
    }
}
