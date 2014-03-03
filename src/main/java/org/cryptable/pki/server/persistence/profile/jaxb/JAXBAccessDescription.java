package org.cryptable.pki.server.persistence.profile.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

/**
 * <Distribution_Point Name="AIA1">
 *   <URL>http://ocsp.cryptable.org</URL>
 *   <Access_Method>1</Access_Method>
 * </Distribution_Point>
 *
 * Author: davidtillemans
 * Date: 3/03/14
 * Hour: 23:21
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JAXBAccessDescription {

    @XmlElement(name = "URL")
    private String url;

    @XmlElement(name = "Access_Method")
    private Integer accessMethod;

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public Integer getAccessMethod() {
        return accessMethod;
    }

    public void setAccessMethod(Integer accessMethod) {
        this.accessMethod = accessMethod;
    }
}
