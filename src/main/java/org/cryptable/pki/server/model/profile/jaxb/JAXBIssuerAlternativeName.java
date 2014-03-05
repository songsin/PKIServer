package org.cryptable.pki.server.model.profile.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

/**
 *
 * <Issuer_Alternative_Name>
 *   <E_Mail>ca@cryptable.org</E_Mail>
 *   <IP_Address>10.2.3.4</IP_Address>
 *   <Domain_Name>cryptable.org</Domain_Name>
 *   <DName>cn=alternative,o=cryptable</DName>
 *   <URL>https://www.cryptable.org</URL>
 * </Issuer_Alternative_Name>
 *
 * Author: davidtillemans
 * Date: 29/12/13
 * Hour: 12:45
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JAXBIssuerAlternativeName {
    @XmlElement(name="E_Mail")
    String eMail;

    @XmlElement(name="IP_Address")
    String ipAddress;

    @XmlElement(name="Domain_Name")
    String domainName;

    @XmlElement(name="DName")
    String dName;

    @XmlElement(name="URL")
    String url;

    public String geteMail() {
        return eMail;
    }

    public void seteMail(String eMail) {
        this.eMail = eMail;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getDomainName() {
        return domainName;
    }

    public void setDomainName(String domainName) {
        this.domainName = domainName;
    }

    public String getdName() {
        return dName;
    }

    public void setdName(String dName) {
        this.dName = dName;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}
