package org.cryptable.pki.server.model.profile.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;

/**
 * <Distribution_Point Name="Distribution 1">
 *   <E_Mail>ca@cryptable.org</E_Mail>
 *   <IP_Address>10.2.3.4</IP_Address>
 *   <Domain_Name>www.cryptable.org</Domain_Name>
 *   <DName>cn=ca, o=cryptable</DName>
 *   <URL>http://www.google.be</URL>
 *   <Add_Issuer_Name/>
 *   <Reason_Codes>
 *     <Key_Compromise/>
 *     <CA_Compromise/>
 *     <Affiliation_Changed/>
 *     <Superseded/>
 *     <Cessation_Of_Operation/>
 *     <Certificate_On_Hold/>
 *   </Reason_Codes>
 * </Distribution_Point>
 * <Distribution_Point Name="Distribution 2">
 *   <Relative_DName>/O=Cryptable</Relative_DName>
 *   <Reason_Codes>
 *     <Affiliation_Changed/>
 *     <Cessation_Of_Operation/>
 *     <Certificate_On_Hold/>
 *   </Reason_Codes>
 * </Distribution_Point>
 *
 * Author: davidtillemans
 * Date: 1/03/14
 * Hour: 09:50
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JAXBDistributionPoint {

    @XmlAttribute(name="Name")
    private String name;

    @XmlElement(name = "E_Mail")
    private String eMail;

    @XmlElement(name = "IP_Address")
    private String ipAddress;

    @XmlElement(name = "Domain_Name")
    private String domainName;

    @XmlElement(name = "DName")
    private String dName;

    @XmlElement(name = "URL")
    private String url;

    @XmlElement(name = "Relative_DName")
    private String relativeDName;

    @XmlElement(name = "Add_Issuer_Name", defaultValue="true")
    private Boolean addIssuerName;

    @XmlElement(name = "Reason_Codes", type = JAXBReasonCodes.class)
    private JAXBReasonCodes reasonCodes;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDomainName() {
        return domainName;
    }

    public void setDomainName(String domainName) {
        this.domainName = domainName;
    }

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

    public String getRelativeDName() {
        return relativeDName;
    }

    public void setRelativeDName(String relativeDName) {
        this.relativeDName = relativeDName;
    }

    public Boolean getAddIssuerName() {
        return addIssuerName != null;
    }

    public void setAddIssuerName(Boolean addIssuerName) {
        this.addIssuerName = addIssuerName;
    }

    public JAXBReasonCodes getReasonCodes() {
        return reasonCodes;
    }

    public void setReasonCodes(JAXBReasonCodes reasonCodes) {
        this.reasonCodes = reasonCodes;
    }
}
