package org.cryptable.pki.server.model.profile.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * XML definition of subject alternative name
 *
 * <Subject_Alternative_Name>
 *   <E_Mail>Leave</E_Mail>
 *   <IP_Address>Delete</IP_Address>
 *   <Domain_Name>Leave</Domain_Name>
 *   <DName>Delete</DName>
 *   <URL>Leave</URL>
 *   <OtherName>User Principal Name</OtherName>
 * </Subject_Alternative_Name>
 *
 * Author: davidtillemans
 * Date: 29/12/13
 * Hour: 12:45
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JAXBSubjectAlternativeName {

    @XmlElement(name="E_Mail")
    @XmlJavaTypeAdapter(BooleanLeaveDeleteAdapter.class)
    private Boolean keepEmail;

    @XmlElement(name="IP_Address")
    @XmlJavaTypeAdapter(BooleanLeaveDeleteAdapter.class)
    private Boolean keepIPAdress;

    @XmlElement(name="Domain_Name")
    @XmlJavaTypeAdapter(BooleanLeaveDeleteAdapter.class)
    private Boolean keepDomainName;

    @XmlElement(name="DName")
    @XmlJavaTypeAdapter(BooleanLeaveDeleteAdapter.class)
    private Boolean keepDName;

    @XmlElement(name="URL")
    @XmlJavaTypeAdapter(BooleanLeaveDeleteAdapter.class)
    private Boolean keepURL;

    @XmlElement(name="OtherName")
    private String otherName;

    public Boolean getKeepEmail() {
        return keepEmail;
    }

    public void setKeepEmail(Boolean keepEmail) {
        this.keepEmail = keepEmail;
    }

    public Boolean getKeepIPAdress() {
        return keepIPAdress;
    }

    public void setKeepIPAdress(Boolean keepIPAdress) {
        this.keepIPAdress = keepIPAdress;
    }

    public Boolean getKeepDomainName() {
        return keepDomainName;
    }

    public void setKeepDomainName(Boolean keepDomainName) {
        this.keepDomainName = keepDomainName;
    }

    public Boolean getKeepDName() {
        return keepDName;
    }

    public void setKeepDName(Boolean keepDName) {
        this.keepDName = keepDName;
    }

    public Boolean getKeepURL() {
        return keepURL;
    }

    public void setKeepURL(Boolean keepURL) {
        this.keepURL = keepURL;
    }

    public String getOtherName() {
        return otherName;
    }

    public void setOtherName(String otherName) {
        this.otherName = otherName;
    }
}
