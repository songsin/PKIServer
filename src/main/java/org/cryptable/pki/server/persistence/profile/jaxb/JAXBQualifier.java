package org.cryptable.pki.server.persistence.profile.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;

/**
 *
 *     <Qualifier ID="1.3.6.1.5.5.7.2.1">
 *       <URI>https://www.google.be</URI>
 *     </Qualifier>
 *     <Qualifier ID="1.3.6.1.5.5.7.2.2">
 *       <Organisation>Cryptable</Organisation>
 *       <Notice_Numbers>11,23,44</Notice_Numbers>
 *       <Explicit_Text>This is a test certificate</Explicit_Text>
 *     </Qualifier>
 *
 * Author: davidtillemans
 * Date: 2/01/14
 * Hour: 00:15
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JAXBQualifier {

    @XmlAttribute(name="ID")
    private String id;

    @XmlElement(name="URI")
    private String uri;

    @XmlElement(name="Organisation")
    private String organisation;

    @XmlElement(name="Notice_Numbers")
    private String noticeNumbers;

    @XmlElement(name="Explicit_Text")
    private String explicitText;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUri() {
        return uri;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }

    public String getOrganisation() {
        return organisation;
    }

    public void setOrganisation(String organisation) {
        this.organisation = organisation;
    }

    public String getNoticeNumbers() {
        return noticeNumbers;
    }

    public void setNoticeNumbers(String noticeNumbers) {
        this.noticeNumbers = noticeNumbers;
    }

    public String getExplicitText() {
        return explicitText;
    }

    public void setExplicitText(String explicitText) {
        this.explicitText = explicitText;
    }
}
