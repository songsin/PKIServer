package org.cryptable.pki.server.persistence.profile.jaxb;

import javax.xml.bind.annotation.*;

/**
 * Constraints profile of the certificate
 *
 * <Profile ID="9" Name="Everything">
 *
 *   <Certificate>
 *   ...
 *   </Certificate>
 *
 *   <PIN_Code>
 *   ...
 *   </PIN_Code>
 *
 *   <CRL>
 *   ...
 *   </CRL>
 *
 *   <Publication>
 *   ...
 *   </Publication>
 *
 *   <Roles>
 *   ...
 *   </Roles>
 *
 *   <Key_Origin Selectable="Yes">Remote</Key_Origin>
 *
 * </Profile>
 *
 * User: davidtillemans
 * Date: 20/12/13
 * Time: 07:00
 *
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name="Profile")
public class JAXBProfile {

    @XmlAttribute(name="ID")
    protected int id;

    @XmlAttribute(name="Name")
    protected String name;

    @XmlElement(name="Certificate")
    protected JAXBCertificate certificateProfile;

    @XmlElement(name="PIN_Code")
    protected JAXBPINcode pinCodeProfile;

    @XmlElement(name="CRL")
    protected JAXBCRL crlProfile;

    @XmlElement(name="Publication")
    protected JAXBPublication publicationProfile;

    @XmlElement(name="Roles")
    protected JAXBRoles rolesProfile;

    @XmlElement(name="Key_Origin")
    protected JAXBKeyOrigin keyOriginProfile;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public JAXBCertificate getCertificateProfile() {
        return certificateProfile;
    }

    public void setCertificateProfile(JAXBCertificate certificateProfile) {
        this.certificateProfile = certificateProfile;
    }

    public JAXBPINcode getPinCodeProfile() {
        return pinCodeProfile;
    }

    public void setPinCodeProfile(JAXBPINcode pinCodeProfile) {
        this.pinCodeProfile = pinCodeProfile;
    }

    public JAXBCRL getCrlProfile() {
        return crlProfile;
    }

    public void setCrlProfile(JAXBCRL crlProfile) {
        this.crlProfile = crlProfile;
    }

    public JAXBPublication getPublicationProfile() {
        return publicationProfile;
    }

    public void setPublicationProfile(JAXBPublication publicationProfile) {
        this.publicationProfile = publicationProfile;
    }

    public JAXBRoles getRolesProfile() {
        return rolesProfile;
    }

    public void setRolesProfile(JAXBRoles rolesProfile) {
        this.rolesProfile = rolesProfile;
    }

    public JAXBKeyOrigin getKeyOriginProfile() {
        return keyOriginProfile;
    }

    public void setKeyOriginProfile(JAXBKeyOrigin keyOriginProfile) {
        this.keyOriginProfile = keyOriginProfile;
    }
}