package org.cryptable.pki.server.persistence.profile.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

/**
 * Key Usage extension of a certificate
 *
 * <Key_Usage>
 *   <Signature>No Overrule</Signature>
 *   <Non_Repudiation>No Overrule</Non_Repudiation>
 *   <Key_Encipherment>No Overrule</Key_Encipherment>
 *   <Data_Encipherment>No Overrule</Data_Encipherment>
 *   <Key_Agreement>No Overrule</Key_Agreement>
 *   <CRL_Signature>No Overrule</CRL_Signature>
 *   <Encipherment_Only>No Overrule</Encipherment_Only>
 *   <Decipherment_Only>No Overrule</Decipherment_Only>
 *   <Key_Certificate_Signature>No Overrule</Key_Certificate_Signature>
 * </Key_Usage>
 *
 * Author: davidtillemans
 * Date: 29/12/13
 * Hour: 12:42
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JAXBKeyUsage {

    @XmlElement(name="Signature")
    private String signature;

    @XmlElement(name="Non_Repudiation")
    private String nonRepudiation;

    @XmlElement(name="Key_Encipherment")
    private String keyEncipherment;

    @XmlElement(name="Data_Encipherment")
    private String dataEncipherment;

    @XmlElement(name="Key_Agreement")
    private String keyAgreement;

    @XmlElement(name="CRL_Signature")
    private String crlSignature;

    @XmlElement(name="Encipherment_Only")
    private String enciphermentOnly;

    @XmlElement(name="Decipherment_Only")
    private String deciphermentOnly;

    @XmlElement(name="Key_Certificate_Signature")
    private String keyCertificateSignature;

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getNonRepudiation() {
        return nonRepudiation;
    }

    public void setNonRepudiation(String nonRepudiation) {
        this.nonRepudiation = nonRepudiation;
    }

    public String getKeyEncipherment() {
        return keyEncipherment;
    }

    public void setKeyEncipherment(String keyEncipherment) {
        this.keyEncipherment = keyEncipherment;
    }

    public String getDataEncipherment() {
        return dataEncipherment;
    }

    public void setDataEncipherment(String dataEncipherment) {
        this.dataEncipherment = dataEncipherment;
    }

    public String getKeyAgreement() {
        return keyAgreement;
    }

    public void setKeyAgreement(String keyAgreement) {
        this.keyAgreement = keyAgreement;
    }

    public String getCrlSignature() {
        return crlSignature;
    }

    public void setCrlSignature(String crlSignature) {
        this.crlSignature = crlSignature;
    }

    public String getEnciphermentOnly() {
        return enciphermentOnly;
    }

    public void setEnciphermentOnly(String enciphermentOnly) {
        this.enciphermentOnly = enciphermentOnly;
    }

    public String getDeciphermentOnly() {
        return deciphermentOnly;
    }

    public void setDeciphermentOnly(String deciphermentOnly) {
        this.deciphermentOnly = deciphermentOnly;
    }

    public String getKeyCertificateSignature() {
        return keyCertificateSignature;
    }

    public void setKeyCertificateSignature(String keyCertificateSignature) {
        this.keyCertificateSignature = keyCertificateSignature;
    }
}
