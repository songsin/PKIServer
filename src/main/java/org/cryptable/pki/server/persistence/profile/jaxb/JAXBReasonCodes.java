package org.cryptable.pki.server.persistence.profile.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

/**
 * <Reason_Codes>
 *   <Key_Compromise/>
 *   <CA_Compromise/>
 *   <Affiliation_Changed/>
 *   <Superseded/>
 *   <Cessation_Of_Operation/>
 *   <Certificate_On_Hold/>
 * </Reason_Codes>
 *
 * Author: davidtillemans
 * Date: 1/03/14
 * Hour: 10:11
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JAXBReasonCodes {

    @XmlElement(name="Key_Compromise", defaultValue = "true", nillable = true)
    private Boolean keyCompromise;

    @XmlElement(name="CA_Compromise", defaultValue = "true", nillable = true)
    private Boolean caCompromise;

    @XmlElement(name="Affiliation_Changed", defaultValue = "true", nillable = true)
    private Boolean affiliationChanged;

    @XmlElement(name="Superseded", defaultValue = "true", nillable = true)
    private Boolean superseded;

    @XmlElement(name="Cessation_Of_Operation", defaultValue = "true", nillable = true)
    private Boolean cessationOfOperation;

    @XmlElement(name="Certificate_On_Hold", defaultValue = "true", nillable = true)
    private Boolean certificateOnHold;

    public Boolean getKeyCompromise() {
        return keyCompromise != null;
    }

    public void setKeyCompromise(Boolean keyCompromise) {
        this.keyCompromise = keyCompromise;
    }

    public Boolean getCaCompromise() {
        return caCompromise != null;
    }

    public void setCaCompromise(Boolean caCompromise) {
        this.caCompromise = caCompromise;
    }

    public Boolean getAffiliationChanged() {
        return affiliationChanged != null;
    }

    public void setAffiliationChanged(Boolean affiliationChanged) {
        this.affiliationChanged = affiliationChanged;
    }

    public Boolean getSuperseded() {
        return superseded != null;
    }

    public void setSuperseded(Boolean superseded) {
        this.superseded = superseded;
    }

    public Boolean getCessationOfOperation() {
        return cessationOfOperation != null;
    }

    public void setCessationOfOperation(Boolean cessationOfOperation) {
        this.cessationOfOperation = cessationOfOperation;
    }

    public Boolean getCertificateOnHold() {
        return certificateOnHold  != null;
    }

    public void setCertificateOnHold(Boolean certificateOnHold) {
        this.certificateOnHold = certificateOnHold;
    }
}
