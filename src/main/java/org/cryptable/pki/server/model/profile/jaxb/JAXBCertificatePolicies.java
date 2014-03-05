package org.cryptable.pki.server.model.profile.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * <Certificate_Policies Critical="No">
 *   <Certificate_Policy OID="1.2.3.4.1.2.3.4.1">
 *     <Qualifier ID="1.3.6.1.5.5.7.2.1">
 *       <URI>https://www.google.be</URI>
 *     </Qualifier>
 *     <Qualifier ID="1.3.6.1.5.5.7.2.2">
 *       <Organisation>Cryptable</Organisation>
 *       <Notice_Numbers>11,23,44</Notice_Numbers>
 *       <Explicit_Text>This is a test certificate</Explicit_Text>
 *     </Qualifier>
 *   </Certificate_Policy>
 *   <Certificate_Policy OID="2.3.4.2.4.5.1">
 *     <Qualifier ID="1.3.6.1.5.5.7.2.1">
 *       <URI>http://www.cryptable.org/cps.pdf</URI>
 *     </Qualifier>
 *   </Certificate_Policy>
 * </Certificate_Policies>
 * Author: davidtillemans
 * Date: 29/12/13
 * Hour: 12:43
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JAXBCertificatePolicies {

    @XmlAttribute(name="Critical")
    @XmlJavaTypeAdapter(BooleanYesNoAdapter.class)
    private Boolean critical;

    @XmlElement(name = "Certificate_Policy", type = JAXBCertificatePolicy.class)
    private List<JAXBCertificatePolicy> certificatePolicies = new ArrayList<JAXBCertificatePolicy>();

    public Boolean getCritical() {
        return critical;
    }

    public void setCritical(Boolean critical) {
        this.critical = critical;
    }

    public List<JAXBCertificatePolicy> getCertificatePolicies() {
        return certificatePolicies;
    }

    public void setCertificatePolicies(List<JAXBCertificatePolicy> certificatePolicies) {
        this.certificatePolicies = certificatePolicies;
    }

}
