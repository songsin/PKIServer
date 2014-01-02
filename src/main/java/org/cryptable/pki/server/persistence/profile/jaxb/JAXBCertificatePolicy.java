package org.cryptable.pki.server.persistence.profile.jaxb;


import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import java.util.List;

/**
 *
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
 *
 * Author: davidtillemans
 * Date: 2/01/14
 * Hour: 00:01
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JAXBCertificatePolicy {

    @XmlAttribute(name="OID")
    private String oid;

    @XmlElement(name = "Qualifier", type = JAXBQualifier.class)
    private List<JAXBQualifier> jaxbQualifiers;

    public String getOid() {
        return oid;
    }

    public void setOid(String oid) {
        this.oid = oid;
    }

    public List<JAXBQualifier> getJaxbQualifiers() {
        return jaxbQualifiers;
    }

    public void setJaxbQualifiers(List<JAXBQualifier> jaxbQualifiers) {
        this.jaxbQualifiers = jaxbQualifiers;
    }
}
