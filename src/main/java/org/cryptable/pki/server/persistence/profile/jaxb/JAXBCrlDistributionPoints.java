package org.cryptable.pki.server.persistence.profile.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import java.util.ArrayList;
import java.util.List;

/**
 * <CRL_Distribution_Points>
 *   <Distribution_Point Name="Distribution 1">
 *     <E_Mail>ca@cryptable.org</E_Mail>
 *     <IP_Address>10.2.3.4</IP_Address>
 *     <Domain_Name>www.cryptable.org</Domain_Name>
 *     <DName>cn=ca, o=cryptable</DName>
 *     <URL>http://www.google.be</URL>
 *     <Add_Issuer_Name/>
 *     <Reason_Codes>
 *       <Key_Compromise/>
 *       <CA_Compromise/>
 *       <Affiliation_Changed/>
 *       <Superseded/>
 *       <Cessation_Of_Operation/>
 *       <Certificate_On_Hold/>
 *     </Reason_Codes>
 *   </Distribution_Point>
 * </CRL_Distribution_Points>
 *
 * Author: davidtillemans
 * Date: 29/12/13
 * Hour: 12:45
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JAXBCrlDistributionPoints {

    @XmlElement(name = "Distribution_Point", type = JAXBDistributionPoint.class)
    private List<JAXBDistributionPoint> distributionPoints = new ArrayList<JAXBDistributionPoint>();

    public List<JAXBDistributionPoint> getDistributionPoints() {
        return distributionPoints;
    }

    public void setDistributionPoints(List<JAXBDistributionPoint> distributionPoints) {
        this.distributionPoints = distributionPoints;
    }
}
