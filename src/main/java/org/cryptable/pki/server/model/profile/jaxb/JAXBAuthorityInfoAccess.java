package org.cryptable.pki.server.model.profile.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import java.util.List;

/**
 * <Authority_Info_Access>
 *   <Distribution_Point Name="AIA1">
 *     <URL>http://ocsp.cryptable.org</URL>
 *     <Access_Method>1</Access_Method>
 *   </Distribution_Point>
 *   <Distribution_Point Name="AIA2">
 *     <URL>http://www.cryptable.org/rootca.der</URL>
 *     <Access_Method>2</Access_Method>
 *   </Distribution_Point>
 * </Authority_Info_Access>
 *
 * Author: davidtillemans
 * Date: 29/12/13
 * Hour: 12:45
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JAXBAuthorityInfoAccess {

    @XmlElement(name = "Distribution_Point")
    private List<JAXBAccessDescription> accessDescriptions;

    public List<JAXBAccessDescription> getAccessDescriptions() {
        return accessDescriptions;
    }

    public void setAccessDescription(List<JAXBAccessDescription> accessDescriptions) {
        this.accessDescriptions = accessDescriptions;
    }
}
