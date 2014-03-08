package org.cryptable.pki.util;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;

/**
 * Author: davidtillemans
 * Date: 1/03/14
 * Hour: 08:31
 */
public class ASN1Utils {
    /**
     * Convert general name der octet to IP address
     *
     * @param generalName
     * @return
     */
    static public String derToIPString(GeneralName generalName) {
        byte[] ipAddress = DEROctetString.getInstance(generalName.getName()).getOctets();
        int ip1 = ipAddress[0] & 0xFF;
        int ip2 = ipAddress[1] & 0xFF;
        int ip3 = ipAddress[2] & 0xFF;
        int ip4 = ipAddress[3] & 0xFF;
        String ip = ip1 + "." + ip2 + "." + ip3 + "." +ip4;

        return ip;
    }

    /**
     * parse a GeneralNames structure to a Map of Strings, Strings
     *
     * @param generalNames
     * @return
     */
    static public Map<Integer, String> parseGeneralNames(GeneralNames generalNames) {
        Map<Integer, String> result = new HashMap<>();

        for (GeneralName generalName : generalNames.getNames()) {
            if (generalName.getTagNo() == GeneralName.iPAddress) {
                result.put(GeneralName.iPAddress, derToIPString(generalName));
            }
            if (generalName.getTagNo() == GeneralName.rfc822Name) {
                String rfc822Name = DERIA5String.getInstance(generalName.getName()).getString();
                result.put(GeneralName.rfc822Name, rfc822Name);
            }
            if (generalName.getTagNo() == GeneralName.directoryName) {
                X500Name directoryName = X500Name.getInstance(generalName.getName());
                result.put(GeneralName.directoryName, directoryName.toString());
            }
            if (generalName.getTagNo() == GeneralName.dNSName) {
                String dNSName = DERIA5String.getInstance(generalName.getName()).getString();
                result.put(GeneralName.dNSName, dNSName);
            }
            if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                String uniformResourceIdentifier = DERIA5String.getInstance(generalName.getName()).getString();
                result.put(GeneralName.uniformResourceIdentifier, uniformResourceIdentifier);
            }
        }

        return result;
    }
}
