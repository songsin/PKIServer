package org.cryptable.pki.server.business;

import java.util.Date;

/**
 * Constraints profile of the certificate
 * User: davidtillemans
 * Date: 20/12/13
 * Time: 07:00
 * To change this template use File | Settings | File Templates.
 */
public class CertificateProfile {

    // Key length constraint
    int maxKeyLength;
    int minKeyLength;

    // Validity constraint in GMT
    Date minCertificate;
    Date maxCertificate;

    // Private Key storage
    boolean storePrivate;

    // Publication settings
    String publicationURL;

    public CertificateProfile() {

    }

}
