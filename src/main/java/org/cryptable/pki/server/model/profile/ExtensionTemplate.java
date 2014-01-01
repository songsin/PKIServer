package org.cryptable.pki.server.model.profile;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x509.Extension;
import org.cryptable.pki.server.model.profile.Result;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

/**
 * Author: davidtillemans
 * Date: 29/12/13
 * Hour: 13:18
 */
public interface ExtensionTemplate {

    /**
     * Return the Object identifier of the extension in question
     * @return
     */
    ASN1ObjectIdentifier getExtensionOID();

    /**
     * Validate the extension and return the updated extension if necessary
     * in the result VALID or OVERRULED
     *
     * @param extension
     * @return
     */
    Result validateExtension(Extension extension) throws IOException, NoSuchAlgorithmException;

    /**
     * Set the certificate template to be used within the extension
     *
     * @param certTemplate
     */
    void initialize(CertTemplate certTemplate) throws ProfileException;

    /**
     * Returns the extension with the optional
     *
     * @return
     */
    Result getExtension() throws IOException, NoSuchAlgorithmException;

    /**
     * Returns the criticality of the extension
     *
     * @return
     */
    Boolean getCriticalility();

}
