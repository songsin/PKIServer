package org.cryptable.pki.server.model.profile;

import org.bouncycastle.asn1.x509.Extension;

import java.util.Date;

/**
 * Constraints profile of the certificate
 *
 * User: davidtillemans
 * Date: 20/12/13
 * Time: 07:00
 *
 */
public class CertificateProfile {

    // Key length constraint
    boolean overRuleKeyLength;
    int useKeyLength;
    int maxKeyLength;
    int minKeyLength;

    // Validity constraint in GMT
    boolean overRuleValidity;
    Date minValidity;
    Date maxValidity;

    // Private Key storage
    boolean storePrivateKey;

    // Publication settings
    String publicationURL;

    public CertificateProfile() {
    }

    /**
     * Get the keyLength if it is between the minimum and maximum keylength and overrule is false.
     * If overrule is true we return the useKeyLength.
     * Otherwise throw an exception
     *
     * @param keyLength
     * @return
     * @throws ProfileException
     */
    public int getKeyLength(int keyLength) throws ProfileException {
        if (overRuleKeyLength)
            return useKeyLength;
        else {
            if ((keyLength >= minKeyLength) && (keyLength <= maxKeyLength))
                return keyLength;
            else {
                throw new ProfileException("Unauthorized keylength [" + minKeyLength + ":" + keyLength + ":" + maxKeyLength + "]");
            }
        }
    }

    /**
     * return the nBefore if overRule is false and nBefore is higher the minValidity
     * Otherwise it returns the minValitity
     *
     * @param nBefore
     * @return
     * @throws ProfileException
     */
    public Date getMinValidity(Date nBefore) throws ProfileException {
        if (overRuleValidity) {
            return minValidity;
        }
        else {
            if (!nBefore.before(minValidity)) {
                return nBefore;
            }
            else {
                throw new ProfileException("Unauthorized nBefore [" + minValidity.toString() + ":" + nBefore.toString() + "]");
            }
        }
    }

    /**
     * return the nAfter if overRule is false and nAfter is lower the maxValidity
     * Otherwise it returns the maxValitity
     *
     * @param nAfter
     * @return
     * @throws ProfileException
     */
    public Date getMaxvalidity(Date nAfter) throws ProfileException {
        if (overRuleValidity) {
            return maxValidity;
        }
        else {
            if (!nAfter.after(maxValidity)) {
                return nAfter;
            }
            else {
                throw new ProfileException("Unauthorized nBefore [" + minValidity.toString() + ":" + nAfter.toString() + "]");
            }
        }
    }

    public boolean getStorePrivateKey() {
        return storePrivateKey;
    }

    public Extension getExtension(Extension extension) {
        // TODO extension handling according to its profile
        return extension;
    }
}
