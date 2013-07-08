package org.cryptable.pki.util;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;

/**
 * Singleton around PKIKeyStore
 *
 * User: davidtillemans
 * Date: 8/06/13
 * Time: 18:41
 * To change this template use File | Settings | File Templates.
 */
public class PKIKeyStoreSingleton {
    static private PKIKeyStore pkiKeyStore;

    private PKIKeyStoreSingleton() {
        pkiKeyStore = null;
    }

    static public void init(Key senderPrivateKey,
                            Certificate senderCertificate,
                            Key caPrivateKey,
                            Certificate caCertificate,
                            Certificate recipientCertificate,
                            Certificate[] certificateChain,
                            String provider,
                            String securePRNG) throws NoSuchProviderException, NoSuchAlgorithmException {

        pkiKeyStore = new PKIKeyStore(senderPrivateKey,
                senderCertificate,
                caPrivateKey,
                caCertificate,
                recipientCertificate,
                certificateChain,
                provider,
                securePRNG);
    }
    static public PKIKeyStore getInstance() {
        return pkiKeyStore;
    }
}
