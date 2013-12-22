package org.cryptable.pki.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
