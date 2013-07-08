package org.cryptable.pki.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.Security;
import java.security.cert.CRLException;
import java.util.Date;

/**
 * This Unit test tests the PKIKeyStore
 * User: davidtillemans
 * Date: 16/06/13
 * Time: 18:10
 * To change this template use File | Settings | File Templates.
 */
public class PKIKeyStoreTest {

    private PKIKeyStore pkiKeyStore;
    private GeneratePKI pki;

    @Before
    public void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        pki = new GeneratePKI();
        pki.createPKI();

        pkiKeyStore = new PKIKeyStore(pki.getRACertPrivateKey(), pki.getRACert(), pki.getSubCACertPrivateKey(), pki.getSubCACert(), pki.getSubCACert(), pki.getCertificateChain());
        pkiKeyStore.setX509CRL(pki.getX509CRL());
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test(expected = PKIKeyStoreException.class)
    public void testValidity() throws PKIKeyStoreException {
        pkiKeyStore.verifyCertificate(pki.getExpiredCert(), new Date());
    }

    @Test(expected = PKIKeyStoreException.class)
    public void testRevocation() throws PKIKeyStoreException, CRLException, IOException {
        pkiKeyStore.verifyCertificate(pki.getRevokedCert(), new Date());
    }

    @Test(expected = PKIKeyStoreException.class)
    public void testNotYetValid() throws PKIKeyStoreException {
        pkiKeyStore.verifyCertificate(pki.getNotYetValidCert(), new Date());
    }
}
