/**
 * The MIT License (MIT)
 *
 * Copyright (c) <2013> <Cryptable>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */
package org.cryptable.pki.util;

import org.bouncycastle.asn1.cmp.CMPCertificate;

import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * This class holds the key and certificate material for the authentication
 * and protection of the data
 *
 * User: David Tillemans
 * Date: 1/06/13
 * Time: 13:02
 * To change this template use File | Settings | File Templates.
 */
public class PKIKeyStore {

    private String provider;

    private SecureRandom secureRandom;

    private PrivateKey senderPrivateKey;

    private X509Certificate senderCertificate;

    private PrivateKey caPrivateKey;

    private X509Certificate caCertificate;

    private X509Certificate recipientCertificate;

    private List<X509Certificate> certificateChain;

    private List<CMPCertificate> cmpCertificateChain;

    private X509CRL x509CRL;

    private void init(String provider, String securePRNG) throws NoSuchProviderException, NoSuchAlgorithmException {
        x509CRL = null;
        byte[] seed = SecureRandom.getInstance(securePRNG).generateSeed(64);
        this.provider = provider;
        this.certificateChain = new ArrayList<X509Certificate>();
        this.cmpCertificateChain = new ArrayList<CMPCertificate>();
        this.secureRandom = SecureRandom.getInstance(securePRNG);
        this.secureRandom.setSeed(seed);
    }
    /**
     * Default Constructor
     */
    public PKIKeyStore() throws NoSuchProviderException, NoSuchAlgorithmException {
        init("BC", "SHA1PRNG");
    }

    /**
     * Construct the PKIKeyStore
     * @param senderPrivateKey private key of the sender (RA)
     * @param senderCertificate certificate of the sender (RA)
     * @param recipientCertificate certificate of the receipient (CA or its communication key)
     * @param certificateChain the certificate chain to validate the RA certificate
     */
    public PKIKeyStore(Key senderPrivateKey,
                       Certificate senderCertificate,
                       Key caPrivateKey,
                       Certificate caCertificate,
                       Certificate recipientCertificate,
                       Certificate[] certificateChain) throws NoSuchProviderException, NoSuchAlgorithmException, CertificateEncodingException {
        init("BC", "SHA1PRNG");
        this.senderPrivateKey = (PrivateKey)senderPrivateKey;
        this.senderCertificate = (X509Certificate)senderCertificate;
        this.caCertificate = (X509Certificate)caCertificate;
        this.caPrivateKey = (PrivateKey)caPrivateKey;
        this.recipientCertificate = (X509Certificate)recipientCertificate;
        for (Certificate certificate : certificateChain) {
            this.certificateChain.add((X509Certificate)certificate);
            this.cmpCertificateChain.add(CMPCertificate.getInstance(certificate.getEncoded()));
        }
    }

    /**
     * Construct the PKIKeyStore
     * @param senderPrivateKey private key of the sender (RA)
     * @param senderCertificate certificate of the sender (RA)
     * @param recipientCertificate certificate of the receipient (CA or its communication key)
     * @param certificateChain the certificate chain to validate the RA certificate
     * @param provider the provider name for the cryptographic information
     */
    public PKIKeyStore(Key senderPrivateKey,
                       Certificate senderCertificate,
                       Key caPrivateKey,
                       Certificate caCertificate,
                       Certificate recipientCertificate,
                       Certificate[] certificateChain,
                       String provider,
                       String securePRNG) throws NoSuchProviderException, NoSuchAlgorithmException {
        init(provider, securePRNG);
        this.provider = provider;
        this.senderPrivateKey = (PrivateKey)senderPrivateKey;
        this.senderCertificate = (X509Certificate)senderCertificate;
        this.caCertificate = (X509Certificate)caCertificate;
        this.caPrivateKey = (PrivateKey)caPrivateKey;
        this.recipientCertificate = (X509Certificate)recipientCertificate;
        for (Certificate certificate : certificateChain) {
            this.certificateChain.add((X509Certificate)certificate);
        }
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public SecureRandom getSecureRandom() {
        return secureRandom;
    }

    public void setSecureRandom(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    public X509Certificate getSenderCertificate() {
        return senderCertificate;
    }

    public X509Certificate getRecipientCertificate() {
        return recipientCertificate;
    }

    public List<X509Certificate> getCertificateChain() {
        return certificateChain;
    }

    public PrivateKey getCAPrivateKey() {
        return caPrivateKey;
    }

    public X509Certificate getCACertificate() {
        return caCertificate;
    }

    public CMPCertificate[] getCMPCertificateChain() {
        return this.cmpCertificateChain.toArray(new CMPCertificate[this.cmpCertificateChain.size()]);
    }

    public PrivateKey getSenderPrivateKey() {
        return this.senderPrivateKey;
    }

    public void setSenderPrivateKey(PrivateKey senderPrivateKey) {
        this.senderPrivateKey = senderPrivateKey;
    }

    public X509CRL getX509CRL() {
        return x509CRL;
    }

    public void setX509CRL(X509CRL x509CRL) {
        this.x509CRL = x509CRL;
    }

    public void verifyCertificate(X509Certificate certificate, Date signatureDate) throws PKIKeyStoreException {

        try {
            certificate.checkValidity();

             if (x509CRL != null) {
                 X509CRLEntry x509CRLEntry = x509CRL.getRevokedCertificate(certificate.getSerialNumber());
                 if ((x509CRLEntry != null) &&
                     (x509CRLEntry.getRevocationDate().before(signatureDate))) {
                     throw new PKIKeyStoreException("E: Certificate [" + certificate.getIssuerDN().getName() + ":"
                             + certificate.getSerialNumber().toString() + "] was revoked on "
                             + x509CRLEntry.getRevocationDate().toString() + " because "
                             + x509CRLEntry.getRevocationReason().toString());
                 }

            }
        } catch (CertificateExpiredException e) {
            throw new PKIKeyStoreException("E: Certificate expired of [" + certificate.getIssuerDN().getName() + ":"
                    + certificate.getSerialNumber().toString() + ":"
                    + certificate.getNotAfter().toString() + "]");
        } catch (CertificateNotYetValidException e) {
            throw new PKIKeyStoreException("E: Certificate not yet valid of [" + certificate.getIssuerDN().getName() + ":"
                    + certificate.getSerialNumber().toString() + ":"
                    + certificate.getNotAfter().toString() + "]");
        }
    }
}
