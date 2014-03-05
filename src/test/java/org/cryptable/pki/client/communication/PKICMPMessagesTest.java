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
package org.cryptable.pki.client.communication;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.jcajce.JceCRMFEncryptorBuilder;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;
import org.cryptable.pki.util.GeneratePKI;
import org.cryptable.pki.util.PKIKeyStore;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.*;
import java.util.*;

public class PKICMPMessagesTest {

	private GeneratePKI pki;
    private String jksFilename;
    private PKIKeyStore pkiKeyStoreCA;
    private PKIKeyStore pkiKeyStoreRA;

	@Before
	public void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        pki = new GeneratePKI();
        pki.createPKI();
        jksFilename = pki.storeJKS();

        pkiKeyStoreCA = new PKIKeyStore(pki.getSubCACertPrivateKey(), pki.getSubCACert(), pki.getSubCACertPrivateKey(), pki.getSubCACert(), pki.getRACert(), pki.getCertificateChain());
        pkiKeyStoreRA = new PKIKeyStore(pki.getRACertPrivateKey(), pki.getRACert(), pki.getSubCACertPrivateKey(), pki.getSubCACert(), pki.getSubCACert(), pki.getCertificateChain());
   }

	@After
	public void tearDown() throws Exception {
	}

//    @Test
//    public void testKeyGeneration() throws NoSuchProviderException, NoSuchAlgorithmException {
//        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", "BC");
//        kGen.initialize(8192);
//        KeyPair kp = kGen.generateKeyPair();
//        System.out.print(kp.getPrivate().toString());
//    }

    //The test response creation for testing the decoding of the responses
    private byte[] createProtectedPKIMessage(byte[] senderNonce, byte[] transactionId, PKIBody pkiBody) throws CMPException, OperatorCreationException, IOException, CertificateEncodingException {
        byte[] recipientNonce = new byte[64];

        pkiKeyStoreCA.getSecureRandom().nextBytes(recipientNonce);

        ContentSigner signer = new JcaContentSignerBuilder("SHA1WithRSAEncryption").setProvider(pkiKeyStoreCA.getProvider()).build(pkiKeyStoreCA.getSenderPrivateKey());
        ProtectedPKIMessage message = new ProtectedPKIMessageBuilder(new GeneralName(JcaX500NameUtil.getSubject(pkiKeyStoreCA.getSenderCertificate())),
                new GeneralName(JcaX500NameUtil.getSubject(pkiKeyStoreCA.getRecipientCertificate())))
                .setMessageTime(new Date())
                .setSenderNonce(recipientNonce)
                .setRecipNonce(senderNonce)
                .setTransactionID(transactionId)
                .addCMPCertificate(new X509CertificateHolder(pkiKeyStoreCA.getSenderCertificate().getEncoded()))
                .setBody(pkiBody)
                .build(signer);

        return message.toASN1Structure().getEncoded();
    }

    private byte[] createInitializationRespons1(byte[] senderNonce, byte[] transactionId) throws CMPException, CertificateEncodingException, OperatorCreationException, IOException {
        X509CertificateHolder x509CertificateHolder = new JcaX509CertificateHolder(pki.getTestUser3Cert());

        // Body
        CertResponse certResponse = new CertResponse(new ASN1Integer(0),
                new PKIStatusInfo(PKIStatus.granted),
                new CertifiedKeyPair(new CertOrEncCert(new CMPCertificate(x509CertificateHolder.toASN1Structure()))),
                null);
        CertResponse[] certResponses = new CertResponse[1];
        certResponses[0] = certResponse;

        PKIBody pkiBody = new PKIBody(PKIBody.TYPE_INIT_REP, new CertRepMessage(pkiKeyStoreCA.getCMPCertificateChain(), certResponses));

        return createProtectedPKIMessage(senderNonce, transactionId, pkiBody);

    }

    private byte[] createInitializationRespons2(byte[] senderNonce, byte[] transactionId) throws CMPException, CertificateEncodingException, OperatorException, IOException, CRMFException {
        X509CertificateHolder x509CertificateHolder = new JcaX509CertificateHolder(pki.getTestUser3Cert());

        //encrypt Private Key
        KeyWrapper keyWrapper = new JceAsymmetricKeyWrapper(pkiKeyStoreCA.getRecipientCertificate().getPublicKey()).setProvider("BC");
        OutputEncryptor encryptor = new JceCRMFEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider("BC").build();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream eOut = encryptor.getOutputStream(bOut);
        eOut.write(pki.getTestUser3CertPrivateKey().getEncoded());
        eOut.close();

        AlgorithmIdentifier intendedAlg = null;
        AlgorithmIdentifier symmAlg = encryptor.getAlgorithmIdentifier();
        DERBitString encSymmKey;
        keyWrapper.generateWrappedKey(encryptor.getKey());
        encSymmKey = new DERBitString(keyWrapper.generateWrappedKey(encryptor.getKey()));

        AlgorithmIdentifier keyAlg = keyWrapper.getAlgorithmIdentifier();
        ASN1OctetString valueHint = null;
        DERBitString encValue = new DERBitString(bOut.toByteArray());

        EncryptedValue encryptedPrivateKey = new EncryptedValue(intendedAlg, symmAlg, encSymmKey, keyAlg, valueHint, encValue);

        // Body
        CertResponse certResponse = new CertResponse(new ASN1Integer(0),
                new PKIStatusInfo(PKIStatus.granted),
                new CertifiedKeyPair(new CertOrEncCert(new CMPCertificate(x509CertificateHolder.toASN1Structure())),
                        encryptedPrivateKey,
                        null),
                null);
        CertResponse[] certResponses = new CertResponse[1];
        certResponses[0] = certResponse;

        PKIBody pkiBody = new PKIBody(PKIBody.TYPE_INIT_REP, new CertRepMessage(pkiKeyStoreCA.getCMPCertificateChain(), certResponses));

        return createProtectedPKIMessage(senderNonce, transactionId, pkiBody);

    }

    private byte[] createRevocationRespons1(byte[] senderNonce, byte[] transactionId) throws CRLException, CMPException, CertificateEncodingException, OperatorCreationException, IOException {

        RevRepContentBuilder revRepContentBuilder = new RevRepContentBuilder();
        revRepContentBuilder.add(new PKIStatusInfo(PKIStatus.granted),
                new CertId(new GeneralName(JcaX500NameUtil.getIssuer(pki.getRevokedCert())),
                           pki.getRevokedCert().getSerialNumber()));
        revRepContentBuilder.addCrl(new JcaX509CRLHolder(pki.getX509CRL()).toASN1Structure());

        PKIBody pkiBody = new PKIBody(PKIBody.TYPE_REVOCATION_REP, revRepContentBuilder.build());

        return createProtectedPKIMessage(senderNonce, transactionId, pkiBody);

    }

}
