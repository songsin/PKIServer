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
package org.cryptable.pki.server.presentation.communication;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.cmp.*;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.jcajce.JceCRMFEncryptorBuilder;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.KeyWrapper;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;
import org.cryptable.pki.util.PKIKeyStore;
import org.cryptable.pki.util.PKIKeyStoreException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.*;
import java.text.ParseException;
import java.util.*;

/**
 * The messages class to process the PKI system calls
 *
 * User: davidtillemans
 * Date: 1/06/13
 * Time: 12:33
 * To change this template use File | Settings | File Templates.
 */
public class PKICMPMessages {
    public static final int TRANSACTIONID_SIZE = 64;

    private PKIKeyStore pkiKeyStore;

    private byte[] senderNonce;

    private byte[] recipientNonce;

    private byte[] transactionId;

    private BigInteger certificateID;

    private Extension[] extensions;

    private OptionalValidity optionalValidity;

    public PKICMPMessages() {
        transactionId = null;
        senderNonce = null;
        recipientNonce = null;
        extensions = null;
        optionalValidity = null;
    }

    public PKIKeyStore getPkiKeyStore() {
        return pkiKeyStore;
    }

    public void setPkiKeyStore(PKIKeyStore keyStore) {
        this.pkiKeyStore = keyStore;
    }

    public BigInteger getCertificateID() {
        return certificateID;
    }

    public void setCertificateID(BigInteger certificateID) {
        this.certificateID = certificateID;
    }

    public void setTransactionId(byte[] transactionId) {
        this.transactionId = transactionId.clone();
    }

    public byte[] getTransactionId() {
        return this.transactionId;
    }

    public byte[] getSenderNonce() {
        return senderNonce;
    }

    public byte[] getRecipientNonce() {
        return senderNonce;
    }

    public Extension[] getExtensions() {
        return extensions;
    }

    public void setExtensions(Extension[] extensions) {
        this.extensions = extensions;
    }

    public OptionalValidity getOptionalValidity() {
        return optionalValidity;
    }

    public void setOptionalValidity(OptionalValidity optionalValidity) {
        this.optionalValidity = optionalValidity;
    }

    public void setValidity(Date notBefore, Date notAfter) {
        this.optionalValidity = new OptionalValidity(new Time(notBefore), new Time(notAfter));
    }

    private byte[] createProtectedPKIMessage(PKIBody pkiBody) throws CMPException, OperatorCreationException, IOException, CertificateEncodingException, PKICMPMessageException {

        senderNonce = new byte[TRANSACTIONID_SIZE];

        pkiKeyStore.getSecureRandom().nextBytes(senderNonce);

        if (transactionId == null) {
            transactionId = new byte[TRANSACTIONID_SIZE];
            pkiKeyStore.getSecureRandom().nextBytes(transactionId);
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA1WithRSAEncryption").setProvider(pkiKeyStore.getProvider()).build(pkiKeyStore.getSenderPrivateKey());
        ProtectedPKIMessage message = new ProtectedPKIMessageBuilder(new GeneralName(JcaX500NameUtil.getSubject(pkiKeyStore.getSenderCertificate())),
                new GeneralName(JcaX500NameUtil.getSubject(pkiKeyStore.getRecipientCertificate())))
                .setMessageTime(new Date())
                .setSenderNonce(senderNonce)
                .setTransactionID(transactionId)
                .addCMPCertificate(new X509CertificateHolder(pkiKeyStore.getSenderCertificate().getEncoded()))
                .setBody(pkiBody)
                .build(signer);

        return message.toASN1Structure().getEncoded();
    }

    /**
     * The message to decode a certification response
     * The checkRepNonce is checked on responses when the CA has send a message. For example: certificateConfirm
     *
     * @param message the response message
     * @return
     * @throws IOException
     * @throws PKICMPMessageException
     * @throws CertificateException
     * @throws OperatorCreationException
     * @throws CMPException
     * @throws PKIKeyStoreException
     * @throws ParseException
     */
    public PKICMPRequest processRequest(byte[] message, boolean checkRepNonce) throws IOException, PKICMPMessageException, CertificateException, OperatorCreationException, CMPException, PKIKeyStoreException, ParseException {
        ProtectedPKIMessage pkiMessage = new ProtectedPKIMessage(new GeneralPKIMessage(message));

        /* Verify Signature */
        ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                .setProvider(pkiKeyStore.getProvider())
                .build(pkiKeyStore.getRecipientCertificate());

        if (!pkiMessage.verify(verifierProvider)) {
            throw new PKICMPMessageException("E: Verification failed, this is an untrusted Message of [" + pkiMessage.getHeader().getSender() + "]");
        }

        if (pkiMessage.getHeader().getSenderNonce().getOctets() != null) {
            recipientNonce = pkiMessage.getHeader().getSenderNonce().getEncoded();
        }

        if (checkRepNonce) {
            if ((pkiMessage.getHeader().getRecipNonce().getOctets() != null) &&
                    !Arrays.equals(senderNonce, pkiMessage.getHeader().getRecipNonce().getOctets())) {
                throw new PKICMPMessageException("E: Recipient Nonce in response does not correspond with Sender Nonce in request!");
            }
        }

        if (pkiMessage.getHeader().getMessageTime() != null) {
            pkiKeyStore.verifyCertificate(pkiKeyStore.getRecipientCertificate(), pkiMessage.getHeader().getMessageTime().getDate());
        } else {
            pkiKeyStore.verifyCertificate(pkiKeyStore.getRecipientCertificate(), new Date());
        }

        PKICMPRequest pkicmpRequest = new PKICMPRequest();

        pkicmpRequest.setPkiBody(pkiMessage.getBody());
        pkicmpRequest.setPkiHeader(pkiMessage.getHeader());

        X509CertificateHolder[] x509CertificateHolders = pkiMessage.getCertificates();
        JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter();
        for (X509CertificateHolder x509CertificateHolder : x509CertificateHolders) {
            pkicmpRequest.getX509CertifificateList().add(jcaX509CertificateConverter.getCertificate(x509CertificateHolder));

        }

        return pkicmpRequest;
    }

    private CertResponse certifyWithPublicKey(CertRequest certRequest) throws OperatorCreationException {
        // Signer of the certificate
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider(pkiKeyStore.getProvider())
                .build(pkiKeyStore.getSenderPrivateKey());

        X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(
                JcaX500NameUtil.getSubject(pkiKeyStore.getSenderCertificate()),
                BigInteger.valueOf(pkiKeyStore.getSecureRandom().nextLong()),
                // Not Before
                new Date(System.currentTimeMillis() - 500L * 60 * 60 * 24 * 30),
                // Not After
                new Date(System.currentTimeMillis() + (500L * 60 * 60 * 24 * 30)),
                // subjects name - the same as we are self signed.
                certRequest.getCertTemplate().getSubject(),
                certRequest.getCertTemplate().getPublicKey());

        X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(sigGen);
        CertResponse certResponse = new CertResponse(certRequest.getCertReqId(),
                new PKIStatusInfo(PKIStatus.granted),
                new CertifiedKeyPair(new CertOrEncCert(new CMPCertificate(x509CertificateHolder.toASN1Structure()))),
                null);

        return certResponse;
    }

    private EncryptedValue encryptPrivateKey(PrivateKey privateKey) throws CRMFException, IOException, OperatorException {
        //encrypt Private Key
        KeyWrapper keyWrapper = new JceAsymmetricKeyWrapper(pkiKeyStore.getRecipientCertificate().getPublicKey()).setProvider("BC");
        OutputEncryptor encryptor = new JceCRMFEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider("BC").build();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream eOut = encryptor.getOutputStream(bOut);
        eOut.write(privateKey.getEncoded());
        eOut.close();

        AlgorithmIdentifier intendedAlg = null;
        AlgorithmIdentifier symmAlg = encryptor.getAlgorithmIdentifier();
        DERBitString encSymmKey;
        keyWrapper.generateWrappedKey(encryptor.getKey());
        encSymmKey = new DERBitString(keyWrapper.generateWrappedKey(encryptor.getKey()));

        AlgorithmIdentifier keyAlg = keyWrapper.getAlgorithmIdentifier();
        ASN1OctetString valueHint = null;
        DERBitString encValue = new DERBitString(bOut.toByteArray());

        return new EncryptedValue(intendedAlg, symmAlg, encSymmKey, keyAlg, valueHint, encValue);

    }

    private CertResponse certifyWithKeyGeneration(CertRequest certRequest) throws NoSuchAlgorithmException, NoSuchProviderException, CRMFException, IOException, OperatorException {
        // Key generation
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", "BC");
        kGen.initialize(2048);
        KeyPair kp = kGen.generateKeyPair();

        // Signer of the certificate
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider(pkiKeyStore.getProvider())
                .build(pkiKeyStore.getSenderPrivateKey());

        X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(
                JcaX500NameUtil.getSubject(pkiKeyStore.getSenderCertificate()),
                BigInteger.valueOf(pkiKeyStore.getSecureRandom().nextLong()),
                // Not Before
                new Date(System.currentTimeMillis() - 500L * 60 * 60 * 24 * 30),
                // Not After
                new Date(System.currentTimeMillis() + (500L * 60 * 60 * 24 * 30)),
                // subjects name - the same as we are self signed.
                certRequest.getCertTemplate().getSubject(),
                new SubjectPublicKeyInfo(ASN1Sequence.getInstance(kp.getPublic().getEncoded())));

        X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(sigGen);
        CertResponse certResponse = new CertResponse(certRequest.getCertReqId(),
                new PKIStatusInfo(PKIStatus.granted),
                new CertifiedKeyPair(new CertOrEncCert(new CMPCertificate(x509CertificateHolder.toASN1Structure())),
                        encryptPrivateKey(kp.getPrivate()),
                        null),
                null);

        return certResponse;
    }

    /**
     * process the certification of a certification request
     *
     * @param pkiBody
     * @return
     * @throws CertificateEncodingException
     * @throws CMPException
     * @throws IOException
     * @throws PKICMPMessageException
     * @throws OperatorException
     * @throws CRMFException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */
    public byte[] processCertificationRequest(PKIBody pkiBody) throws CertificateEncodingException, CMPException, IOException, PKICMPMessageException, NoSuchAlgorithmException, NoSuchProviderException, CRMFException, OperatorException {

        CertReqMsg[] certReqMsgs = CertReqMessages.getInstance(pkiBody.getContent()).toCertReqMsgArray();

        CertReqMsg certReqMsg = certReqMsgs[0];
        CertResponse certResponse = null;
        if (certReqMsg.getCertReq().getCertTemplate().getPublicKey() == null) {
            certResponse = certifyWithKeyGeneration(certReqMsg.getCertReq());
        } else {
            certResponse = certifyWithPublicKey(certReqMsg.getCertReq());
        }

        CertResponse[] certResponses = new CertResponse[1];
        certResponses[0] = certResponse;

        return createProtectedPKIMessage(new PKIBody(pkiBody.getType(), new CertRepMessage(null, certResponses)));
    }

    /**
     * process the revocation response, retrieve the CRL from the body
     *
     * @param pkiBody the message body from the PKI message
     * @return
     * @throws CRLException
     */
    X509CRL processRevocationRequest(PKIBody pkiBody) throws CRLException {
        JcaX509CRLConverter jcaX509CRLConverter = new JcaX509CRLConverter();

        RevRepContent revRepContent = RevRepContent.getInstance(pkiBody.getContent());

        return jcaX509CRLConverter.getCRL(new X509CRLHolder(revRepContent.getCrls()[0]));
    }

}
