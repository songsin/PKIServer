package org.cryptable.pki.server.business;

import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cryptable.pki.util.PKIKeyStore;
import org.cryptable.pki.util.PKIKeyStoreSingleton;

import java.math.BigInteger;
import java.util.Date;

/**
 * ProcessInitialization action
 *
 * User: davidtillemans
 * Date: 6/07/13
 * Time: 08:53
 */
public class ProcessInitialization {
    private CertReqMsg[] certReqMsgs;
    private PKIKeyStore pkiKeyStore;

    public ProcessInitialization(PKIKeyStore pkiKeyStore) {
        this.pkiKeyStore = pkiKeyStore;
        certReqMsgs = null;
    }

    public ProcessInitialization initialize(PKIBody pkiBody) {

        certReqMsgs = CertReqMessages.getInstance(pkiBody.getContent()).toCertReqMsgArray();

        return this;
    }

    public PKIBody getResponse() throws OperatorCreationException {

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
                certReqMsgs[0].getCertReq().getCertTemplate().getSubject(),
                certReqMsgs[0].getCertReq().getCertTemplate().getPublicKey());
        X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(sigGen);
        CertResponse certResponse = new CertResponse(certReqMsgs[0].getCertReq().getCertReqId(),
                new PKIStatusInfo(PKIStatus.granted),
                new CertifiedKeyPair(new CertOrEncCert(new CMPCertificate(x509CertificateHolder.toASN1Structure()))),
                null);
        CertResponse[] certResponses = new CertResponse[1];
        certResponses[0] = certResponse;

        return new PKIBody(PKIBody.TYPE_INIT_REP, new CertRepMessage(null, certResponses));
    }
}
