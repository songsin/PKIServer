package org.cryptable.pki.server.business;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cryptable.pki.server.persistence.profile.jaxb.JAXBProfile;
import org.cryptable.pki.util.PKIKeyStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Process the certification message
 *
 * User: davidtillemans
 * Date: 6/07/13
 * Time: 09:33
 * To change this template use File | Settings | File Templates.
 */
public class ProcessCertification {

    final Logger logger = LoggerFactory.getLogger(ProcessCertification.class);

    private PKIKeyStore pkiKeyStore;

    private List<JAXBProfile> certificationProfiles;

    public PKIKeyStore getPkiKeyStore() {
        return pkiKeyStore;
    }

    public void setPkiKeyStore(PKIKeyStore pkiKeyStore) {
        this.pkiKeyStore = pkiKeyStore;
    }

    public List<JAXBProfile> getCertificationProfiles() {
        return certificationProfiles;
    }

    public void setCertificationProfiles(List<JAXBProfile> certificationProfiles) {
        this.certificationProfiles = certificationProfiles;
    }

    /* private methods */
    private CertResponse processRequest(ContentSigner sigGen, CertReqMsg certReqMsg) throws ProcessRequestException {

//        try {
            // Implement special OID and RegControl to pass the profile
            JAXBProfile certificateProfile = certificationProfiles.get(certReqMsg.getCertReq().getCertReqId().getValue().intValue());

            if (certificateProfile == null)
                throw new ProcessRequestException("Unknown profile according to certificate Id");

            X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(
                    JcaX500NameUtil.getSubject(pkiKeyStore.getCACertificate()),
                    // Serial number
                    BigInteger.valueOf(pkiKeyStore.getSecureRandom().nextLong()),
                    // Not Before
                    new Date(System.currentTimeMillis() - 500L * 60 * 60 * 24 * 30),
                    // Not After
                    new Date(System.currentTimeMillis() + (500L * 60 * 60 * 24 * 30)),
                    // subjects name - the same as we are self signed.
                    certReqMsg.getCertReq().getCertTemplate().getSubject(),
                    certReqMsg.getCertReq().getCertTemplate().getPublicKey());

//            for (ASN1ObjectIdentifier oid: certReqMsg.getCertReq().getCertTemplate().getExtensions().getExtensionOIDs()) {
//                Extension extension = certificateProfile.getCertificateProfile()
//                    .validateExtension(oid, certReqMsg.getCertReq().getCertTemplate().getExtensions().getExtension(oid));
//                x509v3CertificateBuilder.addExtension(extension.getExtnId(), extension.isCritical(), extension.getExtnValue());
//            }

            X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(sigGen);

            CertResponse certResponse = new CertResponse(certReqMsg.getCertReq().getCertReqId(),
                    new PKIStatusInfo(PKIStatus.granted),
                    new CertifiedKeyPair(new CertOrEncCert(new CMPCertificate(x509CertificateHolder.toASN1Structure()))),
                    null);

            return certResponse;

//        } catch (CertIOException e) {
//            throw new ProcessRequestException("Processing message error:" + e.getMessage());
//        }
    }

    /* public methods */
    public ProcessCertification(PKIKeyStore pkiKeyStore) {
        this.pkiKeyStore = pkiKeyStore;
    }

    public PKIBody getResponse(PKIBody pkiBody) throws OperatorCreationException, ProcessRequestException {

        CertReqMsg[] certReqMsgs = CertReqMessages.getInstance(pkiBody.getContent()).toCertReqMsgArray();

        // Signer of the certificate
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider(pkiKeyStore.getProvider())
                .build(pkiKeyStore.getCAPrivateKey());

        List<CertResponse> certResponses = new ArrayList<CertResponse>();
        for (CertReqMsg certRepMsg: certReqMsgs) {
            certResponses.add(processRequest(sigGen, certRepMsg));
        }

        return new PKIBody(PKIBody.TYPE_CERT_REP, new CertRepMessage(null, certResponses.toArray(new CertResponse[certResponses.size()])));
    }
}
