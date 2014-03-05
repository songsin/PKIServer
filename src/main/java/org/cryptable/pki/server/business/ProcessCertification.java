package org.cryptable.pki.server.business;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.util.Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cryptable.pki.server.model.profile.ProfileException;
import org.cryptable.pki.server.model.profile.Profiles;
import org.cryptable.pki.server.model.profile.Profile;
import org.cryptable.pki.server.model.profile.Result;
import org.cryptable.pki.util.PKIKeyStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
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

    private Profiles certificationProfiles;

    public PKIKeyStore getPkiKeyStore() {
        return pkiKeyStore;
    }

    public void setPkiKeyStore(PKIKeyStore pkiKeyStore) {
        this.pkiKeyStore = pkiKeyStore;
    }

    public Profiles getCertificationProfiles() {
        return certificationProfiles;
    }

    public void setCertificationProfiles(Profiles certificationProfiles) {
        this.certificationProfiles = certificationProfiles;
    }

    
    public ProcessCertification(PKIKeyStore pkiKeyStore,
			Profiles certificationProfiles) {
		super();
		this.pkiKeyStore = pkiKeyStore;
		this.certificationProfiles = certificationProfiles;
	}

    /* private methods */
    private CertResponse processRequest(ContentSigner sigGen, CertReqMsg certReqMsg) throws ProcessRequestException, NoSuchAlgorithmException, IOException, ProfileException {
    	
    	Result.Decisions overallResult = Result.Decisions.VALID;

        CertTemplate tempCertTemplate = certReqMsg.getCertReq().getCertTemplate();

        Profile certificateProfile = certificationProfiles.get(certReqMsg.getCertReq().getCertReqId().getPositiveValue().intValue());
        if (certificateProfile == null) {
        	logger.error("Unknown profile according to certificate Id [" + 
        		certReqMsg.getCertReq().getCertReqId().getPositiveValue().toString() + "]");        	
            throw new ProcessRequestException("Unknown profile according to certificate Id");
        }
        
        // Prepare Certificate Template
        CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();
        // Static stuff
        certTemplateBuilder.setVersion(2);
        X500Name issuerName = new X500Name(pkiKeyStore.getCACertificate().getIssuerX500Principal().getName());
        certTemplateBuilder.setIssuer(issuerName);
        certTemplateBuilder.setSubject(tempCertTemplate.getSubject());

        // Validation Dates
        // NBefore
        Result resultNBefore = certificateProfile.validateCertificateNBefore(tempCertTemplate);
        if (resultNBefore.getDecision() == Result.Decisions.INVALID) {
        	logger.error((String) resultNBefore.getValue());
        	throw new ProcessRequestException((String) resultNBefore.getValue());
        }
        overallResult = overallResult == Result.Decisions.OVERRULED ? Result.Decisions.OVERRULED 
        		: resultNBefore.getDecision();
        
        // NAfter
        Result resultNAfter = certificateProfile.validateCertificateNAfter(tempCertTemplate);
        if (resultNAfter.getDecision() == Result.Decisions.INVALID) {
        	logger.error((String) resultNAfter.getValue());
        	throw new ProcessRequestException((String) resultNAfter.getValue());
        }
        overallResult = overallResult == Result.Decisions.OVERRULED ? Result.Decisions.OVERRULED 
        		: resultNAftet.getDecision();
        OptionalValidity optionalValidity = new OptionalValidity(
        		new Time((Date)resultNBefore.getValue()), 
        		new Time((Date)resultNAfter.getValue()));
        
        // Fill in dates for validity period validation
        certTemplateBuilder.setValidity(optionalValidity);
        tempCertTemplate = certTemplateBuilder.build();

        // Only verification of time period no overrule results 
        Result resultValidity = certificateProfile.validateCertificateValidity(tempCertTemplate);
        if (resultNAfter.getDecision() == Result.Decisions.INVALID) {
        	logger.error((String) resultValidity.getValue());
        	throw new ProcessRequestException((String) resultValidity.getValue());
        }
        overallResult = overallResult == Result.Decisions.OVERRULED ? Result.Decisions.OVERRULED 
        		: resultValidity.getDecision();

        //Public Key
        Result resultKeyLength = certificateProfile.validateCertificateKeyLength(tempCertTemplate);
        if (resultKeyLength.getDecision() == Result.Decisions.INVALID) {
        	logger.error((String) resultKeyLength.getValue());
        	throw new ProcessRequestException((String) resultKeyLength.getValue());
        }
        overallResult = overallResult == Result.Decisions.OVERRULED ? Result.Decisions.OVERRULED 
        		: resultKeyLength.getDecision();
        certTemplateBuilder.setPublicKey(tempCertTemplate.getPublicKey());
        
        // Add the extensions to the certificate
        CertTemplate certTemplate = certTemplateBuilder.build();
        List<Result> results = certificateProfile.validateCertificateExtensions(certTemplate);
        List<Extension> extensions = new ArrayList<Extension>();
        Result.Decisions validated;
        for (Result result : results) {
        	if (result.getDecision() == Result.Decisions.INVALID) {
        		validated = Result.Decisions.INVALID;
        		break;
        	}
        	extensions.add((Extension)result.getValue());
        }
        Extension[] extensionsArray = new Extension[extensions.size()]; 
    	certTemplateBuilder.setExtensions(new Extensions(extensions.toArray(extensionsArray)));

        X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(
                // Issuer Name
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
        
        X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(sigGen);

        CertResponse certResponse = new CertResponse(certReqMsg.getCertReq().getCertReqId(),
                new PKIStatusInfo(PKIStatus.granted),
                new CertifiedKeyPair(new CertOrEncCert(new CMPCertificate(x509CertificateHolder.toASN1Structure()))),
                null);

        return certResponse;
    }

    /* public methods */
    public ProcessCertification(PKIKeyStore pkiKeyStore) {
        this.pkiKeyStore = pkiKeyStore;
    }

    public PKIBody getResponse(PKIBody pkiBody) throws OperatorCreationException, ProcessRequestException, NoSuchAlgorithmException, IOException, ProfileException {

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
