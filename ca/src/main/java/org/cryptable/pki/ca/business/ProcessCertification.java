package org.cryptable.pki.ca.business;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cryptable.pki.server.model.profile.Profile;
import org.cryptable.pki.server.model.profile.ProfileException;
import org.cryptable.pki.server.model.profile.Profiles;
import org.cryptable.pki.server.model.profile.Result;
import org.cryptable.pki.util.PKIKeyStore;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
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
    public ProcessCertificationResult processRequest(CertTemplate certTemplate, int profile) throws ProcessRequestException, IOException, ProfileException, NoSuchProviderException, CertificateException, OperatorCreationException, NoSuchAlgorithmException {
    	
    	Result.Decisions overallResult = Result.Decisions.VALID;

        CertTemplate tempCertTemplate = certTemplate;

        Profile certificateProfile = certificationProfiles.get(profile);
        if (certificateProfile == null) {
        	logger.error("Unknown profile according to certificate Id [" + profile + "]");        	
            throw new ProcessRequestException("Unknown profile according to certificate Id");
        }
        
        // Prepare Certificate Template
        CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();
        // Static stuff
        certTemplateBuilder.setVersion(2);
        certTemplateBuilder.setSubject(tempCertTemplate.getSubject());
        X500Name issuerName = new X500Name(pkiKeyStore.getCACertificate().getIssuerDN().getName());
        certTemplateBuilder.setIssuer(issuerName);

        // Only verification of time period no overrule results 
        Result resultValidity = certificateProfile.validateCertificateValidity(tempCertTemplate);
        if (resultValidity.getDecision() == Result.Decisions.INVALID) {
        	logger.error((String) resultValidity.getValue());
        }
        overallResult = (overallResult == Result.Decisions.VALID) ? resultValidity.getDecision() : overallResult;

        //Public Key
        Result resultKeyLength = certificateProfile.validateCertificateKeyLength(tempCertTemplate);
        if (resultKeyLength.getDecision() == Result.Decisions.INVALID) {
        	logger.error((String) resultKeyLength.getValue());
        }
        overallResult = (overallResult == Result.Decisions.VALID) ? resultKeyLength.getDecision() : overallResult;

        KeyPair keyPair = null;
        if (tempCertTemplate.getPublicKey() == null) {
        	keyPair = pkiKeyStore.generateKeyPair(((Integer)resultKeyLength.getValue()).intValue(),
        			certificateProfile.getKeyAlgorithm());
            certTemplateBuilder.setPublicKey(new SubjectPublicKeyInfo(ASN1Sequence.getInstance(
            		keyPair.getPublic().getEncoded())));
        }
        else {
            certTemplateBuilder.setPublicKey(tempCertTemplate.getPublicKey());
        }

        // Add the extensions to the certificate
        tempCertTemplate = certTemplateBuilder.build();
        List<Result> results = certificateProfile.validateCertificateExtensions(tempCertTemplate);
        
        X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(
        		tempCertTemplate.getIssuer(),
        		BigInteger.valueOf(9),
        		tempCertTemplate.getValidity().getNotBefore().getDate(),
        		tempCertTemplate.getValidity().getNotAfter().getDate(),
        		tempCertTemplate.getSubject(),
        		tempCertTemplate.getPublicKey());

        for (Result result : results) {
        	if (result.getDecision() == Result.Decisions.INVALID) {
            	logger.error((String) result.getValue());
        	}
            overallResult = (overallResult == Result.Decisions.VALID) ? result.getDecision() : overallResult;
            
        	Extension extension = (Extension) result.getValue();
        	x509v3CertificateBuilder.addExtension(extension.getExtnId(), 
        			extension.isCritical(), 
        			extension.getParsedValue());
        }
    	
        
        ContentSigner sigGen = new JcaContentSignerBuilder(certificateProfile.getCertificateSignatureAlgorithm())
        	.setProvider(pkiKeyStore.getProvider())
        	.build(pkiKeyStore.getCAPrivateKey());        
        X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(sigGen);

    	PKIStatus pkiStatus = PKIStatus.rejection;
        if (overallResult == Result.Decisions.VALID) {
        	logger.debug("certifcate GRANTED");
        	pkiStatus = PKIStatus.granted;
        }
        else if (overallResult == Result.Decisions.OVERRULED) {
        	logger.debug("certifcate GRANTED with modifications");
        	pkiStatus = PKIStatus.grantedWithMods;
        }
        else {
        	logger.debug("certifcate REJECTED");
        	pkiStatus = PKIStatus.rejection;
        }

        return new ProcessCertificationResult(pkiStatus, 
        		x509CertificateHolder, 
        		keyPair);
    }

    /* public methods */
    public ProcessCertification(PKIKeyStore pkiKeyStore) {
    	super();
        this.pkiKeyStore = pkiKeyStore;
        this.certificationProfiles = null;
    }

}
