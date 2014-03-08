package org.cryptable.pki.ca.business;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.*;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

import javax.xml.bind.JAXBException;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.cryptable.pki.server.model.profile.ProfileException;
import org.cryptable.pki.server.model.profile.Profiles;
import org.cryptable.pki.server.model.profile.impl.ProfilesJAXB;
import org.cryptable.pki.util.GeneratePKI;
import org.cryptable.pki.util.PKIKeyStore;
import org.cryptable.pki.util.PKIKeyStoreSingleton;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ProcessCertificationTest {
	
	final Logger logger = LoggerFactory.getLogger(ProcessCertificationTest.class);

	private PKIKeyStore pkiKeyStore;

	@BeforeClass
	static public void init() throws CertificateException, CertIOException,
			NoSuchAlgorithmException, OperatorCreationException, CRLException,
			NoSuchProviderException, InvalidKeySpecException {
		Security.addProvider(new BouncyCastleProvider());

		GeneratePKI generatePKI = new GeneratePKI();
		generatePKI.createPKI();
		PKIKeyStoreSingleton.init(generatePKI.getCommCertPrivateKey(),
				generatePKI.getCommCert(), generatePKI.getCaCertPrivateKey(),
				generatePKI.getCaCert(), generatePKI.getRACert(),
				generatePKI.getCertificateChain(), "BC", "SHA1PRNG");
	}

	@Before
	public void setup() throws JAXBException, IOException, ProfileException,
			CertificateEncodingException, NoSuchAlgorithmException {
		pkiKeyStore = PKIKeyStoreSingleton.getInstance();
	}

	/**
	 * Test a normal valid certificate request
	 * 
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 * @throws IOException 
	 * @throws ProfileException 
	 * @throws JAXBException 
	 * @throws OperatorCreationException 
	 * @throws ProcessRequestException 
	 * @throws CertificateException 
	 * @throws CertException 
	 */
	@Test
	public void testCertificationRequest() throws NoSuchAlgorithmException,
			NoSuchProviderException, JAXBException, ProfileException, IOException, OperatorCreationException, CertificateException, ProcessRequestException, CertException {
		
		CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();
		X509CertificateHolder x509CertificateHolder = new JcaX509CertificateHolder(pkiKeyStore.getCACertificate());        
		Profiles profiles = new ProfilesJAXB(
				getClass().getResourceAsStream("/Profiles.xml"), 
				x509CertificateHolder.toASN1Structure());
		ProcessCertification processCertification = new ProcessCertification(pkiKeyStore, profiles);
		
		KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", "BC");
		kGen.initialize(2048);
		KeyPair kp = kGen.generateKeyPair();
		System.out.print(kp.getPrivate().toString());

		// Certificate version
		certTemplateBuilder.setVersion(2);
		// Subject Name
		certTemplateBuilder.setSubject(new X500Name(
				"C=BE, O=Cryptable, OU=PKI Devision, CN=David"));
		// Issuer Name
		certTemplateBuilder.setIssuer(x509CertificateHolder.getIssuer());
		// Not Before
		Date nBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30);
		// Not After
		Date nAfter = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30);
		certTemplateBuilder.setValidity(new OptionalValidity(new Time(nBefore), 
        		new Time(nAfter)));
		// Public Key is set
		certTemplateBuilder.setPublicKey(new SubjectPublicKeyInfo(ASN1Sequence.getInstance(kp.getPublic().getEncoded())));
				
		ProcessCertificationResult processCertificationResult = 
				processCertification.processRequest(certTemplateBuilder.build(), 3);
		
		assertEquals(PKIStatus.GRANTED, processCertificationResult.pkiStatus.getValue().intValue());
		
		X509CertificateHolder x509CertificateHolder2 = processCertificationResult.getX509CertificateHolder();

		ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder().build(pkiKeyStore.getCACertificate());

		assertTrue(x509CertificateHolder2.isSignatureValid(contentVerifierProvider));
		assertEquals(3, x509CertificateHolder2.getVersionNumber());
        assertEquals(x509CertificateHolder.getIssuer(), x509CertificateHolder2.getIssuer());
	}

}
