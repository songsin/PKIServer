package org.cryptable.pki.server.business;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

import javax.xml.bind.JAXBException;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.cryptable.pki.server.model.profile.ProfileException;
import org.cryptable.pki.server.model.profile.Profiles;
import org.cryptable.pki.server.model.profile.impl.ProfilesJAXB;
import org.cryptable.pki.util.GeneratePKI;
import org.cryptable.pki.util.PKIKeyStore;
import org.cryptable.pki.util.PKIKeyStoreException;
import org.cryptable.pki.util.PKIKeyStoreSingleton;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class ProcessCertificationTest {

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
	 * @throws CertificateEncodingException 
	 */
	@Test
	public void testCertificationRequest() throws NoSuchAlgorithmException,
			NoSuchProviderException, JAXBException, ProfileException, IOException, CertificateEncodingException {
		CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();
		X509CertificateHolder x509CertificateHolder = new JcaX509CertificateHolder(pkiKeyStore.getCACertificate());        
		Profiles profiles = new ProfilesJAXB(
				getClass().getResourceAsStream("/CRLDistributionPoints.xml"), 
				x509CertificateHolder.toASN1Structure());
		ProcessCertification processCertification = new ProcessCertification(pkiKeyStore, profiles);
		KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", "BC");
		kGen.initialize(2048);
		KeyPair kp = kGen.generateKeyPair();
		System.out.print(kp.getPrivate().toString());

		certTemplateBuilder.setSubject(new X500Name(
				"c=be, o=cryptable, ou=pki, cn=David"));
		certTemplateBuilder.setPublicKey(new SubjectPublicKeyInfo(ASN1Sequence.getInstance(kp.getPublic().getEncoded())));
		Date nBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30);
		Date nAfter = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30);
		certTemplateBuilder.setValidity(new OptionalValidity(new Time(nBefore), 
        		new Time(nAfter)));
		
	}

}
