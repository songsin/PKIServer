package org.cryptable.pki.server.business;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.xml.bind.JAXBException;

import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.cryptable.pki.server.model.profile.ProfileException;
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
    static public void init() throws CertificateException, CertIOException, NoSuchAlgorithmException, OperatorCreationException, CRLException, NoSuchProviderException, InvalidKeySpecException {
        Security.addProvider(new BouncyCastleProvider());
        GeneratePKI generatePKI = new GeneratePKI();
        generatePKI.createPKI();
        PKIKeyStoreSingleton.init(
        		generatePKI.getCommCertPrivateKey(), generatePKI.getCommCert(), 
        		generatePKI.getCaCertPrivateKey(), generatePKI.getCaCert(), 
        		generatePKI.getRACert(), 
        		generatePKI.getCertificateChain(), 
        		"BC", 
        		"SHA1PRNG");
    }

    @Before
    public void setup() throws JAXBException, IOException, ProfileException, CertificateEncodingException, NoSuchAlgorithmException {
        pkiKeyStore = PKIKeyStoreSingleton.getInstance();
    }

    /**
     * Test a normal valid certificate request
     */
    @Test
    public void TestCertificationRequest() {
    	CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();
    	
    	
    }
    
}
