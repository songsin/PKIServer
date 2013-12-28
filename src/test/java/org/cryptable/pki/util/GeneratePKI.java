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

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

public class GeneratePKI {
    private static final String BC = org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

    public GeneratePKI() {
        certificateChain = new ArrayList<Certificate>();
    }

    public static String getBC() {
		return BC;
	}

	private X509Certificate caCert;
    private PrivateKey      caCertPrivateKey;

    private X509CRL x509CRL;

    public X509CRL getX509CRL() {
        return x509CRL;
    }

	public X509Certificate getCaCert() {
		return caCert;
	}
	
    public PrivateKey getCaCertPrivateKey() {
		return caCertPrivateKey;
	}

    private X509Certificate subCACert;
    private PrivateKey      subCACertPrivateKey;
    
	public X509Certificate getSubCACert() {
		return subCACert;
	}

	public PrivateKey getSubCACertPrivateKey() {
		return subCACertPrivateKey;
	}


	private X509Certificate raCert;
    private PrivateKey      raCertPrivateKey;
    
	public X509Certificate getRACert() {
		return raCert;
	}

	public PrivateKey getRACertPrivateKey() {
		return raCertPrivateKey;
	}

    private X509Certificate commCert;
    private PrivateKey      commCertPrivateKey;

    public X509Certificate getCommCert() {
        return commCert;
    }

    public PrivateKey getCommCertPrivateKey() {
        return commCertPrivateKey;
    }

    private X509Certificate testUser1Cert;
    private PrivateKey      testUser1CertPrivateKey;

    public X509Certificate getTestUser1Cert() {
        return testUser1Cert;
    }

    public PrivateKey getTestUser1CertPrivateKey() {
        return testUser1CertPrivateKey;
    }

    private X509Certificate testUser2Cert;
    private PrivateKey      testUser2CertPrivateKey;

    public X509Certificate getTestUser2Cert() {
        return testUser2Cert;
    }

    public PrivateKey getTestUser2CertPrivateKey() {
        return testUser2CertPrivateKey;
    }

    private X509Certificate testUser3Cert;
    private PrivateKey      testUser3CertPrivateKey;

    public X509Certificate getTestUser3Cert() {
        return testUser3Cert;
    }

    public PrivateKey getTestUser3CertPrivateKey() {
        return testUser3CertPrivateKey;
    }

    private X509Certificate testUser4Cert;
    private PrivateKey      testUser4CertPrivateKey;

    public X509Certificate getTestUser4Cert() {
        return testUser4Cert;
    }

    public PrivateKey getTestUser4CertPrivateKey() {
        return testUser4CertPrivateKey;
    }

    private List<Certificate> certificateChain;

    public Certificate[] getCertificateChain() {
        return certificateChain.toArray(new Certificate[certificateChain.size()]);
    }

    private List<Certificate> commChain;

    public Certificate[] getCommChain() {
        return commChain.toArray(new Certificate[commChain.size()]);
    }

    private X509Certificate expiredCert;
    private PrivateKey      expiredCertPrivateKey;

    public X509Certificate getExpiredCert() {
        return expiredCert;
    }

    public PrivateKey getExpiredCertPrivateKey() {
        return expiredCertPrivateKey;
    }

    private X509Certificate revokedCert;
    private PrivateKey      revokedCertPrivateKey;

    public X509Certificate getRevokedCert() {
        return revokedCert;
    }

    public PrivateKey getRevokedCertPrivateKey() {
        return revokedCertPrivateKey;
    }

    private X509Certificate notYetValidCert;
    private PrivateKey      notYetValidCertPrivateKey;

    public X509Certificate getNotYetValidCert() {
        return notYetValidCert;
    }

    public PrivateKey getNotYetValidCertPrivateKey() {
        return notYetValidCertPrivateKey;
    }



    /**
     * we generate the CA's certificate
	 * @throws OperatorCreationException 
	 * @throws NoSuchAlgorithmException 
	 * @throws CertIOException 
	 * @throws CertificateException 
     */
    private static Certificate createMasterCert(
        PublicKey       pubKey,
        PrivateKey      privKey) throws OperatorCreationException, NoSuchAlgorithmException, CertificateException, CertIOException
    {
    	// Signer of the certificate
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BC).build(privKey);
    	// Builder of the certificate
        X509v3CertificateBuilder  v3CertBuilder = new JcaX509v3CertificateBuilder(
    	        // signers name 
    			new X500Name("C=BE, O=Cryptable, OU=PKI Devision, CN=Class 0 CA"),
    			// Serial Number
    			BigInteger.valueOf(1), 
    			// Not Before
    			new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30),
    			// Not After
    			new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)),
    	        // subjects name - the same as we are self signed.
    			new X500Name("C=BE, O=Cryptable, OU=PKI Devision, CN=Class 0 CA"),
    			// Public key of the certificate
    			pubKey);

        v3CertBuilder.addExtension(X509Extension.authorityKeyIdentifier, 
        		false, 
        		(new JcaX509ExtensionUtils()).createAuthorityKeyIdentifier(pubKey));
        v3CertBuilder.addExtension(X509Extension.subjectKeyIdentifier, 
        		false, 
        		(new JcaX509ExtensionUtils()).createSubjectKeyIdentifier(pubKey));
        BasicConstraints extBasicConstraints = new BasicConstraints(1);
        v3CertBuilder.addExtension(X509Extension.basicConstraints, true, extBasicConstraints);

    	return new JcaX509CertificateConverter().setProvider(BC).getCertificate(v3CertBuilder.build(sigGen));
    }

    /**
     * we generate an intermediate certificate signed by our CA
     * @throws OperatorCreationException 
     * @throws NoSuchAlgorithmException 
     * @throws CertIOException 
     * @throws CertificateException 
     */
    private static Certificate createIntermediateCert(
        PublicKey       pubKey,
        PrivateKey      caPrivKey,
        X509Certificate caCert) throws OperatorCreationException, CertIOException, NoSuchAlgorithmException, CertificateException
    {
        // Signer of the certificate
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BC).build(caPrivKey);
    	// Builder of the certificate
        X509v3CertificateBuilder  v3CertBuilder = new JcaX509v3CertificateBuilder(
    	        // signers name 
        		JcaX500NameUtil.getSubject(caCert),
    			// Serial Number
    			BigInteger.valueOf(2), 
    			// Not Before
    			new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30),
    			// Not After
    			new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)),
    	        // subjects name - the same as we are self signed.
    			new X500Name("C=BE, O=Cryptable, OU=PKI Devision, CN=Class 0 SubCA"),
    			// Public key of the certificate
    			pubKey);
        
        v3CertBuilder.addExtension(X509Extension.authorityKeyIdentifier, 
        		false, 
        		(new JcaX509ExtensionUtils()).createAuthorityKeyIdentifier(caCert));
        v3CertBuilder.addExtension(X509Extension.subjectKeyIdentifier, 
        		false, 
        		(new JcaX509ExtensionUtils()).createSubjectKeyIdentifier(pubKey));
            v3CertBuilder.addExtension(X509Extension.basicConstraints, true, new BasicConstraints(0));
    	
        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(v3CertBuilder.build(sigGen));
    }

    /**
     * we generate a certificate signed by our CA's intermediate certficate
     * @throws OperatorCreationException 
     * @throws NoSuchAlgorithmException 
     * @throws CertIOException 
     * @throws CertificateException 
     */
    private static Certificate createRACert(
        PublicKey       pubKey,
        PrivateKey      caPrivKey,
        X509Certificate caCert) throws OperatorCreationException, CertIOException, NoSuchAlgorithmException, CertificateException
    {
        // Signer of the certificate
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BC).build(caPrivKey);
    	// Builder of the certificate
        X509v3CertificateBuilder  v3CertBuilder = new JcaX509v3CertificateBuilder(
    	        // signers name 
        		JcaX500NameUtil.getSubject(caCert),
    			// Serial Number
    			BigInteger.valueOf(2), 
    			// Not Before
    			new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30),
    			// Not After
    			new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)),
    	        // subjects name - the same as we are self signed.
    			new X500Name("C=BE, O=Cryptable, OU=PKI Devision, CN=RA"),
    			// Public key of the certificate
    			pubKey);
        
        v3CertBuilder.addExtension(X509Extension.authorityKeyIdentifier, 
        		false, 
        		(new JcaX509ExtensionUtils()).createAuthorityKeyIdentifier(caCert));
        v3CertBuilder.addExtension(X509Extension.subjectKeyIdentifier, 
        		false, 
        		(new JcaX509ExtensionUtils()).createSubjectKeyIdentifier(pubKey));

    	return new JcaX509CertificateConverter().setProvider(BC).getCertificate(v3CertBuilder.build(sigGen));
    }

    /**
     * we generate a certificate signed by our CA's intermediate certficate
     * @throws OperatorCreationException
     * @throws CertificateException
     */
    private static Certificate createSelfSignedCert(
            String          distinguishedNmae,
            PublicKey       pubKey,
            PrivateKey      privKey) throws OperatorCreationException, CertificateException
    {
        // Signer of the certificate
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BC).build(privKey);
        // Builder of the certificate
        X509v3CertificateBuilder  v3CertBuilder = new JcaX509v3CertificateBuilder(
                // signers name
                new X500Name(distinguishedNmae),
                // Serial Number
                BigInteger.valueOf(new Random(100).nextLong()),
                // Not Before
                new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30),
                // Not After
                new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)),
                // subjects name - the same as we are self signed.
                new X500Name(distinguishedNmae),
                // Public key of the certificate
                pubKey);

        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(v3CertBuilder.build(sigGen));
    }

    /**
     * we generate a certificate signed by our CA's intermediate certficate
     * @throws OperatorCreationException
     * @throws CertificateException
     */
    private static Certificate createCert(
            String          distinguishedNmae,
            PublicKey       pubKey,
            PrivateKey      privKey,
            X509Certificate caCert,
            BigInteger      serNum) throws OperatorCreationException, CertificateException
    {
        // Signer of the certificate
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BC).build(privKey);
        // Builder of the certificate
        X509v3CertificateBuilder  v3CertBuilder = new JcaX509v3CertificateBuilder(
                // signers name
                JcaX500NameUtil.getIssuer(caCert),
                // Serial Number
                serNum,
                // Not Before
                new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30),
                // Not After
                new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)),
                // subjects name - the same as we are self signed.
                new X500Name(distinguishedNmae),
                // Public key of the certificate
                pubKey);

        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(v3CertBuilder.build(sigGen));
    }

    /**
     * we generate an expired certificate signed by our CA's intermediate certficate
     * @throws OperatorCreationException
     * @throws CertificateException
     */
    private static Certificate createExpiredCert(
            String          distinguishedNmae,
            PublicKey       pubKey,
            PrivateKey      privKey,
            X509Certificate caCert,
            BigInteger      serNum) throws OperatorCreationException, CertificateException
    {
        // Signer of the certificate
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BC).build(privKey);
        // Builder of the certificate
        X509v3CertificateBuilder  v3CertBuilder = new JcaX509v3CertificateBuilder(
                // signers name
                JcaX500NameUtil.getIssuer(caCert),
                // Serial Number
                serNum,
                // Not Before
                new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30),
                // Not After
                new Date(System.currentTimeMillis() - (1000L * 60 * 60 * 24)),
                // subjects name - the same as we are self signed.
                new X500Name(distinguishedNmae),
                // Public key of the certificate
                pubKey);

        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(v3CertBuilder.build(sigGen));
    }

    /**
     * we generate a not yet valid certificate signed by our CA's intermediate certficate
     * @throws OperatorCreationException
     * @throws CertificateException
     */
    private static Certificate createNotYetValidCert(
            String          distinguishedNmae,
            PublicKey       pubKey,
            PrivateKey      privKey,
            X509Certificate caCert,
            BigInteger      serNum) throws OperatorCreationException, CertificateException
    {
        // Signer of the certificate
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BC).build(privKey);
        // Builder of the certificate
        X509v3CertificateBuilder  v3CertBuilder = new JcaX509v3CertificateBuilder(
                // signers name
                JcaX500NameUtil.getIssuer(caCert),
                // Serial Number
                serNum,
                // Not Before
                new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24),
                // Not After
                new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)),
                // subjects name - the same as we are self signed.
                new X500Name(distinguishedNmae),
                // Public key of the certificate
                pubKey);

        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(v3CertBuilder.build(sigGen));
    }

    /**
     * we generate an revoked certificate signed by our CA's intermediate certficate
     * @throws OperatorCreationException
     * @throws CertificateException
     */
    private static X509CRL createCRL(
            PrivateKey      privKey,
            X509Certificate caCert,
            BigInteger      serNum) throws OperatorCreationException, CertificateException, CRLException {
        // Signer of the certificate
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BC).build(privKey);
        // Builder of the certificate
        X509v2CRLBuilder jcaX509v2CRLBuilder = new JcaX509v2CRLBuilder(caCert.getSubjectX500Principal(), new Date(System.currentTimeMillis() - (1000L * 60 * 60)))
                .addCRLEntry(serNum, new Date(System.currentTimeMillis() - (1000L * 60 * 60)), ReasonFlags.keyCompromise);

        return new JcaX509CRLConverter().setProvider("BC").getCRL(jcaX509v2CRLBuilder.build(sigGen));
    }

    /**
     * create a small PKI to test the certification process
     *
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeySpecException
     * @throws CertIOException 
     * @throws CertificateException 
     * @throws OperatorCreationException 
     */
    public void createPKI() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, OperatorCreationException, CertificateException, CertIOException, CRLException {
        Security.addProvider(new BouncyCastleProvider());

        for (Provider provider : Security.getProviders()) {
            System.out.println("Provider: " + provider.getName());
            for (Provider.Service service : provider.getServices()) {
                System.out.println("  Algorithm: " + service.getAlgorithm());
            }
        }

        //
        // RA keys
        //
        RSAPublicKeySpec raPubKeySpec = new RSAPublicKeySpec(
            new BigInteger("cc8805843760e83686cceb3ba109b7055d28b436c5d478be8da13fb587dffc4ebbef037af449bb8cefec635af15e52d516d0ee93fae599324555832a3e7350ceb67f7f590fc48e365f4b8170e7b3c8ce4d80fc7a8e2fe452cd04b375565f733c7bb353d71f132243967e24511589522bd8be1cb2638bb321a6ec090d3e20f504b71ee1f7fc0c5fa8c1631a645a049b34b029b3e565c6ce0fe5d8e343155a55ab8c9ebdc63ef6cc7f1d892b95f23cd29e3b683684577c5486d614144bd0f21bfcebd49fc6f4d49b4cc568c835f4e75249c8071e5edbf81636937e6eb86f546fce0af8831cfd4d301b0ba7e16967a669a3228d2606cfb46bf3c11cfdb263259343", 16),
            new BigInteger("10001", 16));

        RSAPrivateCrtKeySpec raPrivKeySpec = new RSAPrivateCrtKeySpec(
            new BigInteger("cc8805843760e83686cceb3ba109b7055d28b436c5d478be8da13fb587dffc4ebbef037af449bb8cefec635af15e52d516d0ee93fae599324555832a3e7350ceb67f7f590fc48e365f4b8170e7b3c8ce4d80fc7a8e2fe452cd04b375565f733c7bb353d71f132243967e24511589522bd8be1cb2638bb321a6ec090d3e20f504b71ee1f7fc0c5fa8c1631a645a049b34b029b3e565c6ce0fe5d8e343155a55ab8c9ebdc63ef6cc7f1d892b95f23cd29e3b683684577c5486d614144bd0f21bfcebd49fc6f4d49b4cc568c835f4e75249c8071e5edbf81636937e6eb86f546fce0af8831cfd4d301b0ba7e16967a669a3228d2606cfb46bf3c11cfdb263259343", 16),
            new BigInteger("10001", 16),
            new BigInteger("a8d9c2741ca3cc10f7c8448abdaf9f80b61fdc673b7ae513ab28ebc7999cb856e79fb267d734e7b8ba7994ac87872f2aebe32092da16a21a7652da2e0dd0756db20c1fbe0ede5de95552a851e576eed821f3d27bfad65ed05ca0fce6699ff32a8394d02a5065236c58d95a71f62d9fc0c2f6700a7553e75668cf83c982f9024ca059c98ba075554a40a9a64d0c3d24b795c377bf2c527e6b809602f4728c18f1da8821a4d2f00237aab5b5453e5c6862394e371ec0d719a85012bb309a1bd13217a05e754e97e3a9cbd71f9d438d0864371bb9cc2f66077242c1dd5da50971a55b878950868ad296330f7a442fc07091ba689608c98cee649e77113575767001", 16),
            new BigInteger("e9ca9e1fdc8dcd04ad1f9aafe9edcb62d2d2a0ba7c65c8632d195f8186951751e55d40414c8f9892b15188a06ca5d2c72a517e76e1f605119ca4bc165daf60f3020e43a7d781afba056b7e1e0c99f067ba1711ebfa1c03473594e0bface5983914db0ca2d1c6c283532ec3f68f181a1cd5432b5b74da6abeab03e368ceb78501", 16),
            new BigInteger("dff5d9c123029d64a5ad307c100badb11c2965e6ded9143840abd078f7a89c329294243d0ad554aafd4854701c501199827e8c3bad84f944f41c951939838ea5a2fa6103fce5aa6b930db387f9aa7b6d8b9278bf2683bb0046d71e9c45f04e41bc676799c72930d56ea2024a68cab8f90ee5707fd36c9c183825f968da49c443", 16),
            new BigInteger("a88e4ea6c60aee2f5aea184a902bc3a142425d635660c3b2cd4727d668c38106a8892cd46770781dfafdbfb579dfac31afcf05908ca5254e675355d00247796c7aa4f21e467fd7c4143845bb4076941f14c9a1403318933c79e3168edb06c553123843c9f7d88750cb5e4226b7503733668680f1f533ac163f921418f240da01", 16),
            new BigInteger("104f92755b7c64442140d4c8244f056e61b3ae253b53aa0252cb709a6ec70be12f05b501f1190a5a8da9c7e4865b5a7cc8a138cb5bded45cae3eaaa934a41d2e79092d29a23083d1e3dada996b987bf6c5747c70c7784e953d938b3a2c69ccf942a4714a24d41e275d3055645fef6bbb4fd76bf3134dd4ac7ae26120becd228b", 16),
            new BigInteger("de627a7088fe4b73c46f3a90399f4390ad0b9af9d9469e65545ec528ab8c7d67db8f98dfe0bf948d1a495ee1d37e9861f14449cad4832d3def11ca28e614464f0ed32a4c2e9b7397f34536a5a96364326d318f7996d390964f0439a22e2506d9c073f27a5e97088a23dfe8268bb39222b5ed845aefd6e01441210ef46c8b146", 16));

        //
        // intermediate keys.
        //
        RSAPublicKeySpec intPubKeySpec = new RSAPublicKeySpec(
            new BigInteger("8e38ece9b03ad58150c062d6cf704098b359461a9befef488f155fc5b0576f683516f3e71f7d92d1dadffcac0654dcca590bd13e2e39523f4aa5da522e4049eeb206068f9e1e0f4dcfd160cf43d42fed344de15f8c7b960beb56dedd151734f93dcfb2e387d7badd3e3655b1e28abe9664f0a8fc7766441c93c7c32604f2e75703def32e8c50fbdd8dade953a9f9db848498872704670471a3e874fc230fbbd5f982bef663e9efef6b6901a719dd5f0e9d3589e2913eb59b73eb6020c32cc7cc0c1fb81bd003ed6b4a17acf60a5bf189b2f45108dd43ee8eb37adfd845293fdb82696b1334eceb7f7e71277ae58761fe59b23083c59d7b51c74e92fb18bd7919", 16),
            new BigInteger("10001", 16));


        RSAPrivateCrtKeySpec intPrivKeySpec = new RSAPrivateCrtKeySpec(
            new BigInteger("8e38ece9b03ad58150c062d6cf704098b359461a9befef488f155fc5b0576f683516f3e71f7d92d1dadffcac0654dcca590bd13e2e39523f4aa5da522e4049eeb206068f9e1e0f4dcfd160cf43d42fed344de15f8c7b960beb56dedd151734f93dcfb2e387d7badd3e3655b1e28abe9664f0a8fc7766441c93c7c32604f2e75703def32e8c50fbdd8dade953a9f9db848498872704670471a3e874fc230fbbd5f982bef663e9efef6b6901a719dd5f0e9d3589e2913eb59b73eb6020c32cc7cc0c1fb81bd003ed6b4a17acf60a5bf189b2f45108dd43ee8eb37adfd845293fdb82696b1334eceb7f7e71277ae58761fe59b23083c59d7b51c74e92fb18bd7919", 16),
            new BigInteger("10001", 16),
            new BigInteger("7adaa9ac64532e437aa1f5bf6189b203364a13c8c0934ebbfafd97b18956be21e25a656e6d416826674fbd504c57da31e121d82a427bb9947ac3320873738d69e7d654ac93059c6ab6ee4316479d6f9913e98299ab1cc6cc9d0a7991b8ba47445624a87eebc56ae1daefccaed0e6d123d126229394007f2dc06a7b24c8799b63c099203d55bf13fbdc98b562c84f36d7ed360948c9c43f837c2dd5756266bdb81df2d63929b7582005688cd4b9159baec251e900c6a775378d00791b965945ee8cb74229c49d4177bef75cd022364191df10f784ae4804ba6ef3523d4c400d9d947440f3ee9452bb1235e0c9be27a654aa80a0319a5da767833bf879a1227c01", 16),
            new BigInteger("cdb817bbf01519b9b50354721989454f0f4bce2375b5ff2e581a5856b36ec139e45d3d3fa22e33612880ed1c426ee01856620af0d2523d0c4518cb97ea71f2a74da0ac5b222515bee4966bbf84e00d5c04358b8709fe807be34b184ffa424702444d1f024bd38da76e9590bfd61b77487ec8bdd3d960017b89ccd70b96e4c2f9", 16),
            new BigInteger("b0fbd26dc0f365928f8406e910268081cebc75964614d7b7e93cc902bc1abf3ffad549148b242fc78569e7f317a234c8043914d3e6eef31797c4eeaabefc94d2c1d59a2c583f01d50530ac6c4d3385a6585368462069dd1f79ef582dfc603e71a9417ad2a2b304bebc03f29ea170a2b7f316fb42886a660b14e22509b5a1cf21", 16),
            new BigInteger("4e15ce8c7bb8c6a702da5cb762920448da1980095da8d34f980987f680ed4d52d827bc13e74f7a192af2a50dd0f99cfe1febdf1342020d4217082e5f5f9218f5003638b5eee3fcb914b333fae248d949501fb2f2730cb360530a3214497dd6ce3976bc8a7695ba730f3a9e52f2c64224b65b2412c1b3fb5c1516379a22907aa1", 16),
            new BigInteger("b6094dd735af23ba2b8350d847945279317b06371abe356324b330cd6f4cd389ab25d5951bc88c9c5bcd229616a8f0410a96eba548d25d96d6b3e80817891449f2b5116eab15a37cc769d8ef4c38c22ee68a63a63d90a5afca6b33f798ae258c22db06c9c02f01a26d20625c6710c34d10eb82645c8b9389b2612857644a9a1", 16),
            new BigInteger("91cbf1ea4db928116faa62c9d0d0449ba51c99338f4c041e05fbdbae87f46d169b7a45efcf963a9b5d44e1608a858f52d79d694fa2fde82cf9befa071ff18d0fd72f4a0f116d1dffab0333c71505e51580c95b5ba5c710f035e6bbebfa89c1d6a16847cb5b7637191c7ded5877ef57913afbd6118f11e02aa49dc07781a2d44b", 16));

        //
        // ca keys
        //
        RSAPublicKeySpec caPubKeySpec = new RSAPublicKeySpec(
            new BigInteger("8b99353b54bb93200ac7c012a46795cd3f0857489ea9a28953a4ba6633b0e9890388d083ee1bb4c25af0800107d8cebd10dba091f9f63d3647b7e615c4012944bff5f312206be6650aa57af5d29627c5e2a41501b89a4d06bf3d0ced50f7b9a152c7c24757c7c04675db675eb55a76cbb881b41205000f6a5b76f9f0292ff5a9fbfb132d27390da0d471bb336e3954434579381fdaa8b35a6afe8bf79f2156dc2ac75c848d5c9490369b3469a2a7b86028b76b85a34870a7b09c27dc934c5854981005142b6e74fb5f9aa33728f1fa0d2a85a64efc7bea1e518e8a19f6c90e7b1a334bb8db3f9d04eeb37fe60a37b50e7f023e0120b20a230ee1bb97326ad243", 16),
            new BigInteger("10001", 16));

        RSAPrivateCrtKeySpec   caPrivKeySpec = new RSAPrivateCrtKeySpec(
            new BigInteger("8b99353b54bb93200ac7c012a46795cd3f0857489ea9a28953a4ba6633b0e9890388d083ee1bb4c25af0800107d8cebd10dba091f9f63d3647b7e615c4012944bff5f312206be6650aa57af5d29627c5e2a41501b89a4d06bf3d0ced50f7b9a152c7c24757c7c04675db675eb55a76cbb881b41205000f6a5b76f9f0292ff5a9fbfb132d27390da0d471bb336e3954434579381fdaa8b35a6afe8bf79f2156dc2ac75c848d5c9490369b3469a2a7b86028b76b85a34870a7b09c27dc934c5854981005142b6e74fb5f9aa33728f1fa0d2a85a64efc7bea1e518e8a19f6c90e7b1a334bb8db3f9d04eeb37fe60a37b50e7f023e0120b20a230ee1bb97326ad243", 16),
            new BigInteger("10001", 16),
            new BigInteger("13dbd0a9c70d0409fbde9ca14a47fe147b920930a8798348bbe0642fe3cc97fc48c76eba45e62519bcec17998def36c1c8a325bd7e6c9c1a9bab3a8d001c162dd48cfd6e27b491caefefc8852dd6f4837f114e77b736241d009983bc42d76acddb43d58c669d60e9e51c38214df5378f158945ff863c92f4d35c22841aa7daef84a25fdc91bdb0a6339f6076f8337149608080be101968204bbdd719cc050ce16f351832be085d87eb572a50f00c7ce59f01ac8b167dcc4244ea173926745c69cfcff46a0af41e2c301fb311f95272a6ca8eca6b15ad88c919f157cf26c7cf681cb62ccb5b7849e68d71c5497de021565a3f1b85c8d4dc39001383c5e712de21", 16),
            new BigInteger("ca82d3e1a59d80b728e831f10848a33f31f1a76ab69d225d79011fa17ea8105910304b0b6302183b88fef6e09c540fdbf01401006805f6c14ec2a54908d4433a3dd2ce1363543d91e0777e76422f1e51fefc296a38dd5c5eaa13b61243b5c5e7c839daaa85b9457f9ea24794aec9a4ea4856c38d5fc775039ce4f79bd1ecd733", 16),
            new BigInteger("b0786d0403975dafb25bd08889a02412eff93613d2dd12771d26d5ed17cd072dad34dd2417595121474bbd76ba1dd00dee3e6f31eb859ec6866a451dd547de3c3405cbe2bb3f48588bda977567eaa5a868eb5a305b25feffdc5a840e54117e579f04310fdd51b15ef16f4d4304e3bf11bebe6e6d97d1ec4104f60ad08b8dd8b1", 16),
            new BigInteger("4f949de2fc8c2a7acfae7f81b2b9a8bd3ac935fb2f8c0c67231817f004afd2cccd19cd43ca4296773edcc2f37d3b6388108e2bde970250f7a215c7922dd00c23250c64432633828682e9325f129f25911f5cc481a39b09a381be813c28339474033109071dc9b2cff5ecdba8480fa1a91788510c8b68fc48d12d0148d073fc15", 16),
            new BigInteger("aec3647b102f6c399eb22ccfbb341be5a140359ce63bc798ad0713df0cae2088ccbac8b2806914de9723dc0b638038d642f613dae53b5c25916256f6978ce7fac92e605f373f119f974930abb5f0fc83cefc1d423c5261b9f3f8b445185e86b7b1a44e0e3f0933562a5626b6d375d4787765522938ac4d838aad3bc2922234d1", 16),
            new BigInteger("89b58ac9738809573205c6db25ddbfe57476eae212f6b27724baa5e178c94bb1cf53408f563b358455fe73bed76262512f617a4a5ab22684cf104a623350aed5797b732347e555c1ba13cea7d03d9823f76d0e229536ca42faef64306e308925c3121b48bb6f7bf0821f2d7813a8cc6db57f03ff2aec1351ddf717ee979e8539", 16));

        //
        // comm keys
        //
        RSAPublicKeySpec commPubKeySpec = new RSAPublicKeySpec(
                new BigInteger("9dd3a0af1e595fb8f926a2422bc6b0343b49bc7931d187b043a176cd62a23ede1076811d9d2161cf6ffd12c209794d3599ea29429a31f4ac13b908764ef7ff374bbabb77804afc1899525ec75779280924266c6ccbce62725ca7df3c9410b1d27796400a6c031aed5e52c0de4210aa2c025ddd9c56b151a33c2a31207bfeb1411f48e417ddc678a22a4c975de126fd64be6ed237cef67e8250ec87977c258c4f362321d7c0835c981660e3dead3fe6d93cbbb155781b89281feb8632e15d62893f4447c8e9dbbd04a31d8cb04228dabfec1662ded5a15345948b37ea3d4632461c768254e15f377fe3e9f1ad5c0a17be0cc422568bf9eaf7c1458b0e7e1fd879", 16),
                new BigInteger("10001", 16));

        RSAPrivateCrtKeySpec   commPrivKeySpec = new RSAPrivateCrtKeySpec(
                new BigInteger("9dd3a0af1e595fb8f926a2422bc6b0343b49bc7931d187b043a176cd62a23ede1076811d9d2161cf6ffd12c209794d3599ea29429a31f4ac13b908764ef7ff374bbabb77804afc1899525ec75779280924266c6ccbce62725ca7df3c9410b1d27796400a6c031aed5e52c0de4210aa2c025ddd9c56b151a33c2a31207bfeb1411f48e417ddc678a22a4c975de126fd64be6ed237cef67e8250ec87977c258c4f362321d7c0835c981660e3dead3fe6d93cbbb155781b89281feb8632e15d62893f4447c8e9dbbd04a31d8cb04228dabfec1662ded5a15345948b37ea3d4632461c768254e15f377fe3e9f1ad5c0a17be0cc422568bf9eaf7c1458b0e7e1fd879", 16),
                new BigInteger("10001", 16),
                new BigInteger("52e847e19624c6e70962e51bb3995518ab086a0c944208706ca6961d003250aa20a5cfdfb99a3ea254a6f1c2a26d6944be0cc70de8a8536a4d9606bef76ec94fc7e558f3469e9d5d62b5657a7c15f6150f3b6bfb9ef854b8d4b98ec868d378462271f8444147444eeb1cb79a49c42d509f11a607a976ce76dc75218779fb6a2b029a321fc0e1ed95055eda04c52b69a0ade32d7dd30d7f48ecd85abedb7e9aa6eeeff7dbefcf473586b6e727906d549f504fc9ed40ffc3772597a8a92b0215052d759202f2ed7db6f33e0af62c849c7bb2e6c4a8b5f9fd5deb4fec0ee37c0b7885220a2174f7457ecc056076ef73031d8f0c718a47f2044dc68fae3e7ceb2b71", 16),
                new BigInteger("da31b0c510f6b85ed6c60bf4ffce808f4d4b024838e77183a2cba145571c31606ab83df3c5c2c0c720ebc09c8a9a9caa36852ac699c79b2a464a1d945a55b939a2c3c1f65e68f5ed21bfb6e247aa0c06b9acd58c169cdddb4fd95290b69b38922a1b575da59e587b11faea56892ac2097e0c1db3eab00b64906d54693fd805bd", 16),
                new BigInteger("b92c40ffa86651d2d3b75455788895d90d51dc58ba3d76c2ff68dc73a27e63c3464c6f0aa4507ede87b6aa39e4533b9e8171282a3522c8118c372b16623df768dc4a4600abbb77ade26636cc69d258032eb87765f4c468dd20a75767a49cfd131daab39b3fc370cb4c6ef82339cd5f61fc9607f612cfe7e3d5e23d19442ff36d", 16),
                new BigInteger("4dcf48958e2e1da39c7db5c7e1ed774523302b992bc9c55e4710cceb185c72734abb77445672d4226ee803a10f80817be5c36974b7644a3e3220be19a879477b7942cc099ab35d77fa000f2cf4977c806d786812f4016ed085d21f32821c2a795d50b0c0318e9d490e2967a602766009d88c638f4493110d04c02848fc3e8215", 16),
                new BigInteger("b5e98ac55e2b7ed0ce5af947aa4d0c611a5bc44b8a531d9bfd8c879e36115272a15a2f7055f21a6105146770ce251299e9f23f920f7766f30e3b9861ba0bc445c8bc52bf0ff6f060ebdc9c92fe96bd0e0b54ff3f3351ccef07c83deebce1d9217170a457ad31945ab47103e69f3f6a27fa1b6e20c964641c089fe48430dfa695", 16),
                new BigInteger("e04718590d168110901f9c75f9c4f74f008e398e3353205c811b28e33ce9e199b9d4a71b8ee9b16fa56edd086fd7e0b7659c05f9482ce42bea5905da85c42da2f0640cd9481f85997641c38e4f38df0f821d30b072f200eaabec1bbbdb54c27845fbcc5fa81c6a3ddf244e1656d02a1d5ee18f8c962d6decf104e914a2c1509", 16));

        //
        // Test User 1
        //
        RSAPublicKeySpec testUser1PubKeySpec = new RSAPublicKeySpec(
                new BigInteger("989992d9bfa0eaadadacc16e010808c230d16468452fa94f9ad0b6a65e800e8458dd2755742a5865d5ab0daf45eeaa52a5182477bbc6285a64e9ec517734bbbe4d2d231e34f8acd616c3cd31a5cc2e7ec0a3fccebb6ac165e380a1b182d9deaa837d4d8e986306ec8c71dd2b62ace6cbb5c940b746c310d84620dccd1ace9a7e80421a5b28ac2cf7084ee45ee1b42284ee5e38568c24093cae4c45002e2a7d3854a7b1dbf889fef66875c5b8d03fe35961de3dcc98c064c4efda5c0836ea9efd6a26ee986b4858f90ec7d09b9eed445f0b46fa0da9bfaec15eead3cd9dbd41a28e93d70587059be44478ca1b684a65a7225d963f9717296f8fa474862f7dc557", 16),
                new BigInteger("10001", 16));

        RSAPrivateCrtKeySpec   testUser1PrivKeySpec = new RSAPrivateCrtKeySpec(
                new BigInteger("989992d9bfa0eaadadacc16e010808c230d16468452fa94f9ad0b6a65e800e8458dd2755742a5865d5ab0daf45eeaa52a5182477bbc6285a64e9ec517734bbbe4d2d231e34f8acd616c3cd31a5cc2e7ec0a3fccebb6ac165e380a1b182d9deaa837d4d8e986306ec8c71dd2b62ace6cbb5c940b746c310d84620dccd1ace9a7e80421a5b28ac2cf7084ee45ee1b42284ee5e38568c24093cae4c45002e2a7d3854a7b1dbf889fef66875c5b8d03fe35961de3dcc98c064c4efda5c0836ea9efd6a26ee986b4858f90ec7d09b9eed445f0b46fa0da9bfaec15eead3cd9dbd41a28e93d70587059be44478ca1b684a65a7225d963f9717296f8fa474862f7dc557", 16),
                new BigInteger("10001", 16),
                new BigInteger("45b2970507664ae9aa926602854c131c06ca0c8f27527e85525393a8e72e9bf2ccd7adb87507463ab4dd9cb17a4268deb8730f6cf481ac3aa52ec675eaf955eab43b3278007fb8094c7a7fc4f6520cc66ddc38827fcd61a9d4c0129a0e06ce9198dee94680c97207269a7706f2d9bfcc392a4379b24333f5640a6c6eed9881ad1fad018e710298f053c493d459f46eac2cc202fb8298b2aac2574b9a23261959c84cdfee063902e88a34794ab4faf0f559875714372dbd47ec0032ae4c9edc15055c5bd20ac37c36f84cb7172583732d0538c7d28ed6ce75e2af4192cfdd9602e1b4eb5a3fcd8c00f8b623bfc43ddf29f6ac4d81e828b87586ba8529b8b7f189", 16),
                new BigInteger("ef697335eb17325bfdf736410f940486ac43d7ed0f0999a5f833ae34efc08ad5dc95c7100c4f9c9a35ba7c9a3d643c0e0327c2c2a4b90964c1bbcb2612a2fd0c45c8a03aa867eeec228b54b286ce02cb9ef834c0f7c5bcd21eb227335e7cb4cb7d2fe61f06e9d98f4a5cbabbb2cb2a66efafe8f7ea21f79b700f0ae1ba6c9e05", 16),
                new BigInteger("a32c4d62441079fc78e45f01d03cba6ddaf125c5a96ff30d858b1d7b8528563a0d9eeb4f825b70317a50ba028fe6e224272449e6804e5f569feac43eba50553c77d63e702d9d72ea5ba6c995bcaed419c745e8f5d9205368c79aee519fe65943d2b6185e5195be7efafd53c4bafb718b041baf6ef384c021649c24f4abecd8ab", 16),
                new BigInteger("7fe6d20a0822486124f8a11f78f716c3ebdc02cb3eb15e4870a50b78746d64be842df03efe94b991190b1bee3ac605df6688236061280980ae8f692459e8814fc128419194ce91b1cd72aa390613a122af36e2d80486bb2d7600af389e4df9388d14bdd7ed959909182d1a0594ab3d67e8bd0db5047c490fdd79ebd2540a1b11", 16),
                new BigInteger("92f5037cccf049ed28b4051d0cfea4a8ebd6e3bdf1abf1aaebeb2ed2604ac3dde5068bc740103a2b558dfef8efc1714a3e36609848564d6726ffb95f054df4765137936454b0c91e690cfde0edde47083080b61f353df7e1166462df00b3e5114064dfed926cdaf461f865c978dd9c95274e07e2554fe9fa2932b7d5e4419ba1", 16),
                new BigInteger("b9aa8cde7df32c0ef92dcda3f308eb7d8bc2b0e942bfe1da609b27b00e1994bc750300bc91347c9b409ad153df2e1e44280b390c5adacfc241d8f15818b116f771d8caefffb1a0c3b2a8e9181e5e43049c571a93854fc992023bb299cb2a79e980264fbf9287bf51a07df12aee3b8b0ebdcf6bb18a1a5a3d54c2958f9c03e967", 16));

        //
        // Test User 2
        //
        RSAPublicKeySpec testUser2PubKeySpec = new RSAPublicKeySpec(
                new BigInteger("87c0ea1ff9658ecf32cc3b1aa280b80ca7a5f341f00ddd849886cb5fc39e399eb297616e3e198eb6c2fe5dbbf3bd6dd090f1c7a01a13ccbd9ba119f5bd8ff770c0d7e2bb6c0ca4d655ecaa40aeadc95284eab93bec8aa488b797dfdac36038b0864856cf5ae9ed598c0897c980db0bcae24618bc791b28140721ce8abaae8273ea5aecc0e5ae39ab9e1c953593450b089987baf31613dcd0e49f586121f349c4ab37c58dd55fdc9f86d03fcc7740567c7230b70b920b0effdf15bf582557cd570ad62abfaead7b0d9c8aad89c5cf867971f2a98d1c283bdb09999b6a0ad9c36d11a3c73ebe7e9fc85aa9a77483517d2f80de3aafa05a01ace499e542982baaa1", 16),
                new BigInteger("10001", 16));

        RSAPrivateCrtKeySpec   testUser2PrivKeySpec = new RSAPrivateCrtKeySpec(
                new BigInteger("87c0ea1ff9658ecf32cc3b1aa280b80ca7a5f341f00ddd849886cb5fc39e399eb297616e3e198eb6c2fe5dbbf3bd6dd090f1c7a01a13ccbd9ba119f5bd8ff770c0d7e2bb6c0ca4d655ecaa40aeadc95284eab93bec8aa488b797dfdac36038b0864856cf5ae9ed598c0897c980db0bcae24618bc791b28140721ce8abaae8273ea5aecc0e5ae39ab9e1c953593450b089987baf31613dcd0e49f586121f349c4ab37c58dd55fdc9f86d03fcc7740567c7230b70b920b0effdf15bf582557cd570ad62abfaead7b0d9c8aad89c5cf867971f2a98d1c283bdb09999b6a0ad9c36d11a3c73ebe7e9fc85aa9a77483517d2f80de3aafa05a01ace499e542982baaa1", 16),
                new BigInteger("10001", 16),
                new BigInteger("5ea03812459366f242a45d66797363d75e5cacad7f990a99cc7fd8ef4db9d2cc2e0c9b1b6f29fd72a3850eed5e3ee27709319f469826c906399f182b55112f1767349494b402343c3af496d033726bec9b3dca145d135f10f57865cf657482cf792a9f683624ed0f082f4d2e662549990814785597cd38288db820f24ea229c782e13acdcc6c0abc4f87c0d56fbb878aa99779031fda591979de9dfde9cd8f9a23e7fd55da517cb3e4365fc3ea5ae484b82b473e70b9f717ccb2c300eeda346ac2f015def6cffa7ef972b1400d060b12e047ea461ae9c106eb619d495917914bc636137a6ac5ea4a0440a2253f8f2c9e92593d832a985a73a03a2231902c1be9", 16),
                new BigInteger("bcad728e92e6d9c1d1aa6e9242d6cd995dc0bc153650c80c1db7f2a449b0c2ab99d13387f262c370090f843bb5667cec5b06acad0af447a384c07d1781fff57c919c8a00f9f9a08ef6955922834cb1d365cb901ab3755562ea636b852218fcbefc284637a17ffdeebede868266fa44a59b6c129587f1b579d60e44cd888d4cfb", 16),
                new BigInteger("b8312eedfe374a58e6b4a81ae92210580f75e168b0c24d6cf7fe79ac7001bcf42122c7291d76cca66f8a2c34112d132f570406cba5eb70524732af1ddf359e48bd9990299d45d16c13bb02d118391abcded2d0118e02c1cb0c082cc303ab58299631ea2202c708f696d5ff863f5456e42032e941c272052fab10b7eac9729c13", 16),
                new BigInteger("21f73f86371fe3d7a67cfe06ca8d8cd9ad2d032ef666387d25e47583e9d82e53620f6d2d6e0f258bc7b5c9624e57b2e981c183d86afe6adf1f08dffc196510b66a283a17cee88764f53311a6cae845a2fed25490d9f9a773752a8cb29cdeceb13b07ad0c5ac085e032f0305acd5b047ca3ac22f45452c90eb3e041b6967c897d", 16),
                new BigInteger("26e503e2efae9f3d7ca223696357751a1351b2229848bf6ec6436f50116adc8ab4c0924bc55403cd157a98f0f9bb89f4922c607efa6f680d87c9551f3ab628d175700af82ea4c29f4edf4badf9ae7d4deac39b7a49819d8891e6dc04e62e75747aa9d9a60aee1a9f6fa48acbbf6dc0d775512ade5f0012c6491a43ac0993f10f", 16),
                new BigInteger("3ec7f63b2bf48c57948b3d01c4ca45a8cf1e868e7ff83c6474d6c815e922a97df56979c0d4bf5139dc1c7bd290edb8ab8432fcf92cb86ab53144abf5bdfa40d0679d607073bc6f2ae9c5d11554433941f8d5e1ff78708d79ed2839cab402139485d0fa42d56003152ba6f66468b18f973b74463e928cc7a6ddde6a20adbe8283", 16));

        //
        // Test User 3
        //
        RSAPublicKeySpec testUser3PubKeySpec = new RSAPublicKeySpec(
                new BigInteger("f7484db57f80aac014509ff5f1968469d26704422b1b57f9b57cfeed007238306fa6d557a8ec999a455579111e6442e5c1e756d5613f632049d1eb894ce04549293440238495c40cea8ade0a3dbbfcb6c788cfcdb3d46df74c09eb92b2967c4a126273eff79c53572d4a1d5118791994ecb652866f14b9257c999e1bf3a233d59dfbd4d31b16149fd51795c57a1d45460ea301123f6e5112d3442e5a9ecf48c709f8e31c1ece93d3748ac78485228cd68c8b078a0c8873d82deeae96d0c1ac4d0983b4a9510cd8f47c3f730a86c6cb2ac07042e303712f29c2edf0b0a23cb46b12faa41f656c29e7d5082187b6a1eb2aab0ca478c2d220019ef9e679ace62b57", 16),
                new BigInteger("10001", 16));

        RSAPrivateCrtKeySpec   testUser3PrivKeySpec = new RSAPrivateCrtKeySpec(
                new BigInteger("f7484db57f80aac014509ff5f1968469d26704422b1b57f9b57cfeed007238306fa6d557a8ec999a455579111e6442e5c1e756d5613f632049d1eb894ce04549293440238495c40cea8ade0a3dbbfcb6c788cfcdb3d46df74c09eb92b2967c4a126273eff79c53572d4a1d5118791994ecb652866f14b9257c999e1bf3a233d59dfbd4d31b16149fd51795c57a1d45460ea301123f6e5112d3442e5a9ecf48c709f8e31c1ece93d3748ac78485228cd68c8b078a0c8873d82deeae96d0c1ac4d0983b4a9510cd8f47c3f730a86c6cb2ac07042e303712f29c2edf0b0a23cb46b12faa41f656c29e7d5082187b6a1eb2aab0ca478c2d220019ef9e679ace62b57", 16),
                new BigInteger("10001", 16),
                new BigInteger("63e8ebb4cc4a413310422f0f20c82ec1cec7de99996f17d18579764a6da6b87b217167bb5e3e122599a3da218784fcde75c4b179cf2bdc321c815b48032e8defec5cf71922a59c2b97cbf9c06b86fba921df6e0e6f7d01dd2bf4ca2060559aec16977ebe52edef6246a32e4b28b72d15d5ba2887b673ca06925c42dc8a485be644f8f6a108e062e06a4dd06cba0e360aaef52dd1cd603e59b2b047c40fead99393cd21ab8aca4e79c99d14cbad279014735897818b3f87821002123b288fcb670ab4d832ac13333b636797240560cd43c3709ac898fa1d7342f46f30d703319ca3b18b1f17069a366513d5594eba7c02a897c234729cc72d10fcc4fb8eef3481", 16),
                new BigInteger("fc1214a4db71ab98d3a7d9f21610be65540b0cde5c4114bd60c569e4e875130047022894975d76383af831810ba7826dfdad48f6f16f3de4e4a81db482ac1d2914987aa851060a127450bb6a213c18b7c0c7cb6dc6c3cc6d1ac4c5a5033fe31ef8fcd1974c1c988958fdeb2a71e0ae34725d71ff1bb4a70ab9f6e164f7bce541", 16),
                new BigInteger("fb231d72c05e3b7baffb23c7eb7d34f8a350738571f1b6535e451560c3c5c0a756387288e0ce14b87354aafc636a752c25e65ea81debbc11bec79a5b41124d25e3a72036d93373c187d24eac904e23d22290d86fa43c039e7f93cba86a534fbccc850d10c3cccbafccb2b8df2fdac3a7d1455f6df9bee463343bb922a1647297", 16),
                new BigInteger("dd698c549aa528135fa70a9bc8a2007bc4ecc7eaf1a200f3aff2f7e72800de25da399d279825725846040887cf92ddd07b89209438d27bcd78c3eb03c9dc20e91abc2cd1780a1402cdc4b43aaee2b8db7f2c8015f707b9a304665f2d68c34f5ebf5a6347c08545bf2f3a2abce7b6718e83fe6cc9a6ae7223cbe17d6e50e5cd81", 16),
                new BigInteger("a6357151f6fae6c74f8b18fd415f96655040f893c2fbc43d9cd07ffb90d61a5125812a5c68dc3b5e7006033c12d7ec4091bccbbcdc409e31e85fd64abae04fead9a64c6dc0868afff4d23d7b7bee1b4b01d1774d3c16f4163c3d26b689d82597c08bf63fb8369c3ff76bf96acd132e16ad2c0aa2907dc44ddbce031366594275", 16),
                new BigInteger("8cbb43a78c38b084215101784f71d9f2315bd5729bd9136301dfa6245db76744b41f46124c03a50eb411e7f3e642fcfe1007faec9ef3288df474f60652fe63df4568e5902bba9720ebc358cc597ed2b4691926c9a22287b45f3d47dbb76a1c6ef76a1a6fd198c85eaf2adf8b38479d5c68567e83994f1a066e0397620535b458", 16));

        //
        // Test User 4
        //
        RSAPublicKeySpec testUser4PubKeySpec = new RSAPublicKeySpec(
                new BigInteger("ab0d7a579c32babe21f9cf7010d32785c2bca7721af34eeae0b15b383e79c528612497d2b3d0744914cd2063b32eb994d013608c6422eb0f8313061b792861436ffdd5466eec5e7cb9c2b9383bdcb09c18fbaad941fd970dafed5bd7122abefb957917bd7e7370a573957c5f29d1862e6c0488944d96a3cf26afc3b22880b0666cc21784c14691f9ae71c253f61c835e55ff2121893a23fe2505c8c5dc7106d0b93a7af69de956f69243748f2d7807de81d8b9380a9a9750053f582c1165eb99b89b7c4804ea774ad0caf4289d26dd9d38d2ab63a5d651ba7013fdb3efeaeea7f27d868fb6807f979936fc2395d6e69e181354515d6f434a92ff20c5c64f0baf", 16),
                new BigInteger("10001", 16));

        RSAPrivateCrtKeySpec   testUser4PrivKeySpec = new RSAPrivateCrtKeySpec(
                new BigInteger("ab0d7a579c32babe21f9cf7010d32785c2bca7721af34eeae0b15b383e79c528612497d2b3d0744914cd2063b32eb994d013608c6422eb0f8313061b792861436ffdd5466eec5e7cb9c2b9383bdcb09c18fbaad941fd970dafed5bd7122abefb957917bd7e7370a573957c5f29d1862e6c0488944d96a3cf26afc3b22880b0666cc21784c14691f9ae71c253f61c835e55ff2121893a23fe2505c8c5dc7106d0b93a7af69de956f69243748f2d7807de81d8b9380a9a9750053f582c1165eb99b89b7c4804ea774ad0caf4289d26dd9d38d2ab63a5d651ba7013fdb3efeaeea7f27d868fb6807f979936fc2395d6e69e181354515d6f434a92ff20c5c64f0baf", 16),
                new BigInteger("10001", 16),
                new BigInteger("8928b28c63d48dc77e28f93c4c5174e49e25764359f6f5b6035c53e002c0d3e630170ea2c6cb0523c0c9470a8b189179116c28440adbb10eec34a9f607ade86811fa41354c26bf1156471d0c497c0a25f1268475d7a387a753058a5a27d81cf251861b1238be4a7a70f7521660cb00c4629b34056f3db6b699b7e0bd101b38d664ff280d640bdb74247bdf89f52a6911adc201c08cfe40839cf1325f92b1a31acb7e4f6486b431c9e83901b65c9f8135407f85ae7ad4e6149567278bfe495293b48ca088d815963d71c0795971c5a48b14cbf1e93cb06d494d3cb31cfedbc9179ad60bd88b2a6419195a9a6613ad83af6bd5dddf8ca8109b1f9349317ceee191", 16),
                new BigInteger("f47b1bde3bd9da94456d125402c298626d1a412f00570ab02e11da1ae99241b7ed8279fefeb7062c94d67b709d72286c751107a778b5f56f61192d962f98f350d6ee818fe1edb69ef78eb68b84003f515aa533cb492fb106eeea242257e856febe46ccbf94705a5356fdacf9795337339d443b49c4632352f2ca6c34cba134e9", 16),
                new BigInteger("b31cb0534837ed4503ecfcdcccb1c604dac5f1841ad8c117c4788aa5ea89fa712cfc95b0565c1ff9fd059265e4cab5b5420bb18418b1b9dcba2160c1600ebd7631fae5df3ca22951de2f63a7c064783f2a94d886cc2187a60acaba635466752291237733e4067e722f417fd63839a9616951ac7b5892143627ab5d8dae3d3cd7", 16),
                new BigInteger("306daa898d258c6cce8bda9395b0626b2cdd848800f33d04c53b780ed8b1c61edf07778f1179c3d954ea5fad6122d9eb120d7b8cab16b0358df064dd59345d0e6864fa793bf1d0b910a4ce78387fac0b3b7f7a110cc04bbae9dcaba7b9ee263d7407a64b54e6249e599f0a82a88bd9657a03a812e6ba14a73bbce94e53ffecf1", 16),
                new BigInteger("45b47786a1c76a267ec59f0ecaf6b06ab93d69a590d1242c7cc0b0acab5f31411451e46b70e07f6d49a3fe7a7b14ccac92dc7c243d7c052a3aa1bcc6e4fc378da51bd0941543c2b2e2b62ca15f457a6a92c6c4918925cf65b633796028bb8b007ddd8089884762b44b61c13f7c382c8c0571cc9f6033d17bd5ea62093e730497", 16),
                new BigInteger("a860a3b1d0138b4501071312b575075f79d3945b4823fc5ab6048007130612fd92ec98d2eb0e894e1a1c5ac27daf3b582c2c43cf3dbf3b5243f6dfdd9b973bcd70cce6e398f7df6d91d44926e7cc8e475212f554e0e779f91d270cffb1a98c0086a9a1295772db461822184a6d1e5eced71a2f7daee87ddf706a1206efb525f5", 16));

        //
        // Expired Certificate
        //
        RSAPublicKeySpec expiredCertPubKeySpec = new RSAPublicKeySpec(
                new BigInteger("8aa4e6483b41d85b84cafaeef13e46d725ab706cddaa69450fcf3347fa820640a69ae33f4ede756ef819fb352367d7713dcdc90d5981ef971fb28b928392f727b94faa779f29dd0860ca2f22597e6998ff8d1e6aa937afd1d7d56a39ae6768e1fb85c52ce0deea4dd4f12136a88572a62b2daa490edb7967b28912a726d88e568109c813fcc15d75d4019132be3f71acd73b2e2c7f1bfd7680d1838fbc27e9174feae6225e8172a63b1d3d1bf6f6f1e36aa1991f88ab64953e93d538809610d5bce36e45d41e30db5a775cdc048587c36f311c0c95a711abe559725c7e6fb38ea9defb7cbe3664b2e61a2fe49214d95d5c59d9945395154967663fe9bfbf682f", 16),
                new BigInteger("10001", 16));

        RSAPrivateCrtKeySpec   expiredCertPrivKeySpec = new RSAPrivateCrtKeySpec(
                new BigInteger("8aa4e6483b41d85b84cafaeef13e46d725ab706cddaa69450fcf3347fa820640a69ae33f4ede756ef819fb352367d7713dcdc90d5981ef971fb28b928392f727b94faa779f29dd0860ca2f22597e6998ff8d1e6aa937afd1d7d56a39ae6768e1fb85c52ce0deea4dd4f12136a88572a62b2daa490edb7967b28912a726d88e568109c813fcc15d75d4019132be3f71acd73b2e2c7f1bfd7680d1838fbc27e9174feae6225e8172a63b1d3d1bf6f6f1e36aa1991f88ab64953e93d538809610d5bce36e45d41e30db5a775cdc048587c36f311c0c95a711abe559725c7e6fb38ea9defb7cbe3664b2e61a2fe49214d95d5c59d9945395154967663fe9bfbf682f", 16),
                new BigInteger("10001", 16),
                new BigInteger("608ba604a4a71c87d67816b7af6ca39e0c904ed0b0a78b78d9227b5e63368a2e191680aac43c2b60a40a4ba15c4f627a6c04523e2697520555c05a6b238e82e7b9a69d59818f8068e625c51ed15d3321a4cb5b640104533df86397fe24d1c3faa1d12c562d1d6de1d72836edbdfa77b4f91a6a9b476a54277eeeeefb5114ba40c02e56c00678a6e4a3bab2973ea5c4a222be736818667eab9a3e4340fbe668f2c70b84e548e6ad89537a118d3c009b2419453e6f0a9ee5e1b8827945f704e3ede7b5fde8cc59361aa4d1a99bbee8259369abe4bc98f68eb0a4cf8a90ef079e712c61a551b98a7dd623f271436bd09c1161a5cf61d026816d6af9d0d55f88a991", 16),
                new BigInteger("d68b1162a1ff2d6ae399538b677802e601746472b7e236203f7562628ca707a9194bb3ad66ae4f9e56d1d9021d9f5b89b5802eb591ce1c2bf7e1720c17bf57e6835da8b852011051cc3a6c86e064f6ac524733c2e556b659025cc63baf031ca8ee4c7c9ea81de027f15cf2f14b9972f08cb4602075cd6171b2af1b6485491439", 16),
                new BigInteger("a56f49b71ead5b8c5a1c43a23a37292cbd8d2d810e63d0d3dfe3e783e6d602ce4f3930607bbe4181d3361ea48496df68f51962726522cdd16fbc16608f2b4edf1ae5353d1f7720f407978621ad44ba77e2e8f0b4761909b743fc32f5ed9271f8a8fbc25bd72ad8f085c4e643190b87e42a6b004197559ba4cabf863840c2efa7", 16),
                new BigInteger("b2fb5dcb9d3e1713bf40a0b401e3daf72b6b80893be2da28d90802c61875182cf84f715c4df749b0dcd940634577369491f897ff1dde871e1f33d343476477de74e563e6317375bbe7d72dc6efd90af903c326e9870e6a1da39ce63bd06b9633506a3ae4d977e3132f86cd9e83e546406c01e6d7edaf238608fd90aab18f1ff1", 16),
                new BigInteger("373767d138e9ffae5ebd244dd74465f7cae47e159f29ed9f6a10f54aef16eb24d5086f7f248e21eb2505e1406408bf5496c9fc33d651c1846fd8c5574131e1475200c2be3dec5311601f50e398a361e175d8edce2dc4b99b73938fa6c9bea14faf87281de33927e34fa2a2802eb1cc8f7920f19af2d9ddf328c0b819ba73d5ed", 16),
                new BigInteger("a692c7747428c0ac9d2bc31666777a8a4acbb5d6d6482256a5f0dda478aa50c02bfee27e978b9fca0e0e9274375e6a0536a861a876de006e6544f092fdb454d39f56dcd7ce99fd94410b08497342583d59ffde632605d156e7eeb7f9382cc39bc8fa3724fd8210a312a4e280194aba627ef577304bbd0bfcb595485f032da030", 16));

        //
        // Net yet valid Certificate
        //
        RSAPublicKeySpec notYetValidCertPubKeySpec = new RSAPublicKeySpec(
                new BigInteger("c2b01d17a30242742cc121137a646f496dbb3a9323a97d9a3098577041e4f8d80f15312c606f8dd1db9f41fa2a0ada5ced55e6d5c889e061c4191829cb40e05abbdde74ec67a7da7ae237a99cdb21667062f46b2dec9aeec5176904095c1e8908cd63bdcfd9df291d80718a305544b1393fae50b1cb760315f6cdd164c8149a76f0d9b75016173872e25ee1fb92284ba0b310b6ccf3665274c87f954bdb30064cafe0b36b276694b6a734131df05af0f8abfec3ebe739e7a38a7cf4d12c93cbff1d16651161dd3d69ede0602796cb8353832a5cf32e53a09eb43a2fd934f6fbde18984993fadf9a7bc4edaebfd925ae8550d442a93b01393cc7d63c5d1a58289", 16),
                new BigInteger("10001", 16));

        RSAPrivateCrtKeySpec   notYetValidCertPrivKeySpec = new RSAPrivateCrtKeySpec(
                new BigInteger("c2b01d17a30242742cc121137a646f496dbb3a9323a97d9a3098577041e4f8d80f15312c606f8dd1db9f41fa2a0ada5ced55e6d5c889e061c4191829cb40e05abbdde74ec67a7da7ae237a99cdb21667062f46b2dec9aeec5176904095c1e8908cd63bdcfd9df291d80718a305544b1393fae50b1cb760315f6cdd164c8149a76f0d9b75016173872e25ee1fb92284ba0b310b6ccf3665274c87f954bdb30064cafe0b36b276694b6a734131df05af0f8abfec3ebe739e7a38a7cf4d12c93cbff1d16651161dd3d69ede0602796cb8353832a5cf32e53a09eb43a2fd934f6fbde18984993fadf9a7bc4edaebfd925ae8550d442a93b01393cc7d63c5d1a58289", 16),
                new BigInteger("10001", 16),
                new BigInteger("5dd70f9ec6069fcb698b098b5ef22c26038b3c7791b7ef7fb3aeaa6ec4843e61be1b63e154f650307820b267877e45b486fd61cf67e2f5518a78e209bb1ba1487ac741e7d9894f29d4a8eb3e59445ec1f7dc2fc2a5da26c3679cb3793df60248326a4cde7f2c73b052a550fdbae2df712761c6a6ed8782092a4ac9e226ac26b88300614f17d30afed5003265b8bed3d591a22f62db16e9b3c5493d1e919b93d1b3302065d52cfb693c9487b53e5a774c0fa278a12d1936eefb49db32613c3fbe693e68348f00f076af98ed167834d39bef7080e7a13c4a08ddce5371210e16d9cf7f06c8cb9fed774c603a1e04a281f4efe02134411b13f09191b3e7f102ec51", 16),
                new BigInteger("ee9c9598016fce10d2716407c8fde6c4b214643ca1abfdf8c9a16f03d84df08da467ed339fcfc066422af68596ccb433c2955c6954e8f1fe94e71e4923769a6d4b4c60778ddb281fc918e719b4d4751bd95c29312824159f5e41d6724ffe3e794b8c29d70d77e0a498de69a192ac6975acde2e931466e397a60c3811b6d9e83d", 16),
                new BigInteger("d0e01c7847f6bec9e31784ff279421f67037fadabda217ce0209922ba0a9af0f2660894f7939d767192da2904a4464af7e5dba9a0d5276ab94e6338bc5a57f9fb86e5e4824ac628142283e8f83e7d248b6d202b2c98ec801097197c64c1581b19542f9765ce5d58717284377dbf43df89e6f25814e42f68ff0b5b4003e449c3d", 16),
                new BigInteger("bb124e82371625f3b059aff81e8f593e7af35bc6e165cb9f22cd8b10f3a3df65dd30919a78bfd373188b406d69d621adb6ef8cdd13f1f1d00b83cb8dc1dcf9a398764fe74b7337d8fbbba76bd30702ad8bd3228464992dce9d82769376bdb8d335f4b4d4e2bd4a852148b67e335532f54c4b812e54bf79cdea24084d7313126d", 16),
                new BigInteger("3448f53772a4244bfb0987242baf1bf5494fe9fe595bbae3b984d5cf0fef89bf9c16ac2875aaf1ed7fd2f98f6ed7c1f0600c6c4a65ad4fc1518b7239b9a6dcd489612f3e95d784ece0379cb9660660900d1b72cb7842c273e7fe4444c204dc2b2cb6d0253dc9d672736c83befc131e741e8ca9f1bd3a6be7ca1461d371c2d0ed", 16),
                new BigInteger("91c898324732a42b8a07b9cd7cdfde093df32a3441ade7478a8c8be59e4814dccafe5587dd691c4c02bfa61108c8a3038900e69c6e7c76671de51d293c593fecae93e71fdb2842b2c4cbca6ddb98e6f57e8160e6a0856dec1548c39c5fa5023432512edc523580720a2d4865c5b54d9effb2e263b381fe52c2ca4889735bf2d8", 16));

        //
        // Revoked Certificate
        //
        RSAPublicKeySpec revokedCertPubKeySpec = new RSAPublicKeySpec(
                new BigInteger("91a3d90ca15013fa7a47dda5aa810ddfddf79b3f5c66cdcf1c6ad2ea8cc3f317d2e72b890092e50d7729ea6ad59afbbbde0f2e6f619240d853f8b8c4f5eebea52721c69e8583ba510701ae078f67d9ef806411626f8566c4cb1d9c22abf97f1baefaeba3619923533876f58a21b9b29f3a1983b47ba2df220879a152a174b352fc3deabe78014922595b8a6a001b5d1f8daff173a174266c53863b6f1b29dc32df6c19e10a5d87f782369cacd788900649fbf9306148244cc81b386eea70a3d450ff2376add8fa3abeaa59e92d1165445cbe47da276cf6b7297156611d3e4dd30e1c4df7ee826cf6388b50d8e26261b14b0d3b0624a768ec58f8a2148f04d713", 16),
                new BigInteger("10001", 16));

        RSAPrivateCrtKeySpec   revokedCertPrivKeySpec = new RSAPrivateCrtKeySpec(
                new BigInteger("91a3d90ca15013fa7a47dda5aa810ddfddf79b3f5c66cdcf1c6ad2ea8cc3f317d2e72b890092e50d7729ea6ad59afbbbde0f2e6f619240d853f8b8c4f5eebea52721c69e8583ba510701ae078f67d9ef806411626f8566c4cb1d9c22abf97f1baefaeba3619923533876f58a21b9b29f3a1983b47ba2df220879a152a174b352fc3deabe78014922595b8a6a001b5d1f8daff173a174266c53863b6f1b29dc32df6c19e10a5d87f782369cacd788900649fbf9306148244cc81b386eea70a3d450ff2376add8fa3abeaa59e92d1165445cbe47da276cf6b7297156611d3e4dd30e1c4df7ee826cf6388b50d8e26261b14b0d3b0624a768ec58f8a2148f04d713", 16),
                new BigInteger("10001", 16),
                new BigInteger("31518be1c40aab094a3965ec80e5bcfe0f5b96fe08db635c7c620c5493209404804dfa2725c398bf4b982d22ca7cf63c33416ed716f280f500d29c374e94ef885bcd0b46892e077d02e365bc77aa9259915fd1a744dea6e38368de83bb3afcf931f314b2ba0d32b22ecfd1ec59e9597ca41f19c3978e9b031a5d9decae72277b2fa44e80e8091c782d7f8bece0b30f92484771a699784baab37755be60f5536cd60eb73f4da4b2a611134c11c10eb4f2ae9d3fdfdc3a242b038f1cbf6d407558718f84574d038311e4f1335f87f50021a5d027f3ce01bea64aab491d396ecc2593243a1909cbaedf9520db66971f3e3b88d2fd6055e4c9bf15694f18dd1b4361", 16),
                new BigInteger("f0eb6cfda4d2428b7bb07c30bc00c65f7c7985e56d36a3b9586ec3e87ef107351bbd27cc669c365bb3617e6852af926eb978b1112ea139fe687c33cac3d4b055f992c80fa2e800b10a74142493bb82d9da2364f9a5dcc2cfce40a8588b83a9dfdf2b887723cfdc66b081c05332f0d56283dffcc5926902cef8dad5f4ec21f503", 16),
                new BigInteger("9ac1a1828177e62c12dc2adc51e983dff0cd4a1769db6118e47b7971a77ec9d2c75e46d44c39ed58ffda4eb1132fb0591b4b10b1b17e2245e3044e0e6ca1050d1a11731324b395686fb70f1e0fda6c295c34eb05713338c2768b7faaf18a387be8093f11b597644336f68f5d10602039cb7f1243cf3d83cbd4deefb52428d0b1", 16),
                new BigInteger("cb62142ab4a00429788beeebbd6af20cde2a410d03fbe28fafc62280fdd9407a67267298adef263c97dcb03825c5ae5ae71caa6e94eceae68912812ea5cfc1e572c1a53efe09d9bb9bd58ec3aa2bdc35496023f8553b5f02cb5dee4081d6eeebdd9d04a17f8c14c6642fc54af77034d3ebfc8589cd25f58700b2cd78ec77663d", 16),
                new BigInteger("6f7dd68cfe175255285543efac77ae91749b81a872942154dcaef42464865c82a52d8f9bbd3af27aef00e9367b5b1d12652e645d90410e1209667d91b8c31caf7ebb598b4e22af1e2975d9c74fa68dcc1268f174df4406bd5ac84f76e9432a44623bdf1b3417589d70089bea7134bfa2c3afcd89dad137956ecc1a28075ffc51", 16),
                new BigInteger("a604352139367d5fea84815ee0645877e73a2655e2d3151fdd1ffe5d02def407a0708e0aec50e567b7adf7152dd7269aaa1596b65421de24b8609110b3e2d62b7d7dbed78003f429e71733c10f32165b088495f6f930803b732e1cd8031643254a10b2406a3250a4c97898cf092960cca2409ae04e3b940535f1c7c060512b16", 16));

        //
        // set up the keys
        //
        KeyFactory          fact = KeyFactory.getInstance("RSA", "BC");
        caCertPrivateKey = fact.generatePrivate(caPrivKeySpec);
        PublicKey           caPubKey = fact.generatePublic(caPubKeySpec);
        subCACertPrivateKey = fact.generatePrivate(intPrivKeySpec);
        PublicKey           subCAPubKey = fact.generatePublic(intPubKeySpec);
        raCertPrivateKey = fact.generatePrivate(raPrivKeySpec);
        PublicKey           raPubKey = fact.generatePublic(raPubKeySpec);
        commCertPrivateKey = fact.generatePrivate(commPrivKeySpec);
        PublicKey           commPubKey = fact.generatePublic(commPubKeySpec);
        testUser1CertPrivateKey = fact.generatePrivate(testUser1PrivKeySpec);
        PublicKey           testUser1PubKey = fact.generatePublic(testUser1PubKeySpec);
        testUser2CertPrivateKey = fact.generatePrivate(testUser2PrivKeySpec);
        PublicKey           testUser2PubKey = fact.generatePublic(testUser2PubKeySpec);

        testUser3CertPrivateKey = fact.generatePrivate(testUser3PrivKeySpec);
        PublicKey           testUser3PubKey = fact.generatePublic(testUser3PubKeySpec);
        testUser4CertPrivateKey = fact.generatePrivate(testUser4PrivKeySpec);
        PublicKey           testUser4PubKey = fact.generatePublic(testUser4PubKeySpec);

        expiredCertPrivateKey = fact.generatePrivate(expiredCertPrivKeySpec);
        PublicKey           expiredCertPubKey = fact.generatePublic(expiredCertPubKeySpec);

        notYetValidCertPrivateKey = fact.generatePrivate(notYetValidCertPrivKeySpec);
        PublicKey           notYetValidCertPubKey = fact.generatePublic(notYetValidCertPubKeySpec);

        revokedCertPrivateKey = fact.generatePrivate(revokedCertPrivKeySpec);
        PublicKey           revokedCertPubKey = fact.generatePublic(revokedCertPubKeySpec);

        caCert = (X509Certificate) createMasterCert(caPubKey, caCertPrivateKey);
        certificateChain.add(caCert);
    	subCACert = (X509Certificate) createIntermediateCert(subCAPubKey, caCertPrivateKey, caCert);
        certificateChain.add(subCACert);
        raCert = (X509Certificate) createRACert(raPubKey, subCACertPrivateKey, subCACert);

        commChain = new ArrayList<Certificate>(certificateChain);
        commCert = (X509Certificate) createCert("C=BE, O=Cryptable, OU=PKI Devision, CN=CA Communication", commPubKey, subCACertPrivateKey, subCACert, BigInteger.valueOf(10));
        commChain.add(commCert);

        testUser1Cert = (X509Certificate) createSelfSignedCert("C=BE, O=Cryptable, OU=PKI Devision, CN=Test User 1", testUser1PubKey, testUser1CertPrivateKey);
        testUser2Cert = (X509Certificate) createSelfSignedCert("C=BE, O=Cryptable, OU=PKI Devision, CN=Test User 2", testUser2PubKey, testUser2CertPrivateKey);

        testUser3Cert = (X509Certificate) createCert("C=BE, O=Cryptable, OU=PKI Devision, CN=Test User 3", testUser3PubKey, subCACertPrivateKey, subCACert, BigInteger.valueOf(10));
        testUser4Cert = (X509Certificate) createCert("C=BE, O=Cryptable, OU=PKI Devision, CN=Test User 4", testUser4PubKey, subCACertPrivateKey, subCACert, BigInteger.valueOf(20));

        expiredCert = (X509Certificate) createExpiredCert("C=BE, O=Cryptable, OU=PKI Devision, CN=Expired Certificate", expiredCertPubKey, subCACertPrivateKey, subCACert, BigInteger.valueOf(30));

        notYetValidCert = (X509Certificate) createNotYetValidCert("C=BE, O=Cryptable, OU=PKI Devision, CN=Net Yet Valid Certificate", notYetValidCertPubKey, subCACertPrivateKey, subCACert, BigInteger.valueOf(35));

        revokedCert = (X509Certificate) createCert("C=BE, O=Cryptable, OU=PKI Devision, CN=Revoked Certificate", revokedCertPubKey, subCACertPrivateKey, subCACert, BigInteger.valueOf(40));

        x509CRL = createCRL(subCACertPrivateKey, subCACert, BigInteger.valueOf(40));
    }

    public String storeJKS() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        String fileName = "keystore.jks";
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        keyStore.setKeyEntry("COMM", subCACertPrivateKey, "ca-system".toCharArray(), commChain.toArray(new Certificate[certificateChain.size()]));
        keyStore.setKeyEntry("CA", subCACertPrivateKey, "ca-system".toCharArray(), certificateChain.toArray(new Certificate[certificateChain.size()]));
        keyStore.setCertificateEntry("RA", raCert);
        FileOutputStream fileOutputStream = new FileOutputStream(fileName);
        keyStore.store(fileOutputStream, "system".toCharArray());

        return fileName;
    }
}
