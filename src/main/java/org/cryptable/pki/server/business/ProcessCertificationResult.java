package org.cryptable.pki.server.business;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.cert.X509CertificateHolder;

public class ProcessCertificationResult {
	PKIStatus pkiStatus;
	
	X509CertificateHolder x509CertificateHolder;
	
	KeyPair keyPair;

	public ProcessCertificationResult(PKIStatus pkiStatus, X509CertificateHolder x509CertificateHolder, KeyPair keyPair) {
		this.pkiStatus = pkiStatus;
		this.x509CertificateHolder = x509CertificateHolder;
		this.keyPair = keyPair;
	}
	
	public PKIStatus getPkiStatus() {
		return pkiStatus;
	}

	public void setPkiStatus(PKIStatus pkiStatus) {
		this.pkiStatus = pkiStatus;
	}

	public X509CertificateHolder getX509CertificateHolder() {
		return x509CertificateHolder;
	}

	public void setX509CertificateHolder(X509CertificateHolder x509CertificateHolder) {
		this.x509CertificateHolder = x509CertificateHolder;
	}

	public KeyPair getKeyPair() {
		return keyPair;
	}

	public void setKeyPair(KeyPair keyPair) {
		this.keyPair = keyPair;
	}
	
	
}
