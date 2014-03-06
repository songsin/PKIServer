package org.cryptable.pki.server.business;

import java.security.KeyPair;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.cmp.PKIStatus;

public class ProcessCertificationResult {
	PKIStatus pkiStatus;
	
	X509Certificate x509Certificate;
	
	KeyPair keyPair;

	public ProcessCertificationResult(PKIStatus pkiStatus, X509Certificate x509Certificate, KeyPair keyPair) {
		this.pkiStatus = pkiStatus;
		this.x509Certificate = x509Certificate;
		this.keyPair = keyPair;
	}
	
	public PKIStatus getPkiStatus() {
		return pkiStatus;
	}

	public void setPkiStatus(PKIStatus pkiStatus) {
		this.pkiStatus = pkiStatus;
	}

	public X509Certificate getX509Certificate() {
		return x509Certificate;
	}

	public void setX509Certificate(X509Certificate x509Certificate) {
		this.x509Certificate = x509Certificate;
	}

	public KeyPair getKeyPair() {
		return keyPair;
	}

	public void setKeyPair(KeyPair keyPair) {
		this.keyPair = keyPair;
	}
	
	
}
