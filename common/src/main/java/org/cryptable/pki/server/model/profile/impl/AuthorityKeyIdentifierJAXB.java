package org.cryptable.pki.server.model.profile.impl;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.cryptable.pki.server.model.profile.ExtensionTemplate;
import org.cryptable.pki.server.model.profile.Result;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;


/**
 * Author: davidtillemans
 * Date: 1/01/14
 * Hour: 16:00
 */
public class AuthorityKeyIdentifierJAXB implements ExtensionTemplate {

    private Extension authorityKeyIdExtension;

    public AuthorityKeyIdentifierJAXB(String authorityKeyIdentifier, Certificate caCertificate) throws NoSuchAlgorithmException, IOException {

        X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(caCertificate);
         if (authorityKeyIdentifier.equals("Issuer and Serial Number")) {
             authorityKeyIdExtension = new Extension(Extension.authorityKeyIdentifier, false,
                new DEROctetString(new AuthorityKeyIdentifier(new GeneralNames(new GeneralName(x509CertificateHolder.getIssuer())),
                    x509CertificateHolder.getSerialNumber())));
        }
        else {
             authorityKeyIdExtension = new Extension(Extension.authorityKeyIdentifier, false,
                 new DEROctetString(new AuthorityKeyIdentifier(x509CertificateHolder.getSubjectPublicKeyInfo())));
         }
    }

    @Override
    public ASN1ObjectIdentifier getExtensionOID() {
        return Extension.authorityKeyIdentifier;
    }

    @Override
    public Result validateExtension(Extension extension) throws IOException, NoSuchAlgorithmException {
        Result result = new Result(Result.Decisions.INVALID, null);
        AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(extension.getParsedValue());

        // Validate the extension
        if (extension.isCritical() == false &&
            authorityKeyIdentifier.equals(AuthorityKeyIdentifier.getInstance(authorityKeyIdExtension.getParsedValue()))) {
            return new Result(Result.Decisions.VALID, extension);
        }

        return new Result(Result.Decisions.OVERRULED, authorityKeyIdExtension);
    }

    @Override
    public void initialize(CertTemplate certTemplate) {

    }

    @Override
    public Result getExtension() throws IOException, NoSuchAlgorithmException {

        return new Result(Result.Decisions.VALID, authorityKeyIdExtension);
    }

    @Override
    public Boolean getCriticalility() {
        return false;
    }
}
