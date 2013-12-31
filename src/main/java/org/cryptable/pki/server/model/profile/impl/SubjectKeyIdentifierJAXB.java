package org.cryptable.pki.server.model.profile.impl;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.cryptable.pki.server.model.profile.ExtensionTemplate;
import org.cryptable.pki.server.model.profile.Result;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

/**
 * Glue class between JAXB and the Bouncycastle extensions
 *
 * Author: davidtillemans
 * Date: 30/12/13
 * Hour: 22:37
 */
public class SubjectKeyIdentifierJAXB implements ExtensionTemplate {

    private boolean truncatedSHA1 = false;

    private SubjectPublicKeyInfo publicKeyData;

    public SubjectKeyIdentifierJAXB(String subjectKeyId) {

        if (subjectKeyId == null || subjectKeyId.equals("160 bit SHA-1"))
            truncatedSHA1 = false;
        else
            truncatedSHA1 = true;
        publicKeyData = null;
    }

    @Override
    public ASN1ObjectIdentifier getExtensionOID() {
        return Extension.subjectKeyIdentifier;
    }

    @Override
    public Result validateExtension(Extension extension) throws IOException, NoSuchAlgorithmException {
        Result result = new Result(Result.Decisions.VALID, null);
        SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.getInstance(extension.getParsedValue());
        X509ExtensionUtils x509ExtensionUtils = new JcaX509ExtensionUtils();

        // Validate the extension
        if (extension.isCritical() == false) {
            if ((subjectKeyIdentifier.getKeyIdentifier().length == 8) && truncatedSHA1)
                return new Result(Result.Decisions.VALID, extension);

            if ((subjectKeyIdentifier.getKeyIdentifier().length == 20) && !truncatedSHA1)
                return new Result(Result.Decisions.VALID, extension);
        }

        // Overrule the extension
        if (truncatedSHA1)
            subjectKeyIdentifier = x509ExtensionUtils.createTruncatedSubjectKeyIdentifier(publicKeyData);
        else
            subjectKeyIdentifier = x509ExtensionUtils.createSubjectKeyIdentifier(publicKeyData);

        Extension tempExtension = new Extension(Extension.subjectKeyIdentifier,
            false,
            new DEROctetString(subjectKeyIdentifier));

        return new Result(Result.Decisions.OVERRULED, tempExtension);
    }

    public void setSubjectPublicKeyInfo(SubjectPublicKeyInfo subjectPublicKeyInfo) {
        publicKeyData = subjectPublicKeyInfo;
    }

    @Override
    public Result getExtension() throws IOException, NoSuchAlgorithmException {
        Result result = new Result(Result.Decisions.INVALID, null);
        X509ExtensionUtils x509ExtensionUtils = new JcaX509ExtensionUtils();
        SubjectKeyIdentifier subjectKeyIdentifier = null;

        if (publicKeyData != null) {
            if (truncatedSHA1)
                subjectKeyIdentifier = x509ExtensionUtils.createTruncatedSubjectKeyIdentifier(publicKeyData);
            else
                subjectKeyIdentifier = x509ExtensionUtils.createSubjectKeyIdentifier(publicKeyData);

            Extension extension = new Extension(Extension.subjectKeyIdentifier,
                false,
                new DEROctetString(subjectKeyIdentifier));
            result.setDecision(Result.Decisions.VALID);
            result.setValue(extension);
        }
        else {
            result.setValue(String.valueOf("No public key to generate Subject Key Identifier"));
        }

        return result;
    }

    @Override
    public Boolean getCriticalility() {
        return false;
    }
}
