package org.cryptable.pki.server.model.profile.impl;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.cryptable.pki.server.model.profile.ExtensionTemplate;
import org.cryptable.pki.server.model.profile.ProfileException;
import org.cryptable.pki.server.model.profile.Result;
import org.cryptable.pki.server.persistence.profile.jaxb.JAXBSubjectAlternativeName;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

/**
 * Adapter for the JAXB implementation
 *
 * Author: davidtillemans
 * Date: 2/01/14
 * Hour: 20:35
 */
public class SubjectAlternativeNameJAXB implements ExtensionTemplate {

    private boolean[] keep = new boolean[9];
    private String otherName = null;

    public SubjectAlternativeNameJAXB(JAXBSubjectAlternativeName jaxbSubjectAlternativeName) {
        for (int i=0; i<keep.length; i++) keep[i] = false;
        if (jaxbSubjectAlternativeName.getKeepDName())
            keep[GeneralName.directoryName] = true;
        if (jaxbSubjectAlternativeName.getKeepDomainName())
            keep[GeneralName.dNSName] = true;
        if (jaxbSubjectAlternativeName.getKeepEmail())
            keep[GeneralName.rfc822Name] = true;
        if (jaxbSubjectAlternativeName.getKeepIPAdress())
            keep[GeneralName.iPAddress] = true;
        if (jaxbSubjectAlternativeName.getKeepURL())
            keep[GeneralName.uniformResourceIdentifier] = true;
        if (!jaxbSubjectAlternativeName.getOtherName().isEmpty()) {
            keep[GeneralName.otherName] = true;
        }
    }

    @Override
    public ASN1ObjectIdentifier getExtensionOID() {
        return Extension.subjectAlternativeName;
    }

    @Override
    public Result validateExtension(Extension extension) throws IOException, NoSuchAlgorithmException {
        Result result = new Result(Result.Decisions.INVALID, null);

        GeneralNamesBuilder generalNamesBuilder = new GeneralNamesBuilder();
        GeneralNames generalNames = GeneralNames.getInstance(extension.getParsedValue());
        for (GeneralName generalName : generalNames.getNames()) {
            if ((generalName.getTagNo() < keep.length) && keep[generalName.getTagNo()]) {
                generalNamesBuilder.addName(generalName);
            }
            else {
                result.setDecision(Result.Decisions.OVERRULED);
            }
        }
        if (extension.isCritical())
            result.setDecision(Result.Decisions.OVERRULED);

        GeneralNames temp = generalNamesBuilder.build();
        Extension tempExtension = new Extension(Extension.subjectAlternativeName,
            false,
            new DEROctetString(temp));

        result.setValue(tempExtension);

        return result;
    }

    @Override
    public void initialize(CertTemplate certTemplate) throws ProfileException {

    }

    @Override
    public Result getExtension() throws IOException, NoSuchAlgorithmException {
        return null;
    }

    @Override
    public Boolean getCriticalility() {
        return false;
    }
}
