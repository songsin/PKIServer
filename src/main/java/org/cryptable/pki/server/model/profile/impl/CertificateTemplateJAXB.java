package org.cryptable.pki.server.model.profile.impl;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.microsoft.MicrosoftObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.cryptable.pki.server.model.profile.ExtensionTemplate;
import org.cryptable.pki.server.model.profile.Result;
import org.cryptable.pki.server.persistence.profile.jaxb.JAXBBasicConstraints;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * <Certificate_Template_Name>User</Certificate_Template_Name>
 *
 * Author: davidtillemans
 * Date: 29/12/13
 * Hour: 13:44
 */
public class CertificateTemplateJAXB implements ExtensionTemplate {

    private final Logger logger = LoggerFactory.getLogger(CertificateTemplateJAXB.class);

    private Extension certificateTemplate;

    public CertificateTemplateJAXB(String certificateTemplate) throws IOException {

        if (certificateTemplate.equals("User") ||
            certificateTemplate.equals("DomainController")) {
            this.certificateTemplate = new Extension(MicrosoftObjectIdentifiers.microsoftCertTemplateV1,
                false,
                new DEROctetString(new DERBMPString(certificateTemplate)));
        }
        else {
            this.certificateTemplate = null;
        }
    }

    @Override
    public ASN1ObjectIdentifier getExtensionOID() {
        return MicrosoftObjectIdentifiers.microsoftCertTemplateV1;
    }

    @Override
    public Result validateExtension(Extension extension) throws IOException {
        return new Result(Result.Decisions.OVERRULED, this.certificateTemplate);
    }

    @Override
    public void initialize(CertTemplate certTemplate) {

    }

    @Override
    public Result getExtension() throws IOException {
        return new Result(Result.Decisions.VALID, this.certificateTemplate);
    }

    @Override
    public Boolean getCriticalility() {
        return false;
    }
}
