package org.cryptable.pki.server.model.profile.impl;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.cryptable.pki.server.model.profile.ExtensionTemplate;
import org.cryptable.pki.server.model.profile.Result;
import org.cryptable.pki.server.model.profile.jaxb.JAXBBasicConstraints;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * <Basic_Constraints>
 *   <Use_CA_Key>Yes</Use_CA_Key>
 *   <Certificate_Path_lentgh>2</Certificate_Path_lentgh>
 * </Basic_Constraints>
 *
 * Author: davidtillemans
 * Date: 29/12/13
 * Hour: 13:44
 */
public class BasicConstraintsJAXB implements ExtensionTemplate {

    private final Logger logger = LoggerFactory.getLogger(BasicConstraintsJAXB.class);

    private Extension basicConstraintsExtension;

    public BasicConstraintsJAXB(JAXBBasicConstraints jaxbBasicConstraints) throws IOException {
        BasicConstraints basicConstraints = null;
        if (jaxbBasicConstraints != null) {
            if (jaxbBasicConstraints.isCA()) {
                if (jaxbBasicConstraints.getPathLength() >= 0) {
                    basicConstraints = new BasicConstraints(jaxbBasicConstraints.getPathLength());
                }
                else {
                    basicConstraints = new BasicConstraints(true);
                }
            }
            else {
                basicConstraints = new BasicConstraints(false);
            }
        }
        basicConstraintsExtension = new Extension(Extension.basicConstraints, true, new DEROctetString(basicConstraints));
    }

    @Override
    public ASN1ObjectIdentifier getExtensionOID() {
        return Extension.basicConstraints;
    }

    @Override
    public Result validateExtension(Extension extension) throws IOException {
        return new Result(Result.Decisions.OVERRULED, basicConstraintsExtension);
    }

    @Override
    public void initialize(CertTemplate certTemplate) {

    }

    @Override
    public Result getExtension() throws IOException {
        return new Result(Result.Decisions.VALID, basicConstraintsExtension);
    }

    @Override
    public Boolean getCriticalility() {
        return true;
    }
}
