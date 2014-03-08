package org.cryptable.pki.server.model.profile.impl;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x509.*;
import org.cryptable.pki.server.model.profile.ExtensionTemplate;
import org.cryptable.pki.server.model.profile.ProfileException;
import org.cryptable.pki.server.model.profile.Result;
import org.cryptable.pki.server.model.profile.jaxb.JAXBCertificatePolicies;
import org.cryptable.pki.server.model.profile.jaxb.JAXBCertificatePolicy;
import org.cryptable.pki.server.model.profile.jaxb.JAXBQualifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

/**
 * Author: davidtillemans
 * Date: 2/01/14
 * Hour: 00:23
 */
public class CertificatePoliciesJAXB implements ExtensionTemplate {

    final Logger logger = LoggerFactory.getLogger(CertificatePoliciesJAXB.class);

    boolean critical;

    private Extension certificatePoliciesExtension;

    public CertificatePoliciesJAXB(JAXBCertificatePolicies jaxbCertificatePolicies) throws IOException {
        critical = jaxbCertificatePolicies.getCritical();

        List<PolicyInformation> policyInformationList = new ArrayList<PolicyInformation>();

        for (JAXBCertificatePolicy jaxbCertificatePolicy : jaxbCertificatePolicies.getCertificatePolicies()) {
            ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
            if (jaxbCertificatePolicy.getJaxbQualifiers() != null) {
                for(JAXBQualifier jaxbQualifier : jaxbCertificatePolicy.getJaxbQualifiers()) {
                    PolicyQualifierInfo policyQualifierInfo = null;
                    if (PolicyQualifierId.id_qt_unotice.getId().equals(jaxbQualifier.getId())) {
                        String[] temp = jaxbQualifier.getNoticeNumbers().split(",");
                        Vector<Integer> noticeNumbers = new Vector<Integer>(temp.length);
                        for (String nbr : temp) {
                            noticeNumbers.add(Integer.parseInt(nbr.trim()));
                        }
                        policyQualifierInfo = new PolicyQualifierInfo(PolicyQualifierId.id_qt_unotice,
                            (new UserNotice(new NoticeReference(jaxbQualifier.getOrganisation(), noticeNumbers), jaxbQualifier.getExplicitText())).toASN1Primitive());
                    }
                    else if (PolicyQualifierId.id_qt_cps.getId().equals(jaxbQualifier.getId())) {
                        policyQualifierInfo = new PolicyQualifierInfo(jaxbQualifier.getUri());

                    }
                    else {
                        logger.error("Unknown qualifier " + jaxbQualifier.getId());
                    }
                    if (policyQualifierInfo != null)
                        asn1EncodableVector.add(policyQualifierInfo);
                }
            }
            if (asn1EncodableVector.size() > 0) {
                PolicyInformation policyInformation = new PolicyInformation(new ASN1ObjectIdentifier(jaxbCertificatePolicy.getOid()),
                    new DERSequence(asn1EncodableVector));
                policyInformationList.add(policyInformation);
            }
            else {
                PolicyInformation policyInformation = new PolicyInformation(new ASN1ObjectIdentifier(jaxbCertificatePolicy.getOid()));
                policyInformationList.add(policyInformation);
            }
        }

        PolicyInformation[] policyInformations = new PolicyInformation[policyInformationList.size()];
        certificatePoliciesExtension = new Extension(Extension.certificatePolicies, critical,
            new DEROctetString(new CertificatePolicies(policyInformationList.toArray(policyInformations))));
    }

    @Override
    public ASN1ObjectIdentifier getExtensionOID() {
        return Extension.certificatePolicies;
    }

    @Override
    public Result validateExtension(Extension extension) throws IOException, NoSuchAlgorithmException {
        return new Result(Result.Decisions.OVERRULED, certificatePoliciesExtension);
    }

    @Override
    public void initialize(CertTemplate certTemplate) throws ProfileException {

    }

    @Override
    public Result getExtension() throws IOException, NoSuchAlgorithmException {
        return new Result(Result.Decisions.VALID, certificatePoliciesExtension);
    }

    @Override
    public Boolean getCriticalility() {
        return critical;
    }
}
