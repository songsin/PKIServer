package org.cryptable.pki.server.persistence.profile.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

/**
 * <Extensions>
 *   <Authority_Key_Identifier>Subject Key Identifier</Authority_Key_Identifier>
 *   <Subject_Key_Identifier>160 bit SHA-1</Subject_Key_Identifier>
 *   <Key_Usage>
 *   ...
 *   </Key_Usage>
 *   <Certificate_Policies Critical="No">
 *   ...
 *   </Certificate_Policies>
 *   <Subject_Alternative_Name>
 *   ...
 *   </Subject_Alternative_Name>
 *   <Issuer_Alternative_Name/>
 *   <Extended_Key_Usage>
 *   ...
 *   </Extended_Key_Usage>
 *   <CRL_Distribution_Points>
 *   ...
 *   </CRL_Distribution_Points>
 *   <Basic_Constraints>
 *   ...
 *   </Basic_Constraints>
 *   <Qualified_Statements>
 *   ...
 *   </Qualified_Statements>
 *   <Certificate_Template_Name>DomainController</Certificate_Template_Name>
 *   <Authority_Info_Access>
 *   ...
 *   </Authority_Info_Access>
 * </Extensions>
 *
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 10:43
 */
@SuppressWarnings("ALL")
@XmlAccessorType(XmlAccessType.FIELD)
public class JAXBCertificateExtensions {

    @XmlElement(name="Authority_Key_Identifier")
    protected String authorityKeyIdentifier;

    @XmlElement(name="Subject_Key_Identifier")
    protected String subjectKeyIdentifier;

    @XmlElement(name="Key_Usage")
    protected JAXBKeyUsage keyUsage;

    @XmlElement(name="Certificate_Policies")
    protected JAXBCertificatePolicies certificatePolicies;

    @XmlElement(name="Subject_Alternative_Name")
    protected JAXBSubjectAlternativeName subjectAlternativeName;

    @XmlElement(name="Issuer_Alternative_Name")
    protected JAXBIssuerAlternativeName issuerAlternativeName;

    @XmlElement(name="Extended_Key_Usage")
    protected JAXBExtendedKeyUsage extendedKeyUsage;

    @XmlElement(name="CRL_Distribution_Points")
    protected JAXBCrlDistributionPoints crlDistributionPoints;

    @XmlElement(name="Basic_Constraints")
    protected JAXBBasicConstraints basicConstraints;

    @XmlElement(name="Qualified_Statements")
    protected JAXBQualifiedStatements qualifiedStatements;

    @XmlElement(name="Certificate_Template_Name")
    protected String certificateTemplateName;

    @XmlElement(name="Authority_Info_Access")
    protected JAXBAuthorityInfoAccess authorityInfoAccess;

    public String getAuthorityKeyIdentifier() {
        return authorityKeyIdentifier;
    }

    public void setAuthorityKeyIdentifier(String authorityKeyIdentifier) {
        this.authorityKeyIdentifier = authorityKeyIdentifier;
    }

    public String getSubjectKeyIdentifier() {
        return subjectKeyIdentifier;
    }

    public void setSubjectKeyIdentifier(String subjectKeyIdentifier) {
        this.subjectKeyIdentifier = subjectKeyIdentifier;
    }

    public JAXBKeyUsage getKeyUsage() {
        return keyUsage;
    }

    public void setKeyUsage(JAXBKeyUsage keyUsage) {
        this.keyUsage = keyUsage;
    }

    public JAXBCertificatePolicies getCertificatePolicies() {
        return certificatePolicies;
    }

    public void setCertificatePolicies(JAXBCertificatePolicies certificatePolicies) {
        this.certificatePolicies = certificatePolicies;
    }

    public JAXBSubjectAlternativeName getSubjectAlternativeName() {
        return subjectAlternativeName;
    }

    public void setSubjectAlternativeName(JAXBSubjectAlternativeName subjectAlternativeName) {
        this.subjectAlternativeName = subjectAlternativeName;
    }

    public JAXBIssuerAlternativeName getIssuerAlternativeName() {
        return issuerAlternativeName;
    }

    public void setIssuerAlternativeName(JAXBIssuerAlternativeName issuerAlternativeName) {
        this.issuerAlternativeName = issuerAlternativeName;
    }

    public JAXBExtendedKeyUsage getExtendedKeyUsage() {
        return extendedKeyUsage;
    }

    public void setExtendedKeyUsage(JAXBExtendedKeyUsage extendedKeyUsage) {
        this.extendedKeyUsage = extendedKeyUsage;
    }

    public JAXBCrlDistributionPoints getCrlDistributionPoints() {
        return crlDistributionPoints;
    }

    public void setCrlDistributionPoints(JAXBCrlDistributionPoints crlDistributionPoints) {
        this.crlDistributionPoints = crlDistributionPoints;
    }

    public JAXBBasicConstraints getBasicConstraints() {
        return basicConstraints;
    }

    public void setBasicConstraints(JAXBBasicConstraints basicConstraints) {
        this.basicConstraints = basicConstraints;
    }

    public JAXBQualifiedStatements getQualifiedStatements() {
        return qualifiedStatements;
    }

    public void setQualifiedStatements(JAXBQualifiedStatements qualifiedStatements) {
        this.qualifiedStatements = qualifiedStatements;
    }

    public String getCertificateTemplateName() {
        return certificateTemplateName;
    }

    public void setCertificateTemplateName(String certificateTemplateName) {
        this.certificateTemplateName = certificateTemplateName;
    }

    public JAXBAuthorityInfoAccess getAuthorityInfoAccess() {
        return authorityInfoAccess;
    }

    public void setAuthorityInfoAccess(JAXBAuthorityInfoAccess authorityInfoAccess) {
        this.authorityInfoAccess = authorityInfoAccess;
    }
}
