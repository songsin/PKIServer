package org.cryptable.pki.server.model.profile.impl;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.asn1.x509.qualified.SemanticsInformation;
import org.cryptable.pki.server.model.profile.ExtensionTemplate;
import org.cryptable.pki.server.model.profile.Result;
import org.cryptable.pki.server.persistence.profile.jaxb.JAXBBasicConstraints;
import org.cryptable.pki.server.persistence.profile.jaxb.JAXBQualifiedStatements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * <Qualified_Statements>
 *   <Issue_Qualified_Statement/>
 *   <Liability_Limit>
 *     <Amount>10000</Amount>
 *     <Exponent>1</Exponent>
 *     <Currency_Code>978</Currency_Code>
 *   </Liability_Limit>
 *   <Retention_Period>30</Retention_Period>
 *   <Semantic_ID>11</Semantic_ID>
 *   <Registration_Agents>
 *     <DName>cn=RA1, o=Cryptable, c=be</DName>
 *     <DName>cn=RA2, o=Cryptable, c=be</DName>
 *   </Registration_Agents>
 * </Qualified_Statements>
 *
 * Author: davidtillemans
 * Date: 29/12/13
 * Hour: 13:44
 */
public class QualifiedStatementsJAXB implements ExtensionTemplate {

    private final Logger logger = LoggerFactory.getLogger(QualifiedStatementsJAXB.class);

    private Extension qualifiedStatements;

    public QualifiedStatementsJAXB(JAXBQualifiedStatements jaxbQualifiedStatements) throws IOException {
        ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();

        if (jaxbQualifiedStatements.getIssueQualifiedStatement() != null) {
            asn1EncodableVector.add(new QCStatement(QCStatement.id_etsi_qcs_QcCompliance));
        }

        if (jaxbQualifiedStatements.getLiabilityLimit() != null) {
            MonetaryValue monetaryValue = new MonetaryValue(
                new Iso4217CurrencyCode(jaxbQualifiedStatements.getLiabilityLimit().getCurrencyCode()),
                jaxbQualifiedStatements.getLiabilityLimit().getAmount(),
                jaxbQualifiedStatements.getLiabilityLimit().getExponent());
            asn1EncodableVector.add(new QCStatement(QCStatement.id_etsi_qcs_LimiteValue, monetaryValue));
        }

        if (jaxbQualifiedStatements.getRetentionPeriod() != null) {
            asn1EncodableVector.add(new QCStatement(QCStatement.id_etsi_qcs_RetentionPeriod,
                new ASN1Integer(jaxbQualifiedStatements.getRetentionPeriod())));
        }

        if ((jaxbQualifiedStatements.getSemanticOID() != null) &&
            ((jaxbQualifiedStatements.getRegistrationAgents() != null) &&
                (jaxbQualifiedStatements.getRegistrationAgents().getDnames().size() > 0))) {
            List<GeneralName> generalNames = new ArrayList<>(jaxbQualifiedStatements.getRegistrationAgents().getDnames().size());
            for (String dname : jaxbQualifiedStatements.getRegistrationAgents().getDnames()) {
                generalNames.add(new GeneralName(GeneralName.directoryName, dname));
            }
            GeneralName[] generalNamesArray = new GeneralName[generalNames.size()];
            SemanticsInformation semanticsInformation = new SemanticsInformation(new ASN1ObjectIdentifier(jaxbQualifiedStatements.getSemanticOID()),
                generalNames.toArray(generalNamesArray));
            asn1EncodableVector.add(new QCStatement(QCStatement.id_qcs_pkixQCSyntax_v2, semanticsInformation));
        }
        else if (jaxbQualifiedStatements.getSemanticOID() != null) {
            SemanticsInformation semanticsInformation = new SemanticsInformation(new ASN1ObjectIdentifier(jaxbQualifiedStatements.getSemanticOID()));
            asn1EncodableVector.add(new QCStatement(QCStatement.id_qcs_pkixQCSyntax_v2, semanticsInformation));
        }
        else if ((jaxbQualifiedStatements.getRegistrationAgents() != null) &&
            (jaxbQualifiedStatements.getRegistrationAgents().getDnames().size() > 0)) {
            List<GeneralName> generalNames = new ArrayList<>(jaxbQualifiedStatements.getRegistrationAgents().getDnames().size());
            for (String dname : jaxbQualifiedStatements.getRegistrationAgents().getDnames()) {
                generalNames.add(new GeneralName(GeneralName.directoryName, dname));
            }
            GeneralName[] generalNamesArray = new GeneralName[generalNames.size()];
            SemanticsInformation semanticsInformation = new SemanticsInformation(generalNames.toArray(generalNamesArray));
            asn1EncodableVector.add(new QCStatement(QCStatement.id_qcs_pkixQCSyntax_v2, semanticsInformation));
        }

        qualifiedStatements = new Extension(Extension.qCStatements, false, new DEROctetString(
            new DERSequence(asn1EncodableVector)));
    }

    @Override
    public ASN1ObjectIdentifier getExtensionOID() {
        return Extension.qCStatements;
    }

    @Override
    public Result validateExtension(Extension extension) throws IOException {
        return new Result(Result.Decisions.OVERRULED, qualifiedStatements);
    }

    @Override
    public void initialize(CertTemplate certTemplate) {

    }

    @Override
    public Result getExtension() throws IOException {
        return new Result(Result.Decisions.VALID, qualifiedStatements);
    }

    @Override
    public Boolean getCriticalility() {
        return false;
    }
}