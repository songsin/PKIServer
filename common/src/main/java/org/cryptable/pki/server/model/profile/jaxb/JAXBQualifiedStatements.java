package org.cryptable.pki.server.model.profile.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

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
 * Hour: 12:45
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JAXBQualifiedStatements {

    @XmlElement(name="Issue_Qualified_Statement", defaultValue = "true", nillable = true)
    private Boolean issueQualifiedStatement;

    @XmlElement(name = "Liability_Limit", type = JAXBLiabilityLimit.class)
    private JAXBLiabilityLimit liabilityLimit;

    @XmlElement(name = "Retention_Period")
    private Integer retentionPeriod;

    @XmlElement(name = "Semantic_ID")
    private String SemanticOID;

    @XmlElement(name = "Registration_Agents", type = JAXBRegistrationAgents.class)
    private JAXBRegistrationAgents registrationAgents;

    public Boolean getIssueQualifiedStatement() {
        return issueQualifiedStatement;
    }

    public void setIssueQualifiedStatement(Boolean issueQualifiedStatement) {
        this.issueQualifiedStatement = issueQualifiedStatement;
    }

    public JAXBLiabilityLimit getLiabilityLimit() {
        return liabilityLimit;
    }

    public void setLiabilityLimit(JAXBLiabilityLimit liabilityLimit) {
        this.liabilityLimit = liabilityLimit;
    }

    public Integer getRetentionPeriod() {
        return retentionPeriod;
    }

    public void setRetentionPeriod(Integer retentionPeriod) {
        this.retentionPeriod = retentionPeriod;
    }

    public String getSemanticOID() {
        return SemanticOID;
    }

    public void setSemanticOID(String semanticOID) {
        SemanticOID = semanticOID;
    }

    public JAXBRegistrationAgents getRegistrationAgents() {
        return registrationAgents;
    }

    public void setRegistrationAgents(JAXBRegistrationAgents registrationAgents) {
        this.registrationAgents = registrationAgents;
    }
}
