package org.cryptable.pki.server.model.profile.impl;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.cryptable.pki.server.model.profile.ExtensionTemplate;
import org.cryptable.pki.server.model.profile.ProfileException;
import org.cryptable.pki.server.model.profile.Result;
import org.cryptable.pki.server.model.profile.jaxb.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * Translate the XML to profile
 *
 * Author: davidtillemans
 * Date: 2/01/14
 * Hour: 00:23
 */
public class CRLDistributionPointJAXB implements ExtensionTemplate {

    final Logger logger = LoggerFactory.getLogger(CRLDistributionPointJAXB.class);

    boolean critical;

    private Extension crlDistributionPoints;

    public CRLDistributionPointJAXB(JAXBCrlDistributionPoints jaxbCrlDistributionPoints, Certificate caCertificate) throws IOException {
        critical = false;

        List<DistributionPoint> distributionPointList = new ArrayList<DistributionPoint>();

        for (JAXBDistributionPoint jaxbDistributionPoint : jaxbCrlDistributionPoints.getDistributionPoints()) {
            DistributionPointName distributionPointName = null;
            GeneralNames issuerName = null;
            ReasonFlags reasonFlags = null;

            logger.debug("Parsing distribution point with name [" + jaxbDistributionPoint.getName() + "]");

            if (jaxbDistributionPoint.getRelativeDName() != null) {
                String relativeDName = jaxbDistributionPoint.getRelativeDName().replaceFirst("/","");
                relativeDName =relativeDName.replaceAll("/", ",");
                RDN[] rdns = IETFUtils.rDNsFromString(relativeDName, BCStyle.INSTANCE);
                Set<AttributeTypeAndValue> attributeTypeAndValues = new HashSet<AttributeTypeAndValue>();
                for (RDN rdn : rdns) {
                    attributeTypeAndValues.addAll(Arrays.asList(rdn.getTypesAndValues()));
                }
                AttributeTypeAndValue[] avs = new AttributeTypeAndValue[attributeTypeAndValues.size()];
                RDN out = new RDN(attributeTypeAndValues.toArray(avs));
                distributionPointName = new DistributionPointName(DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER, out.toASN1Primitive());
            }
            else {
                GeneralNamesBuilder generalNamesBuilder = new GeneralNamesBuilder();
                // rfc822Name                      [1]     IA5String,
                if (jaxbDistributionPoint.geteMail() != null)
                    generalNamesBuilder.addName(new GeneralName(GeneralName.rfc822Name, jaxbDistributionPoint.geteMail()));
                // dNSName                         [2]     IA5String,
                if (jaxbDistributionPoint.getDomainName() != null)
                    generalNamesBuilder.addName(new GeneralName(GeneralName.dNSName, jaxbDistributionPoint.getDomainName()));
                // directoryName                   [4]     Name,
                if (jaxbDistributionPoint.getdName() != null)
                    generalNamesBuilder.addName(new GeneralName(GeneralName.directoryName, jaxbDistributionPoint.getdName()));
                // uniformResourceIdentifier       [6]     IA5String,
                if (jaxbDistributionPoint.getUrl() != null)
                    generalNamesBuilder.addName(new GeneralName(GeneralName.uniformResourceIdentifier, jaxbDistributionPoint.getUrl()));
                // iPAddress                       [7]     OCTET STRING,
                if (jaxbDistributionPoint.getIpAddress() != null)
                    generalNamesBuilder.addName(new GeneralName(GeneralName.iPAddress, jaxbDistributionPoint.getIpAddress()));
                distributionPointName = new DistributionPointName(generalNamesBuilder.build());
            }

            if (jaxbDistributionPoint.getAddIssuerName()) {
                GeneralNamesBuilder generalNamesBuilder = new GeneralNamesBuilder();
                issuerName = new GeneralNames(new GeneralName(caCertificate.getSubject()));
            }

            if (jaxbDistributionPoint.getReasonCodes() != null) {
                int rc = 0;

                if (jaxbDistributionPoint.getReasonCodes().getKeyCompromise()) {
                    rc |= ReasonFlags.keyCompromise;
                }
                if (jaxbDistributionPoint.getReasonCodes().getCaCompromise()) {
                    rc |= ReasonFlags.cACompromise;
                }
                if (jaxbDistributionPoint.getReasonCodes().getAffiliationChanged()) {
                    rc |= ReasonFlags.affiliationChanged;
                }
                if (jaxbDistributionPoint.getReasonCodes().getSuperseded()) {
                    rc |= ReasonFlags.superseded;
                }
                if (jaxbDistributionPoint.getReasonCodes().getCessationOfOperation()) {
                    rc |= ReasonFlags.cessationOfOperation;
                }
                if (jaxbDistributionPoint.getReasonCodes().getCertificateOnHold()) {
                    rc |= ReasonFlags.certificateHold;
                }
                reasonFlags = new ReasonFlags(rc);
            }

            distributionPointList.add(new DistributionPoint(distributionPointName, reasonFlags, issuerName));
        }

        DistributionPoint[] distributionPointArray = new DistributionPoint[distributionPointList.size()];
        crlDistributionPoints = new Extension(Extension.cRLDistributionPoints, critical,
            new DEROctetString(new CRLDistPoint(distributionPointList.toArray(distributionPointArray))));
    }

    @Override
    public ASN1ObjectIdentifier getExtensionOID() {
        return Extension.cRLDistributionPoints;
    }

    @Override
    public Result validateExtension(Extension extension) throws IOException, NoSuchAlgorithmException {
        return new Result(Result.Decisions.OVERRULED, crlDistributionPoints);
    }

    @Override
    public void initialize(CertTemplate certTemplate) throws ProfileException {

    }

    @Override
    public Result getExtension() throws IOException, NoSuchAlgorithmException {
        return new Result(Result.Decisions.VALID, crlDistributionPoints);
    }

    @Override
    public Boolean getCriticalility() {
        return critical;
    }
}
