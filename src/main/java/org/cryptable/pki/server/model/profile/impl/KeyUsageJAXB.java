package org.cryptable.pki.server.model.profile.impl;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.cryptable.pki.server.model.profile.ExtensionTemplate;
import org.cryptable.pki.server.model.profile.Result;
import org.cryptable.pki.server.persistence.profile.jaxb.JAXBKeyUsage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.BitSet;

/**
 * <Key_Usage>
 *   <Signature>No Overrule</Signature>
 *   <Non_Repudiation>No Overrule</Non_Repudiation>
 *   <Key_Encipherment>No Overrule</Key_Encipherment>
 *   <Data_Encipherment>No Overrule</Data_Encipherment>
 *   <Key_Agreement>No Overrule</Key_Agreement>
 *   <CRL_Signature>No Overrule</CRL_Signature>
 *   <Encipherment_Only>No Overrule</Encipherment_Only>
 *   <Decipherment_Only>No Overrule</Decipherment_Only>
 *   <Key_Certificate_Signature>No Overrule</Key_Certificate_Signature>
 * </Key_Usage>
 *
 * Author: davidtillemans
 * Date: 29/12/13
 * Hour: 13:44
 */
public class KeyUsageJAXB implements ExtensionTemplate {

    final Logger logger = LoggerFactory.getLogger(KeyUsageJAXB.class);

    final static int SIGNATURE                  = 0;
    final static int NON_REPUDIATION            = 1;
    final static int KEY_ENCIPHERMENT           = 2;
    final static int DATA_ENCIPHERMENT          = 3;
    final static int KEY_AGREEMENT              = 4;
    final static int CRL_SIGNATURE              = 5;
    final static int ENCIPHERMENT_ONLY          = 6;
    final static int DECIPHERMENT_ONLY          = 7;
    final static int KEY_CERTIFICATE_SIGNATURE  = 8;

    private BitSet overRuleKeyUsage = new BitSet(9);
    private BitSet enabeKeyUsage = new BitSet(9);

    private void setBits(int position, String xmlEntry) {
        if (xmlEntry == null)
            return;
        if (xmlEntry.equals("No Overrule"))
            overRuleKeyUsage.set(position, false);
        if (xmlEntry.equals("Enable"))
            enabeKeyUsage.set(position, true);
    }

    private int validateBits(int position, int keyUsage, KeyUsage ext, Result result) {
        int tempKeyUsage = 0;

        if (overRuleKeyUsage.get(position)) {
            if (enabeKeyUsage.get(position))  {
                result.setDecision(Result.Decisions.OVERRULED);
                tempKeyUsage |= keyUsage;
            }
        }
        else {
            if (ext.hasUsages(keyUsage)) tempKeyUsage |= keyUsage;
        }

        return tempKeyUsage;
    }

    public KeyUsageJAXB(JAXBKeyUsage keyUsage) {
        overRuleKeyUsage.set(0, 9, true); // Initialize all to over rule
        enabeKeyUsage.set(0, 9, false); // disable all key usages

        setBits(SIGNATURE, keyUsage.getSignature());
        setBits(NON_REPUDIATION, keyUsage.getNonRepudiation());
        setBits(KEY_ENCIPHERMENT, keyUsage.getKeyEncipherment());
        setBits(DATA_ENCIPHERMENT, keyUsage.getDataEncipherment());
        setBits(KEY_AGREEMENT, keyUsage.getKeyAgreement());
        setBits(CRL_SIGNATURE, keyUsage.getCrlSignature());
        setBits(ENCIPHERMENT_ONLY, keyUsage.getEnciphermentOnly());
        setBits(DECIPHERMENT_ONLY, keyUsage.getDeciphermentOnly());
        setBits(KEY_CERTIFICATE_SIGNATURE, keyUsage.getKeyCertificateSignature());
    }

    @Override
    public ASN1ObjectIdentifier getExtensionOID() {
        return new ASN1ObjectIdentifier("2.5.29.15");
    }

    @Override
    public Result validateExtension(Extension extension) throws IOException {
        Result result = new Result(Result.Decisions.VALID, null);
        KeyUsage keyUsage = KeyUsage.getInstance(extension.getParsedValue());

        int tempKeyUsage = 0;
        tempKeyUsage |= validateBits(SIGNATURE, KeyUsage.digitalSignature, keyUsage, result);
        tempKeyUsage |= validateBits(NON_REPUDIATION, KeyUsage.nonRepudiation, keyUsage, result);
        tempKeyUsage |= validateBits(KEY_ENCIPHERMENT, KeyUsage.keyEncipherment, keyUsage, result);
        tempKeyUsage |= validateBits(DATA_ENCIPHERMENT, KeyUsage.dataEncipherment, keyUsage, result);
        tempKeyUsage |= validateBits(KEY_AGREEMENT, KeyUsage.keyAgreement, keyUsage, result);
        tempKeyUsage |= validateBits(CRL_SIGNATURE, KeyUsage.cRLSign, keyUsage, result);
        tempKeyUsage |= validateBits(ENCIPHERMENT_ONLY, KeyUsage.encipherOnly, keyUsage, result);
        tempKeyUsage |= validateBits(DECIPHERMENT_ONLY, KeyUsage.decipherOnly, keyUsage, result);
        tempKeyUsage |= validateBits(KEY_CERTIFICATE_SIGNATURE, KeyUsage.keyCertSign, keyUsage, result);

        KeyUsage newKeyUsage = new KeyUsage(tempKeyUsage);

        Extension newExtension = new Extension(Extension.keyUsage, true,  new DEROctetString(newKeyUsage));

        result.setValue(newExtension);

        logger.debug(newKeyUsage.toString());
        return result;
    }

    @Override
    public Result getExtension() throws IOException {
        int tempKeyUsage = 0;

        if (enabeKeyUsage.get(SIGNATURE)) tempKeyUsage |= KeyUsage.digitalSignature;
        if (enabeKeyUsage.get(NON_REPUDIATION)) tempKeyUsage |= KeyUsage.nonRepudiation;
        if (enabeKeyUsage.get(KEY_ENCIPHERMENT)) tempKeyUsage |= KeyUsage.keyEncipherment;
        if (enabeKeyUsage.get(DATA_ENCIPHERMENT)) tempKeyUsage |= KeyUsage.dataEncipherment;
        if (enabeKeyUsage.get(KEY_AGREEMENT)) tempKeyUsage |= KeyUsage.keyAgreement;
        if (enabeKeyUsage.get(CRL_SIGNATURE)) tempKeyUsage |= KeyUsage.cRLSign;
        if (enabeKeyUsage.get(ENCIPHERMENT_ONLY)) tempKeyUsage |= KeyUsage.encipherOnly;
        if (enabeKeyUsage.get(DECIPHERMENT_ONLY)) tempKeyUsage |= KeyUsage.decipherOnly;
        if (enabeKeyUsage.get(KEY_CERTIFICATE_SIGNATURE)) tempKeyUsage |= KeyUsage.keyCertSign;

        KeyUsage keyUsage = new KeyUsage(tempKeyUsage);

        Extension extension = new Extension(Extension.keyUsage, true,  new DEROctetString(keyUsage));

        return new Result(Result.Decisions.VALID, extension);
    }

    @Override
    public Boolean getCriticalility() {
        return true;
    }
}
