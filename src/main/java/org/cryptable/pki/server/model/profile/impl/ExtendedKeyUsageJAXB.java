package org.cryptable.pki.server.model.profile.impl;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.cryptable.pki.server.model.profile.ExtensionTemplate;
import org.cryptable.pki.server.model.profile.Result;
import org.cryptable.pki.server.model.profile.jaxb.JAXBExtendedKeyUsage;
import org.cryptable.pki.server.model.profile.jaxb.JAXBKeyUsage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.BitSet;
import java.util.Vector;

/**
 * <Extended_Key_Usage>
 *   <Server_Authentication>Enable</Server_Authentication>
 *   <Client_Authentication>Enable</Client_Authentication>
 *   <Code_Signing>Enable</Code_Signing>
 *   <E_Mail_Protection>Enable</E_Mail_Protection>
 *   <Time_Stamping>Enable</Time_Stamping>
 *   <IPSec_End_System>Enable</IPSec_End_System>
 *   <IPSec_Tunnel>Enable</IPSec_Tunnel>
 *   <IPSec_User>Enable</IPSec_User>
 *   <IKE_Intermediate>Enable</IKE_Intermediate>
 *   <OCSP_Signing>Enable</OCSP_Signing>
 *   <Smartcard_Logon>Enable</Smartcard_Logon>
 *   <Key_Recovery_Agent>Enable</Key_Recovery_Agent>
 *   <Drive_Encryption>Enable</Drive_Encryption>
 *   <Drive_Recovery>Enable</Drive_Recovery>
 * </Extended_Key_Usage>
 *
 * Author: davidtillemans
 * Date: 29/12/13
 * Hour: 13:44
 */
public class ExtendedKeyUsageJAXB implements ExtensionTemplate {

    private final Logger logger = LoggerFactory.getLogger(ExtendedKeyUsageJAXB.class);

    private final static int SERVER_AUTHENTICATION  = 0;
    private final static int CLIENT_AUTHENTICATION  = 1;
    private final static int CODE_SIGNING           = 2;
    private final static int EMAIL_PROTECTION       = 3;
    private final static int TIME_STAMPING          = 4;
    private final static int IPSEC_END_SYSTEM       = 5;
    private final static int IPSEC_TUNNEL           = 6;
    private final static int IPSEC_USER             = 7;
    private final static int IKE_INTERMEDIATE       = 8;
    private final static int OCSP_SIGNING           = 9;
    private final static int SMARTCARD_LOGON        = 10;
    private final static int KEY_RECOVERY_AGENT     = 11;
    private final static int DRIVE_ENCRYPTION       = 12;
    private final static int DRIVE_RECOVERY         = 13;

    private final BitSet overRuleKeyUsage = new BitSet(14);
    private final BitSet enabeKeyUsage = new BitSet(14);

    public final static KeyPurposeId id_kp_key_recovery_agent = KeyPurposeId.getInstance(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.6"));
    public final static KeyPurposeId id_kp_bitlocker_drive_encryption = KeyPurposeId.getInstance(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.67.1.1"));
    public final static KeyPurposeId id_kp_bitlocker_drive_recovery = KeyPurposeId.getInstance(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.67.1.2"));
    
    private void setBits(int position, String xmlEntry) {
        if (xmlEntry == null)
            return;
        if (xmlEntry.equals("No Overrule"))
            overRuleKeyUsage.set(position, false);
        if (xmlEntry.equals("Enable"))
            enabeKeyUsage.set(position, true);
    }

    private void validateBits(int position, KeyPurposeId keyPurposeId, Vector<KeyPurposeId> keyPurposeIds, ExtendedKeyUsage extendedKeyUsage, Result result) {
        int tempKeyUsage = 0;

        if (overRuleKeyUsage.get(position)) {
            if (enabeKeyUsage.get(position))  {
                if (!extendedKeyUsage.hasKeyPurposeId(keyPurposeId))
                    result.setDecision(Result.Decisions.OVERRULED);
                keyPurposeIds.add(keyPurposeId);
            }
            else {
                if (extendedKeyUsage.hasKeyPurposeId(keyPurposeId))
                    result.setDecision(Result.Decisions.OVERRULED);
            }
        }
        else {
            if (extendedKeyUsage.hasKeyPurposeId(keyPurposeId)) {
                keyPurposeIds.add(keyPurposeId);
            }
        }
    }

    public ExtendedKeyUsageJAXB(JAXBExtendedKeyUsage keyUsage) {
        overRuleKeyUsage.set(0, 14, true); // Initialize all to over rule
        enabeKeyUsage.set(0, 14, false); // disable all key usages

        setBits(SERVER_AUTHENTICATION, keyUsage.getServerAuthentication());
        setBits(CLIENT_AUTHENTICATION, keyUsage.getClientAuthentication());
        setBits(CODE_SIGNING, keyUsage.getCodeSigning());
        setBits(EMAIL_PROTECTION, keyUsage.geteMailProtection());
        setBits(TIME_STAMPING, keyUsage.getTimeStamping());
        setBits(IPSEC_END_SYSTEM, keyUsage.getIpSecEndSystem());
        setBits(IPSEC_TUNNEL, keyUsage.getIpSecTunnel());
        setBits(IPSEC_USER, keyUsage.getIpSecUser());
        setBits(IKE_INTERMEDIATE, keyUsage.getIkeIntermediate());
        setBits(OCSP_SIGNING, keyUsage.getOcspSigning());
        setBits(SMARTCARD_LOGON, keyUsage.getSmartcardLogon());
        setBits(KEY_RECOVERY_AGENT, keyUsage.getKeyRecoveryAgent());
        setBits(DRIVE_ENCRYPTION, keyUsage.getDriveEncryption());
        setBits(DRIVE_RECOVERY, keyUsage.getDriveRecovery());
    }

    @Override
    public ASN1ObjectIdentifier getExtensionOID() {
        return Extension.extendedKeyUsage;
    }

    @Override
    public Result validateExtension(Extension extension) throws IOException {
        Result result = new Result(Result.Decisions.VALID, null);
        ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(extension.getParsedValue());

        Vector<KeyPurposeId> keyPurposeIds = new Vector<org.bouncycastle.asn1.x509.KeyPurposeId>();
        validateBits(SERVER_AUTHENTICATION, KeyPurposeId.id_kp_serverAuth, keyPurposeIds, extendedKeyUsage, result);
        validateBits(CLIENT_AUTHENTICATION, KeyPurposeId.id_kp_clientAuth, keyPurposeIds, extendedKeyUsage, result);
        validateBits(CODE_SIGNING, KeyPurposeId.id_kp_codeSigning, keyPurposeIds, extendedKeyUsage, result);
        validateBits(EMAIL_PROTECTION, KeyPurposeId.id_kp_emailProtection, keyPurposeIds, extendedKeyUsage, result);
        validateBits(TIME_STAMPING, KeyPurposeId.id_kp_timeStamping, keyPurposeIds, extendedKeyUsage, result);
        validateBits(IPSEC_END_SYSTEM, KeyPurposeId.id_kp_ipsecEndSystem, keyPurposeIds, extendedKeyUsage, result);
        validateBits(IPSEC_TUNNEL, KeyPurposeId.id_kp_ipsecTunnel, keyPurposeIds, extendedKeyUsage, result);
        validateBits(IPSEC_USER, KeyPurposeId.id_kp_ipsecUser, keyPurposeIds, extendedKeyUsage, result);
        validateBits(IKE_INTERMEDIATE, KeyPurposeId.id_kp_ipsecIKE, keyPurposeIds, extendedKeyUsage, result);
        validateBits(OCSP_SIGNING, KeyPurposeId.id_kp_OCSPSigning, keyPurposeIds, extendedKeyUsage, result);
        validateBits(SMARTCARD_LOGON, KeyPurposeId.id_kp_smartcardlogon, keyPurposeIds, extendedKeyUsage, result);
        validateBits(KEY_RECOVERY_AGENT, id_kp_key_recovery_agent, keyPurposeIds, extendedKeyUsage, result);
        validateBits(DRIVE_ENCRYPTION, id_kp_bitlocker_drive_encryption, keyPurposeIds, extendedKeyUsage, result);
        validateBits(DRIVE_RECOVERY, id_kp_bitlocker_drive_recovery, keyPurposeIds, extendedKeyUsage, result);

        if (keyPurposeIds.size() > 0) {
            KeyPurposeId[] keyPurposeIdsArray = new KeyPurposeId[keyPurposeIds.size()];
            Extension newExtension = new Extension(Extension.extendedKeyUsage, false,
                new DEROctetString(new ExtendedKeyUsage(keyPurposeIds.toArray(keyPurposeIdsArray))));

            result.setValue(newExtension);
        }
        else {
            result.setDecision(Result.Decisions.INVALID);
            result.setValue(null);
        }

        return result;
    }

    @Override
    public void initialize(CertTemplate certTemplate) {

    }

    @Override
    public Result getExtension() throws IOException {

        Vector<KeyPurposeId> keyPurposeIds = new Vector<org.bouncycastle.asn1.x509.KeyPurposeId>();
        if (enabeKeyUsage.get(SERVER_AUTHENTICATION)) keyPurposeIds.add(KeyPurposeId.id_kp_serverAuth);
        if (enabeKeyUsage.get(CLIENT_AUTHENTICATION)) keyPurposeIds.add(KeyPurposeId.id_kp_clientAuth);
        if (enabeKeyUsage.get(CODE_SIGNING))  keyPurposeIds.add(KeyPurposeId.id_kp_codeSigning);
        if (enabeKeyUsage.get(EMAIL_PROTECTION))  keyPurposeIds.add(KeyPurposeId.id_kp_emailProtection);
        if (enabeKeyUsage.get(TIME_STAMPING))  keyPurposeIds.add(KeyPurposeId.id_kp_timeStamping);
        if (enabeKeyUsage.get(IPSEC_END_SYSTEM))  keyPurposeIds.add(KeyPurposeId.id_kp_ipsecEndSystem);
        if (enabeKeyUsage.get(IPSEC_TUNNEL))  keyPurposeIds.add(KeyPurposeId.id_kp_ipsecTunnel);
        if (enabeKeyUsage.get(IPSEC_USER))  keyPurposeIds.add(KeyPurposeId.id_kp_ipsecUser);
        if (enabeKeyUsage.get(IKE_INTERMEDIATE))  keyPurposeIds.add(KeyPurposeId.id_kp_ipsecIKE);
        if (enabeKeyUsage.get(OCSP_SIGNING)) keyPurposeIds.add(KeyPurposeId.id_kp_OCSPSigning);
        if (enabeKeyUsage.get(SMARTCARD_LOGON))  keyPurposeIds.add(KeyPurposeId.id_kp_smartcardlogon);
        if (enabeKeyUsage.get(KEY_RECOVERY_AGENT))  keyPurposeIds.add(id_kp_key_recovery_agent);
        if (enabeKeyUsage.get(DRIVE_ENCRYPTION))  keyPurposeIds.add(id_kp_bitlocker_drive_encryption);
        if (enabeKeyUsage.get(DRIVE_RECOVERY))  keyPurposeIds.add(id_kp_bitlocker_drive_recovery);

        if (keyPurposeIds.size() > 0) {
            KeyPurposeId[] keyPurposeIdsTmp = new KeyPurposeId[keyPurposeIds.size()];
            ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(keyPurposeIds.toArray(keyPurposeIdsTmp));

            // create new extension
            Extension extension = new Extension(Extension.extendedKeyUsage, true,  new DEROctetString(extendedKeyUsage));

            return new Result(Result.Decisions.VALID, extension);

        }
        else {
            return null;
        }
    }

    @Override
    public Boolean getCriticalility() {
        return false;
    }
}
