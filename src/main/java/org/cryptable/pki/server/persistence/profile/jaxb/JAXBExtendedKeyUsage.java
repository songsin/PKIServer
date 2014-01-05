package org.cryptable.pki.server.persistence.profile.jaxb;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

/**
 *
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
 * Hour: 12:45
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class JAXBExtendedKeyUsage {

    @XmlElement(name="Server_Authentication")
    String serverAuthentication;

    @XmlElement(name="Client_Authentication")
    String clientAuthentication;

    @XmlElement(name="Code_Signing")
    String codeSigning;

    @XmlElement(name="E_Mail_Protection")
    String eMailProtection;

    @XmlElement(name="Time_Stamping")
    String timeStamping;

    @XmlElement(name="IPSec_End_System")
    String ipSecEndSystem;

    @XmlElement(name="IPSec_Tunnel")
    String ipSecTunnel;

    @XmlElement(name="IPSec_User")
    String ipSecUser;

    @XmlElement(name="IKE_Intermediate")
    String ikeIntermediate;

    @XmlElement(name="OCSP_Signing")
    String ocspSigning;

    @XmlElement(name="Smartcard_Logon")
    String smartcardLogon;

    @XmlElement(name="Key_Recovery_Agent")
    String keyRecoveryAgent;

    @XmlElement(name="Drive_Encryption")
    String driveEncryption;

    @XmlElement(name="Drive_Recovery")
    String driveRecovery;

    public String getServerAuthentication() {
        return serverAuthentication;
    }

    public void setServerAuthentication(String serverAuthentication) {
        this.serverAuthentication = serverAuthentication;
    }

    public String getClientAuthentication() {
        return clientAuthentication;
    }

    public void setClientAuthentication(String clientAuthentication) {
        this.clientAuthentication = clientAuthentication;
    }

    public String getCodeSigning() {
        return codeSigning;
    }

    public void setCodeSigning(String codeSigning) {
        this.codeSigning = codeSigning;
    }

    public String geteMailProtection() {
        return eMailProtection;
    }

    public void seteMailProtection(String eMailProtection) {
        this.eMailProtection = eMailProtection;
    }

    public String getTimeStamping() {
        return timeStamping;
    }

    public void setTimeStamping(String timeStamping) {
        this.timeStamping = timeStamping;
    }

    public String getIpSecEndSystem() {
        return ipSecEndSystem;
    }

    public void setIpSecEndSystem(String ipSecEndSystem) {
        this.ipSecEndSystem = ipSecEndSystem;
    }

    public String getIpSecTunnel() {
        return ipSecTunnel;
    }

    public void setIpSecTunnel(String ipSecTunnel) {
        this.ipSecTunnel = ipSecTunnel;
    }

    public String getIpSecUser() {
        return ipSecUser;
    }

    public void setIpSecUser(String ipSecUser) {
        this.ipSecUser = ipSecUser;
    }

    public String getIkeIntermediate() {
        return ikeIntermediate;
    }

    public void setIkeIntermediate(String ikeIntermediate) {
        this.ikeIntermediate = ikeIntermediate;
    }

    public String getOcspSigning() {
        return ocspSigning;
    }

    public void setOcspSigning(String ocspSigning) {
        this.ocspSigning = ocspSigning;
    }

    public String getSmartcardLogon() {
        return smartcardLogon;
    }

    public void setSmartcardLogon(String smartcardLogon) {
        this.smartcardLogon = smartcardLogon;
    }

    public String getKeyRecoveryAgent() {
        return keyRecoveryAgent;
    }

    public void setKeyRecoveryAgent(String keyRecoveryAgent) {
        this.keyRecoveryAgent = keyRecoveryAgent;
    }

    public String getDriveEncryption() {
        return driveEncryption;
    }

    public void setDriveEncryption(String driveEncryption) {
        this.driveEncryption = driveEncryption;
    }

    public String getDriveRecovery() {
        return driveRecovery;
    }

    public void setDriveRecovery(String driveRecovery) {
        this.driveRecovery = driveRecovery;
    }
}
