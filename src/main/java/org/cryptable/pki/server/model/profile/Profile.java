package org.cryptable.pki.server.model.profile;

import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x509.Extensions;
import org.joda.time.DateTime;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * The profile model
 *
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 09:53
 */
public interface Profile {

     /**
     * Verify the validity of the NBefore. Returns a result object, because it can be overruled.
     * The Result object has the overruled or copied object. If invalid a String is return with
     * an error message
     *
     * @param certTemplate template of the certificate extensions (Bouncycastle)
     * @return
     */
    public Result validateCertificateNBefore(CertTemplate certTemplate) throws ProfileException;

    /**
     * Verify the validity of the NAfter. Returns a result object, because it can be overruled.
     * The Result object has the overruled or copied object. If invalid a String is return with
     * an error message
     *
     * @param certTemplate template of the certificate extensions (Bouncycastle)
     * @return return a result object with a copy of the input if VALID, null when INVALID and
     * a new value if overruled
     */
    public Result validateCertificateNAfter(CertTemplate certTemplate) throws ProfileException;

    /**
     * Verify the lenth of the validity.
     *
     * @param certTemplate template of the certificate extensions (Bouncycastle)
     * @return return a result object with a copy of the input if VALID, null when INVALID and
     * a new value if overruled
     */
    public Result validateCertificateValidity(CertTemplate certTemplate) throws ProfileException;

    /**
     * Verify the keylength against the profile. Also here the keylength can be overruled
     * The Result object has the overruled or copied object. If invalid a String is return with
     * an error message
     *
     * @param certTemplate template of the certificate extensions (Bouncycastle)
     * @return return a result object with a copy of the input if VALID, null when INVALID and
     * a new value if overruled
     */
    public Result validateCertificateKeyLength(CertTemplate certTemplate) throws ProfileException, IOException;

    /**
     * Signing algorithm of the certificate
     * Returns following strings
     * MD2WITHRSAENCRYPTION
     * MD5WITHRSAENCRYPTION
     * SHA1WithRSAEncryption
     * SHA224WITHRSAENCRYPTION
     * SHA256WithRSAEncryption
     * SHA384WITHRSAENCRYPTION
     * SHA256WithRSAEncryption
     * SHA512WITHRSAENCRYPTION
     * SHA1WITHRSAANDMGF1
     * SHA224WITHRSAANDMGF1
     * SHA256WITHRSAANDMGF1
     * SHA384WITHRSAANDMGF1
     * SHA512WITHRSAANDMGF1
     * RIPEMD160WITHRSAENCRYPTION
     * RIPEMD128WITHRSAENCRYPTION
     * RIPEMD256WITHRSAENCRYPTION
     * SHA1WITHDSA
     * SHA224WITHDSA
     * SHA256WITHDSA
     * SHA384WITHDSA
     * SHA512WITHDSA
     * SHA1WITHECDSA
     * SHA224WITHECDSA
     * SHA256WITHECDSA
     * SHA384WITHECDSA
     * SHA512WITHECDSA
     * GOST3411WITHGOST3410
     * GOST3411WITHGOST3410-94
     * GOST3411WITHECGOST3410
     * GOST3411WITHECGOST3410-2001
     * GOST3411WITHGOST3410-2001
     *
     * @return Signing algorithm
     */
    public String getCertificateSignatureAlgorithm() throws ProfileException;

    /**
     * Private Key Escrow service of the CA
     *
     * @return true if the private keys must be backed up
     */
    public boolean usePrivateKeyEscrow() throws ProfileException;

    /**
     * Get Publication delay. These are the number of milli-seconds before publication.
     *
     * @return number of milliseconds to wait before publishing
     */
    public long certificatePublicationDelay() throws ProfileException;

    /**
     * Validate the extensions. This will return a list of result, because some settings can be overruled,
     * the new or copied Extension will be stored in the result.
     * In case of invalid the result extension is null
     *
     * @param certTemplate template of the certificate extensions (Bouncycastle)
     * @return returns a result list with the old and update extensions included when OVERRULED and VALID.
     * Stops at the extension when INVALID extension is found
     */
    public List<Result> validateCertificateExtensions(CertTemplate certTemplate) throws IOException, NoSuchAlgorithmException, ProfileException;

}
