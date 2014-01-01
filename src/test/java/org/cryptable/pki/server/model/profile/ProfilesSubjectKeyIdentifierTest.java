package org.cryptable.pki.server.model.profile;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.cryptable.pki.server.model.profile.impl.ProfilesJAXB;
import org.cryptable.pki.util.GeneratePKI;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.xml.bind.JAXBException;
import java.awt.*;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;

import static junit.framework.Assert.assertNotNull;
import static junit.framework.TestCase.assertFalse;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 00:27
 */
public class ProfilesSubjectKeyIdentifierTest {

    static private Profiles profiles;

    private CertTemplate certTemplateNoSubjectKeyId;
    private CertTemplate certTemplateTruncatedSHA1;
    private CertTemplate certTemplateSHA1;
    private X509ExtensionUtils x509ExtensionUtils = new BcX509ExtensionUtils();

    final private RSAPublicKeySpec key2048PubKeySpec = new RSAPublicKeySpec(
        new BigInteger("87fc4b405757781e622e5f6f49446b28476aef614c27e7e3d58e83ce58c384ac01bd1312bce1278c6715b8521e2430b9a06c4b95b1635b94e71a08cc17fe4a2072873ae4ad6ba153578dc31c3ff0e18dda35c5e35691f215916c6d26757773407a839e715f1b23a81c8000f1e92e5dcd3f6b5ba9b6d03a29e7d9a30b0497c50a0bb3c0dceb7e70928942708f0f27d33a8c93549c9991c70c25e04aa5bca39f33393e659ae7dc426d2223abe321a61b6a16fb7df91abb58925747f621f8631c4860e9c8e245917b55e3c8b209437d04611cb5bfc1afc878f4e8e413147b2b9ab36c885ef1d9d5f1b9629766d56aa006ba698b845f4065eefb4103ce17ff127c13", 16),
        new BigInteger("10001", 16));

    final private RSAPrivateCrtKeySpec key2048PrivKeySpec = new RSAPrivateCrtKeySpec(
        new BigInteger("87fc4b405757781e622e5f6f49446b28476aef614c27e7e3d58e83ce58c384ac01bd1312bce1278c6715b8521e2430b9a06c4b95b1635b94e71a08cc17fe4a2072873ae4ad6ba153578dc31c3ff0e18dda35c5e35691f215916c6d26757773407a839e715f1b23a81c8000f1e92e5dcd3f6b5ba9b6d03a29e7d9a30b0497c50a0bb3c0dceb7e70928942708f0f27d33a8c93549c9991c70c25e04aa5bca39f33393e659ae7dc426d2223abe321a61b6a16fb7df91abb58925747f621f8631c4860e9c8e245917b55e3c8b209437d04611cb5bfc1afc878f4e8e413147b2b9ab36c885ef1d9d5f1b9629766d56aa006ba698b845f4065eefb4103ce17ff127c13", 16),
        new BigInteger("10001", 16),
        new BigInteger("b1bf761d840d315585c057be7f668f2af72f2ff75e344b47e3bd854c137a7dd0d7f4ed19710a5d4788f73b171b8ef2a1b0afdd9cad61d233b060b75f0f7db426f58d0dce1b60b45edbf2d135fbde40f5ca64bf6589a2fb6c75c9e46280e8c21d6606e4f40bfccd7ed0c2007a34f2066a629b5215648089867d285d95e94af8a14cc29e990e82a9962ba18f877e8d491aebb4a0980d9f6e48fa21b3a54a8155d87c9ce737548aea39c751c89e98f34c39dcb98d0751481b65d657d7f6520929680c1daac7d00a6ebf7e18db721e0eff6e635f4433dc006b7485c2374c866eacfe75c5b081d10f2bdb21246328d5d993b390dbc1c81ba019fe4fb2754e422e091", 16),
        new BigInteger("f8e2276c6e865486c793f520bf84a5bdb23fbe54b71253642273cb56699ce42b10e5fc0c1b73ef7a01e642a5b1b778bd4aeded5baf2bfb0b758d2b6594065b6d516a0764899a7a2dd1cdad6b753b5ae84bd24b6f4d71ab9b5621764c229b1851f23760b98a47ffab12f67db5e4ff8bbd01e4093b2deff996e046e3ab1772f6ff", 16),
        new BigInteger("8bdfb7f5473cfc8277050a8fa4c7f8ddf33d44c44194373180db93d96b33637429e83a41a36032fed5ff344ed64c3dbf2195545da3ef6f5e2facb1109c980ea58a14332d9cbc322f4cb849b9454fd299b441260a2eeceb072f5551187d7de62dbbe7e0a5e5bcd02c1bcc813ae494670f46235c6eabbaf03b9c5c50a6b0be2eed", 16),
        new BigInteger("c133f67cb333ee4c0e842a2738e54530843dfd878ff256f005dab3ffa9ced445264212ae67655182fa1480aa55d2629537a489bcc1b8379306b706f83cb7cea3872ef2fc35e1c874e7486e165c142e96e3bd25380afb71c70d4ebea18dbfae5a76d84c6adc10d6453c5c42ec400facaf95d72adf58e2d073323975a52c77df8b", 16),
        new BigInteger("7b37d0b155594744931eb0c80bac51f30c252c200b794b09e3ef0b16dc160005c4291cb0d80095cbe2ae97e0df6d7873985d195e085d93e90fec7c6b1ad7e50735554824654f7092346ea01b8310a780d9c70e80a807f39f77b61be38c214d957a53f1959385ba8930cffe03e87b4732b061d43a76340f0f24563a822d6ecc9d", 16),
        new BigInteger("7257407dc5b1baec85676b8bc081d2895183a09c51a9eb16f430212887bb0c3670a206fa0513581505c5754b00d0e7b982ed3509543069709967bd82e632f8491ee431ab44942d19bc03002f280f73a02ed15d3752372f2d0c18e5c68c758663e0442e983e1e6b9a2f6e4ca15651cec5c23869eb19b2e23f2d6b0f46b960fe99", 16));

    static private GeneratePKI generatePKI;

    @BeforeClass
    static public void init() throws CertificateException, CertIOException, NoSuchAlgorithmException, OperatorCreationException, CRLException, NoSuchProviderException, InvalidKeySpecException {
        Security.addProvider(new BouncyCastleProvider());
        generatePKI = new GeneratePKI();
        generatePKI.createPKI();
    }

    @Before
    public void setup() throws JAXBException, IOException, ProfileException, InvalidKeySpecException, NoSuchProviderException, NoSuchAlgorithmException, CertificateEncodingException {
        X509CertificateHolder x509CertificateHolder = new JcaX509CertificateHolder(generatePKI.getCaCert());
        if (profiles == null)
            profiles = new ProfilesJAXB(getClass().getResourceAsStream("/SubjectKeyIdentifier.xml"), x509CertificateHolder.toASN1Structure());

        KeyFactory fact = KeyFactory.getInstance("RSA", "BC");
        KeyPair keyPair2048 = new KeyPair(fact.generatePublic(key2048PubKeySpec), fact.generatePrivate(key2048PrivKeySpec));
        SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(keyPair2048.getPublic().getEncoded()));
        X509ExtensionUtils x509ExtensionUtils = new BcX509ExtensionUtils();

        CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();
        certTemplateNoSubjectKeyId = certTemplateBuilder.setPublicKey(subjectPublicKeyInfo)
            .build();
        // SHA1 cert template
        Extension extension = new Extension(Extension.subjectKeyIdentifier,
            false,
            new DEROctetString(x509ExtensionUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo)));
        Extensions extensions = new Extensions(extension);
        certTemplateSHA1 = certTemplateBuilder.setPublicKey(subjectPublicKeyInfo)
            .setExtensions(extensions)
            .build();
        // Truncated SHA1 cert template
        extension = new Extension(Extension.subjectKeyIdentifier,
            false,
            new DEROctetString(x509ExtensionUtils.createTruncatedSubjectKeyIdentifier(subjectPublicKeyInfo)));
        extensions = new Extensions(extension);
        certTemplateSHA1 = certTemplateBuilder.setPublicKey(subjectPublicKeyInfo)
            .setExtensions(extensions)
            .build();

    }

    /**
     * Test a normal SHA1 Subject Key Identifier. Template has no SHA1 extension
     *
     * <Subject_Key_Identifier>160 bit SHA-1</Subject_Key_Identifier>
     */
    @Test
    public void testCertificateSubjectKeyIdentifierValid() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(1);
        Extension ext = null;
        Result result = null;

        List<Result> results = profile.validateCertificateExtensions(certTemplateNoSubjectKeyId);

        for (Result res : results) {
            if (((Extension)res.getValue()).getExtnId().equals(Extension.subjectKeyIdentifier)) {
                result = res;
            }
        }

        // Subject Key Identifier found
        assertNotNull(result);

        ext = (Extension)result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertFalse(ext.isCritical());

        // Verify the SHA1 content
        assertArrayEquals((new DEROctetString(x509ExtensionUtils.createSubjectKeyIdentifier(certTemplateNoSubjectKeyId.getPublicKey()))).getEncoded(),
            ext.getExtnValue().getEncoded());

        // Reference check to a real certificate (non) Bouncycastle
//        System.out.print(ASN1Dump.dumpAsString(ext.getExtnValue(), true));
//        System.out.print(ASN1Dump.dumpAsString(x509ExtensionUtils.createSubjectKeyIdentifier(certTemplateNoSubjectKeyId.getPublicKey()), true));
//        File file = new File(getClass().getResource("/TestCert.der").getFile());
//        FileInputStream fis = new FileInputStream(file);
//        byte[] data = new byte[(int)file.length()];
//        fis.read(data);
//        fis.close();
//
//        Certificate certificate = Certificate.getInstance(data);
//
//        Extension ext2 = certificate.getTBSCertificate().getExtensions().getExtension(Extension.subjectKeyIdentifier);
//        System.out.print(ASN1Dump.dumpAsString(ext2.getExtnValue(), true));


    }

    /**
     * Test a truncated Subject Key Identifier.
     *
     * <Subject_Key_Identifier>160 bit SHA-1</Subject_Key_Identifier>
     */
    @Test
    public void testCertificateSubjectKeyIdentifierTruncatedSHA1() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(2);
        Extension ext = null;
        Result result = null;

        List<Result> results = profile.validateCertificateExtensions(certTemplateNoSubjectKeyId);

        for (Result res : results) {
            if (((Extension)res.getValue()).getExtnId().equals(Extension.subjectKeyIdentifier)) {
                result = res;
            }
        }

        // Subject Key Identifier found
        assertNotNull(result);

        ext = (Extension)result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertFalse(ext.isCritical());

        // Verify the Truncated SHA1 content
        assertArrayEquals((new DEROctetString(x509ExtensionUtils.createTruncatedSubjectKeyIdentifier(certTemplateNoSubjectKeyId.getPublicKey()))).getEncoded(),
            ext.getExtnValue().getEncoded());


    }

    /**
     * Test a truncated Subject Key Identifier override
     *
     * <Subject_Key_Identifier>160 bit SHA-1</Subject_Key_Identifier>
     */
    @Test
    public void testCertificateSubjectKeyIdentifierOverruledSHA1() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(1);
        Extension ext = null;
        Result result = null;

        List<Result> results = profile.validateCertificateExtensions(certTemplateSHA1);

        for (Result res : results) {
            if (((Extension)res.getValue()).getExtnId().equals(Extension.subjectKeyIdentifier)) {
                result = res;
            }
        }

        // Subject Key Identifier found
        assertNotNull(result);

        ext = (Extension)result.getValue();

        assertEquals(Result.Decisions.OVERRULED, result.getDecision());
        assertFalse(ext.isCritical());

        // Verify the Truncated SHA1 content
        assertArrayEquals((new DEROctetString(x509ExtensionUtils.createSubjectKeyIdentifier(certTemplateNoSubjectKeyId.getPublicKey()))).getEncoded(),
            ext.getExtnValue().getEncoded());


    }

    /**
     * Test a truncated Subject Key Identifier no override
     *
     * <Subject_Key_Identifier>160 bit SHA-1</Subject_Key_Identifier>
     */
    @Test
    public void testCertificateSubjectKeyIdentifierNoOverruledSHA1() throws ProfileException, IOException, NoSuchAlgorithmException {
        Profile profile = profiles.get(3);
        Extension ext = null;
        Result result = null;

        List<Result> results = profile.validateCertificateExtensions(certTemplateSHA1);

        for (Result res : results) {
            if (((Extension)res.getValue()).getExtnId().equals(Extension.subjectKeyIdentifier)) {
                result = res;
                break;
            }
        }

        // Subject Key Identifier found
        assertNotNull(result);

        ext = (Extension)result.getValue();

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertFalse(ext.isCritical());

        Extension origExt = certTemplateSHA1.getExtensions().getExtension(Extension.subjectKeyIdentifier);

        // Verify the Truncated SHA1 content
        assertArrayEquals(origExt.getExtnValue().getEncoded(),
            ext.getExtnValue().getEncoded());


    }
}
