package org.cryptable.pki.server.model.profile;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.cryptable.pki.server.model.profile.impl.ProfilesJAXB;
import org.cryptable.pki.util.GeneratePKI;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import static org.junit.Assert.assertEquals;

/**
 * Author: davidtillemans
 * Date: 28/12/13
 * Hour: 00:27
 */
public class ProfilesKeyLengthTest {

    static private Profiles profiles;
    static private KeyPair keyPair512;
    static private KeyPair keyPair1024;
    static private KeyPair keyPair2048;
    static private KeyPair keyPair8192;
    private CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();

    private RSAPublicKeySpec key512PubKeySpec = new RSAPublicKeySpec(
        new BigInteger("924f9ee9c90476a675fcda5d4ef37828899814d0539fb54bf935912948e7b1b06f9f020bc5d78e5642c4cf6041c366a3c1f2f2fb85574d2d9ff493cb43e1027f", 16),
        new BigInteger("10001", 16));

    private RSAPrivateCrtKeySpec key512PrivKeySpec = new RSAPrivateCrtKeySpec(
        new BigInteger("924f9ee9c90476a675fcda5d4ef37828899814d0539fb54bf935912948e7b1b06f9f020bc5d78e5642c4cf6041c366a3c1f2f2fb85574d2d9ff493cb43e1027f", 16),
        new BigInteger("10001", 16),
        new BigInteger("7f4d23998a3b85f8e3e3f3230894b251a3165dd5bd4cd2739e0bcb97be4549c644fd7b99aa0c0ca71702b09469eaf4e789dd469cf7504a1d194d0bd31797af91", 16),
        new BigInteger("d8f0108530171374f5faa18b98389dafae1c081205bceefab5058ff5bc6ba67b", 16),
        new BigInteger("aca7f48501998d8d1f997847906e439614fc3489eadc42246da19586cdd076cd", 16),
        new BigInteger("8216d3914ad94bada3a3fc23bdd0959eb805cf411f77c0c74eae5b39bd17c0e9", 16),
        new BigInteger("5934ca24b287e8d8027ca3e5addd1ab47f91338012c5ccb2cfa60e00c17434fd", 16),
        new BigInteger("7a356cc21516e87d00d74cd36bb0dc0f90b9275f11888159c5cf519af731062c", 16));

    private RSAPublicKeySpec key1024PubKeySpec = new RSAPublicKeySpec(
        new BigInteger("bae21e5afb48e11342f299c3054e5eb5562184109e7d53d9019ea6510b9a847a50eb5f4ef9001a279dea300a741bfa36ae4258ee0888731bb49b6d22b7fe02aecd31ffc32e7444442b11b1f9add0b8473b5e03b5e55bb5df639d4ad066ee7d5763f2c668bdc87ee268f732d059f8b346f5555694f879c3b715025bd74315a093", 16),
        new BigInteger("10001", 16));

    private RSAPrivateCrtKeySpec key1024PrivKeySpec = new RSAPrivateCrtKeySpec(
        new BigInteger("bae21e5afb48e11342f299c3054e5eb5562184109e7d53d9019ea6510b9a847a50eb5f4ef9001a279dea300a741bfa36ae4258ee0888731bb49b6d22b7fe02aecd31ffc32e7444442b11b1f9add0b8473b5e03b5e55bb5df639d4ad066ee7d5763f2c668bdc87ee268f732d059f8b346f5555694f879c3b715025bd74315a093", 16),
        new BigInteger("10001", 16),
        new BigInteger("b62e5889390e02dc54174bede1ee54455281b9ccb9b45358e94b4fb71228bf9cbde5b633b6697315cbcbd0a9602725f4c84bc585c6abbe0af435d05e581f375ca4c21d601d4b097b0cb0450adceb12daa113e9948242fbb7c0bf2a886725132205f50ce79e9951b7360dc4fa3f8b7db0273c0d96176186f9e85aa529172b4b81", 16),
        new BigInteger("ecb9da40576e855f114a58d1ed0ed48f544c263ec2a29772cddc243de021bb26c81f97d9323802c4ae939e94ab11ab36886baa651780fab19a8011fdcac79e87", 16),
        new BigInteger("ca1961519f854d438363e73f56a0be9316224c9a2855c0c6ff51ce841837666ab8d6e390137a7e3acdcb865a4f8b6d1f58070444c26c83ab988f2f5b2f01c495", 16),
        new BigInteger("92c26e1271a1ed4191009cac18e196d9fd12f0aafc13bcfcc9af6f308521a45b58ba6d7393f4b192aa008ed1f07495c6cb30a484e3db6c906b0e7718f67c6745", 16),
        new BigInteger("70617a9f63e0415da8837644df4c158d3f02a5ac177fcfea18720a2fa433b24ce829fe72d0920dfd6f109cce3d6b5fabcd4c619046b906e2f5bbb16eb80df89d", 16),
        new BigInteger("2e5d0addaab6412c8e5994660364d627a6076ba1a79c5fb9942edb632722d4d20901e57d6ce35d80e81cf506b6f4f15d63c88edf1a8191cc76219c890ed6bcb3", 16));

    private RSAPublicKeySpec key2048PubKeySpec = new RSAPublicKeySpec(
        new BigInteger("87fc4b405757781e622e5f6f49446b28476aef614c27e7e3d58e83ce58c384ac01bd1312bce1278c6715b8521e2430b9a06c4b95b1635b94e71a08cc17fe4a2072873ae4ad6ba153578dc31c3ff0e18dda35c5e35691f215916c6d26757773407a839e715f1b23a81c8000f1e92e5dcd3f6b5ba9b6d03a29e7d9a30b0497c50a0bb3c0dceb7e70928942708f0f27d33a8c93549c9991c70c25e04aa5bca39f33393e659ae7dc426d2223abe321a61b6a16fb7df91abb58925747f621f8631c4860e9c8e245917b55e3c8b209437d04611cb5bfc1afc878f4e8e413147b2b9ab36c885ef1d9d5f1b9629766d56aa006ba698b845f4065eefb4103ce17ff127c13", 16),
        new BigInteger("10001", 16));

    private RSAPrivateCrtKeySpec key2048PrivKeySpec = new RSAPrivateCrtKeySpec(
        new BigInteger("87fc4b405757781e622e5f6f49446b28476aef614c27e7e3d58e83ce58c384ac01bd1312bce1278c6715b8521e2430b9a06c4b95b1635b94e71a08cc17fe4a2072873ae4ad6ba153578dc31c3ff0e18dda35c5e35691f215916c6d26757773407a839e715f1b23a81c8000f1e92e5dcd3f6b5ba9b6d03a29e7d9a30b0497c50a0bb3c0dceb7e70928942708f0f27d33a8c93549c9991c70c25e04aa5bca39f33393e659ae7dc426d2223abe321a61b6a16fb7df91abb58925747f621f8631c4860e9c8e245917b55e3c8b209437d04611cb5bfc1afc878f4e8e413147b2b9ab36c885ef1d9d5f1b9629766d56aa006ba698b845f4065eefb4103ce17ff127c13", 16),
        new BigInteger("10001", 16),
        new BigInteger("b1bf761d840d315585c057be7f668f2af72f2ff75e344b47e3bd854c137a7dd0d7f4ed19710a5d4788f73b171b8ef2a1b0afdd9cad61d233b060b75f0f7db426f58d0dce1b60b45edbf2d135fbde40f5ca64bf6589a2fb6c75c9e46280e8c21d6606e4f40bfccd7ed0c2007a34f2066a629b5215648089867d285d95e94af8a14cc29e990e82a9962ba18f877e8d491aebb4a0980d9f6e48fa21b3a54a8155d87c9ce737548aea39c751c89e98f34c39dcb98d0751481b65d657d7f6520929680c1daac7d00a6ebf7e18db721e0eff6e635f4433dc006b7485c2374c866eacfe75c5b081d10f2bdb21246328d5d993b390dbc1c81ba019fe4fb2754e422e091", 16),
        new BigInteger("f8e2276c6e865486c793f520bf84a5bdb23fbe54b71253642273cb56699ce42b10e5fc0c1b73ef7a01e642a5b1b778bd4aeded5baf2bfb0b758d2b6594065b6d516a0764899a7a2dd1cdad6b753b5ae84bd24b6f4d71ab9b5621764c229b1851f23760b98a47ffab12f67db5e4ff8bbd01e4093b2deff996e046e3ab1772f6ff", 16),
        new BigInteger("8bdfb7f5473cfc8277050a8fa4c7f8ddf33d44c44194373180db93d96b33637429e83a41a36032fed5ff344ed64c3dbf2195545da3ef6f5e2facb1109c980ea58a14332d9cbc322f4cb849b9454fd299b441260a2eeceb072f5551187d7de62dbbe7e0a5e5bcd02c1bcc813ae494670f46235c6eabbaf03b9c5c50a6b0be2eed", 16),
        new BigInteger("c133f67cb333ee4c0e842a2738e54530843dfd878ff256f005dab3ffa9ced445264212ae67655182fa1480aa55d2629537a489bcc1b8379306b706f83cb7cea3872ef2fc35e1c874e7486e165c142e96e3bd25380afb71c70d4ebea18dbfae5a76d84c6adc10d6453c5c42ec400facaf95d72adf58e2d073323975a52c77df8b", 16),
        new BigInteger("7b37d0b155594744931eb0c80bac51f30c252c200b794b09e3ef0b16dc160005c4291cb0d80095cbe2ae97e0df6d7873985d195e085d93e90fec7c6b1ad7e50735554824654f7092346ea01b8310a780d9c70e80a807f39f77b61be38c214d957a53f1959385ba8930cffe03e87b4732b061d43a76340f0f24563a822d6ecc9d", 16),
        new BigInteger("7257407dc5b1baec85676b8bc081d2895183a09c51a9eb16f430212887bb0c3670a206fa0513581505c5754b00d0e7b982ed3509543069709967bd82e632f8491ee431ab44942d19bc03002f280f73a02ed15d3752372f2d0c18e5c68c758663e0442e983e1e6b9a2f6e4ca15651cec5c23869eb19b2e23f2d6b0f46b960fe99", 16));

    private RSAPublicKeySpec key8192PubKeySpec = new RSAPublicKeySpec(
        new BigInteger("bf022aa743c23765a9762d28874ac6829ee01b813e30a5674fb31bc56ce6fcfe936246073f8cf17c9eabc9e1f12f74016a2e1c909c86e891b45a28396ffb30b53528f3d7882a8a4acb542611eac611cb4d073a0d6e2823c6dfa06fd2305c612590af05020014b8bdf49b541e9e8003473754ce5fdaf024ac31d92eb09767b5c33b6990a46815e07c678b5d2c15ae7587dd4a9127ea27754a21e22760d9144604289e0643cce7edd98f52e96542fb15df3c560b31942172a770718fe68a20de305d9b1e539a38bd3a28d0587f06073e2bed69710e36102ed066a40c6be0db9caa51b122773feb576cc85bb10cab1d5c9535a7866beb9131c8f49db2278c092bf3807495355dd88b09adb75bb6c7b26ba316e3a037775c7aae18c66531c2842a5a6100cf65c61fedd3414353ed4faec68b8422d3141e369340561ea0135fca203608979e0ba760f3ad8f066d27460c3fec4382aba681ec21f99cd5a732dc9cd8486df16f8a7b1006efb1798b4ca96e6b53c7c9582e981ed371af53a380cbd0a41c0fb7354e3fcc63b209523a3f8c682bc2cb9e9e3005bc73e290e74a314b277dee024f7b628f3d64e7700c01a786c6e16ea35b2d009bc7da0449b9d67838374f8f3006b786db0639e95aed80e533a2faa0d430886c3996c20808cc65b63fa318d4e40dd17270866c002b7c1c4a350982f294dcad886e2ae1c9ff1d50facd6e215aeff56bdbb9f66c3693af635f8dfe674d061f0703a50c720ff7b0e340e5c6e50912a496249c2c39819d2527f64c7c1bfc49b530fcf5c70b2d38e092b43cc426795f9809b9a4f0c774ab30ce7bfc184e943f88e444ecf3fc48095c1f92dee76f5558f8588845aa20038abf3a0b30ae1732ea83c36ea9432e52a520fa8a00f08dc9795eedb184040be367a7a834c68f6f8ae45d3f0132dc9e3df0101792fa5c4e86d78570584073ff81681d7d8e04aee8600331f082e55b7d0b5e8972bcf02e9974dc500ee04dacc4665484f8e7004e99b49adae7a74f8b042c31bff4bab49954fba3ad053476edd8a2833e0fa2608a3467cf2cf736926f706d530928141dc19eeab3caeeb6b54276e4fea729cdc21136f3f0203d679cc129a0f61fbace95e7a0686260ecb68b4e0c6f13cef160cac8890765324699bf90eb667cfaee37a840751972ce5c3b4d5b0730f02e950311b9c1fd2f82a91d1f30b351911907965f943e0d925b6c7984a2c889af9ece3eb3af7fd8f80739a0e7c297807f86949bc7b8ff050c2480e18dec052384c3190e68c1b794fac3eb834ae1cdf798d7cacd45ad79c7db4ac5ae2853b61f0b9f3dae52fdcfbbb93f178044c48589d5c3857c30f7fa918680027108a84bdfdfc6a87247044f67ddb255f8ccde7439f7ada89a815190d6a87ac52cd31a19b71ae47fe3fb749c3876541d38a351271c4d4decb4408f1331", 16),
        new BigInteger("10001", 16));

    private RSAPrivateCrtKeySpec key8192PrivKeySpec = new RSAPrivateCrtKeySpec(
        new BigInteger("bf022aa743c23765a9762d28874ac6829ee01b813e30a5674fb31bc56ce6fcfe936246073f8cf17c9eabc9e1f12f74016a2e1c909c86e891b45a28396ffb30b53528f3d7882a8a4acb542611eac611cb4d073a0d6e2823c6dfa06fd2305c612590af05020014b8bdf49b541e9e8003473754ce5fdaf024ac31d92eb09767b5c33b6990a46815e07c678b5d2c15ae7587dd4a9127ea27754a21e22760d9144604289e0643cce7edd98f52e96542fb15df3c560b31942172a770718fe68a20de305d9b1e539a38bd3a28d0587f06073e2bed69710e36102ed066a40c6be0db9caa51b122773feb576cc85bb10cab1d5c9535a7866beb9131c8f49db2278c092bf3807495355dd88b09adb75bb6c7b26ba316e3a037775c7aae18c66531c2842a5a6100cf65c61fedd3414353ed4faec68b8422d3141e369340561ea0135fca203608979e0ba760f3ad8f066d27460c3fec4382aba681ec21f99cd5a732dc9cd8486df16f8a7b1006efb1798b4ca96e6b53c7c9582e981ed371af53a380cbd0a41c0fb7354e3fcc63b209523a3f8c682bc2cb9e9e3005bc73e290e74a314b277dee024f7b628f3d64e7700c01a786c6e16ea35b2d009bc7da0449b9d67838374f8f3006b786db0639e95aed80e533a2faa0d430886c3996c20808cc65b63fa318d4e40dd17270866c002b7c1c4a350982f294dcad886e2ae1c9ff1d50facd6e215aeff56bdbb9f66c3693af635f8dfe674d061f0703a50c720ff7b0e340e5c6e50912a496249c2c39819d2527f64c7c1bfc49b530fcf5c70b2d38e092b43cc426795f9809b9a4f0c774ab30ce7bfc184e943f88e444ecf3fc48095c1f92dee76f5558f8588845aa20038abf3a0b30ae1732ea83c36ea9432e52a520fa8a00f08dc9795eedb184040be367a7a834c68f6f8ae45d3f0132dc9e3df0101792fa5c4e86d78570584073ff81681d7d8e04aee8600331f082e55b7d0b5e8972bcf02e9974dc500ee04dacc4665484f8e7004e99b49adae7a74f8b042c31bff4bab49954fba3ad053476edd8a2833e0fa2608a3467cf2cf736926f706d530928141dc19eeab3caeeb6b54276e4fea729cdc21136f3f0203d679cc129a0f61fbace95e7a0686260ecb68b4e0c6f13cef160cac8890765324699bf90eb667cfaee37a840751972ce5c3b4d5b0730f02e950311b9c1fd2f82a91d1f30b351911907965f943e0d925b6c7984a2c889af9ece3eb3af7fd8f80739a0e7c297807f86949bc7b8ff050c2480e18dec052384c3190e68c1b794fac3eb834ae1cdf798d7cacd45ad79c7db4ac5ae2853b61f0b9f3dae52fdcfbbb93f178044c48589d5c3857c30f7fa918680027108a84bdfdfc6a87247044f67ddb255f8ccde7439f7ada89a815190d6a87ac52cd31a19b71ae47fe3fb749c3876541d38a351271c4d4decb4408f1331", 16),
        new BigInteger("10001", 16),
        new BigInteger("a6c4b980f8c425a1f96758de3de1a7987c26a75d1c7354b6f2fb2a9021193c62f943a068cbafbf585321224ec749eb3b20fdc9aae93f50e786540132c4f6c7fc2ec1e6c493fab06bc5435f49dd75ba2b8ac1788a29579a8514d2fb4ec532a30f2d57e24370d6a6c6133f5b1eb0bc8c202dcb39b4af6f645583e05fc78729e1a4e7c6afa71bc99e0a804d49b827e5fe6ff5621982840a9779764402a5a862ef0eca77ce787bfb33cbf43b2bd461badfc9dce0333dc25bc1c33785af6255cf84af2dcb359b40d7b13f8a4afe394986215e311712c299a95f764d678600da7e6436c0c4ab96fa93fbecdab253ceffc7cf01e7aab0cea10a5031688216fe3861f9a1ccd1fd446eff95c5898ac1e4c04ea373ed94285ac53855549405046d81abeb5ea5bb135984b673eb32dc19f6e4cf704277c8000b5ca5c1c3366ddecd8ba0eaa6c2b1be27e6a7db99f97a5eeb1f59aaa619fb88eb041cab3d4915b1b9d2ac8e9a0e83f223327737d727593baa5f742cf92542425fcc297deb906cb220cdd308b60772aa73fb77f4c38927e5fb7e17a5bd9a128f82d63f47ded52d5bb5d62c50e2f1d97b9cfdfb5892495df243d684e666b6f1f044cbbe9e3788375d6df187394b875f15f6045d574acb3cfa8123a874b2df10d0cbcd2c3794d439c1c471a37116cf56d13bddcb3f98965ef244483259c67afa81f8d057587408ee0bba2e8aad4b3a36141a0ebebdcac26cff9ed6ba626d4e711cc990a55bb8de71a3e674ed2efd2fc19f4fd2264989a1bd2c9d095249983181b801889634606db51f7adf49d90f0c41681bcd425b190a93a8dfbc5a9e81390bed4937bb222fe4fff4d9f663ee7ec65312a255ff0867ec5fd0f533727ff579130fab37b7d2d7a0d02418370dd9c2d6c7a589d40886c0dd7cd2fe6df8b6b09f20fab177c2d53697ec000db46f5e00f0f35c5dd1eddbda3dcf71da0ea5ce2885a975c4a0db95e34da44ff4f6bfdc58a05c1bcf979c1bb43b6b6e29e6b81eb608b854ef566419365d4de7252c3471d7f4f1be3f2380448952fb372fc7014d2eb16f3c52f0a37430e6b5a676a79a4d8497cb46a21eade311c1cc698459a7bc441cbf0565ed9eaa63aff21c5424464c77d2743e8ffba31bbf18da1b5d20787668b310e0a6d15d12413d25640b842d43eaa1bbd5a62a1579370576f17e0fa78bc5c32a7ccdbd4182f00e5e3b9160e0a458900d0a8eed69c9fe4f562991f6c1c625d366f74a0f226e3ef6f650a9c8cf678c131afada8252be259e856b37f2b7f983f2de797dcc15e9b2dc2f77cfed7ddbcb43f8082546b1128a318711de452f3414b2d95fee33b007f66dc27bdc1d8880f8de8e7f7337f35303bb5659588ea8f35a233bce2f42b04cb0417026e24b563297b61f3b86be7115a09a184af183f38fe5d66d13a9b1dee4d041f036c5a265ffd1", 16),
        new BigInteger("e5940de4a30cc7418b9a760127a69081455bbdfe7db6a3674b0d59b8b0d01e0d7a1364301a05bf0c025a9961c39e4e06011240c77403e36fa4473a942ec56663eab5ff964940913d8e1183cdcbce2cff8671cd8bf076e54c1abe0152e77983140fd310df78c49c5cc68aafe93c19673059c0a137360180cebdf206f48e308484396c40f49866dec8da6a249f808e36b753d7de98d5b393992413d3efe3e77e271fe3cd623b17b1996b0b6eb475e9112ca2f4c5b61f2ec60e707f817037be903099f1b20bacb410ccd309ae572455eb04cd0dbfaecece132016787fe8e82619a24832bffebbd6f1be67419ce65b5aa1fd58c59964b0a9a4236cea8d6b187e0d9c5b372c525b22bea73cc895560aee950363a32aeda664c554eb2622c3a464ed48bf5e20b0fe9d754a85d277e76121957d27f99a5b50097a8c610f45c66fea9063b52091301eda1c144c0e71239335835e98bdeb3b57c8bda1d32f15e067cd1064b380601b769eda9668d8a69e197a58926c1605d9653b05e9865b4da6e5999e57d41ab315deb8944bb9e67bdc9bedec3a2135047bd6d6e67cb99f64c11a6da3d2271393fbae4a68705183a57e6d9d302ff82b2175533f6985e8d59b0226aa08a76add608fc5258a6bd7511bc6a7df3166d56333cd15b44fb801a6cb363648ec44b52394c4650b47d2dc77c3bac7af4dcc8780229281107fa7945b3fcbc8ec5fe3", 16),
        new BigInteger("d4fdbf9ab2ccbd7c52b9f4192b0c797871a70364b1713442f1d94498caea3266a2f850ad020addd14537fac02c86e3a89a16fc6f6a48be4deb42f93dd22a85a1ca3553414f46e01141ae281bbdd136ce5e15aeb4f485fe4acd7e3cc586cd693ecffb864e71035f2609c47cde055e529806e3ea5f1308efc00d721c4b93f935b3ea4e2393e0cfef28f4f06aa3bf330157e56965b1a2eabde665dc31e99cf051f4cfeebe6d049c418ec0a0f532c8bcf15a9f501a815e008486d658b1ecc037f8faafb0e5c0c45a58267e3e74ca4905062b7c0f7d15b63fc7a4a8477d77a46d838e95c1bb6870977bbdd50fffa69b66105de7e3fc395e88200eb8e73aaa63a9039c9940dade051e5ea36b70d3ec41bcf9c155c4577a80ecfd7993cc6c703b2d42fa8fb80a9eccb9a6011e41d1e6aae4add930620c9d464c2be828f470838234bff860ae59c59f28d695486b20dcadeef1323bffec6468cb4c74d73e7e4d61f1ed1173b956b989d55dfee71e6092442ef9adc34ef24fcfc8a1be522435c21b2fe4d6f9d62a66637ef589fa737c70641e7d94746f95479a52b655a3e29b2119eb0eb3d497a261a57a186d83a52505781de24c3f2517c73ec42d0a8a0cfe66abb44c4847292a0f423a91884c6b13ce8952be1ab390493018976f6f602a4c110cb349f90b981b9aa79c97265ec6c3ab4ac316823d1766ba3955e7020404d62653f884db", 16),
        new BigInteger("c513c2956a0eb72222385762886a29147fb8d0b19db3623472ae243e32b28589e628ad51c994f33ad8ee734b048569cf27ae46a3b18900fdbe9552c910196edb090a713ccee7398710e5223350e84da29104328215cbcaecf8ebf0f0fd3a4776ba5ae2da23af0bd76cac7374119e7101859aa20a6637061ef3d9c774ba7715daf7fc610a57a5bf4bc68b65a2f2d5a24ce011a8c9a471c29bace7c480e330bf0fd1055a33202d27cd5ea1f2c7c18c70acd3bab1dab48c0f8327b99d20fb098077e83f1e2b7d771a10ea7d1e073a6ef3102d02c770c5a10bb3f8f63a3f72c1fa31602f08b82101d48631d7965bfd42215afd90ab2c4fa760faf42da976ad10d0984f895e67d84a4c45fe1ce66d7576f7be70130aeff56dfe23f6b4c71511937e4a7bd4ced581cd2379f4c5071f3e37793f764883e42d21e5ec8a097549729b7695d15002b2bf5956cf69b6e012bcf52c2fd188ff5cf2efa5323cbae7d9bae1c357deebae1505503aaef19441fbe83d29b990459b81d2afc7547f7cf37cf90e556a69eefd9b21956be051d674af9dbfb190f91ead19ae04ced974f34aa7a60b469d49e4399dcd319cd40675af6487ae6f464e909fe93aac6de68148950754af943c3bb58c85fea44a5e66f8fe921b5bb2e9e6f680ea65de62acbfe631fdf8bdc2ecfc5e6dffe609b7ff60390371dca7356f0546cee6db1a91ab06e50a2fe2ec5f27", 16),
        new BigInteger("cd05b923838b5bb6c9b72005fe0f52fa2284beda7587dfe3b5040c68fba276839fca6176382a179d7300d0c99dd2f65ffc7bb5e0d5b152269518f1ec955ac3299b08bbac7950632d9948b86903cdd8f0cb5619c72c3db32b7425590056a371f4b9a58782087d5360bd343b72483ea4489d115530d194df9bc2159eb10dae6d0853b985bbba42ce1761b7ef1ed25499ad6f32866678c977a4c9562d618fe5312ef3dcffc6d7124674d06ddfb953cbb4942418aa7aeeee96a368bf15fe2c85749073005818b7a9b382d230f2a129aac166a8540c7712e8d0176ab8ee4875a9c9623e3baf5778520916117b05feed4550e9e3e6ec8a98b9760a55e896eb1f65b9094be84706426d1a723a60f04e52754300dcbb53eda31efd5bc36e9acf69d746cb03ff079216c579cb47c1d9f82d7654f665016cdd13a70cf8bc3b97f6af2671c7f7e0bc9f63769f203206952a77ef3293c577b3a86fcb8a3c4a5968a0ba70736042421cfe1a749db759e83ed36cf8bef489b57bc061e5e1f3df03e60f83b61594ee073ee7324d2ab3f7b6a509570696a18977437e1a4a1623d7ceb0bf2b40bdf552e5e7b410e2b792eb8ed355316baac2f461934302e339ec14392fc5caf092215d067deb1438669089e6e4b9022cf8bba12f7993e788160762cd344d91292042afeb6a5ef38ae3605709039ee627668a559e2a0f86536f3bdc7c7f5b83a70cd3", 16),
        new BigInteger("cf12d6e43c2fd810e5d4e55e743fc5c1325f6cd0168a94e5f48424ee428a4192bec33d9c7e0a4307cc0dd8f9f890442e09f84c45df9b551743140383d20f0d1bd744f8637b43c6d453164a444bb17fb9f4070f8905746b4f1d80f8f55e11e2d23d37d5fd0a1b47fa3a0e914d4345f7dfa342f0e059565eae3d87e8015251bf95b5ca6f066f61b19258fcb63214e0e29a0a1ebdb4de8724702f3681dd35af19b44d901935970c8bbbfdb83a2e5ef3f38fed50b14b50ba40f1b33a24592cef6d17e6293e36d17f86fc9818c88d66bca9926cc1a29d16eebe18c0a9c43ab179b094591f95633414f400e8c28d950ebd033b7aa3ff7524a05938cb371764f9ae1fecc61cc87e4ad8c41245a5e8c7534cd21d8dfb830adab3fe2cb1197206e0a9a1f5a03d63aefb818e273c8ad001a87dc4bdc827405e5c7fa228d306ac0baeed2c433bd7e2ebd683627294b482fa2bd8751265eaea6d8116bf9a4583229c27e05633a69414240b2e502996b42f50d7f22b7eb27b988fee5e7e2711a9e44e5193cf5fff0a36bd7e299f170f334af7f5fb19c2db4f0ef159dc8ec3c6a74668dcb21cd8986c5e8db3801cda4cee338b914a08818919ab2a57ddd0355486e11b630099042c5aef88afe5941fc610a47c92508cf4fe3be8047c0ca7e853c619794605ab4e3f40bb9a94eec4d1f29cb2676a739e3b5794580b26edf2bf714b8f926775d96f", 16));

    static private GeneratePKI generatePKI;

    @BeforeClass
    static public void init() throws CertificateException, CertIOException, NoSuchAlgorithmException, OperatorCreationException, CRLException, NoSuchProviderException, InvalidKeySpecException {
        Security.addProvider(new BouncyCastleProvider());
        generatePKI = new GeneratePKI();
        generatePKI.createPKI();
    }

    @Before
    public void setup() throws JAXBException, IOException, ProfileException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateEncodingException {
        X509CertificateHolder x509CertificateHolder = new JcaX509CertificateHolder(generatePKI.getCaCert());
        if (profiles == null)
            profiles = new ProfilesJAXB(getClass().getResourceAsStream("/KeyLength.xml"), x509CertificateHolder.toASN1Structure());

        KeyFactory          fact = KeyFactory.getInstance("RSA", "BC");

//        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", "BC");
//        kGen.initialize(512);
//        keyPair512 = new KeyPair(fact.generatePublic(key512PubKeySpec), fact.generatePrivate(key512PrivKeySpec));
//        keyPair512.toString();
//        System.out.print(keyPair512.getPrivate().toString());
//        kGen.initialize(1024);
//        keyPair1024 = kGen.generateKeyPair();
//        keyPair1024.toString();
//        System.out.print(keyPair1024.getPrivate().toString());
//        kGen.initialize(2048);
//        keyPair2048 = kGen.generateKeyPair();
//        keyPair2048.toString();
//        System.out.print(keyPair2048.getPrivate().toString());
//        kGen.initialize(8192);
//        keyPair8192 = kGen.generateKeyPair();
//        keyPair8192.toString();
//        System.out.print(keyPair8192.getPrivate().toString());

        keyPair512 = new KeyPair(fact.generatePublic(key512PubKeySpec), fact.generatePrivate(key512PrivKeySpec));
        keyPair1024 = new KeyPair(fact.generatePublic(key1024PubKeySpec), fact.generatePrivate(key1024PrivKeySpec));
        keyPair2048 = new KeyPair(fact.generatePublic(key2048PubKeySpec), fact.generatePrivate(key2048PrivKeySpec));
        keyPair8192 = new KeyPair(fact.generatePublic(key8192PubKeySpec), fact.generatePrivate(key8192PrivKeySpec));
    }

    /**
     * Test the keyLengths of the profile key length.
     * <Key_Length>
     *   <Minimum_Key_Length>2048</Minimum_Key_Length>
     *   <Maximum_Key_Length>4096</Maximum_Key_Length>
     * </Key_Length>
     */
    @Test
    public void testCertificateKeyLengthValid() throws ProfileException, IOException {
        Profile profile = profiles.get(1);

        int keyLength = 2048;
        CertTemplate certTemplate = certTemplateBuilder
            .setPublicKey(new SubjectPublicKeyInfo(ASN1Sequence.getInstance(keyPair2048.getPublic().getEncoded())))
            .build();
        Result result = profile.validateCertificateKeyLength(certTemplate);

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertEquals(Integer.valueOf(2048), result.getValue());
    }

    /**
     * Test invalid minimum key length
     */
    @Test
    public void testCertificateKeyLengthInValidMinimum() throws ProfileException, IOException {
        Profile profile = profiles.get(1);
        int keyLength = 512;

        CertTemplate certTemplate = certTemplateBuilder
            .setPublicKey(new SubjectPublicKeyInfo(ASN1Sequence.getInstance(keyPair512.getPublic().getEncoded())))
            .build();

        Result result = profile.validateCertificateKeyLength(certTemplate);

        assertEquals(Result.Decisions.INVALID, result.getDecision());
        assertEquals(String.valueOf("Invalid minimum key length [2048:512]"), result.getValue());
    }

    /**
     * Test invalid maximum key length
     */
    @Test
    public void testCertificateKeyLengthInValidMaximum() throws ProfileException, IOException {
        Profile profile = profiles.get(1);

        int keyLength = 8192;

        CertTemplate certTemplate = certTemplateBuilder
            .setPublicKey(new SubjectPublicKeyInfo(ASN1Sequence.getInstance(keyPair8192.getPublic().getEncoded())))
            .build();

        Result result = profile.validateCertificateKeyLength(certTemplate);

        assertEquals(Result.Decisions.INVALID, result.getDecision());
        assertEquals(String.valueOf("Invalid maximum key length [4096:8192]"), result.getValue());
    }

    /**
     * Test minimum key length only, empty maximum test
     */
    @Test
    public void testCertificateKeyLengthValidMinimumNoMaximum() throws ProfileException, IOException {
        Profile profile = profiles.get(2);

        int keyLength = 8192;

        CertTemplate certTemplate = certTemplateBuilder
            .setPublicKey(new SubjectPublicKeyInfo(ASN1Sequence.getInstance(keyPair8192.getPublic().getEncoded())))
            .build();

        Result result = profile.validateCertificateKeyLength(certTemplate);

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertEquals(Integer.valueOf(keyLength), result.getValue());
    }

    /**
     * Test minimum key length only, empty maximum test, but invalid keylength
     */
    @Test
    public void testCertificateKeyLengthInValidMinimumNoMaximum() throws ProfileException, IOException {
        Profile profile = profiles.get(2);

        int keyLength = 512;

        CertTemplate certTemplate = certTemplateBuilder
            .setPublicKey(new SubjectPublicKeyInfo(ASN1Sequence.getInstance(keyPair512.getPublic().getEncoded())))
            .build();

        Result result = profile.validateCertificateKeyLength(certTemplate);

        assertEquals(Result.Decisions.INVALID, result.getDecision());
        assertEquals(String.valueOf("Invalid minimum key length [1024:512]"), result.getValue());
    }

    /**
     * Test maximum key length only, empty minimum test
     */
    @Test
    public void testCertificateKeyLengthValidMaximumNoMinimum() throws ProfileException, IOException {
        Profile profile = profiles.get(3);

        int keyLength = 1024;

        CertTemplate certTemplate = certTemplateBuilder
            .setPublicKey(new SubjectPublicKeyInfo(ASN1Sequence.getInstance(keyPair1024.getPublic().getEncoded())))
            .build();

        Result result = profile.validateCertificateKeyLength(certTemplate);

        assertEquals(Result.Decisions.VALID, result.getDecision());
        assertEquals(Integer.valueOf(keyLength), result.getValue());
    }

    /**
     * Test maximum key length only, empty minimum test, but invalid keylength
     */
    @Test
    public void testCertificateKeyLengthInValidMaximumNoMinimum() throws ProfileException, IOException {
        Profile profile = profiles.get(3);

        int keyLength = 8192;

        CertTemplate certTemplate = certTemplateBuilder
            .setPublicKey(new SubjectPublicKeyInfo(ASN1Sequence.getInstance(keyPair8192.getPublic().getEncoded())))
            .build();

        Result result = profile.validateCertificateKeyLength(certTemplate);

        assertEquals(Result.Decisions.INVALID, result.getDecision());
        assertEquals(String.valueOf("Invalid maximum key length [2048:8192]"), result.getValue());
    }

}
