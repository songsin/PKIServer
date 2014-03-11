package org.cryptable.pki.server.model.profile;

import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.cryptable.pki.server.model.profile.impl.ProfilesJAXB;
import org.cryptable.pki.util.GeneratePKI;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.JAXBException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.*;

/**
 * Author: davidtillemans Date: 28/12/13 Hour: 00:27
 */
public class ProfilesValidityTest {

	final Logger logger = LoggerFactory.getLogger(ProfilesValidityTest.class);

	static private Profiles profiles = null;
	private CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();
	static private GeneratePKI generatePKI;

	@BeforeClass
	static public void init() throws CertificateException, CertIOException,
			NoSuchAlgorithmException, OperatorCreationException, CRLException,
			NoSuchProviderException, InvalidKeySpecException {
		Security.addProvider(new BouncyCastleProvider());
		generatePKI = new GeneratePKI();
		generatePKI.createPKI();
	}

	@Before
	public void setup() throws JAXBException, IOException, ProfileException,
			ClassNotFoundException, CertificateEncodingException,
			NoSuchAlgorithmException {
		X509CertificateHolder x509CertificateHolder = new JcaX509CertificateHolder(
				generatePKI.getCaCert());
		if (profiles == null)
			profiles = new ProfilesJAXB(getClass().getResourceAsStream(
					"/Validity.xml"), x509CertificateHolder.toASN1Structure());
	}

	/**
	 * Test profile validity
	 */
	@Test
	public void testCertificateValidity1() throws ProfileException,
			JAXBException, IOException {

		Profile profile = profiles.get(1);
		DateTime nBefore = new DateTime(2013, 1, 1, 0, 0, 0, DateTimeZone.UTC);
		DateTime nAfter = new DateTime(2015, 12, 31, 23, 59, 59,
				DateTimeZone.UTC);

		CertTemplate certTemplate = certTemplateBuilder.setValidity(
				new OptionalValidity(new Time(nBefore.toDate()), new Time(
						nAfter.toDate()))).build();

		Result result3 = profile.validateCertificateValidity(certTemplate);

		assertEquals(Result.Decisions.VALID, result3.getDecision());

	}

	/**
	 * Test profile validity invalid nBefore
	 */
	@Test
	public void testCertificateInValidityNBefore() throws JAXBException,
			IOException, ProfileException {

		Profile profile = profiles.get(1);
		DateTime nBefore = new DateTime(2009, 1, 1, 0, 0, 0, DateTimeZone.UTC);
		DateTime nAfter = new DateTime(2015, 12, 31, 23, 59, 59,
				DateTimeZone.UTC);

		CertTemplate certTemplate = certTemplateBuilder.setValidity(
				new OptionalValidity(new Time(nBefore.toDate()), new Time(
						nAfter.toDate()))).build();

		Result result3 = profile.validateCertificateValidity(certTemplate);

		assertEquals(Result.Decisions.INVALID, result3.getDecision());
		logger.debug((String) result3.getValue());
	}

	/**
	 * Test profile validity invalid nAfter
	 */
	@Test
	public void testCertificateInValidityNAfter() throws JAXBException,
			IOException, ProfileException {

		Profile profile = profiles.get(1);
		DateTime nBefore = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeZone.UTC);
		DateTime nAfter = new DateTime(2034, 12, 31, 23, 59, 59,
				DateTimeZone.UTC);

		CertTemplate certTemplate = certTemplateBuilder.setValidity(
				new OptionalValidity(new Time(nBefore.toDate()), new Time(
						nAfter.toDate()))).build();

		Result result3 = profile.validateCertificateValidity(certTemplate);

		assertEquals(Result.Decisions.INVALID, result3.getDecision());
		logger.debug((String) result3.getValue());

	}

	/**
	 * Test profile validity invalid Minimum
	 */
	@Test
	public void testCertificateInValidityMinimum() throws JAXBException,
			IOException, ProfileException {

		Profile profile = profiles.get(1);
		DateTime nBefore = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeZone.UTC);
		DateTime nAfter = new DateTime(2025, 12, 31, 23, 59, 59,
				DateTimeZone.UTC);

		CertTemplate certTemplate = certTemplateBuilder.setValidity(
				new OptionalValidity(new Time(nBefore.toDate()), new Time(
						nAfter.toDate()))).build();

		Result result3 = profile.validateCertificateValidity(certTemplate);

		assertEquals(Result.Decisions.INVALID, result3.getDecision());
		assertEquals("Invalid minimum duration [364]", result3.getValue()
				.toString());

	}

	/**
	 * Test profile validity invalid Maximum
	 */
	@Test
	public void testCertificateInValidityMaximum() throws JAXBException,
			IOException, ProfileException {

		Profile profile = profiles.get(1);
		DateTime nBefore = new DateTime(2015, 1, 1, 0, 0, 0, DateTimeZone.UTC);
		DateTime nAfter = new DateTime(2025, 12, 31, 23, 59, 59,
				DateTimeZone.UTC);

		CertTemplate certTemplate = certTemplateBuilder.setValidity(
				new OptionalValidity(new Time(nBefore.toDate()), new Time(
						nAfter.toDate()))).build();

		Result result3 = profile.validateCertificateValidity(certTemplate);

		assertEquals(Result.Decisions.INVALID, result3.getDecision());
		assertEquals("Invalid maximum duration [4017]", result3.getValue()
				.toString());

	}

	/**
	 * Test profile validity overrule nBefore and nAfter <Not_Before
	 * Overrule="Yes">20130101000000</Not_Before> <Not_After
	 * Overrule="Yes">20171231000000</Not_After>
	 */
	@Test
	public void testCertificateValidityOverrule() throws JAXBException,
			IOException, ProfileException {

		Profile profile = profiles.get(4);
		DateTime nBefore = new DateTime(2015, 1, 1, 0, 0, 0, DateTimeZone.UTC);
		DateTime nAfter = new DateTime(2025, 12, 31, 23, 59, 59,
				DateTimeZone.UTC);

		CertTemplate certTemplate = certTemplateBuilder.setValidity(
				new OptionalValidity(new Time(nBefore.toDate()), new Time(
						nAfter.toDate()))).build();

		Result result3 = profile.validateCertificateValidity(certTemplate);

		assertEquals(Result.Decisions.OVERRULED, result3.getDecision());
		OptionalValidity optionalValidity = (OptionalValidity) result3
				.getValue();

		assertEquals(new DateTime(2013, 1, 1, 0, 0, 0, DateTimeZone.UTC),
				new DateTime(optionalValidity.getNotBefore().getDate(),
						DateTimeZone.UTC));
		assertEquals(new DateTime(2017, 12, 31, 0, 0, 0, DateTimeZone.UTC),
				new DateTime(optionalValidity.getNotAfter().getDate(),
						DateTimeZone.UTC));

	}

	/**
	 * No Minimum and Maximum dates are defined in the profile
	 */
	@Test
	public void testCertificateValidityEmptyMinimumMaximum()
			throws JAXBException, IOException, ProfileException {

		Profile profile = profiles.get(2);
		DateTime nBefore = new DateTime(2015, 1, 1, 0, 0, 0, DateTimeZone.UTC);
		DateTime nAfter = new DateTime(2017, 12, 31, 23, 59, 59,
				DateTimeZone.UTC);

		CertTemplate certTemplate = certTemplateBuilder.setValidity(
				new OptionalValidity(new Time(nBefore.toDate()), new Time(
						nAfter.toDate()))).build();

		Result result3 = profile.validateCertificateValidity(certTemplate);
		OptionalValidity optionalValidity = (OptionalValidity) result3
				.getValue();

		assertEquals(Result.Decisions.VALID, result3.getDecision());
		assertEquals(new DateTime(2015, 1, 1, 0, 0, 0, DateTimeZone.UTC),
				new DateTime(optionalValidity.getNotBefore().getDate(),
						DateTimeZone.UTC));
		assertEquals(new DateTime(2017, 12, 31, 23, 59, 59, DateTimeZone.UTC),
				new DateTime(optionalValidity.getNotAfter().getDate(),
						DateTimeZone.UTC));
	}

	/**
	 * No NBefore and NAfter are defined in the profile
	 */
	@Test
	public void testCertificateValidityEmptyNBeforeNAfter()
			throws JAXBException, IOException, ProfileException {

		Profile profile = profiles.get(3);
		DateTime nBefore = new DateTime(2015, 1, 1, 0, 0, 0, DateTimeZone.UTC);
		DateTime nAfter = new DateTime(2016, 12, 31, 23, 59, 59,
				DateTimeZone.UTC);

		CertTemplate certTemplate = certTemplateBuilder.setValidity(
				new OptionalValidity(new Time(nBefore.toDate()), new Time(
						nAfter.toDate()))).build();

		Result result3 = profile.validateCertificateValidity(certTemplate);
		OptionalValidity optionalValidity = (OptionalValidity) result3
				.getValue();

		assertEquals(Result.Decisions.VALID, result3.getDecision());
		assertEquals(new DateTime(2015, 1, 1, 0, 0, 0, DateTimeZone.UTC),
				new DateTime(optionalValidity.getNotBefore().getDate(),
						DateTimeZone.UTC));
		assertEquals(new DateTime(2016, 12, 31, 23, 59, 59, DateTimeZone.UTC),
				new DateTime(optionalValidity.getNotAfter().getDate(),
						DateTimeZone.UTC));
	}

	/**
	 * No NBefore and NAfter are defined in the profile invalid maximum
	 */
	@Test
	public void testCertificateValidityEmptyNBeforeNAfterInvalidMaximum()
			throws JAXBException, IOException, ProfileException {

		Profile profile = profiles.get(3);
		DateTime nBefore = new DateTime(2015, 1, 1, 0, 0, 0, DateTimeZone.UTC);
		DateTime nAfter = new DateTime(2025, 12, 31, 23, 59, 59,
				DateTimeZone.UTC);

		CertTemplate certTemplate = certTemplateBuilder.setValidity(
				new OptionalValidity(new Time(nBefore.toDate()), new Time(
						nAfter.toDate()))).build();

		Result result3 = profile.validateCertificateValidity(certTemplate);

		logger.debug((String)result3.getValue());
		assertEquals(Result.Decisions.INVALID, result3.getDecision());
		assertEquals("Invalid maximum duration [4017]", (String)result3.getValue());
	}

}
