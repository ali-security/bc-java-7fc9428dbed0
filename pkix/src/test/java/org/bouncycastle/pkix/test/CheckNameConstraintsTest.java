package org.bouncycastle.pkix.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkix.PKIXNameConstraintValidator;
import org.bouncycastle.pkix.PKIXNameConstraintValidatorException;
import org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer;
import org.bouncycastle.pkix.util.ErrorBundle;
import org.bouncycastle.test.TestResourceFinder;

/**
 * Name constraint checking in the {@link PKIXCertPathReviewer} must not process an unbounded number
 * of subject alternative names. The malicious chain (root, ca1, ca2, leaf) is built in code: both CA
 * certificates carry a large name constraints extension and ca2 and the leaf carry a large subject
 * alternative name extension, so that checking every name against every constraint becomes expensive.
 */
public class CheckNameConstraintsTest
    extends TestCase
{
    private static final String SUBJ_ALT_NAME_EXT_ERROR = "CertPathReviewer.subjAltNameExtError";
    private static final String NOT_PERMITTED_ERROR = "CertPathReviewer.notPermittedEmail";

    private static final int NAME_CHECK_MAX = 1 << 10;

    private static final int MAL_PERMITTED_COUNT = 1500;
    private static final int MAL_EXCLUDED_COUNT = 500;
    private static final int MAL_ALT_NAME_COUNT = 1500;

    private static final X500Name ROOT_NAME = new X500Name("CN=Name Constraints Test Root");
    private static final X500Name CA1_NAME = new X500Name("CN=Name Constraints Test CA1");
    private static final X500Name CA2_NAME = new X500Name("CN=Name Constraints Test CA2");
    private static final X500Name LEAF_NAME = new X500Name("CN=Name Constraints Test Leaf");

    private static final X500Name SAN_ROOT_NAME = new X500Name("CN=SAN Limit Test Root");
    private static final X500Name SAN_CA_NAME = new X500Name("CN=SAN Limit Test CA");
    private static final X500Name SAN_EE_NAME = new X500Name("CN=SAN Limit Test EE");

    private static final X500Name NC_ROOT_NAME = new X500Name("CN=NC Trailing Dot Test Root CA");
    private static final X500Name NC_CA_NAME = new X500Name("CN=NC Trailing Dot Constrained CA");
    private static final X500Name NC_SUB_CA_NAME = new X500Name("CN=NC Trailing Dot Sub CA");
    private static final X500Name NC_LEAF_NAME = new X500Name("CN=NC Trailing Dot Leaf");

    private static BigInteger serialNumber = BigInteger.ONE;

    public void testPKIXCertPathReviewer()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate root = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-root.crt"));
        X509Certificate ca1 = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-ca1.crt"));
        X509Certificate ca2 = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-ca2.crt"));
        X509Certificate leaf = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-leaf.crt"));

        List certchain = new ArrayList();
        certchain.add(root);
        certchain.add(ca1);
        certchain.add(ca2);
        certchain.add(leaf);

        CertPath cp = cf.generateCertPath(certchain);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(root, null));
        PKIXParameters param = new PKIXParameters(trust);

        PKIXCertPathReviewer certPathReviewer = new PKIXCertPathReviewer();
        certPathReviewer.init(cp, param);

        assertFalse(certPathReviewer.isValidCertPath()); // hit
    }

    public void testPKIXCertPathBuilder()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate rootCert = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-root.crt"));
        X509Certificate endCert = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-ca1.crt"));

        // create CertStore to support path building
        List list = new ArrayList();
        list.add(endCert);

        CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
        CertStore                     store = CertStore.getInstance("Collection", params, "BC");

        // build the path
        CertPathBuilder  builder = CertPathBuilder.getInstance("PKIX", "BC");
        X509CertSelector pathConstraints = new X509CertSelector();

        pathConstraints.setCertificate(endCert);

        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), pathConstraints);

        buildParams.addCertStore(store);
        buildParams.setDate(new Date(1744869361113L)); // 17th April 2025
        buildParams.setRevocationEnabled(false);

        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(buildParams);
        CertPath                  path = result.getCertPath();

        if (path.getCertificates().size() != 1)
        {
            fail("wrong number of certs in testPKIXCertPathBuilder path");
        }
    }

    public void testPKIXCertPathValidator()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate rootCert = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-root.crt"));
        X509Certificate endCert = (X509Certificate) cf.generateCertificate(TestResourceFinder.findTestResource("pkix", "mal-ca1.crt"));

        List list = new ArrayList();
        list.add(endCert);

        CertPath certPath = cf.generateCertPath(list);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters param = new PKIXParameters(trust);
        param.setDate(new Date(1744869361113L)); // 17th April 2025
        param.setRevocationEnabled(false);

        cpv.validate(certPath, param);
    }

    public void testPKIXCertPathReviewerGeneratedChain()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        X509Certificate[] mal = generateMaliciousChain(MAL_ALT_NAME_COUNT);

        PKIXCertPathReviewer certPathReviewer = reviewMaliciousChain(mal);

        assertFalse("malicious chain must not be valid", certPathReviewer.isValidCertPath()); // hit
        assertTrue("malicious subject alternative names in ca2 must be rejected, errors: " + errorIds(certPathReviewer),
            hasError(certPathReviewer, 1, SUBJ_ALT_NAME_EXT_ERROR));
        assertFalse("subject alternative names of ca2 must not be checked one by one, errors: " + errorIds(certPathReviewer),
            hasError(certPathReviewer, 1, NOT_PERMITTED_ERROR));
    }

    /**
     * The same chain shape with a ca2 subject alternative name extension at the limit is accepted, which shows
     * the names are well formed and permitted, so the rejection above is down to the number of names only.
     */
    public void testPKIXCertPathReviewerGeneratedChainAtLimit()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        X509Certificate[] mal = generateMaliciousChain(NAME_CHECK_MAX);

        PKIXCertPathReviewer certPathReviewer = reviewMaliciousChain(mal);

        assertFalse("subject alternative names at the limit must not be rejected, errors: " + errorIds(certPathReviewer),
            hasError(certPathReviewer, SUBJ_ALT_NAME_EXT_ERROR));
        assertTrue("chain should be valid, errors: " + errorIds(certPathReviewer),
            certPathReviewer.isValidCertPath());
    }

    /**
     * Below the limit the subject alternative names are still checked against the name constraints, so a
     * name outside the permitted subtrees is reported as such and not as a subject alternative name error.
     */
    public void testPKIXCertPathReviewerGeneratedChainNotPermittedWithinLimit()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        GeneralName[] altNames = new GeneralName[] {
            new GeneralName(GeneralName.dNSName, "ca2-host0.sub.p0.example.com"),
            new GeneralName(GeneralName.dNSName, "ca2-host1.not-permitted.example.net")
        };

        X509Certificate[] chain = generateChain(new GeneralNames(altNames));

        PKIXCertPathReviewer certPathReviewer = reviewMaliciousChain(chain);

        assertFalse("chain with a not permitted subject alternative name must not be valid",
            certPathReviewer.isValidCertPath());
        assertTrue("not permitted subject alternative name in ca2 must be reported, errors: " + errorIds(certPathReviewer),
            hasError(certPathReviewer, 1, NOT_PERMITTED_ERROR));
        assertFalse("subject alternative names within the limit must not be rejected by count, errors: " + errorIds(certPathReviewer),
            hasError(certPathReviewer, SUBJ_ALT_NAME_EXT_ERROR));
    }

    public void testPKIXCertPathBuilderGeneratedChain()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        X509Certificate[] mal = generateMaliciousChain(MAL_ALT_NAME_COUNT);
        X509Certificate rootCert = mal[0];
        X509Certificate endCert = mal[1];

        // create CertStore to support path building
        List list = new ArrayList();
        list.add(endCert);

        CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
        CertStore                     store = CertStore.getInstance("Collection", params, "BC");

        // build the path
        CertPathBuilder  builder = CertPathBuilder.getInstance("PKIX", "BC");
        X509CertSelector pathConstraints = new X509CertSelector();

        pathConstraints.setCertificate(endCert);

        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), pathConstraints);

        buildParams.addCertStore(store);
        buildParams.setDate(new Date());
        buildParams.setRevocationEnabled(false);

        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(buildParams);
        CertPath                  path = result.getCertPath();

        if (path.getCertificates().size() != 1)
        {
            fail("wrong number of certs in testPKIXCertPathBuilderGeneratedChain path");
        }
    }

    public void testPKIXCertPathValidatorGeneratedChain()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        X509Certificate[] mal = generateMaliciousChain(MAL_ALT_NAME_COUNT);
        X509Certificate rootCert = mal[0];
        X509Certificate endCert = mal[1];

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        List list = new ArrayList();
        list.add(endCert);

        CertPath certPath = cf.generateCertPath(list);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);

        cpv.validate(certPath, param);
    }

    /**
     * A CA certificate carrying exactly the maximum number of subject alternative names (1024)
     * must still be processed normally by the reviewer.
     */
    public void testPKIXCertPathReviewerSubjAltNamesAtLimit()
        throws Exception
    {
        PKIXCertPathReviewer certPathReviewer = reviewPathWithCaSubjAltNames(NAME_CHECK_MAX);

        assertFalse("subject alternative names at the limit must not be rejected, errors: " + errorIds(certPathReviewer),
            hasError(certPathReviewer, 1, SUBJ_ALT_NAME_EXT_ERROR));
        assertTrue("path should be valid, errors: " + errorIds(certPathReviewer),
            certPathReviewer.isValidCertPath());
    }

    /**
     * A CA certificate carrying one more subject alternative name than the maximum (1025)
     * must be rejected before the names are checked against the name constraints.
     */
    public void testPKIXCertPathReviewerSubjAltNamesOverLimit()
        throws Exception
    {
        PKIXCertPathReviewer certPathReviewer = reviewPathWithCaSubjAltNames(NAME_CHECK_MAX + 1);

        assertFalse("path with too many subject alternative names must not be valid", certPathReviewer.isValidCertPath());
        assertTrue("subject alternative names over the limit must be rejected, errors: " + errorIds(certPathReviewer),
            hasError(certPathReviewer, 1, SUBJ_ALT_NAME_EXT_ERROR));
    }

    /**
     * An RFC 1034 root-label trailing dot must not let a host escape an excluded rfc822Name, URI or
     * dNSName subtree: the host is canonicalised before it is compared.
     */
    public void testTrailingDotBypass()
        throws Exception
    {
        assertTrue("trailing-dot email must be caught by the excluded bank.com subtree",
            isExcluded(emailName("bank.com"), emailName("ceo@bank.com.")));
        assertTrue("trailing-dot email must be caught by the excluded mailbox",
            isExcluded(emailName("ceo@bank.com"), emailName("ceo@bank.com.")));
        assertTrue("trailing-dot email must be caught by the excluded .bank.com domain",
            isExcluded(emailName(".bank.com"), emailName("ceo@mail.bank.com.")));
        assertTrue("trailing-dot URI host must be caught by the excluded competitor.example subtree",
            isExcluded(uriName("competitor.example"), uriName("https://competitor.example./")));
        assertTrue("trailing-dot URI host must be caught by the excluded .competitor.example domain",
            isExcluded(uriName(".competitor.example"), uriName("https://www.competitor.example./")));
        assertTrue("trailing-dot DNS name must be caught by the excluded bank.com subtree",
            isExcluded(dnsName("bank.com"), dnsName("bank.com.")));
        assertTrue("trailing-dot DNS name must be caught by the excluded bank.com subtree",
            isExcluded(dnsName("bank.com"), dnsName("www.bank.com.")));

        // canonicalisation is symmetric: a fully-qualified name is still within its permitted subtree
        assertTrue("trailing-dot email must still be permitted",
            isPermitted(emailName("bank.com"), emailName("ceo@bank.com.")));
        assertTrue("trailing-dot URI host must still be permitted",
            isPermitted(uriName("competitor.example"), uriName("https://competitor.example./")));
        assertTrue("trailing-dot DNS name must still be permitted",
            isPermitted(dnsName("bank.com"), dnsName("www.bank.com.")));

        // and other hosts are unaffected
        assertFalse(isExcluded(emailName("bank.com"), emailName("ceo@notbank.com.")));
        assertFalse(isExcluded(uriName("competitor.example"), uriName("https://other.example./")));
        assertFalse(isExcluded(dnsName("bank.com"), dnsName("notbank.com.")));
        assertFalse(isPermitted(emailName("bank.com"), emailName("ceo@notbank.com.")));
    }

    /**
     * Only the single root-label dot of RFC 1034 sec. 3.1 is canonicalized away. A host carrying any
     * other empty label - a second trailing dot, a doubled dot, a leading dot - is not a name
     * RFC 5280 sec. 4.2.1.6 admits, and stripping the extra dots would decide on the caller's behalf
     * that "example.com.." names example.com. It is refused instead, in both directions, so it can
     * neither escape an excluded subtree nor be admitted by a permitted one.
     */
    public void testEmptyLabelRefused()
        throws Exception
    {
        // dNSName: every shape of empty label is refused, whichever domain the name appears to carry.
        assertTrue("two trailing dots must be refused",
            isExcluded(dnsName("example.com"), dnsName("example.com..")));
        assertTrue("three trailing dots must be refused",
            isExcluded(dnsName("example.com"), dnsName("example.com...")));
        assertTrue("a doubled inner dot must be refused",
            isExcluded(dnsName("example.com"), dnsName("foo..example.com")));
        assertTrue("a leading dot must be refused",
            isExcluded(dnsName("example.com"), dnsName(".example.com")));
        assertTrue("a sibling domain with an empty label must be refused too",
            isExcluded(dnsName("example.com"), dnsName("notexample.com..")));

        // the permitted direction refuses it as well, so canonicalizing has not admitted anything new.
        assertFalse("an empty label must not be permitted",
            isPermitted(dnsName("example.com"), dnsName("example.com..")));
        assertTrue("a well-formed name is still permitted",
            isPermitted(dnsName("example.com"), dnsName("example.com.")));

        // rfc822Name and URI share the guard, applied to the host.
        assertTrue("two trailing dots on a mail host must be refused",
            isExcluded(emailName("bank.com"), emailName("ceo@bank.com..")));
        assertTrue("a doubled inner dot on a mail host must be refused",
            isExcluded(emailName(".bank.com"), emailName("ceo@mail..bank.com")));
        assertFalse("an empty label on a mail host must not be permitted",
            isPermitted(emailName("bank.com"), emailName("ceo@bank.com..")));
        assertTrue("two trailing dots on a URI host must be refused",
            isExcluded(uriName("competitor.example"), uriName("https://competitor.example../")));
        assertFalse("an empty label on a URI host must not be permitted",
            isPermitted(uriName("competitor.example"), uriName("https://competitor.example../")));

        // the guard is scoped to the host: a quoted local part may legally carry a doubled dot.
        assertTrue("a doubled dot in a quoted local part must not be refused, and the host still matches",
            isExcluded(emailName("bank.com"), emailName("\"a..b\"@bank.com")));
        assertTrue("a doubled dot in a quoted local part must still be permitted",
            isPermitted(emailName("bank.com"), emailName("\"a..b\"@bank.com")));

        // a bare "." is the root label, not an empty one, and is left alone.
        assertFalse("a bare root label must not be refused", isExcluded(dnsName("example.com"), dnsName(".")));

        // nothing is refused where no constraint of that type is in force.
        assertFalse("an empty label is immaterial with no dNSName constraint",
            isExcluded(emailName("bank.com"), dnsName("example.com..")));
        assertTrue("an empty label is immaterial with no dNSName constraint",
            isPermitted(emailName("bank.com"), dnsName("example.com..")));
    }

    /**
     * End to end: a trailing dot (or an extra empty label) on a subject alternative name must not let
     * it escape the excluded subtrees of its name-constrained issuer. The reviewer applies the name
     * constraints to every certificate but the end entity, so the evading names sit on a sub CA issued
     * by the constrained CA.
     */
    public void testPKIXCertPathReviewerTrailingDotExcluded()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        NameConstraints excluded = new NameConstraints(null, new GeneralSubtree[]{
            new GeneralSubtree(emailName("bank.com")),
            new GeneralSubtree(uriName("competitor.example")),
            new GeneralSubtree(dnsName("bank.com")) });

        GeneralName[] evasions = new GeneralName[]{
            emailName("ceo@bank.com."),
            emailName("ceo@bank.com.."),
            uriName("https://competitor.example./"),
            uriName("https://competitor.example../"),
            dnsName("bank.com."),
            dnsName("www.bank.com."),
            dnsName("bank.com..") };

        for (int i = 0; i != evasions.length; i++)
        {
            PKIXCertPathReviewer badReviewer = reviewConstrainedPath(excluded,
                new GeneralNames(evasions[i]));

            assertFalse("reviewer accepted excluded name " + evasions[i], badReviewer.isValidCertPath());
            assertTrue("reviewer did not report excluded name " + evasions[i] + " against the sub CA, got "
                + errorIds(badReviewer), hasError(badReviewer, 1, NOT_PERMITTED_ERROR));
        }

        PKIXCertPathReviewer goodReviewer = reviewConstrainedPath(excluded,
            new GeneralNames(new GeneralName[]{
                emailName("ceo@other.com."), uriName("https://other.example./"), dnsName("other.com.") }));

        assertTrue("reviewer rejected a compliant sub CA, got " + errorIds(goodReviewer),
            goodReviewer.isValidCertPath());
    }

    /**
     * Generate root, ca1, ca2 and leaf. ca1 permits p[i].example.com and excludes x[i].example.org, ca2 narrows
     * that to sub.p[i].example.com with the same exclusions. Every subject alternative name in ca2 and the leaf
     * lies inside the permitted subtrees and outside the excluded ones.
     */
    private static X509Certificate[] generateMaliciousChain(int ca2AltNameCount)
        throws Exception
    {
        return generateChain(createAltNames("ca2-", ca2AltNameCount));
    }

    private static X509Certificate[] generateChain(GeneralNames ca2AltNames)
        throws Exception
    {
        KeyPair rootKp = generateKeyPair();
        KeyPair ca1Kp = generateKeyPair();
        KeyPair ca2Kp = generateKeyPair();
        KeyPair leafKp = generateKeyPair();

        X509Certificate root = makeCertificate(ROOT_NAME, rootKp.getPrivate(), ROOT_NAME, rootKp.getPublic(),
            true, null, null);
        X509Certificate ca1 = makeCertificate(ROOT_NAME, rootKp.getPrivate(), CA1_NAME, ca1Kp.getPublic(),
            true, null, createNameConstraints(""));
        X509Certificate ca2 = makeCertificate(CA1_NAME, ca1Kp.getPrivate(), CA2_NAME, ca2Kp.getPublic(),
            true, ca2AltNames, createNameConstraints("sub."));
        X509Certificate leaf = makeCertificate(CA2_NAME, ca2Kp.getPrivate(), LEAF_NAME, leafKp.getPublic(),
            false, createAltNames("leaf-", MAL_ALT_NAME_COUNT), null);

        return new X509Certificate[] { root, ca1, ca2, leaf };
    }

    private static PKIXCertPathReviewer reviewMaliciousChain(X509Certificate[] mal)
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        List certchain = new ArrayList();
        certchain.add(mal[3]);
        certchain.add(mal[2]);
        certchain.add(mal[1]);
        certchain.add(mal[0]);

        CertPath cp = cf.generateCertPath(certchain);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(mal[0], null));
        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);

        PKIXCertPathReviewer certPathReviewer = new PKIXCertPathReviewer();
        certPathReviewer.init(cp, param);

        assertEquals("trust anchor must be removed from the reviewed path", 3, certPathReviewer.getCertPathSize());

        return certPathReviewer;
    }

    private static NameConstraints createNameConstraints(String permittedPrefix)
    {
        GeneralSubtree[] permitted = new GeneralSubtree[MAL_PERMITTED_COUNT];
        for (int i = 0; i != permitted.length; i++)
        {
            permitted[i] = new GeneralSubtree(new GeneralName(GeneralName.dNSName, permittedPrefix + "p" + i + ".example.com"));
        }

        GeneralSubtree[] excluded = new GeneralSubtree[MAL_EXCLUDED_COUNT];
        for (int i = 0; i != excluded.length; i++)
        {
            excluded[i] = new GeneralSubtree(new GeneralName(GeneralName.dNSName, "x" + i + ".example.org"));
        }

        return new NameConstraints(permitted, excluded);
    }

    private static GeneralNames createAltNames(String hostPrefix, int count)
    {
        GeneralName[] altNames = new GeneralName[count];
        for (int i = 0; i != altNames.length; i++)
        {
            altNames[i] = new GeneralName(GeneralName.dNSName,
                hostPrefix + "host" + i + ".sub.p" + (i % MAL_PERMITTED_COUNT) + ".example.com");
        }
        return new GeneralNames(altNames);
    }

    private static PKIXCertPathReviewer reviewPathWithCaSubjAltNames(int altNameCount)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        KeyPair rootKp = generateKeyPair();
        KeyPair caKp = generateKeyPair();
        KeyPair eeKp = generateKeyPair();

        GeneralName[] altNames = new GeneralName[altNameCount];
        for (int i = 0; i != altNames.length; i++)
        {
            altNames[i] = new GeneralName(GeneralName.dNSName, "host" + i + ".example.com");
        }

        X509Certificate rootCert = makeCertificate(SAN_ROOT_NAME, rootKp.getPrivate(), SAN_ROOT_NAME, rootKp.getPublic(),
            true, null, null);
        X509Certificate caCert = makeCertificate(SAN_ROOT_NAME, rootKp.getPrivate(), SAN_CA_NAME, caKp.getPublic(),
            true, new GeneralNames(altNames), null);
        X509Certificate eeCert = makeCertificate(SAN_CA_NAME, caKp.getPrivate(), SAN_EE_NAME, eeKp.getPublic(),
            false, null, null);

        List certchain = new ArrayList();
        certchain.add(eeCert);
        certchain.add(caCert);

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        CertPath cp = cf.generateCertPath(certchain);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));
        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);

        PKIXCertPathReviewer certPathReviewer = new PKIXCertPathReviewer();
        certPathReviewer.init(cp, param);

        return certPathReviewer;
    }

    /**
     * Review root, constrained CA, sub CA and leaf, where the constrained CA carries
     * <code>nameConstraints</code> and the sub CA carries <code>subCaAltNames</code>.
     */
    private static PKIXCertPathReviewer reviewConstrainedPath(NameConstraints nameConstraints,
        GeneralNames subCaAltNames)
        throws Exception
    {
        KeyPair rootKp = generateKeyPair();
        KeyPair caKp = generateKeyPair();
        KeyPair subCaKp = generateKeyPair();
        KeyPair leafKp = generateKeyPair();

        X509Certificate rootCert = makeCertificate(NC_ROOT_NAME, rootKp.getPrivate(), NC_ROOT_NAME, rootKp.getPublic(),
            true, null, null);
        X509Certificate caCert = makeCertificate(NC_ROOT_NAME, rootKp.getPrivate(), NC_CA_NAME, caKp.getPublic(),
            true, null, nameConstraints);
        X509Certificate subCaCert = makeCertificate(NC_CA_NAME, caKp.getPrivate(), NC_SUB_CA_NAME, subCaKp.getPublic(),
            true, subCaAltNames, null);
        X509Certificate leafCert = makeCertificate(NC_SUB_CA_NAME, subCaKp.getPrivate(), NC_LEAF_NAME, leafKp.getPublic(),
            false, null, null);

        List certchain = new ArrayList();
        certchain.add(leafCert);
        certchain.add(subCaCert);
        certchain.add(caCert);

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        CertPath cp = cf.generateCertPath(certchain);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));
        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);

        PKIXCertPathReviewer certPathReviewer = new PKIXCertPathReviewer();
        certPathReviewer.init(cp, param);

        return certPathReviewer;
    }

    private static boolean isPermitted(GeneralName constraint, GeneralName name)
    {
        PKIXNameConstraintValidator validator = new PKIXNameConstraintValidator();

        validator.intersectPermittedSubtree(new GeneralSubtree(constraint));

        try
        {
            validator.checkPermitted(name);
            return true;
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            return false;
        }
    }

    private static boolean isExcluded(GeneralName constraint, GeneralName name)
    {
        PKIXNameConstraintValidator validator = new PKIXNameConstraintValidator();

        validator.addExcludedSubtree(new GeneralSubtree(constraint));

        try
        {
            validator.checkExcluded(name);
            return false;
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            return true;
        }
    }

    private static GeneralName emailName(String name)
    {
        return new GeneralName(GeneralName.rfc822Name, name);
    }

    private static GeneralName uriName(String name)
    {
        return new GeneralName(GeneralName.uniformResourceIdentifier, name);
    }

    private static GeneralName dnsName(String name)
    {
        return new GeneralName(GeneralName.dNSName, name);
    }

    private static KeyPair generateKeyPair()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(1024);

        return kpGen.generateKeyPair();
    }

    private static X509Certificate makeCertificate(X500Name issuer, PrivateKey issuerKey, X500Name subject,
        PublicKey subjectKey, boolean isCa, GeneralNames subjectAltNames, NameConstraints nameConstraints)
        throws Exception
    {
        long now = System.currentTimeMillis();

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
            issuer,
            allocateSerialNumber(),
            new Date(now - (1000L * 60 * 60)),
            new Date(now + (1000L * 60 * 60 * 24)),
            subject,
            subjectKey);

        if (isCa)
        {
            certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        }
        else
        {
            certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        }

        if (subjectAltNames != null)
        {
            certGen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
        }

        if (nameConstraints != null)
        {
            certGen.addExtension(Extension.nameConstraints, true, nameConstraints);
        }

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC");

        return new JcaX509CertificateConverter().setProvider("BC")
            .getCertificate(certGen.build(contentSignerBuilder.build(issuerKey)));
    }

    private static synchronized BigInteger allocateSerialNumber()
    {
        BigInteger serial = serialNumber;
        serialNumber = serialNumber.add(BigInteger.ONE);
        return serial;
    }

    private static boolean hasError(PKIXCertPathReviewer certPathReviewer, int index, String id)
    {
        for (Iterator it = certPathReviewer.getErrors(index).iterator(); it.hasNext();)
        {
            ErrorBundle msg = (ErrorBundle)it.next();
            if (id.equals(msg.getId()))
            {
                return true;
            }
        }
        return false;
    }

    private static boolean hasError(PKIXCertPathReviewer certPathReviewer, String id)
    {
        List[] errors = certPathReviewer.getErrors();
        for (int i = 0; i != errors.length; i++)
        {
            if (hasError(certPathReviewer, i - 1, id))
            {
                return true;
            }
        }
        return false;
    }

    private static String errorIds(PKIXCertPathReviewer certPathReviewer)
    {
        StringBuffer sb = new StringBuffer();
        List[] errors = certPathReviewer.getErrors();
        for (int i = 0; i != errors.length; i++)
        {
            for (Iterator it = errors[i].iterator(); it.hasNext();)
            {
                ErrorBundle msg = (ErrorBundle)it.next();
                sb.append('[').append(i - 1).append("] ").append(msg.getId()).append(' ');
            }
        }
        return sb.toString();
    }
}
