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
import java.security.cert.CertPathValidatorException;
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
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkix.PKIXNameConstraintValidator;
import org.bouncycastle.pkix.PKIXNameConstraintValidatorException;
import org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer;
import org.bouncycastle.pkix.util.ErrorBundle;

/**
 * Name constraint checking in the {@link PKIXCertPathReviewer} must not process an unbounded number
 * of subject alternative names. The malicious chain (root, ca1, ca2, leaf) is generated in code: both
 * CA certificates carry a large name constraints extension and ca2 and the leaf carry a large subject
 * alternative name extension, so that checking every name against every constraint becomes expensive.
 */
public class CheckNameConstraintsTest
    extends TestCase
{
    private static final String SUBJ_ALT_NAME_EXT_ERROR = "CertPathReviewer.subjAltNameExtError";

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

    private static BigInteger serialNumber = BigInteger.ONE;

    public void testPKIXCertPathReviewer()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        X509Certificate[] mal = generateMaliciousChain(MAL_ALT_NAME_COUNT);

        PKIXCertPathReviewer certPathReviewer = reviewMaliciousChain(mal);

        assertFalse("malicious chain must not be valid", certPathReviewer.isValidCertPath()); // hit
        assertTrue("malicious subject alternative names in ca2 must be rejected, errors: " + errorIds(certPathReviewer),
            hasError(certPathReviewer, 1, SUBJ_ALT_NAME_EXT_ERROR));
        assertFalse("subject alternative names of ca2 must not be checked one by one, errors: " + errorIds(certPathReviewer),
            hasError(certPathReviewer, 1, "CertPathReviewer.notPermittedEmail"));
    }

    /**
     * The same chain shape with a ca2 subject alternative name extension at the limit is accepted, which shows
     * the names are well formed and permitted, so the rejection above is down to the number of names only.
     */
    public void testPKIXCertPathReviewerMaliciousChainAtLimit()
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

    public void testPKIXCertPathBuilder()
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
            fail("wrong number of certs in testPKIXCertPathBuilder path");
        }
    }

    public void testPKIXCertPathValidator()
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
     * Generate root, ca1, ca2 and leaf. ca1 permits p[i].example.com and excludes x[i].example.org, ca2 narrows
     * that to sub.p[i].example.com with the same exclusions. Every subject alternative name in ca2 and the leaf
     * lies inside the permitted subtrees and outside the excluded ones.
     */
    private static X509Certificate[] generateMaliciousChain(int ca2AltNameCount)
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
            true, createAltNames("ca2-", ca2AltNameCount), createNameConstraints("sub."));
        X509Certificate leaf = makeCertificate(CA2_NAME, ca2Kp.getPrivate(), LEAF_NAME, leafKp.getPublic(),
            false, createAltNames("leaf-", NAME_CHECK_MAX), null);

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

    /**
     * RFC 5280 sec. 6.1.3 (b) and (c) apply the accumulated name constraints to every
     * certificate in the path, the target certificate included - the self-issued exemption in
     * sec. 4.2.1.10 is waived for the final certificate, and sec. 6.1.5 (wrap-up) does not
     * revisit name constraints. PKIXCertPathReviewer drove the check from a loop
     * bound of index &gt; 0, which is the bound the CA-only steps want; index 0 is the end-entity
     * certificate under the standard CertPath ordering, so a leaf whose subject or SAN violated
     * its issuing CA's constraints reviewed as valid with no errors at all, while
     * CertPathValidator("PKIX") rejected the identical chain.
     */
    public void testNameConstraintsAppliedToLeaf()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        KeyPair ncRootKp = generateKeyPair();
        KeyPair ncIntKp = generateKeyPair();

        X500Name rootDn = new X500Name("CN=NC Test Root CA");
        X500Name intDn = new X500Name("CN=NC Constrained Intermediate CA");

        X509Certificate rootCert = generateRoot(rootDn, ncRootKp);
        X509Certificate intCert = generateConstrainedCA(rootDn, ncRootKp, intDn, ncIntKp, "partner-a.example.com");

        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        // a leaf the constrained CA was never authorised to vouch for
        CertPath badPath = generatePath(intDn, ncIntKp, intCert, "attacker.evil.com");

        PKIXParameters badParam = new PKIXParameters(trust);
        badParam.setRevocationEnabled(false);

        // ground truth: the trust-deciding validator rejects it
        try
        {
            CertPathValidator.getInstance("PKIX", "BC").validate(badPath, badParam);
            fail("CertPathValidator accepted a name-constraint-violating leaf");
        }
        catch (CertPathValidatorException e)
        {
            // expected
        }

        PKIXCertPathReviewer reviewer = new PKIXCertPathReviewer();
        reviewer.init(badPath, badParam);
        assertFalse("pkix reviewer accepted a name-constraint-violating leaf", reviewer.isValidCertPath());
        assertTrue("pkix reviewer did not report the violation against the leaf, got "
            + errorIds(reviewer),
            hasError(reviewer, 0, "CertPathReviewer.notPermittedEmail"));

        // compatibility control: a leaf inside the permitted subtree still reviews as valid
        CertPath goodPath = generatePath(intDn, ncIntKp, intCert, "host.partner-a.example.com");

        PKIXParameters goodParam = new PKIXParameters(trust);
        goodParam.setRevocationEnabled(false);

        CertPathValidator.getInstance("PKIX", "BC").validate(goodPath, goodParam);

        PKIXCertPathReviewer okReviewer = new PKIXCertPathReviewer();
        okReviewer.init(goodPath, goodParam);
        assertTrue("pkix reviewer rejected a compliant leaf, got " + errorIds(okReviewer),
            okReviewer.isValidCertPath());

        org.bouncycastle.x509.PKIXCertPathReviewer okLegacy = new org.bouncycastle.x509.PKIXCertPathReviewer();
        okLegacy.init(goodPath, goodParam);
        assertTrue("legacy reviewer rejected a compliant leaf", okLegacy.isValidCertPath());
    }

    /**
     * The remaining leaf vectors: a subject DN outside a permitted directoryName subtree, a
     * SAN inside an excluded subtree, and a self-issued leaf (issuer == subject), which the
     * RFC 5280 self-issued exemption must not cover when it is the target certificate.
     */
    public void testNameConstraintsAppliedToLeafSubjectExcludedAndSelfIssued()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        KeyPair ncRootKp = generateKeyPair();
        KeyPair ncIntKp = generateKeyPair();

        X500Name rootDn = new X500Name("CN=NC Test Root CA");
        X500Name intDn = new X500Name("CN=NC Constrained Intermediate CA");

        X509Certificate rootCert = generateRoot(rootDn, ncRootKp);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        // subject DN outside a permitted directoryName subtree
        GeneralSubtree permittedDn = new GeneralSubtree(
            new GeneralName(new X500Name("C=US,O=Partner A")));
        X509Certificate dnCA = generateConstrainedCA(rootDn, ncRootKp, intDn, ncIntKp,
            new NameConstraints(new GeneralSubtree[]{permittedDn}, null));

        assertLeafRejected(trust, generatePath(intDn, ncIntKp, dnCA,
            new X500Name("C=US,O=Evil Corp,CN=attacker"), null), "CertPathReviewer.notPermittedDN");
        assertLeafAccepted(trust, generatePath(intDn, ncIntKp, dnCA,
            new X500Name("C=US,O=Partner A,CN=host"), null));

        // SAN inside an excluded dNSName subtree
        GeneralSubtree excludedDns = new GeneralSubtree(new GeneralName(GeneralName.dNSName, "evil.com"));
        X509Certificate exCA = generateConstrainedCA(rootDn, ncRootKp, intDn, ncIntKp,
            new NameConstraints(null, new GeneralSubtree[]{excludedDns}));

        assertLeafRejected(trust, generatePath(intDn, ncIntKp, exCA, new X500Name("CN=attacker"),
            new GeneralNames(new GeneralName(GeneralName.dNSName, "attacker.evil.com"))),
            "CertPathReviewer.notPermittedEmail");
        assertLeafAccepted(trust, generatePath(intDn, ncIntKp, exCA, new X500Name("CN=host"),
            new GeneralNames(new GeneralName(GeneralName.dNSName, "host.partner-a.example.com"))));

        // self-issued leaf (subject == issuer) with a SAN outside the permitted dNSName subtree
        X509Certificate dnsCA = generateConstrainedCA(rootDn, ncRootKp, intDn, ncIntKp, "partner-a.example.com");

        assertLeafRejected(trust, generatePath(intDn, ncIntKp, dnsCA, intDn,
            new GeneralNames(new GeneralName(GeneralName.dNSName, "attacker.evil.com"))),
            "CertPathReviewer.notPermittedEmail");
    }

    private static void assertLeafRejected(Set trust, CertPath path, String errorId)
        throws Exception
    {
        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);

        // ground truth: the trust-deciding validator rejects it
        try
        {
            CertPathValidator.getInstance("PKIX", "BC").validate(path, param);
            fail("CertPathValidator accepted a name-constraint-violating leaf");
        }
        catch (CertPathValidatorException e)
        {
            // expected
        }

        PKIXCertPathReviewer reviewer = new PKIXCertPathReviewer();
        reviewer.init(path, param);
        assertFalse("pkix reviewer accepted a name-constraint-violating leaf", reviewer.isValidCertPath());
        assertTrue("pkix reviewer did not report " + errorId + " against the leaf, got " + errorIds(reviewer),
            hasError(reviewer, 0, errorId));
    }

    private static void assertLeafAccepted(Set trust, CertPath path)
        throws Exception
    {
        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);

        CertPathValidator.getInstance("PKIX", "BC").validate(path, param);

        PKIXCertPathReviewer reviewer = new PKIXCertPathReviewer();
        reviewer.init(path, param);
        assertTrue("pkix reviewer rejected a compliant leaf, got " + errorIds(reviewer),
            reviewer.isValidCertPath());
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
     * End to end: a trailing dot (or an extra empty label) on a leaf's subject alternative name must
     * not let it escape the excluded subtrees of its name-constrained issuer.
     */
    public void testPKIXCertPathReviewerTrailingDotExcluded()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        KeyPair rootKp = generateKeyPair();
        KeyPair intKp = generateKeyPair();

        X500Name rootDn = new X500Name("CN=NC Trailing Dot Test Root CA");
        X500Name intDn = new X500Name("CN=NC Trailing Dot Constrained Intermediate CA");

        X509Certificate rootCert = generateRoot(rootDn, rootKp);
        X509Certificate intCert = generateConstrainedCA(rootDn, rootKp, intDn, intKp,
            new NameConstraints(null, new GeneralSubtree[]{
                new GeneralSubtree(emailName("bank.com")),
                new GeneralSubtree(uriName("competitor.example")),
                new GeneralSubtree(dnsName("bank.com")) }));

        GeneralName[] evasions = new GeneralName[]{
            emailName("ceo@bank.com."),
            uriName("https://competitor.example./"),
            dnsName("bank.com."),
            dnsName("bank.com..") };

        for (int i = 0; i != evasions.length; i++)
        {
            PKIXCertPathReviewer badReviewer = review(rootCert, generatePath(intDn, intKp, intCert,
                new X500Name("CN=Trailing Dot Leaf"), new GeneralNames(evasions[i])));
            assertFalse("reviewer accepted excluded name " + evasions[i], badReviewer.isValidCertPath());
            assertTrue("reviewer did not report excluded name " + evasions[i] + " against the leaf, got "
                + errorIds(badReviewer), hasError(badReviewer, 0, "CertPathReviewer.notPermittedEmail"));
        }

        PKIXCertPathReviewer goodReviewer = review(rootCert, generatePath(intDn, intKp, intCert,
            new X500Name("CN=Trailing Dot Leaf"), new GeneralNames(new GeneralName[]{
                emailName("ceo@other.com."), uriName("https://other.example./"), dnsName("other.com.") })));
        assertTrue("reviewer rejected a compliant leaf, got " + errorIds(goodReviewer),
            goodReviewer.isValidCertPath());
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

    private static PKIXCertPathReviewer review(X509Certificate rootCert, CertPath path)
        throws Exception
    {
        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);

        PKIXCertPathReviewer reviewer = new PKIXCertPathReviewer();
        reviewer.init(path, param);

        return reviewer;
    }

    private static X509Certificate sign(JcaX509v3CertificateBuilder builder, PrivateKey signerKey)
        throws Exception
    {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(signerKey);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    private static X509Certificate generateRoot(X500Name rootDn, KeyPair rootKp)
        throws Exception
    {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            rootDn, BigInteger.valueOf(1), notBefore(), notAfter(), rootDn, rootKp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        return sign(builder, rootKp.getPrivate());
    }

    private static X509Certificate generateConstrainedCA(X500Name issuerDn, KeyPair issuerKp,
        X500Name subjectDn, KeyPair subjectKp, String permittedDns)
        throws Exception
    {
        GeneralSubtree permitted = new GeneralSubtree(new GeneralName(GeneralName.dNSName, permittedDns));
        return generateConstrainedCA(issuerDn, issuerKp, subjectDn, subjectKp,
            new NameConstraints(new GeneralSubtree[]{permitted}, null));
    }

    private static X509Certificate generateConstrainedCA(X500Name issuerDn, KeyPair issuerKp,
        X500Name subjectDn, KeyPair subjectKp, NameConstraints nameConstraints)
        throws Exception
    {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            issuerDn, BigInteger.valueOf(2), notBefore(), notAfter(), subjectDn, subjectKp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        builder.addExtension(Extension.nameConstraints, true, nameConstraints);
        return sign(builder, issuerKp.getPrivate());
    }

    private static CertPath generatePath(X500Name issuerDn, KeyPair issuerKp, X509Certificate issuerCert,
        String leafDns)
        throws Exception
    {
        return generatePath(issuerDn, issuerKp, issuerCert, new X500Name("CN=" + leafDns),
            new GeneralNames(new GeneralName(GeneralName.dNSName, leafDns)));
    }

    private static CertPath generatePath(X500Name issuerDn, KeyPair issuerKp, X509Certificate issuerCert,
        X500Name leafDn, GeneralNames leafSubjectAltNames)
        throws Exception
    {
        KeyPair leafKp = generateKeyPair();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            issuerDn, BigInteger.valueOf(3), notBefore(), notAfter(),
            leafDn, leafKp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        if (leafSubjectAltNames != null)
        {
            builder.addExtension(Extension.subjectAlternativeName, false, leafSubjectAltNames);
        }
        X509Certificate leafCert = sign(builder, issuerKp.getPrivate());

        List chain = new ArrayList();
        chain.add(leafCert);
        chain.add(issuerCert);

        return CertificateFactory.getInstance("X.509", "BC").generateCertPath(chain);
    }

    private static Date notBefore()
    {
        return new Date(System.currentTimeMillis() - 86400000L);
    }

    private static Date notAfter()
    {
        return new Date(System.currentTimeMillis() + 86400000L * 3650);
    }
}
