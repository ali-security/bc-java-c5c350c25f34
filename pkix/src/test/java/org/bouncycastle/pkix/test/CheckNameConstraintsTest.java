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
