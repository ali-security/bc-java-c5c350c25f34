package org.bouncycastle.cms.test;

import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.Hashtable;
import java.util.Map;

import javax.crypto.SecretKey;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSAuthEnvelopedData;
import org.bouncycastle.cms.CMSAuthEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTagLengthException;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.bc.BcCMSContentEncryptorBuilder;
import org.bouncycastle.cms.bc.BcKEKEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransAuthEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JcePasswordEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.bc.BcAESSymmetricKeyUnwrapper;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;

public class AuthEnvelopedDataTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static String _signDN;
    private static KeyPair _signKP;
    private static X509Certificate _signCert;

    private static String _origDN;
    private static KeyPair _origKP;
    private static X509Certificate _origCert;

    private static String _reciDN;
    private static KeyPair _reciKP;
    private static X509Certificate _reciCert;

    private static KeyPair _origEcKP;
    private static KeyPair _reciEcKP;
    private static X509Certificate _reciEcCert;

    private static boolean _initialised = false;

    public boolean DEBUG = true;

    private static final byte[] Sample1 = Base64.decode(
        "MIAGCyqGSIb3DQEJEAEXoIAwgAIBADGBmzCBmAIBAoABATANBgkqhkiG9w0BAQEF" +
            "AASBgG9yJPC3zFmIbPTtSrrTD+71lluua3F1/V/XzzDOczjdymy4tI4sle5HSxJ" +
            "N8yrw+m2JdWKb4s/u4frvmNqE6fcqfFtLpLEMXJneoEWWXZFKbndoqQNRMgfKGC" +
            "ncpeWhktRcSRtbEEk/H4hWggJGmVClS7f/nmCDjwyANBnI3shYMIAGCSqGSIb3D" +
            "QEHATAfBglghkgBZQMEAQYwEgQQLO0PwnuhYXRk8pLLhgik0aCABBMKvxIkbmBK" +
            "T73Oz4xtf0DNNGmdAAAAAAQMn+tzPcOldJUQWCEnAAAAAAAA");

    private static final byte[] Sample1Key = Base64.decode("MIICdAIBADANBgkqhkiG9w0BAQEFAASCAl4wggJaAgEAAoGBAMtFuFyzl4jgeuPL\n" +
        "uGp8Niqf11QGWVDTpZvE7VabLoPanzuVgjTYC8oJOq4PvVYW5V56KeGzXhsnhsDt\n" +
        "IBaRESTFuXM50uiH4mRPGsqCFJvbmokvxfhb24TPg3gQ5E2SEvmXFN425J/jvcqq\n" +
        "XpX7wQGtr9DWLIXsqPeLKhoy/qdhAgMBAAECf3xBB80spVPEggTXW2aoebwXt1pw\n" +
        "8BqzUnSWqlZaHJGdtgbxL0qNsjECX42Djj+1vzddJud0dRHvu4m8y8zlVl/Ro+fv\n" +
        "xETE9nCKzt1MlaNUG9mywZeWLjyOKZFY5fxc+yzoH+d8fcXTM7SwKG9bl6hisU0j\n" +
        "LWdramL5eV/kILECQQDxD5WuYZY2gF2DhtqAxCaf2MLgDlXzj1PcX3X1nPlrNKy3\n" +
        "G0jyMWofmZFORzUz1G0Dlyfxk3Wlc+1IIWbxH5dNAkEA196fcWJN9ZpavkuLKG3W\n" +
        "5sSWAs05Jdk2FGw/pbycoIaMOtf/3KeWJTSNxK1jKsoTQN3RUF9h2jtFhf+yqOjO\n" +
        "ZQJAGpf7jVdauPyEVIRGCrqZAD1rkkhClzISsFcfrk74/Si8fR7Xd1CYQpAwhZA5\n" +
        "gFRJCoJcd7wq2Gvnm3OD5cn0aQJAP98H8CV1CaltFgcGGqU9Q7SA6j1Mnm1BehN5\n" +
        "VZGUCk8lKLgGZYRUgZemJr5irCN0ROoc55oBOu/0pyw78YxInQJBAKjibmupsLLt\n" +
        "kUQF7vyalONmkebwEDwTHODWOGXC7xmcvXhFAnlpYkv3QCohF53X0RS+VprfojbI\n" +
        "X0T/eAP0zJA=");

    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            _initialised = true;
            Security.addProvider(new BouncyCastleProvider());

            _signDN = "O=Bouncy Castle, C=AU";
            _signKP = CMSTestUtil.makeKeyPair();
            _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

            _origDN = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            _origKP = CMSTestUtil.makeKeyPair();
            _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);

            _reciDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP = CMSTestUtil.makeKeyPair();
            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);

            _origEcKP = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcKP = CMSTestUtil.makeEcDsaKeyPair();
            _reciEcCert = CMSTestUtil.makeCertificate(_reciEcKP, _reciDN, _signKP, _signDN);
        }
    }

    public void setUp()
        throws Exception
    {
        init();
    }

    public AuthEnvelopedDataTest(String name)
    {
        super(name);
    }

    public static void main(String args[])
    {
        junit.textui.TestRunner.run(AuthEnvelopedDataTest.class);
    }

    public static Test suite()
        throws Exception
    {
        init();

        return new CMSTestSetup(new TestSuite(AuthEnvelopedDataTest.class));
    }

    public void testKeyTransMinimumTagSize()
        throws Exception
    {
        byte[] message = Strings.toByteArray("Hello, world!");

        // generate AuthEnvelopedData with a 96-bit (12-octet) GCM tag - valid under RFC 5084
        AlgorithmParameters algParams = AlgorithmParameters.getInstance("GCM", BC);
        algParams.init(new AEADParameterSpec(new byte[12], 96));

        OutputEncryptor enc = new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_GCM)
            .setProvider(BC).setAlgorithmParameters(algParams).build();

        assertEquals(12, GCMParameters.getInstance(enc.getAlgorithmIdentifier().getParameters()).getIcvLen());

        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();
        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));

        byte[] encoded = authGen.generate(new CMSProcessableByteArray(message), (OutputAEADEncryptor)enc).getEncoded();

        // a minimum at or below the actual tag size recovers as normal
        RecipientInformation recipient = (RecipientInformation)new CMSAuthEnvelopedData(encoded)
            .getRecipientInfos().getRecipients().iterator().next();
        byte[] recData = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate())
            .setProvider(BC).setMinimumTagSize(96));
        assertEquals("Hello, world!", Strings.fromByteArray(recData));

        // a minimum above the actual tag size is refused with CMSTagLengthException
        try
        {
            recipient = (RecipientInformation)new CMSAuthEnvelopedData(encoded)
                .getRecipientInfos().getRecipients().iterator().next();
            recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate())
                .setProvider(BC).setMinimumTagSize(128));

            fail("content recovered under a tag shorter than the configured minimum");
        }
        catch (CMSTagLengthException e)
        {
            // expected
        }

        // a default (128-bit) tag satisfies a 128-bit minimum
        OutputEncryptor fullEnc = new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_GCM).setProvider(BC).build();
        CMSAuthEnvelopedDataGenerator fullGen = new CMSAuthEnvelopedDataGenerator();
        fullGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC));
        byte[] fullEncoded = fullGen.generate(new CMSProcessableByteArray(message), (OutputAEADEncryptor)fullEnc).getEncoded();

        recipient = (RecipientInformation)new CMSAuthEnvelopedData(fullEncoded)
            .getRecipientInfos().getRecipients().iterator().next();
        byte[] fullRec = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate())
            .setProvider(BC).setMinimumTagSize(128));
        assertEquals("Hello, world!", Strings.fromByteArray(fullRec));
    }

    public void testMinimumTagSizeOtherRecipients()
        throws Exception
    {
        byte[] message = Strings.toByteArray("Hello, world!");
        SecretKey kek = CMSTestUtil.makeAESKey(128);
        char[] password = "password".toCharArray();

        // KEK recipient, downgraded 64-bit GCM tag
        byte[] encoded = generateShortTagData(NISTObjectIdentifiers.id_aes128_GCM, "GCM",
            new JceKEKRecipientInfoGenerator(new byte[]{ 1, 2, 3, 4, 5 }, kek).setProvider(BC), message);

        assertEquals("KEK recipient", "Hello, world!", Strings.fromByteArray(firstRecipient(encoded).getContent(
            new JceKEKEnvelopedRecipient(kek).setProvider(BC).setMinimumTagSize(64))));
        confirmTagSizeRefused("KEK recipient", encoded,
            new JceKEKEnvelopedRecipient(kek).setProvider(BC).setMinimumTagSize(128));
        confirmTagSizeRefused("Bc KEK recipient", encoded,
            new BcKEKEnvelopedRecipient(new BcAESSymmetricKeyUnwrapper(new KeyParameter(kek.getEncoded())))
            {
                {
                    setMinimumTagSizeInBits(128);
                }
            });

        // password recipient, downgraded 64-bit GCM tag
        encoded = generateShortTagData(NISTObjectIdentifiers.id_aes128_GCM, "GCM",
            new JcePasswordRecipientInfoGenerator(CMSAlgorithm.AES128_CBC, password).setProvider(BC), message);

        assertEquals("password recipient", "Hello, world!", Strings.fromByteArray(firstRecipient(encoded).getContent(
            new JcePasswordEnvelopedRecipient(password).setProvider(BC).setMinimumTagSize(64))));
        confirmTagSizeRefused("password recipient", encoded,
            new JcePasswordEnvelopedRecipient(password).setProvider(BC).setMinimumTagSize(128));

        // key agreement recipient, downgraded 64-bit GCM tag
        encoded = generateShortTagData(NISTObjectIdentifiers.id_aes128_GCM, "GCM",
            new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECDH_SHA1KDF, _origEcKP.getPrivate(), _origEcKP.getPublic(),
                CMSAlgorithm.AES128_WRAP).addRecipient(_reciEcCert).setProvider(BC), message);

        assertEquals("key agree recipient", "Hello, world!", Strings.fromByteArray(firstRecipient(encoded).getContent(
            new JceKeyAgreeEnvelopedRecipient(_reciEcKP.getPrivate()).setProvider(BC).setMinimumTagSize(64))));
        confirmTagSizeRefused("key agree recipient", encoded,
            new JceKeyAgreeEnvelopedRecipient(_reciEcKP.getPrivate()).setProvider(BC).setMinimumTagSize(128));

        // key transport recipient, downgraded 64-bit CCM tag
        encoded = generateShortTagData(NISTObjectIdentifiers.id_aes128_CCM, "CCM",
            new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC), message);

        confirmTagSizeRefused("CCM key trans recipient", encoded,
            new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC).setMinimumTagSize(128));
    }

    public void testHKDFMinimumTagSize()
        throws Exception
    {
        byte[] message = Strings.toByteArray("Hello, world!");
        SecretKey kek = CMSTestUtil.makeAESKey(128);

        // RFC 9709: the content algorithm is an outer id-alg-cek-hkdf-sha256 carrying the real AES-GCM
        // AlgorithmIdentifier, here with a 96-bit tag, in its parameters - the minimum applies to the inner one.
        byte[] encoded = generateHKDFTagData(NISTObjectIdentifiers.id_aes128_GCM, "GCM", 96,
            new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC), message);

        assertEquals(CMSObjectIdentifiers.id_alg_cek_hkdf_sha256.getId(), org.bouncycastle.asn1.cms.AuthEnvelopedData.getInstance(
            new CMSAuthEnvelopedData(encoded).toASN1Structure().getContent()).getAuthEncryptedContentInfo()
            .getContentEncryptionAlgorithm().getAlgorithm().getId());

        // a minimum at or below the actual tag size recovers as normal
        assertEquals("Hello, world!", Strings.fromByteArray(firstRecipient(encoded).getContent(
            new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC).setMinimumTagSize(96))));

        // a minimum above the tag size of the wrapped algorithm is refused with CMSTagLengthException
        try
        {
            firstRecipient(encoded).getContent(
                new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC).setMinimumTagSize(128));

            fail("content recovered under an RFC 9709 wrapped tag shorter than the configured minimum");
        }
        catch (CMSTagLengthException e)
        {
            assertEquals("AEAD tag size 96 bits below required minimum 128 bits", e.getMessage());
        }

        // KEK recipients, JCE and lightweight, RFC 9709 wrapped AES-GCM with a downgraded 64-bit tag
        encoded = generateHKDFTagData(NISTObjectIdentifiers.id_aes128_GCM, "GCM", 64,
            new JceKEKRecipientInfoGenerator(new byte[]{ 1, 2, 3, 4, 5 }, kek).setProvider(BC), message);

        assertEquals("HKDF KEK recipient", "Hello, world!", Strings.fromByteArray(firstRecipient(encoded).getContent(
            new JceKEKEnvelopedRecipient(kek).setProvider(BC).setMinimumTagSize(64))));
        confirmTagSizeRefused("HKDF KEK recipient", encoded,
            new JceKEKEnvelopedRecipient(kek).setProvider(BC).setMinimumTagSize(128));
        confirmTagSizeRefused("HKDF Bc KEK recipient", encoded,
            new BcKEKEnvelopedRecipient(new BcAESSymmetricKeyUnwrapper(new KeyParameter(kek.getEncoded())))
            {
                {
                    setMinimumTagSizeInBits(128);
                }
            });

        // key transport recipient, RFC 9709 wrapped AES-CCM with a downgraded 64-bit tag
        encoded = generateHKDFTagData(NISTObjectIdentifiers.id_aes128_CCM, "CCM", 64,
            new JceKeyTransRecipientInfoGenerator(_reciCert).setProvider(BC), message);

        confirmTagSizeRefused("HKDF CCM key trans recipient", encoded,
            new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC).setMinimumTagSize(128));
    }

    private static byte[] generateHKDFTagData(ASN1ObjectIdentifier contentAlgorithm, String paramsName,
        int tagSizeInBits, RecipientInfoGenerator recipientGen, byte[] message)
        throws Exception
    {
        AlgorithmParameters algParams = AlgorithmParameters.getInstance(paramsName, BC);
        algParams.init(new AEADParameterSpec(new byte[12], tagSizeInBits));

        OutputEncryptor enc = new JceCMSContentEncryptorBuilder(contentAlgorithm)
            .setEnableSha256HKdf(true)
            .setProvider(BC).setAlgorithmParameters(algParams).build();

        assertEquals(CMSObjectIdentifiers.id_alg_cek_hkdf_sha256, enc.getAlgorithmIdentifier().getAlgorithm());

        AlgorithmIdentifier contentAlgId = AlgorithmIdentifier.getInstance(enc.getAlgorithmIdentifier().getParameters());

        assertEquals(contentAlgorithm, contentAlgId.getAlgorithm());
        assertEquals(tagSizeInBits / 8, GCMParameters.getInstance(contentAlgId.getParameters()).getIcvLen());

        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();
        authGen.addRecipientInfoGenerator(recipientGen);

        return authGen.generate(new CMSProcessableByteArray(message), (OutputAEADEncryptor)enc).getEncoded();
    }

    private static byte[] generateShortTagData(ASN1ObjectIdentifier contentAlgorithm, String paramsName,
        RecipientInfoGenerator recipientGen, byte[] message)
        throws Exception
    {
        AlgorithmParameters algParams = AlgorithmParameters.getInstance(paramsName, BC);
        algParams.init(new AEADParameterSpec(new byte[12], 64));

        OutputEncryptor enc = new JceCMSContentEncryptorBuilder(contentAlgorithm)
            .setProvider(BC).setAlgorithmParameters(algParams).build();

        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();
        authGen.addRecipientInfoGenerator(recipientGen);

        return authGen.generate(new CMSProcessableByteArray(message), (OutputAEADEncryptor)enc).getEncoded();
    }

    private static RecipientInformation firstRecipient(byte[] encoded)
        throws Exception
    {
        return (RecipientInformation)new CMSAuthEnvelopedData(encoded).getRecipientInfos().getRecipients().iterator().next();
    }

    private static void confirmTagSizeRefused(String label, byte[] encoded, Recipient recipient)
        throws Exception
    {
        try
        {
            firstRecipient(encoded).getContent(recipient);

            fail(label + ": content recovered under a tag shorter than the configured minimum");
        }
        catch (CMSTagLengthException e)
        {
            assertTrue(label + ": unexpected message " + e.getMessage(), e.getMessage().indexOf("64 bits") >= 0);
        }
    }

    public void testSample1()
        throws Exception
    {
        CMSAuthEnvelopedData authEnv = new CMSAuthEnvelopedData(Sample1);

        RecipientInformationStore recipients = authEnv.getRecipientInfos();

        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        KeyFactory keyFact = KeyFactory.getInstance("RSA", "BC");

        PrivateKey privKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(Sample1Key));

        byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(privKey).setProvider(BC));

        assertEquals("auth-enveloped data", Strings.fromByteArray(recData));

        assertTrue(Arrays.areEqual(Sample1, authEnv.getEncoded()));
    }

    public void testGCM()
        throws Exception
    {
        if (!CMSTestUtil.isAeadAvailable())
        {
            return;
        }
        byte[] message = Strings.toByteArray("Hello, world!");
        OutputEncryptor candidate = new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_GCM).setProvider(BC).build();

        assertEquals(NISTObjectIdentifiers.id_aes128_GCM, candidate.getAlgorithmIdentifier().getAlgorithm());
        assertNotNull(GCMParameters.getInstance(candidate.getAlgorithmIdentifier().getParameters()));

        assertTrue(candidate instanceof OutputAEADEncryptor);

        OutputAEADEncryptor macProvider = (OutputAEADEncryptor)candidate;

        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();

        authGen.setAuthenticatedAttributeGenerator(new CMSAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
                throws CMSAttributeTableGenerationException
            {
                Hashtable<ASN1ObjectIdentifier, Attribute> attrs = new Hashtable<ASN1ObjectIdentifier, Attribute>();
                 Attribute testAttr = new Attribute(CMSAttributes.signingTime,
                     new DERSet(new Time(new Date())));
                 attrs.put(testAttr.getAttrType(), testAttr);
                 return new AttributeTable(attrs);
            }
        });

        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert));

        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message), macProvider);

        CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(authData.getEncoded());

        RecipientInformationStore recipients = encAuthData.getRecipientInfos();

        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        byte[] recData = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

        assertEquals("Hello, world!", Strings.fromByteArray(recData));
    }

    public void testGCMwithHKDF()
        throws Exception
    {
        if (!CMSTestUtil.isAeadAvailable())
        {
            return;
        }
        byte[] message = Strings.toByteArray("Hello, world!");
        OutputEncryptor candidate = new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_GCM)
            .setEnableSha256HKdf(true)
            .setProvider(BC).build();

        assertEquals(CMSObjectIdentifiers.id_alg_cek_hkdf_sha256, candidate.getAlgorithmIdentifier().getAlgorithm());

        AlgorithmIdentifier kdfParams = AlgorithmIdentifier.getInstance(candidate.getAlgorithmIdentifier().getParameters());

        assertEquals(NISTObjectIdentifiers.id_aes128_GCM, kdfParams.getAlgorithm());
        assertNotNull(GCMParameters.getInstance(kdfParams.getParameters()));

        assertTrue(candidate instanceof OutputAEADEncryptor);

        OutputAEADEncryptor macProvider = (OutputAEADEncryptor)candidate;

        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();

        authGen.setAuthenticatedAttributeGenerator(new CMSAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
                throws CMSAttributeTableGenerationException
            {
                Hashtable<ASN1ObjectIdentifier, Attribute> attrs = new Hashtable<ASN1ObjectIdentifier, Attribute>();
                 Attribute testAttr = new Attribute(CMSAttributes.signingTime,
                     new DERSet(new Time(new Date())));
                 attrs.put(testAttr.getAttrType(), testAttr);
                 return new AttributeTable(attrs);
            }
        });

        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert));

        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message), macProvider);

        CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(authData.getEncoded());

        RecipientInformationStore recipients = encAuthData.getRecipientInfos();

        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        byte[] recData = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));

        assertEquals("Hello, world!", Strings.fromByteArray(recData));
    }

    public void testCCM()
        throws Exception
    {
        if (!CMSTestUtil.isAeadAvailable())
        {
            return;
        }
        byte[] message = Strings.toByteArray("Hello, world!");
        OutputEncryptor candidate = new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_CCM).setProvider(BC).build();

        assertEquals(NISTObjectIdentifiers.id_aes128_CCM, candidate.getAlgorithmIdentifier().getAlgorithm());
        assertNotNull(GCMParameters.getInstance(candidate.getAlgorithmIdentifier().getParameters()));

        assertTrue(candidate instanceof OutputAEADEncryptor);

        OutputAEADEncryptor macProvider = (OutputAEADEncryptor)candidate;

        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();

        authGen.setAuthenticatedAttributeGenerator(new CMSAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
                throws CMSAttributeTableGenerationException
            {
                Hashtable<ASN1ObjectIdentifier, Attribute> attrs = new Hashtable<ASN1ObjectIdentifier, Attribute>();
                 Attribute testAttr = new Attribute(CMSAttributes.signingTime,
                     new DERSet(new Time(new Date())));
                 attrs.put(testAttr.getAttrType(), testAttr);
                 return new AttributeTable(attrs);
            }
        });

        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert));

        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message), macProvider);

        CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(authData.getEncoded());

        RecipientInformationStore recipients = encAuthData.getRecipientInfos();

        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        byte[] recData = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));
        assertTrue(java.util.Arrays.equals(authData.getMac(), recipient.getMac()));
        assertEquals("Hello, world!", Strings.fromByteArray(recData));
    }

    public void testCCMwithHKDF()
        throws Exception
    {
        if (!CMSTestUtil.isAeadAvailable())
        {
            return;
        }
        byte[] message = Strings.toByteArray("Hello, world!");
        OutputEncryptor candidate = new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_CCM)
                                            .setEnableSha256HKdf(true).setProvider(BC).build();

        assertEquals(CMSObjectIdentifiers.id_alg_cek_hkdf_sha256, candidate.getAlgorithmIdentifier().getAlgorithm());

        AlgorithmIdentifier kdfParams = AlgorithmIdentifier.getInstance(candidate.getAlgorithmIdentifier().getParameters());

        assertEquals(NISTObjectIdentifiers.id_aes128_CCM, kdfParams.getAlgorithm());
        assertNotNull(GCMParameters.getInstance(kdfParams.getParameters()));

        assertTrue(candidate instanceof OutputAEADEncryptor);

        OutputAEADEncryptor macProvider = (OutputAEADEncryptor)candidate;

        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();

        authGen.setAuthenticatedAttributeGenerator(new CMSAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
                throws CMSAttributeTableGenerationException
            {
                Hashtable<ASN1ObjectIdentifier, Attribute> attrs = new Hashtable<ASN1ObjectIdentifier, Attribute>();
                 Attribute testAttr = new Attribute(CMSAttributes.signingTime,
                     new DERSet(new Time(new Date())));
                 attrs.put(testAttr.getAttrType(), testAttr);
                 return new AttributeTable(attrs);
            }
        });

        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert));

        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message), macProvider);

        CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(authData.getEncoded());

        RecipientInformationStore recipients = encAuthData.getRecipientInfos();

        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        byte[] recData = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));
        assertTrue(java.util.Arrays.equals(authData.getMac(), recipient.getMac()));
        assertEquals("Hello, world!", Strings.fromByteArray(recData));
    }

    public void testBcCCM()
        throws Exception
    {
        byte[] message = Strings.toByteArray("Hello, world!");
        OutputEncryptor candidate = new BcCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_CCM).build();

        assertEquals(NISTObjectIdentifiers.id_aes128_CCM, candidate.getAlgorithmIdentifier().getAlgorithm());
        assertNotNull(GCMParameters.getInstance(candidate.getAlgorithmIdentifier().getParameters()));

        assertTrue(candidate instanceof OutputAEADEncryptor);

        OutputAEADEncryptor macProvider = (OutputAEADEncryptor)candidate;

        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();

        authGen.setAuthenticatedAttributeGenerator(new CMSAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
                throws CMSAttributeTableGenerationException
            {
                Hashtable<ASN1ObjectIdentifier, Attribute> attrs = new Hashtable<ASN1ObjectIdentifier, Attribute>();
                 Attribute testAttr = new Attribute(CMSAttributes.signingTime,
                     new DERSet(new Time(new Date())));
                 attrs.put(testAttr.getAttrType(), testAttr);
                 return new AttributeTable(attrs);
            }
        });

        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert));

        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message), macProvider);

        CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(authData.getEncoded());

        RecipientInformationStore recipients = encAuthData.getRecipientInfos();

        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        if (System.getProperty("java.version").indexOf("1.5.") < 0)
        {
            byte[] recData = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));
            assertTrue(java.util.Arrays.equals(authData.getMac(), recipient.getMac()));
            assertEquals("Hello, world!", Strings.fromByteArray(recData));
        }
    }

    public void testBcAttributes()
        throws Exception
    {
        byte[] message = Strings.toByteArray("Hello, world!");
        OutputEncryptor candidate = new BcCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes128_GCM).build();

        assertEquals(NISTObjectIdentifiers.id_aes128_GCM, candidate.getAlgorithmIdentifier().getAlgorithm());
        assertNotNull(GCMParameters.getInstance(candidate.getAlgorithmIdentifier().getParameters()));

        assertTrue(candidate instanceof OutputAEADEncryptor);

        OutputAEADEncryptor macProvider = (OutputAEADEncryptor)candidate;

        CMSAuthEnvelopedDataGenerator authGen = new CMSAuthEnvelopedDataGenerator();

        authGen.setAuthenticatedAttributeGenerator(new CMSAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
                throws CMSAttributeTableGenerationException
            {
                Hashtable<ASN1ObjectIdentifier, Attribute> attrs = new Hashtable<ASN1ObjectIdentifier, Attribute>();
                 Attribute testAttr = new Attribute(CMSAttributes.signingTime,
                     new DERSet(new Time(new Date())));
                 attrs.put(testAttr.getAttrType(), testAttr);
                 return new AttributeTable(attrs);
            }
        });

        authGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(_reciCert));
        
        CMSAuthEnvelopedData authData = authGen.generate(new CMSProcessableByteArray(message), macProvider);

        CMSAuthEnvelopedData encAuthData = new CMSAuthEnvelopedData(authData.getEncoded());

        RecipientInformationStore recipients = encAuthData.getRecipientInfos();

        RecipientInformation recipient = (RecipientInformation)recipients.getRecipients().iterator().next();

        if (System.getProperty("java.version").indexOf("1.5.") < 0)
        {
            byte[] recData = recipient.getContent(new JceKeyTransAuthEnvelopedRecipient(_reciKP.getPrivate()).setProvider(BC));
                                    
            assertEquals("Hello, world!", Strings.fromByteArray(recData));
        }
    }
}