package org.bouncycastle.pkcs.test;

import java.math.BigInteger;
import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PBMAC1Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorProviderBuilder;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class PBETest
    extends TestCase
{
    private static final String PBE_MAX_ITERATION_COUNT = "org.bouncycastle.pbe.max_iteration_count";

    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testPBESHA256()
        throws Exception
    {
        MacCalculator pbCalculator = new JcePBMac1CalculatorBuilder("HmacSHA256", 256)
            .setIterationCount(1)
            .setSalt(Strings.toByteArray("salt"))
            .setPrf(JcePBMac1CalculatorBuilder.PRF_SHA256)
            .setProvider("BC").build("passwd".toCharArray());

        assertEquals("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc", Hex.toHexString((byte[])pbCalculator.getKey().getRepresentation()));

    }

    // A PBMAC1 protection algorithm whose PBKDF2 iteration count exceeds the PBE max iteration count
    // (default 10_000_000) must be rejected by the JCE PBMAC1 builder before running the KDF, not spin
    // PBKDF2 on the attacker-supplied count - a pre-auth CPU DoS on CMP PBMAC1 verify.
    public void testPbmac1IterationCountCapped()
        throws Exception
    {
        AlgorithmIdentifier prf = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, null);
        AlgorithmIdentifier protectionAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBMAC1,
            new PBMAC1Params(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, new PBKDF2Params("salt".getBytes(), 10000001, 32, prf)),
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, null)
            )
        );
        try
        {
            new JcePBMac1CalculatorProviderBuilder().setProvider(new BouncyCastleProvider())
                .build().get(protectionAlgorithm, "foobar123".toCharArray());
            fail("PBMAC1 iteration count above the cap should be rejected");
        }
        catch (OperatorCreationException e)
        {
            assertTrue("unexpected message: " + e.getMessage(),
                e.getMessage().indexOf("iteration count (10000001) greater than 10000000") >= 0);
        }
    }

    // The cap honours the org.bouncycastle.pbe.max_iteration_count property: a count at the
    // configured bound is still accepted, one above it is refused before deriving.
    public void testPbmac1IterationCountProperty()
        throws Exception
    {
        String old = System.getProperty(PBE_MAX_ITERATION_COUNT);
        System.setProperty(PBE_MAX_ITERATION_COUNT, "1000");
        try
        {
            MacCalculator calc = new JcePBMac1CalculatorProviderBuilder().setProvider("BC")
                .build().get(createPbmac1(1000, BigInteger.valueOf(32)), "foobar123".toCharArray());
            assertEquals("unexpected key length", 32, ((byte[])calc.getKey().getRepresentation()).length);

            try
            {
                new JcePBMac1CalculatorProviderBuilder().setProvider("BC")
                    .build().get(createPbmac1(1001, BigInteger.valueOf(32)), "foobar123".toCharArray());
                fail("PBMAC1 iteration count above the configured cap should be rejected");
            }
            catch (OperatorCreationException e)
            {
                assertTrue("unexpected message: " + e.getMessage(),
                    e.getMessage().indexOf("iteration count (1001) greater than 1000") >= 0);
            }
        }
        finally
        {
            if (old == null)
            {
                System.clearProperty(PBE_MAX_ITERATION_COUNT);
            }
            else
            {
                System.setProperty(PBE_MAX_ITERATION_COUNT, old);
            }
        }
    }

    // A PBMAC1 keyLength is attacker-controlled and read before any password/MAC check, so an
    // oversized value must be rejected before the derivation it sizes runs, not after.
    public void testPbmac1KeyLengthBound()
        throws Exception
    {
        PBMAC1Params pbmac1Params = new PBMAC1Params(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2,
                new PBKDF2Params(Strings.toByteArray("saltsalt"), 1, 2000, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256))),
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512));

        JcePBMac1CalculatorBuilder builder = new JcePBMac1CalculatorBuilder(pbmac1Params).setProvider("BC");

        try
        {
            builder.build("passwd".toCharArray());
            fail("no exception");
        }
        catch (OperatorCreationException e)
        {
            assertTrue("unexpected message: " + e.getMessage(),
                e.getMessage().indexOf("keyLength 2000 greater than 1024") >= 0);
        }
    }

    // The same bound applies on the CMP PBMAC1 verification path; a keyLength large enough to
    // overflow the keyLength * 8 bit-count conversion must be refused rather than reach the KDF.
    public void testPbmac1KeyLengthOverflow()
        throws Exception
    {
        BigInteger[] hostile = { BigInteger.valueOf(1025), BigInteger.valueOf(268435456), BigInteger.ONE.shiftLeft(40) };

        for (int i = 0; i != hostile.length; i++)
        {
            try
            {
                new JcePBMac1CalculatorProviderBuilder().setProvider("BC")
                    .build().get(createPbmac1(1, hostile[i]), "foobar123".toCharArray());
                fail("excessive PBMAC1 keyLength accepted: " + hostile[i]);
            }
            catch (OperatorCreationException e)
            {
                assertTrue("unexpected message: " + e.getMessage(),
                    e.getMessage().indexOf("keyLength " + hostile[i] + " greater than 1024") >= 0);
            }
        }
    }

    public void testPbmac1KeyLengthNotPositive()
        throws Exception
    {
        BigInteger[] hostile = { BigInteger.ZERO, BigInteger.valueOf(-8) };

        for (int i = 0; i != hostile.length; i++)
        {
            try
            {
                new JcePBMac1CalculatorProviderBuilder().setProvider("BC")
                    .build().get(createPbmac1(1, hostile[i]), "foobar123".toCharArray());
                fail("non-positive PBMAC1 keyLength accepted: " + hostile[i]);
            }
            catch (OperatorCreationException e)
            {
                assertTrue("unexpected message: " + e.getMessage(),
                    e.getMessage().indexOf("keyLength must be positive") >= 0);
            }
        }
    }

    // A keyLength at the bound is still honoured.
    public void testPbmac1KeyLengthAtBound()
        throws Exception
    {
        MacCalculator calc = new JcePBMac1CalculatorProviderBuilder().setProvider("BC")
            .build().get(createPbmac1(1, BigInteger.valueOf(1024)), "foobar123".toCharArray());

        assertEquals("unexpected key length", 1024, ((byte[])calc.getKey().getRepresentation()).length);
    }

    // Build the PBMAC1 parameters by hand, as an attacker supplied encoding would arrive, so that
    // keyLength values the PBKDF2Params constructors would not emit can be represented.
    private static AlgorithmIdentifier createPbmac1(int iterationCount, BigInteger keyLength)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DEROctetString(Strings.toByteArray("saltsalt")));
        v.add(new ASN1Integer(iterationCount));
        v.add(new ASN1Integer(keyLength));
        v.add(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256));

        return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBMAC1,
            new PBMAC1Params(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, PBKDF2Params.getInstance(new DERSequence(v))),
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256)));
    }
}
