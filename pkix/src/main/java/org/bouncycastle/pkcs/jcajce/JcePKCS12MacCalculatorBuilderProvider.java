package org.bouncycastle.pkcs.jcajce;

import java.io.OutputStream;
import java.math.BigInteger;
import java.security.Provider;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.PKCS12Key;
import org.bouncycastle.jcajce.io.MacOutputStream;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.PKCS12MacCalculatorBuilderProvider;
import org.bouncycastle.util.Properties;

public class JcePKCS12MacCalculatorBuilderProvider
    implements PKCS12MacCalculatorBuilderProvider
{
    // Upper bound on the PKCS#12 iteration count honoured on MAC verification (default 5,000,000).
    private static final String PKCS12_MAX_IT_COUNT = "org.bouncycastle.pkcs12.max_it_count";
    private static final BigInteger DEFAULT_MAX_IT_COUNT = BigInteger.valueOf(5000000);

    private JcaJceHelper helper = new DefaultJcaJceHelper();

    public JcePKCS12MacCalculatorBuilderProvider()
    {
    }

    public JcePKCS12MacCalculatorBuilderProvider setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public JcePKCS12MacCalculatorBuilderProvider setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    public PKCS12MacCalculatorBuilder get(final AlgorithmIdentifier algorithmIdentifier)
    {
        return new PKCS12MacCalculatorBuilder()
        {
            public MacCalculator build(final char[] password)
                throws OperatorCreationException
            {
                final PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(algorithmIdentifier.getParameters());

                try
                {
                    final ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();

                    final Mac mac = helper.createMac(algorithm.getId());

                    PBEParameterSpec defParams = new PBEParameterSpec(pbeParams.getIV(), validateIterationCount(pbeParams.getIterations()));

                    final SecretKey key = new PKCS12Key(password);

                    mac.init(key, defParams);

                    return new MacCalculator()
                    {
                        public AlgorithmIdentifier getAlgorithmIdentifier()
                        {
                            return new AlgorithmIdentifier(algorithm, pbeParams);
                        }

                        public OutputStream getOutputStream()
                        {
                            return new MacOutputStream(mac);
                        }

                        public byte[] getMac()
                        {
                            return mac.doFinal();
                        }

                        public GenericKey getKey()
                        {
                            return new GenericKey(getAlgorithmIdentifier(), key.getEncoded());
                        }
                    };
                }
                catch (Exception e)
                {
                    throw new OperatorCreationException("unable to create MAC calculator: " + e.getMessage(), e);
                }
            }

            public AlgorithmIdentifier getDigestAlgorithmIdentifier()
            {
                return new AlgorithmIdentifier(algorithmIdentifier.getAlgorithm(), DERNull.INSTANCE);
            }
        };
    }

    // The MAC key is derived from the wire-supplied iteration count before the MAC can be checked,
    // so the count is bounded (as the PKCS#12 keystore does) to cap a pre-authentication CPU DoS.
    private static int validateIterationCount(BigInteger ic)
    {
        if (ic.signum() < 0)
        {
            throw new IllegalStateException("negative iteration count found");
        }
        if (ic.bitLength() > 31)
        {
            throw new IllegalStateException("iteration counts >= 2^31 are not suppported");
        }

        BigInteger max = Properties.asBigInteger(PKCS12_MAX_IT_COUNT);
        if (max == null)
        {
            max = DEFAULT_MAX_IT_COUNT;
        }

        if (ic.compareTo(max) > 0)
        {
            throw new IllegalStateException("iteration count " + ic + " greater than " + max);
        }

        return ic.intValue();
    }
}
