package org.bouncycastle.cms.jcajce;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.CCMParameters;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSTagLengthException;
import org.bouncycastle.jcajce.util.AlgorithmParametersUtils;
import org.bouncycastle.jcajce.util.AnnotatedPrivateKey;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorCreationException;

class CMSUtils
{
    private static final Set mqvAlgs = new HashSet();
    private static final Set ecAlgs = new HashSet();
    private static final Set gostAlgs = new HashSet();
    private static final Map asymmetricWrapperAlgNames = new HashMap();
    private static final Set gcmAlgs = new HashSet();
    private static final Set ccmAlgs = new HashSet();

    private static Map<ASN1ObjectIdentifier,String> wrapAlgNames = new HashMap();

    static
    {
       wrapAlgNames.put(CMSAlgorithm.AES128_WRAP, "AESWRAP");
       wrapAlgNames.put(CMSAlgorithm.AES192_WRAP, "AESWRAP");
       wrapAlgNames.put(CMSAlgorithm.AES256_WRAP, "AESWRAP");
    }

    static
    {
        mqvAlgs.add(X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme);
        mqvAlgs.add(SECObjectIdentifiers.mqvSinglePass_sha224kdf_scheme);
        mqvAlgs.add(SECObjectIdentifiers.mqvSinglePass_sha256kdf_scheme);
        mqvAlgs.add(SECObjectIdentifiers.mqvSinglePass_sha384kdf_scheme);
        mqvAlgs.add(SECObjectIdentifiers.mqvSinglePass_sha512kdf_scheme);

        ecAlgs.add(X9ObjectIdentifiers.dhSinglePass_cofactorDH_sha1kdf_scheme);
        ecAlgs.add(X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme);
        ecAlgs.add(SECObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme);

        gostAlgs.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_ESDH);
        gostAlgs.add(CryptoProObjectIdentifiers.gostR3410_2001);
        gostAlgs.add(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256);
        gostAlgs.add(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512);
        gostAlgs.add(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256);
        gostAlgs.add(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512);

        asymmetricWrapperAlgNames.put(PKCSObjectIdentifiers.rsaEncryption, "RSA/ECB/PKCS1Padding");
        asymmetricWrapperAlgNames.put(OIWObjectIdentifiers.elGamalAlgorithm, "Elgamal/ECB/PKCS1Padding");
        asymmetricWrapperAlgNames.put(PKCSObjectIdentifiers.id_RSAES_OAEP, "RSA/ECB/OAEPPadding");
        asymmetricWrapperAlgNames.put(CryptoProObjectIdentifiers.gostR3410_2001, "ECGOST3410");
        asymmetricWrapperAlgNames.put(ISOIECObjectIdentifiers.id_kem_rsa, "RSA-KTS-KEM-KWS");

        gcmAlgs.add(NISTObjectIdentifiers.id_aes128_GCM);
        gcmAlgs.add(NISTObjectIdentifiers.id_aes192_GCM);
        gcmAlgs.add(NISTObjectIdentifiers.id_aes256_GCM);

        ccmAlgs.add(NISTObjectIdentifiers.id_aes128_CCM);
        ccmAlgs.add(NISTObjectIdentifiers.id_aes192_CCM);
        ccmAlgs.add(NISTObjectIdentifiers.id_aes256_CCM);
    }

    static boolean isMQV(ASN1ObjectIdentifier algorithm)
    {
        return mqvAlgs.contains(algorithm);
    }

    static boolean isEC(ASN1ObjectIdentifier algorithm)
    {
        return ecAlgs.contains(algorithm);
    }

    static boolean isGOST(ASN1ObjectIdentifier algorithm)
    {
        return gostAlgs.contains(algorithm);
    }

    static boolean isRFC2631(ASN1ObjectIdentifier algorithm)
    {
        return algorithm.equals(PKCSObjectIdentifiers.id_alg_ESDH) || algorithm.equals(PKCSObjectIdentifiers.id_alg_SSDH);
    }

    static String getWrapAlgorithmName(ASN1ObjectIdentifier oid)
    {
        return (String)wrapAlgNames.get(oid);
    }

    static PrivateKey cleanPrivateKey(PrivateKey key)
    {
        if (key instanceof AnnotatedPrivateKey)
        {
            return cleanPrivateKey(((AnnotatedPrivateKey)key).getKey());
        }
        else
        {
            return key;
        }
    }

    static IssuerAndSerialNumber getIssuerAndSerialNumber(X509Certificate cert)
        throws CertificateEncodingException
    {
        Certificate certStruct = Certificate.getInstance(cert.getEncoded());

        return new IssuerAndSerialNumber(certStruct.getIssuer(), cert.getSerialNumber());
    }

    static byte[] getSubjectKeyId(X509Certificate cert)
    {
        byte[] ext = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());

        if (ext != null)
        {
            return ASN1OctetString.getInstance(ASN1OctetString.getInstance(ext).getOctets()).getOctets();
        }
        else
        {
            return null;
        }
    }

    static EnvelopedDataHelper createContentHelper(Provider provider)
    {
        if (provider != null)
        {
            return new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));
        }
        else
        {
            return new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
        }
    }

    static EnvelopedDataHelper createContentHelper(String providerName)
    {
        if (providerName != null)
        {
            return new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));
        }
        else
        {
            return new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
        }
    }

    static ASN1Encodable extractParameters(AlgorithmParameters params)
        throws CMSException
    {
        try
        {
            return AlgorithmParametersUtils.extractParameters(params);
        }
        catch (IOException e)
        {
            throw new CMSException("cannot extract parameters: " + e.getMessage(), e);
        }
    }

    static void loadParameters(AlgorithmParameters params, ASN1Encodable sParams)
        throws CMSException
    {
        try
        {
            AlgorithmParametersUtils.loadParameters(params, sParams);
        }
        catch (IOException e)
        {
            throw new CMSException("error encoding algorithm parameters.", e);
        }
    }

    static Key getJceKey(GenericKey key)
    {
        if (key.getRepresentation() instanceof Key)
        {
            return (Key)key.getRepresentation();
        }

        if (key.getRepresentation() instanceof byte[])
        {
            return new SecretKeySpec((byte[])key.getRepresentation(), "ENC");
        }

        throw new IllegalArgumentException("unknown generic key type");
    }

    static Cipher createAsymmetricWrapper(JcaJceHelper helper, ASN1ObjectIdentifier algorithm, Map extraAlgNames)
        throws OperatorCreationException
    {
        try
        {
            String cipherName = null;

            if (!extraAlgNames.isEmpty())
            {
                cipherName = (String)extraAlgNames.get(algorithm);
            }

            if (cipherName == null)
            {
                cipherName = (String)asymmetricWrapperAlgNames.get(algorithm);
            }

            if (cipherName != null)
            {
                try
                {
                    // this is reversed as the Sun policy files now allow unlimited strength RSA
                    return helper.createCipher(cipherName);
                }
                catch (NoSuchAlgorithmException e)
                {
                    // try alternate for RSA
                    if (cipherName.equals("RSA/ECB/PKCS1Padding"))
                    {
                        try
                        {
                            return helper.createCipher("RSA/NONE/PKCS1Padding");
                        }
                        catch (NoSuchAlgorithmException ex)
                        {
                            // Ignore
                        }
                    }
                    // Ignore
                }
            }

            return helper.createCipher(algorithm.getId());
        }
        catch (GeneralSecurityException e)
        {
            throw new OperatorCreationException("cannot create cipher: " + e.getMessage(), e);
        }
    }

    public static int getKekSize(ASN1ObjectIdentifier symWrapAlg)
    {
        // TODO: add table
        if (symWrapAlg.equals(CMSAlgorithm.AES256_WRAP))
        {
            return 32;
        }
        else if (symWrapAlg.equals(CMSAlgorithm.AES128_WRAP))
        {
            return  16;
        }
        else if (symWrapAlg.equals(CMSAlgorithm.AES192_WRAP))
        {
            return  24;
        }
        else
        {
            throw new IllegalArgumentException("unknown wrap algorithm");
        }
    }

    /**
     * Return the content-encryption algorithm an EncryptedContentInfo actually names, resolving the
     * RFC 9709 id-alg-cek-hkdf-sha256 wrapper to the AlgorithmIdentifier carried in its parameters.
     * <p>
     * org.bouncycastle.cms.bc.CMSUtils carries the same method for the lightweight side of the package,
     * which cannot see this one - keep the two in step.
     *
     * @param contentAlgorithm the content-encryption AlgorithmIdentifier taken from the message.
     * @return the algorithm the content is encrypted under.
     * @throws CMSException if the key derivation carries no readable content-encryption algorithm.
     */
    static AlgorithmIdentifier getContentEncryptionAlgorithm(AlgorithmIdentifier contentAlgorithm)
        throws CMSException
    {
        if (!CMSObjectIdentifiers.id_alg_cek_hkdf_sha256.equals(contentAlgorithm.getAlgorithm()))
        {
            return contentAlgorithm;
        }

        ASN1Encodable params = contentAlgorithm.getParameters();

        if (params == null)
        {
            throw new CMSException("RFC 9709 key derivation names no content-encryption algorithm");
        }

        try
        {
            return AlgorithmIdentifier.getInstance(params);
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException("unable to read RFC 9709 content-encryption algorithm: " + e.getMessage(), e);
        }
    }

    /**
     * Return the length, in octets, of the AEAD authentication tag (ICV) carried by a content-encryption
     * AlgorithmIdentifier.
     *
     * @param contentAlgorithm the content-encryption AlgorithmIdentifier.
     * @return the tag length in octets, 0 if the AEAD parameters cannot be interpreted, or -1 when the
     * algorithm is not recognised.
     */
    static int getAEADMacLength(AlgorithmIdentifier contentAlgorithm)
    {
        ASN1ObjectIdentifier algorithm = contentAlgorithm.getAlgorithm();

        try
        {
            if (gcmAlgs.contains(algorithm))
            {
                return Math.max(0, GCMParameters.getInstance(contentAlgorithm.getParameters()).getIcvLen());
            }
            if (ccmAlgs.contains(algorithm))
            {
                return Math.max(0, CCMParameters.getInstance(contentAlgorithm.getParameters()).getIcvLen());
            }
        }
        catch (RuntimeException e)
        {
            // malformed or absent AEAD parameters - report no usable tag so a minimum fails closed.
            return 0;
        }

        return -1;
    }

    /**
     * Refuse an AEAD content algorithm whose authentication tag is shorter than the configured
     * minimum. A no-op when no minimum is set or when the content algorithm is not AEAD. An RFC 9709
     * key-derivation wrapper is resolved to the content-encryption algorithm it carries first, so the
     * minimum is applied to the algorithm the content is actually encrypted under.
     *
     * @param minimumTagSizeInBits the minimum acceptable tag size in bits, 0 or less for no minimum.
     * @param contentAlgorithm the content-encryption AlgorithmIdentifier (carries the AEAD ICV length).
     * @throws CMSTagLengthException if the tag size is below the configured minimum.
     * @throws CMSException if an RFC 9709 key derivation carries no readable content-encryption algorithm.
     */
    static void checkTagSize(int minimumTagSizeInBits, AlgorithmIdentifier contentAlgorithm)
        throws CMSException
    {
        if (minimumTagSizeInBits > 0)
        {
            // RFC 9709: the EncryptedContentInfo may carry an outer id-alg-cek-hkdf-sha256 wrapping the
            // real inner content-encryption AlgorithmIdentifier - it is the inner one the tag size is read from.
            int macLenOctets = getAEADMacLength(getContentEncryptionAlgorithm(contentAlgorithm));

            if (macLenOctets >= 0 && (long)macLenOctets * 8 < minimumTagSizeInBits)
            {
                throw new CMSTagLengthException("AEAD tag size " + ((long)macLenOctets * 8)
                    + " bits below required minimum " + minimumTagSizeInBits + " bits");
            }
        }
    }
}
