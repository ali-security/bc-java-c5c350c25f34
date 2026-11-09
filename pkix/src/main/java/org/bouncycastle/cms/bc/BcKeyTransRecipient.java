package org.bouncycastle.cms.bc;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyTransRecipient;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.AsymmetricKeyUnwrapper;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.bc.BcRSAAsymmetricKeyUnwrapper;

public abstract class BcKeyTransRecipient
    implements KeyTransRecipient
{
    private AsymmetricKeyParameter recipientKey;
    private int minimumTagSizeInBits = 0;

    public BcKeyTransRecipient(AsymmetricKeyParameter recipientKey)
    {
        this.recipientKey = recipientKey;
    }

    /**
     * Set the minimum AEAD authentication tag size (in bits) this recipient will accept. When set, an
     * attempt to recover content whose AEAD content algorithm carries a shorter tag is rejected,
     * mitigating an attacker downgrading the tag to a weaker length.
     *
     * @param tagSizeInBits the minimum acceptable AEAD tag size, in bits.
     */
    protected final void setMinimumTagSizeInBits(int tagSizeInBits)
    {
        this.minimumTagSizeInBits = tagSizeInBits;
    }

    protected CipherParameters extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedEncryptionKey)
        throws CMSException
    {
        CMSUtils.checkTagSize(minimumTagSizeInBits, encryptedKeyAlgorithm);

        AsymmetricKeyUnwrapper unwrapper = new BcRSAAsymmetricKeyUnwrapper(keyEncryptionAlgorithm, recipientKey);

        try
        {
            return CMSUtils.getBcKey(unwrapper.generateUnwrappedKey(encryptedKeyAlgorithm, encryptedEncryptionKey));
        }
        catch (OperatorException e)
        {
            throw new CMSException("exception unwrapping key: " + e.getMessage(), e);
        }
    }
}
