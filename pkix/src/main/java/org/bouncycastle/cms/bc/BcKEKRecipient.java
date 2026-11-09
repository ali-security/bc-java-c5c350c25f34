package org.bouncycastle.cms.bc;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KEKRecipient;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.SymmetricKeyUnwrapper;
import org.bouncycastle.operator.bc.BcSymmetricKeyUnwrapper;

public abstract class BcKEKRecipient
    implements KEKRecipient
{
    private SymmetricKeyUnwrapper unwrapper;
    private int minimumTagSizeInBits = 0;

    public BcKEKRecipient(BcSymmetricKeyUnwrapper unwrapper)
    {
        this.unwrapper = unwrapper;
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

    protected CipherParameters extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        CMSUtils.checkTagSize(minimumTagSizeInBits, contentEncryptionAlgorithm);

        try
        {
            return CMSUtils.getBcKey(unwrapper.generateUnwrappedKey(contentEncryptionAlgorithm, encryptedContentEncryptionKey));
        }
        catch (OperatorException e)
        {
            throw new CMSException("exception unwrapping key: " + e.getMessage(), e);
        }
    }
}
