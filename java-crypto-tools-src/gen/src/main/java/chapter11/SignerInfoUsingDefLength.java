package chapter11;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.cms.SignerInformation;

/**
 * Override for SignerInformation to stop DER sorting of the signed attributes
 * in signature evaluation.
 */
public class SignerInfoUsingDefLength
    extends SignerInformation
{
    protected SignerInfoUsingDefLength(SignerInformation baseInfo)
    {
        super(baseInfo);
    }

    /**
     * Override to allow the encoded attributes to be returned as they are
     * in the SignerInfo.
     *
     * @return the signed attributes as a definite length encoding.
     * @throws IOException in case of an encoding error.
     */
    public byte[] getEncodedSignedAttributes()
        throws IOException
    {
        return signedAttributeSet.getEncoded(ASN1Encoding.DL);
    }
}
