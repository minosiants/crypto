package chapter3;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class JcaUtils
{
    /**
     * Return a digest computed over data using the passed in algorithm
     * digestName.
     *
     * @param digestName the name of the digest algorithm.
     * @param data the input for the digest function.
     * @return the computed message digest.
     */
    public static byte[] computeDigest(String digestName, byte[] data)
        throws NoSuchProviderException, NoSuchAlgorithmException
    {
        MessageDigest digest = MessageDigest.getInstance(digestName, "BC");

        digest.update(data);

        return digest.digest();
    }

    /**
     * Return a DigestCalculator for the passed in algorithm digestName.
     *
     * @param digestName the name of the digest algorithm.
     * @return a DigestCalculator for the digestName.
     */
    public static DigestCalculator createDigestCalculator(String digestName)
        throws OperatorCreationException
    {
        DigestAlgorithmIdentifierFinder algFinder =
                                  new DefaultDigestAlgorithmIdentifierFinder();
        DigestCalculatorProvider        digCalcProv =
            new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();

        return digCalcProv.get(algFinder.find(digestName));
    }
}
