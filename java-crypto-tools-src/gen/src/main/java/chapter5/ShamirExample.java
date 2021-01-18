package chapter5;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

/**
 * Simple example of use of the ShamirSecretSplitter and
 * LagrangeWeightCalculator for the splitting and recovery of a BigInteger
 * secret.
 */
public class ShamirExample
{
    // recover the shared secret.
    // Note: we use the position of the share in the activeShares array to
    // determine its index value for the f(i) function.
    static BigInteger recoverSecret(BigInteger field, BigInteger[] activeShares)
    {
        LagrangeWeightCalculator lagrangeWeightCalculator =
                       new LagrangeWeightCalculator(activeShares.length, field);

        BigInteger[] weights =
                       lagrangeWeightCalculator.computeWeights(activeShares);

        // weighting
        int index = 0;
        while (weights[index] == null)
        {
            index++;
        }
        BigInteger weightedValue = activeShares[index]
                                          .multiply(weights[index]).mod(field);
        for (int i = index + 1; i < weights.length; i++)
        {
            if (weights[i] != null)
            {
                weightedValue = weightedValue.add(
                    activeShares[i].multiply(weights[i]).mod(field)).mod(field);
            }
        }

        return weightedValue;
    }

    // Create a new shares array with just the ones listed in index present and
    // the rest of the entries null.
    private static BigInteger[] copyShares(int[] indexes, BigInteger[] shares)
    {
        // note: the activeShares array  needs to be the same size as the shares
        // array. The order of the shares is important.
        BigInteger[] activeShares = new BigInteger[shares.length];

        for (int i = 0; i != indexes.length; i++)
        {
            activeShares[indexes[i]] = shares[indexes[i]];
        }

        return activeShares;
    }

    /**
     * Create a shared secret and generate a polynomial for the prime field p
     * to split it over, do the split and then show a recovery of the secret.
     */
    public static void main(String[] args)
    {
        SecureRandom random = new SecureRandom();
        BigInteger p = new BigInteger(384, 256, random);
        int numberOfPeers = 10;
        int threshold = 4;

        byte[] secretKey = new byte[32];

        random.nextBytes(secretKey);

        BigInteger secretValue = new BigInteger(1, secretKey);

        ShamirSecretSplitter splitter =
                    new ShamirSecretSplitter(
                            numberOfPeers, threshold, p, random);

        SplitSecret secret = splitter.split(secretValue);

        BigInteger[] s = secret.getShares();

        BigInteger recoveredSecret = recoverSecret(p,
                                       copyShares(new int[] { 1, 2, 3, 7 }, s));

        System.err.println(Hex.toHexString(
            BigIntegers.asUnsignedByteArray(secretValue)));
        System.err.println(Hex.toHexString(
            BigIntegers.asUnsignedByteArray(recoveredSecret))
            + ", matched: " + secretValue.equals(recoveredSecret));
    }
}
