package chapter5;

import java.math.BigInteger;

/**
 * A basic calculator for Lagrangian weights for a given number of peers in a
 * given field.
 */
public class LagrangeWeightCalculator
{
    private final int numberOfPeers;
    private final BigInteger field;
    private final BigInteger[] alphas;

    /**
     * Construct a calculator over the specified field to calculate weights for
     * use to process secrets shared among the specified number of peers
     *
     * @param numberOfPeers the number of peers among which the secret is shared
     * @param field the group's field.
     */
    public LagrangeWeightCalculator(int numberOfPeers, BigInteger field)
    {
        this.numberOfPeers = numberOfPeers;
        this.field = field;

        this.alphas = new BigInteger[numberOfPeers];

        for (int i = 0; i < numberOfPeers; i++)
        {
            alphas[i] = BigInteger.valueOf(i + 1);
        }
    }

    /**
     * Computes the Lagrange weights used for interpolation to reconstruct the
     * shared secret.
     *
     * @param activePeers an ordered array of peers available, entries are null
     *                    if no peer present.
     * @return the Lagrange weights
     */
    public BigInteger[] computeWeights(Object[] activePeers)
    {
        BigInteger[] weights = new BigInteger[numberOfPeers];

        for (int i = 0; i < numberOfPeers; i++)
        {
            if (activePeers[i] != null)
            {
                BigInteger numerator = BigInteger.ONE;
                BigInteger denominator = BigInteger.ONE;

                for (int peerIndex = 0; peerIndex < numberOfPeers; peerIndex++)
                {
                    if (peerIndex != i && activePeers[peerIndex] != null)
                    {
                        numerator = numerator.multiply(alphas[peerIndex])
                                             .mod(field);
                        denominator = denominator.multiply(alphas[peerIndex]
                                                .subtract(alphas[i]).mod(field))
                                                .mod(field);
                    }
                }

                weights[i] = numerator.multiply(denominator.modInverse(field))
                                          .mod(field);
            }
        }

        return weights;
    }
}
