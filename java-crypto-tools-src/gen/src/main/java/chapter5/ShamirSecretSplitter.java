package chapter5;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * A secret splitter based on Shamir's method.
 * <p>
 * Reference: Shamir, Adi (1979), "How to share a secret",
 * Communications of the ACM, 22 (11): 612–613.
 * </p>
 */
public class ShamirSecretSplitter
{
    private final int numberOfPeers;
    private final int k;
    private final BigInteger order;
    private final SecureRandom random;
    private final BigInteger[] alphas;
    private final BigInteger[][] alphasPow;

    /**
     * Creates a ShamirSecretSplitter instance over the specified field
     * to share secrets among the specified number of peers
     *
     * @param numberOfPeers the number of peers among which the secret is
     *                      shared.
     * @param threshold number of peers that must be available for secret
     *                  reconstruction.
     * @param field the prime field representing the group we are operating on.
     * @param random a source of randomness.
     */
    public ShamirSecretSplitter(
            int numberOfPeers, int threshold, BigInteger field,
            SecureRandom random)
    {
        this.numberOfPeers = numberOfPeers;
        this.k = threshold;
        this.order = field;
        this.random = random;

         // Pre-calculate powers for each peer.
        alphas = new BigInteger[numberOfPeers];
        alphasPow = new BigInteger[numberOfPeers][k];

        if (k > 1)
        {
            for (int i = 0; i < numberOfPeers; i++)
            {
                alphas[i] = alphasPow[i][1] = BigInteger.valueOf(i + 1);
                for (int degree = 2; degree < k; degree++)
                {
                    alphasPow[i][degree] = alphasPow[i][degree - 1]
                                                    .multiply(alphas[i]);
                }
            }
        }
        else
        {
            for (int i = 0; i < numberOfPeers; i++)
            {
                alphas[i] = BigInteger.valueOf(i + 1);
            }
        }
    }

    /**
     * Given the secret, generate random coefficients (except for a<sub>0</sub>
     * which is the secret) and compute the function for each privacy peer
     * (who is assigned a dedicated alpha). Coefficients are picked from (0,
     * fieldSize).
     *
     * @param secret the secret to be shared
     * @return the shares of the secret for each privacy peer
     */
    public SplitSecret split(BigInteger secret)
    {
        BigInteger[] shares = new BigInteger[numberOfPeers];
        BigInteger[] coefficients = new BigInteger[k];

        // D0: for each share
        for (int peerIndex = 0; peerIndex < numberOfPeers; peerIndex++)
        {
            shares[peerIndex] = secret;
        }

        coefficients[0] = secret;

        // D1 to DT: for each share
        for (int degree = 1; degree < k; degree++)
        {
            BigInteger coefficient = generateCoeff(order, random);

            coefficients[degree] = coefficient;

            for (int peerIndex = 0; peerIndex < numberOfPeers; peerIndex++)
            {
                shares[peerIndex] = shares[peerIndex].add(
                                      coefficient
                                         .multiply(alphasPow[peerIndex][degree])
                                         .mod(order)
                                    ).mod(order);
            }
        }

        return new SplitSecret(shares);
    }

    // Shamir's original paper actually gives the set [0, fieldSize) as the range
    // in which coefficients can be chosen, this isn't true for the highest
    // order term as it would have the effect of reducing the order of the
    // polynomial. We guard against this by using the set (0, fieldSize) and
    // so removing the chance of 0.
    private static BigInteger generateCoeff(BigInteger n, SecureRandom random)
    {
        int nBitLength = n.bitLength();
        BigInteger k = new BigInteger(nBitLength, random);

        while (k.equals(BigInteger.ZERO) || k.compareTo(n) >= 0)
        {
            k = new BigInteger(nBitLength, random);
        }

        return k;
    }
}
