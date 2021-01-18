package chapter5;

import java.math.BigInteger;

/**
 * A holder for shares from a split secret for a BigInteger value.
 */
public class SplitSecret
{
    private final BigInteger[] shares;

    /**
     * Base constructor.
     *
     * @param shares the shares the initial secret has been split into.
     */
    public SplitSecret(BigInteger[] shares)
    {
        this.shares = shares.clone();
    }

    /**
     * Return a copy of the shares associated with the split secret.
     *
     * @return an array of the secret's shares.
     */
    public BigInteger[] getShares()
    {
        return shares.clone();
    }
}
