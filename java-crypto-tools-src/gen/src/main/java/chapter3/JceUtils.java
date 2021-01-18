package chapter3;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class JceUtils
{
    /**
     * Return a MAC computed over data using the passed in MAC algorithm
     * type algorithm.
     *
     * @param algorithm the name of the MAC algorithm.
     * @param key an appropriate secret key for the MAC algorithm.
     * @param data the input for the MAC function.
     * @return the computed MAC.
     */
    public static byte[] computeMac(String algorithm, SecretKey key, byte[] data)
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidKeyException
    {
        Mac mac = Mac.getInstance(algorithm, "BC");

        mac.init(key);

        mac.update(data);

        return mac.doFinal();
    }
}
