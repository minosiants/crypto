package chapter3;

import java.math.BigInteger;
import java.security.MessageDigest;

import org.bouncycastle.util.BigIntegers;

/**
 * Example code building and using a MerkleTree.
 */
public class MerkleExample
{
    public static void main(String[] args)
        throws Exception
    {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        MerkleTree tree = new MerkleTree(sha256);

        // populate the tree with data.
        for (int i = 0; i != 1000; i += 2)
        {
            tree.insert(BigIntegers.asUnsignedByteArray(BigInteger.valueOf(i)));
        }

        for (int i = 1001; i > 0; i -= 2)
        {
            tree.insert(BigIntegers.asUnsignedByteArray(BigInteger.valueOf(i)));
        }

        // generate an audit path for a value of interest.
        byte[] value = BigIntegers.asUnsignedByteArray(BigInteger.valueOf(239));

        AuditPath path = tree.generateAuditPath(value);

        System.out.println("Value on path: " + path.isMatched(sha256, value));

        // try using the path to match a different value.
        value = BigIntegers.asUnsignedByteArray(BigInteger.valueOf(100));

        System.out.println("Value on path: " + path.isMatched(sha256, value));
    }
}

