package chapter1;

import java.security.MessageDigest;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * A simple application demonstrating the effect of provider precedence on
 * what is returned by a JVM.
 */
public class PrecedenceDemo
{
    public static void main(String[] args)
        throws Exception
    {
        // adds BC to the end of the precedence list
        Security.addProvider(new BouncyCastleProvider());

        System.out.println(MessageDigest.getInstance("SHA1")
                                        .getProvider().getName());

        System.out.println(MessageDigest.getInstance("SHA1", "BC")
                                        .getProvider().getName());
    }
}
