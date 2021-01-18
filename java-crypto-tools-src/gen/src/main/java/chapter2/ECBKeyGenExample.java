package chapter2;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;

public class ECBKeyGenExample
{
    public static void main(String[] args)
        throws Exception
    {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");

        SecretKey key = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", "BC");

        byte[] input = Hex.decode("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7");

        System.out.println("input    : " + Hex.toHexString(input));

        cipher.init(Cipher.ENCRYPT_MODE, key);

        System.out.println("encrypted: " + Hex.toHexString(cipher.doFinal(input)));

        cipher.init(Cipher.DECRYPT_MODE, key);

        System.out.println("decrypted: " + Hex.toHexString(input));

         cipher.init(Cipher.ENCRYPT_MODE, key);
    }
}
