package chapter2;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * A simple example of AES in CBC mode with block aligned padding.
 */
public class CBCPadExample
{
    public static void main(String[] args)
        throws Exception
    {
        byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");

        byte[] input = Hex.decode("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7"
                                + "a0a1a2a3a4a5a6a7a0");

        System.out.println("input    : " + Hex.toHexString(input));

        byte[] iv = Hex.decode("9f741fdb5d8845bdb48a94394e84f8a3");

        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        byte[] output = cipher.doFinal(input);

        System.out.println("encrypted: " + Hex.toHexString(output));

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        byte[] finalOutput = new byte[cipher.getOutputSize(output.length)];

        int len = cipher.update(output, 0, output.length, finalOutput, 0);

        len += cipher.doFinal(finalOutput, len);

        System.out.println("decrypted: "
                 + Hex.toHexString(Arrays.copyOfRange(finalOutput, 0, len)));
    }
}
