package chapter4;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import static chapter4.AEADUtils.createConstantKey;
import static chapter4.AEADUtils.gcmDecrypt;

/**
 * A GCM example showing the use of AlgorithmParameterGenerator
 */
public class GCMWithParamGenExample
{
    public static void main(String[] args)
        throws Exception
    {
        SecretKey aesKey = createConstantKey();

        AlgorithmParameterGenerator pGen =
            AlgorithmParameterGenerator.getInstance("GCM","BC");

        byte[] msg = Strings.toByteArray("hello, world!");

        System.out.println("msg  : " + Hex.toHexString(msg));

        AlgorithmParameters pGCM = pGen.generateParameters();

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");

        cipher.init(Cipher.ENCRYPT_MODE, aesKey, pGCM);

        byte[] cText = cipher.doFinal(msg);

        System.out.println("cText: " + Hex.toHexString(cText));

        GCMParameterSpec gcmSpec = pGCM.getParameterSpec(GCMParameterSpec.class);

        byte[] pText = gcmDecrypt(
                            aesKey, gcmSpec.getIV(), gcmSpec.getTLen(), cText);

        System.out.println("pText: " + Hex.toHexString(pText));
    }
}
