package chapter6;

import java.io.IOException;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.DSAParameterSpec;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DsaUtils
{
    /**
     * Return a generated set of DSA parameters suitable for creating 2048
     * bit keys.
     *
     * @return a DSAParameterSpec holding the generated parameters.
     */
    public static DSAParameterSpec generateDSAParams()
        throws GeneralSecurityException
    {
        AlgorithmParameterGenerator paramGen =
            AlgorithmParameterGenerator.getInstance("DSA", "BC");

        paramGen.init(2048);

        AlgorithmParameters params = paramGen.generateParameters();

        return params.getParameterSpec(DSAParameterSpec.class);
    }
    /**
     * Generate a 2048 bit DSA key pair using provider based parameters.
     *
     * @return a DSA KeyPair
     */
    public static KeyPair generateDSAKeyPair()
        throws GeneralSecurityException
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("DSA", "BC");

        keyPair.initialize(2048);

        return keyPair.generateKeyPair();
    }
    /**
     * Generate a DSA key pair using our own specified parameters.
     *
     * @param dsaSpec the DSA parameters to use for key generation.
     * @return a DSA KeyPair
     */
    public static KeyPair generateDSAKeyPair(DSAParameterSpec dsaSpec)
        throws GeneralSecurityException
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("DSA", "BC");

        keyPair.initialize(dsaSpec);

        return keyPair.generateKeyPair();
    }
    /**
     * Generate an encoded DSA signature using the passed in private key and
     * input data.
     * 
     * @param dsaPrivate the private key for generating the signature with.
     * @param input the input to be signed.
     * @return the encoded signature.
     */
    public static byte[] generateDSASignature(PrivateKey dsaPrivate, byte[] input)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA256withDSA", "BC");

        signature.initSign(dsaPrivate);

        signature.update(input);

        return signature.sign();
    }
    /**
     * Return true if the passed in signature verifies against
     * the passed in DSA public key and input.
     *
     * @param dsaPublic the public key of the signature creator.
     * @param input the input that was supposed to have been signed.
     * @param encSignature the encoded signature.
     * @return true if the signature verifies, false otherwise.
     */
    public static boolean verifyDSASignature(
        PublicKey dsaPublic, byte[] input, byte[] encSignature)
        throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA256withDSA", "BC");

        signature.initVerify(dsaPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }
    /**
     * Fix a faulty DSA signature that has been encoded using
     * unsigned integers.
     *
     * @param encSignature the encoded signature.
     * @return the corrected signature with signed integer components.
     */
    public static byte[] patchDSASignature(byte[] encSignature)
        throws IOException
    {
        ASN1Sequence sigSeq = ASN1Sequence.getInstance(encSignature);

        ASN1EncodableVector sigV = new ASN1EncodableVector();

        // fix R
        sigV.add(new ASN1Integer(
            ASN1Integer.getInstance(sigSeq.getObjectAt(0)).getPositiveValue()));

        // fix S
        sigV.add(new ASN1Integer(
            ASN1Integer.getInstance(sigSeq.getObjectAt(1)).getPositiveValue()));

        return new DERSequence(sigV).getEncoded();
    }
}
