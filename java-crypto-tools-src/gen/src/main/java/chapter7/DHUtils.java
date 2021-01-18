package chapter7;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jcajce.spec.DHUParameterSpec;
import org.bouncycastle.jcajce.spec.MQVParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.util.Arrays;

public class DHUtils
{
    /**
     * Return a generated set of DH parameters suitable for creating 2048
     * bit keys.
     *
     * @return a DHParameterSpec holding the generated parameters.
     */
    public static DHParameterSpec generateDHParams()
        throws GeneralSecurityException
    {
        AlgorithmParameterGenerator paramGen =
            AlgorithmParameterGenerator.getInstance("DH", "BC");

        paramGen.init(2048);

        AlgorithmParameters params = paramGen.generateParameters();

        return params.getParameterSpec(DHParameterSpec.class);
    }
    /**
     * Generate a 2048 bit DH key pair using provider based parameters.
     *
     * @return a DH KeyPair
     */
    public static KeyPair generateDHKeyPair()
        throws GeneralSecurityException
    {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH", "BC");

        keyPairGen.initialize(2048);

        return keyPairGen.generateKeyPair();
    }
    /**
     * Generate a DH key pair using our own specified parameters.
     *
     * @param dhSpec the DH parameters to use for key generation.
     * @return a DH KeyPair
     */
    public static KeyPair generateDHKeyPair(DHParameterSpec dhSpec)
        throws GeneralSecurityException
    {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH", "BC");

        keyPairGen.initialize(dhSpec);

        return keyPairGen.generateKeyPair();
    }
    /**
     * Generate an agreed secret byte value of 32 bytes in length.
     *
     * @param aPriv Party A's private key.
     * @param bPub Party B's public key.
     * @return the first 32 bytes of the generated secret.
     */
    public static byte[] generateSecret(PrivateKey aPriv, PublicKey bPub)
        throws GeneralSecurityException
    {
        KeyAgreement agreement = KeyAgreement.getInstance("DH", "BC");

        agreement.init(aPriv);

        agreement.doPhase(bPub, true);

        return Arrays.copyOfRange(agreement.generateSecret(), 0, 32);
    }
    /**
     * Generate an agreed AES key value of 256 bits in length.
     *
     * @param aPriv Party A's private key.
     * @param bPub Party B's public key.
     * @return the generated AES key (256 bits).
     */
    public static SecretKey generateAESKey(PrivateKey aPriv, PublicKey bPub)
        throws GeneralSecurityException
    {
        KeyAgreement agreement = KeyAgreement.getInstance("DH", "BC");

        agreement.init(aPriv);

        agreement.doPhase(bPub, true);

        return agreement.generateSecret("AES");
    }
    /**
     * Generate an agreed AES key value of 256 bits in length.
     *
     * @param aPriv Party A's private key.
     * @param bPub Party B's public key.
     * @return the generated AES key (256 bits).
     */
    public static SecretKey generateAESKey(
        PrivateKey aPriv, PublicKey bPub, byte[] keyMaterial)
        throws GeneralSecurityException
    {
        KeyAgreement agreement = KeyAgreement.getInstance("DHwithSHA256KDF", "BC");

        agreement.init(aPriv, new UserKeyingMaterialSpec(keyMaterial));

        agreement.doPhase(bPub, true);

        return agreement.generateSecret("AES");
    }

    /**
     * Generate an agreed AES key value of 256 bits in length
     * using the Unified Diffie-Hellman model.
     *
     * @param aPriv Party A's private key.
     * @param aPubEph Party A's ephemeral public key.
     * @param aPrivEph Party A's ephemeral private key.
     * @param bPub Party B's public key.
     * @param bPubEph Party B's ephemeral public key.
     * @return the generated AES key (256 bits).
     */
    public static SecretKey dhuGenerateAESKey(
        PrivateKey aPriv, PublicKey aPubEph, PrivateKey aPrivEph,
        PublicKey bPub, PublicKey bPubEph, byte[] keyMaterial)
        throws GeneralSecurityException
    {
        KeyAgreement agreement =
            KeyAgreement.getInstance("DHUwithSHA256KDF", "BC");

        agreement.init(aPriv,
            new DHUParameterSpec(aPubEph, aPrivEph, bPubEph, keyMaterial));

        agreement.doPhase(bPub, true);

        return agreement.generateSecret("AES");
    }

    /**
     * Generate an agreed AES key value of 256 bits in length
     * using MQV.
     *
     * @param aPriv Party A's private key.
     * @param aPubEph Party A's ephemeral public key.
     * @param aPrivEph Party A's ephemeral private key.
     * @param bPub Party B's public key.
     * @param bPubEph Party B's ephemeral public key.
     * @return the generated AES key (256 bits).
     */
    public static SecretKey mqvGenerateAESKey(
        PrivateKey aPriv, PublicKey aPubEph, PrivateKey aPrivEph,
        PublicKey bPub, PublicKey bPubEph, byte[] keyMaterial)
        throws GeneralSecurityException
    {
        KeyAgreement agreement =
            KeyAgreement.getInstance("MQVwithSHA256KDF", "BC");

        agreement.init(aPriv,
            new MQVParameterSpec(aPubEph, aPrivEph, bPubEph, keyMaterial));

        agreement.doPhase(bPub, true);

        return agreement.generateSecret("AES");
    }
}
