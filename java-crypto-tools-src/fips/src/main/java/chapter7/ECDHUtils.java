package chapter7;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.bouncycastle.jcajce.AgreedKeyWithMacKey;
import org.bouncycastle.jcajce.ZeroizableSecretKey;
import org.bouncycastle.jcajce.spec.MQVParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;

public class ECDHUtils
{
    /**
     * Generate a EC key pair on the passed in named curve..
     *
     * @param curveName the name of the curve to generate the key pair on.
     * @return a EC KeyPair
     */
    public static KeyPair generateECKeyPair(String curveName)
        throws GeneralSecurityException
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("EC", "BCFIPS");

        keyPair.initialize(new ECGenParameterSpec(curveName));

        return keyPair.generateKeyPair();
    }

    /**
     * Generate a EC key pair on the P-256 curve.
     *
     * @return a EC KeyPair
     */
    public static KeyPair generateECKeyPair()
        throws GeneralSecurityException
    {
        return generateECKeyPair("P-256");
    }

    /**
     * Generate an agreed AES key of 256 bits with an associated
     * 256 bit SHA-512 MAC key using ECMQV.
     *
     * @param aPriv Party A's private key.
     * @param aPubEph Party A's ephemeral public key.
     * @param aPrivEph Party A's ephemeral private key.
     * @param bPub Party B's public key.
     * @param bPubEph Party B's ephemeral public key.
     * @return an AgreedKeyWithMacKey containing the two keys.
     */
    public static AgreedKeyWithMacKey keyConfGenerateAESKey(
        PrivateKey aPriv, PublicKey aPubEph, PrivateKey aPrivEph,
        PublicKey bPub, PublicKey bPubEph, byte[] keyMaterial)
        throws GeneralSecurityException
    {
        KeyAgreement agreement =
            KeyAgreement.getInstance("ECMQVwithSHA256KDF", "BCFIPS");

        agreement.init(aPriv,
            new MQVParameterSpec(aPubEph, aPrivEph, bPubEph, keyMaterial));

        agreement.doPhase(bPub, true);

        return (AgreedKeyWithMacKey)
                    agreement.generateSecret("HmacSHA512[256]/AES[256]");
    }

    /**
     * Calculate a MAC tag value for the passed in MAC data.
     * Note: we zeroize the MAC key before returning the tag value.
     *
     * @param macKey key to initialize the MAC with.
     * @param macData data to calculate the MAC tag from.
     * @return the MAC tag value
     */
    public static byte[] calculateMAC(
        ZeroizableSecretKey macKey, byte[] macData)
        throws GeneralSecurityException
    {
        Mac mac = Mac.getInstance("HmacSHA512", "BCFIPS");

        mac.init(macKey);

        byte[] rv = mac.doFinal(macData);

        macKey.zeroize();

        return rv;
    }
}
