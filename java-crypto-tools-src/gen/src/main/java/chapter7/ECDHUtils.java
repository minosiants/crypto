package chapter7;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import org.bouncycastle.jcajce.spec.DHUParameterSpec;
import org.bouncycastle.jcajce.spec.MQVParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;

public class ECDHUtils
{
    /**
     * Generate an agreed AES key value of 256 bits in length.
     *
     * @param aPriv Party A's private key.
     * @param bPub Party B's public key.
     * @return the generated AES key (256 bits).
     */
    public static SecretKey ecGenerateAESKey(
        PrivateKey aPriv, PublicKey bPub, byte[] keyMaterial)
        throws GeneralSecurityException
    {
        KeyAgreement agreement =
            KeyAgreement.getInstance("ECCDHwithSHA256KDF", "BC");

        agreement.init(aPriv, new UserKeyingMaterialSpec(keyMaterial));

        agreement.doPhase(bPub, true);

        return agreement.generateSecret("AES");
    }

    /**
     * Generate an agreed AES key value of 256 bits in length
     * using the EC Unified Diffie-Hellman model.
     *
     * @param aPriv Party A's private key.
     * @param aPubEph Party A's ephemeral public key.
     * @param aPrivEph Party A's ephemeral private key.
     * @param bPub Party B's public key.
     * @param bPubEph Party B's ephemeral public key.
     * @return the generated AES key (256 bits).
     */
    public static SecretKey ecdhuGenerateAESKey(
        PrivateKey aPriv, PublicKey aPubEph, PrivateKey aPrivEph,
        PublicKey bPub, PublicKey bPubEph, byte[] keyMaterial)
        throws GeneralSecurityException
    {
        KeyAgreement agreement =
            KeyAgreement.getInstance("ECCDHUwithSHA256CKDF", "BC");

        agreement.init(aPriv,
            new DHUParameterSpec(aPubEph, aPrivEph, bPubEph, keyMaterial));

        agreement.doPhase(bPub, true);

        return agreement.generateSecret("AES");
    }

    /**
     * Generate an agreed AES key value of 256 bits in length
     * using ECMQV.
     *
     * @param aPriv Party A's private key.
     * @param aPubEph Party A's ephemeral public key.
     * @param aPrivEph Party A's ephemeral private key.
     * @param bPub Party B's public key.
     * @param bPubEph Party B's ephemeral public key.
     * @return the generated AES key (256 bits).
     */
    public static SecretKey ecmqvGenerateAESKey(
        PrivateKey aPriv, PublicKey aPubEph, PrivateKey aPrivEph,
        PublicKey bPub, PublicKey bPubEph, byte[] keyMaterial)
        throws GeneralSecurityException
    {
        KeyAgreement agreement =
            KeyAgreement.getInstance("ECMQVwithSHA256KDF", "BC");

        agreement.init(aPriv,
            new MQVParameterSpec(aPubEph, aPrivEph, bPubEph, keyMaterial));

        agreement.doPhase(bPub, true);

        return agreement.generateSecret("AES");
    }
}
