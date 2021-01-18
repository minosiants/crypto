package chapter6;

import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import static chapter6.EcDsaUtils.generateECDDSASignature;
import static chapter6.EcDsaUtils.verifyECDSASignature;
import static chapter6.JcaUtils.createPrivateKey;
import static chapter6.JcaUtils.createPublicKey;

/**
 * An example of using Deterministic ECDSA (ECDDSA) to sign data and then
 * verifying the resulting signature.
 */
public class EcDDsaExample
{
    public static void main(String[] args)
        throws GeneralSecurityException
    {
        byte[] msg = Strings.toByteArray("hello, world!");

        PKCS8EncodedKeySpec ecPrivSpec = new PKCS8EncodedKeySpec(
          Base64.decode(
            "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgguOIC1cI1lPdLPHglG"
          + "qRYLLYbQJ03/bSyHdTGTqGcwegCgYIKoZIzj0DAQehRANCAATQN4K61MQt/SrSqkJ+"
          + "SAMm6g7BjATXKG1f4QqXf8V4syevh6kck426Jb7A5apWZjktuEKfzFvzMj0IaDa1zM"
          + "18"));

        X509EncodedKeySpec ecPubSpec = new X509EncodedKeySpec(
            Base64.decode(
             "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0DeCutTELf0q0qpCfkgDJuoOwYwE1"
          + "yhtX+EKl3/FeLMnr4epHJONuiW+wOWqVmY5LbhCn8xb8zI9CGg2tczNfA=="));

        ECPrivateKey ecPriv = (ECPrivateKey)createPrivateKey("EC", ecPrivSpec);
        byte[] ecdsaSignature = generateECDDSASignature(ecPriv, msg);

        // Note that the verification step is the same as for regular ECDSA.
        ECPublicKey ecPub = (ECPublicKey)createPublicKey("EC", ecPubSpec);
        System.out.println("ECDSA verified: " + verifyECDSASignature(
            ecPub, msg, ecdsaSignature));
        System.out.println("sig: " + Hex.toHexString(ecdsaSignature));
    }
}
