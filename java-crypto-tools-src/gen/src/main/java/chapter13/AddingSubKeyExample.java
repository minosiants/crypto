package chapter13;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.Security;
import java.util.Date;

import chapter6.RsaUtils;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.jcajce.JcaPGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

public class AddingSubKeyExample
{
    /**
     * Generate secret/public keys rings from an original secret key ring and a new subkey.
     *
     * @param original the original secret key ring to base the new ones on.
     * @param passphrase the passphrase to encrypt/decrypt the secret keys with.
     * @param subKey the public/private subkey pair to add.
     * @return a byte[][] containing the encoding of secret and public key rings respectively.
     */
    public static byte[][] addSubKey(PGPSecretKeyRing original, char[] passphrase, PGPKeyPair subKey)
        throws PGPException, IOException
    {
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder()
                                            .build()
                                            .get(HashAlgorithmTags.SHA1);

        PBESecretKeyDecryptor keyDecryptor = new JcePBESecretKeyDecryptorBuilder().build(passphrase);
        PBESecretKeyEncryptor keyEncryptor = new JcePBESecretKeyEncryptorBuilder(
                                    PGPEncryptedData.AES_256, sha1Calc)
                                .setProvider("BC").build(passphrase);

        PGPKeyRingGenerator keyRingGen =
            new PGPKeyRingGenerator(
                 original, keyDecryptor, sha1Calc,
                 new JcaPGPContentSignerBuilder(
                        original.getPublicKey().getAlgorithm(),
                        HashAlgorithmTags.SHA384),
                 keyEncryptor);

        keyRingGen.addSubKey(subKey);

        // create an encoding of the secret key ring
        ByteArrayOutputStream secretOut = new ByteArrayOutputStream();
        keyRingGen.generateSecretKeyRing().encode(secretOut);
        secretOut.close();

        // create an encoding of the public key ring
        ByteArrayOutputStream publicOut = new ByteArrayOutputStream();
        keyRingGen.generatePublicKeyRing().encode(publicOut);
        publicOut.close();

        return new byte [][]{secretOut.toByteArray(), publicOut.toByteArray()};
    }

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        
        byte[][] encRings = BasicKeyRingExample.generateKeyRings("eric@bouncycastle.org", "echidna".toCharArray());

        KeyPair rsaKp = RsaUtils.generateRSAKeyPair();
        PGPKeyPair rsaKeyPair = new JcaPGPKeyPair(
                                                PGPPublicKey.RSA_ENCRYPT, rsaKp, new Date());

        encRings = addSubKey(new JcaPGPSecretKeyRing(encRings[0]), "echidna".toCharArray(), rsaKeyPair);

        FileOutputStream fOut = new FileOutputStream("secring.gpg");
        fOut.write(encRings[0]);
        fOut.close();

        fOut = new FileOutputStream("pubring.gpg");
        fOut.write(encRings[1]);
        fOut.close();
    }
}
