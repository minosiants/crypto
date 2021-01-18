package chapter10;

import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;

import javax.security.auth.x500.X500PrivateCredential;

import static chapter10.KeyStoreUtils.createSelfSignedCredentials;
/**
 * Basic example of using BCFKS to store a single private key and self-signed
 * certificate.
 */
public class BCFKSExample
{
    public static void main(String[] args)
        throws Exception
    {
        PrivateCredential cred = createSelfSignedCredentials();

        KeyStore store = KeyStore.getInstance("BCFKS", "BC");

        store.load(null, null);

        store.setKeyEntry("key", cred.getPrivateKey(), "keyPass".toCharArray(),
            new Certificate[] { cred.getCertificate() });

        FileOutputStream fOut = new FileOutputStream("basic.fks");

        store.store(fOut, "storePass".toCharArray());

        fOut.close();
    }
}
