package chapter10;

import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;

import static chapter10.KeyStoreUtils.createSelfSignedCredentials;
/**
 * Basic example of using JKS to store a single private key and self-signed
 * certificate.
 */
public class PKCS12Example
{
    public static void main(String[] args)
        throws Exception
    {
        PrivateCredential cred = createSelfSignedCredentials();

        KeyStore store = KeyStore.getInstance("PKCS12", "BC");

        store.load(null, null);

        store.setKeyEntry("key", cred.getPrivateKey(), null,
            new Certificate[] { cred.getCertificate() });

        FileOutputStream fOut = new FileOutputStream("basic.p12");

        store.store(fOut, "storePass".toCharArray());

        fOut.close();
    }
}
