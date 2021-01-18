package chapter14;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Enumeration;

import javax.security.auth.x500.X500PrivateCredential;

import chapter10.PrivateCredential;

import static chapter10.KeyStoreUtils.createSelfSignedCredentials;

public class TLSUtils
{
    public static final int PORT_NO = 9090;
    public static final char[] ID_STORE_PASSWORD = "passwd".toCharArray();

    /**
     * Create a KeyStore containing a single key with a self-signed certificate.
     *
     * @return a KeyStore containing a single key with a self-signed certificate.
     */
    public static KeyStore createIdentityKeyStore()
        throws Exception
    {
        PrivateCredential cred = createSelfSignedCredentials();

        KeyStore store = KeyStore.getInstance("JKS");

        store.load(null, null);

        store.setKeyEntry("identity", cred.getPrivateKey(), ID_STORE_PASSWORD,
                                    new Certificate[]{cred.getCertificate()});

        return store;
    }

    /**
     * Create a key store suitable for use as a trust store, containing only
     * the certificates associated with each alias in the passed in
     * credentialStore.
     *
     * @param credentialStore key store containing public/private credentials.
     * @return a key store containing only certificates.
     */
    public static KeyStore createTrustStore(KeyStore credentialStore)
        throws Exception
    {
        KeyStore store = KeyStore.getInstance("JKS");

        store.load(null, null);

        for (Enumeration<String> en = credentialStore.aliases(); en.hasMoreElements();)
        {
            String alias = en.nextElement();

            store.setCertificateEntry(alias, credentialStore.getCertificate(alias));
        }

        return store;
    }
}
