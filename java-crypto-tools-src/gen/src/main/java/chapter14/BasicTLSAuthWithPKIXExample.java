package chapter14;

import java.security.KeyStore;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import static chapter14.TLSUtils.ID_STORE_PASSWORD;
import static chapter14.TLSUtils.createIdentityKeyStore;
import static chapter14.TLSUtils.createTrustStore;

public class BasicTLSAuthWithPKIXExample
{
    public static void main(
        String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleJsseProvider());

        KeyStore serverStore = createIdentityKeyStore();
        KeyStore clientStore = createIdentityKeyStore();
        
        TLSServerWithClientAuthWithPKIX server =
            new TLSServerWithClientAuthWithPKIX(
                 serverStore, ID_STORE_PASSWORD, createTrustStore(clientStore));

        server.start();
        
        new Thread(new TLSClientWithClientAuth(
                createTrustStore(serverStore), clientStore, ID_STORE_PASSWORD))
            .start();
    }
}
