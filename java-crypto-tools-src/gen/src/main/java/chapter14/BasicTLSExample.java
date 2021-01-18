package chapter14;

import java.security.KeyStore;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import static chapter14.TLSUtils.ID_STORE_PASSWORD;
import static chapter14.TLSUtils.createIdentityKeyStore;
import static chapter14.TLSUtils.createTrustStore;

public class BasicTLSExample
{
    public static void main(
        String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleJsseProvider());

        KeyStore serverStore = createIdentityKeyStore();

        BasicTLSServer server = new BasicTLSServer(serverStore, ID_STORE_PASSWORD);

        server.start();
        
        new Thread(new BasicTLSClient(createTrustStore(serverStore))).start();
    }
}
