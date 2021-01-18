package chapter14;

import java.security.KeyStore;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import static chapter14.TLSUtils.PORT_NO;

/**
 * TLS client with client-side authentication - using the '!' protocol.
 */
public class TLSClientWithClientAuth
    implements Runnable
{
    private static Logger LOG = Logger.getLogger(BasicTLSClient.class.getName());

    private final KeyStore trustStore;
    private final KeyStore clientStore;
    private final char[] passwd;

    /**
     * Base client with authentication constructor.
     *
     * @param trustStore the certificates we are willing to trust from a server.
     * @param clientStore the public/private keys for the client.
     * @param passwd the password to unlock the private keys in the clientStore.
     */
    public TLSClientWithClientAuth(
        KeyStore trustStore, KeyStore clientStore, char[] passwd)
    {
        this.trustStore = trustStore;
        this.clientStore = clientStore;
        this.passwd = passwd;
    }

    /**
     * Task for bringing up a TLS client with authentication.
     */
    public void run()
    {
        try
        {
            SSLContext sslContext = SSLContext.getInstance("TLS", "BCJSSE");

            KeyManagerFactory keyMgrFact =
                            KeyManagerFactory.getInstance("PKIX", "BCJSSE");
            keyMgrFact.init(clientStore, passwd);

            TrustManagerFactory trustMgrFact =
                            TrustManagerFactory.getInstance("PKIX", "BCJSSE");
            trustMgrFact.init(trustStore);

            sslContext.init(
                keyMgrFact.getKeyManagers(),
                trustMgrFact.getTrustManagers(), null);

            SSLSocketFactory fact = sslContext.getSocketFactory();
            SSLSocket cSock = (SSLSocket)fact.createSocket("localhost", PORT_NO);

            Protocol.doClientSide(cSock);
        }
        catch (Exception e)
        {
            LOG.log(Level.SEVERE, "client: " + e.getMessage(), e);
        }
    }
}
