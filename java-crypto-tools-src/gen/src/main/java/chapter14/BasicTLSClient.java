package chapter14;

import java.security.KeyStore;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import static chapter14.TLSUtils.PORT_NO;

/**
 * Basic TLS client - using the '!' protocol.
 */
public class BasicTLSClient
    implements Runnable
{
    private static Logger LOG = Logger.getLogger(BasicTLSClient.class.getName());

    private final KeyStore trustStore;

    /**
     * Base client constructor.
     *
     * @param trustStore the certificates we are willing to trust from a server.
     */
    public BasicTLSClient(KeyStore trustStore)
    {
        this.trustStore = trustStore;
    }

    /**
     * Task for bringing up a TLS client.
     */
    public void run()
    {
        try
        {
            SSLContext sslContext = SSLContext.getInstance("TLS", "BCJSSE");

            TrustManagerFactory trustMgrFact =
                            TrustManagerFactory.getInstance("PKIX", "BCJSSE");
            trustMgrFact.init(trustStore);

            sslContext.init(null, trustMgrFact.getTrustManagers(), null);

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
