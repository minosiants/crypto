package chapter14;

import java.security.KeyStore;
import java.util.concurrent.CountDownLatch;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import static chapter14.TLSUtils.PORT_NO;

/**
 * TLS server with client-side authentication - using the '!' protocol.
 */
public class TLSServerWithClientAuth
{
    private static Logger LOG = Logger.getLogger(BasicTLSServer.class.getName());

    private final CountDownLatch readyLatch = new CountDownLatch(1);

    private final KeyStore serverStore;
    private final char[] passwd;
    private final KeyStore trustStore;

    /**
     * Base server constructor.
     *
     * @param serverStore the public/private keys for the server.
     * @param passwd the password to unlock the private keys in the serverStore.
     * @param trustStore the trust store for validating any certificates presented.
     */
    public TLSServerWithClientAuth(
        KeyStore serverStore, char[] passwd, KeyStore trustStore)
    {
        this.serverStore = serverStore;
        this.passwd = passwd;
        this.trustStore = trustStore;
    }

    /**
     * Start our server thread.
     */
    public void start()
        throws InterruptedException
    {
        new Thread(new ServerTask()).start();

        readyLatch.await();
    }

    /**
     * Task for bringing up a server-side of the TLS connection.
     */
    private class ServerTask
        implements Runnable
    {
        public void run()
        {
            try
            {
                SSLContext sslContext = SSLContext.getInstance("TLS", "BCJSSE");

                KeyManagerFactory keyMgrFact =
                                KeyManagerFactory.getInstance("PKIX", "BCJSSE");
                keyMgrFact.init(serverStore, passwd);

                TrustManagerFactory trustMgrFact =
                                TrustManagerFactory.getInstance("PKIX", "BCJSSE");
                trustMgrFact.init(trustStore);

                sslContext.init(
                    keyMgrFact.getKeyManagers(),
                    trustMgrFact.getTrustManagers(), null);

                // create the server socket and make client auth mandatory.
                SSLServerSocketFactory fact = sslContext.getServerSocketFactory();
                SSLServerSocket sSock =
                    (SSLServerSocket)fact.createServerSocket(PORT_NO);
                sSock.setNeedClientAuth(true);

                readyLatch.countDown();

                SSLSocket sslSock = (SSLSocket)sSock.accept();

                Protocol.doServerSide(sslSock);
            }
            catch (Exception e)
            {
                LOG.log(Level.SEVERE, "server: " + e.getMessage(), e);
            }
        }
    }
}
