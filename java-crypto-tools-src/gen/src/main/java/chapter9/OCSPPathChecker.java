package chapter9;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.*;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

/**
 * A basic path checker that does an OCSP check for a single CA
 */
public class OCSPPathChecker
    extends PKIXCertPathChecker
{
    private KeyPair         responderPair;
    private X509Certificate caCert;
    private BigInteger      revokedSerialNumber;
    
    public OCSPPathChecker(
        KeyPair         responderPair,
        X509Certificate caCert,
        BigInteger      revokedSerialNumber)
    {
        this.responderPair = responderPair;
        this.caCert = caCert;
        this.revokedSerialNumber = revokedSerialNumber;
    }
    
    public void init(boolean forwardChecking)
        throws CertPathValidatorException
    {
        // ignore
    }

    public boolean isForwardCheckingSupported()
    {
        return true;
    }

    public Set getSupportedExtensions()
    {
        return null;
    }

    public void check(Certificate cert, Collection extensions)
        throws CertPathValidatorException
    {
        try
        {
            X509CertificateHolder issuerCert =
                                    new JcaX509CertificateHolder(caCert);
            X509CertificateHolder certToCheck =
                        new JcaX509CertificateHolder((X509Certificate)cert);

            if (certToCheck.getIssuer().equals(issuerCert.getSubject()))
            {
                String message = OCSPProcessingExample.getStatusMessage(
                    responderPair.getPrivate(),
                    issuerCert,
                    revokedSerialNumber, certToCheck);

                if (message.endsWith("good"))
                {
                    System.out.println(message);
                }
                else
                {
                    throw new CertPathValidatorException(message);
                }
            }
        }
        catch (Exception e)
        {
            throw new CertPathValidatorException(
                           "exception verifying certificate: " + e, e);
        }
    }
}
