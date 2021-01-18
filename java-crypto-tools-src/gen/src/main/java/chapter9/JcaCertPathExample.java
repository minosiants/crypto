package chapter9;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import static chapter8.JcaX509Certificate.createEndEntity;
import static chapter8.JcaX509Certificate.createIntermediateCertificate;
import static chapter8.JcaX509Certificate.createTrustAnchor;
import static chapter9.JcaX509CRL.createEmptyCRL;

/**
 * Basic example of certificate path validation using a CertPathValidator.
 */
public class JcaCertPathExample
{
    public static void main(String[] args)
        throws Exception
    {
        //
        // set up our sample data
        //
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
        JcaX509CertificateConverter certConverter =
                           new JcaX509CertificateConverter().setProvider("BC");
        JcaX509CRLConverter crlConverter =
                                   new JcaX509CRLConverter().setProvider("BC");

        KeyPair trustKp = kpGen.generateKeyPair();

        X509CertificateHolder trustHldr =
                           createTrustAnchor(trustKp, "SHA256withECDSA");
        X509Certificate trustCert = certConverter.getCertificate(trustHldr);

        KeyPair caKp = kpGen.generateKeyPair();

        X509CertificateHolder caHldr = createIntermediateCertificate(
                                        trustHldr,
                                        trustKp.getPrivate(),
                                        "SHA256withECDSA", caKp.getPublic(), 0);
        X509Certificate caCert = certConverter.getCertificate(caHldr);

        KeyPair eeKp = kpGen.generateKeyPair();

        X509Certificate eeCert = certConverter.getCertificate(
            createEndEntity(
                caHldr, caKp.getPrivate(), "SHA256withECDSA", eeKp.getPublic()));

        X509CRL trustCRL = crlConverter.getCRL(
            createEmptyCRL(trustKp.getPrivate(), "SHA256withECDSA", trustHldr));
        X509CRL caCRL = crlConverter.getCRL(
            createEmptyCRL(caKp.getPrivate(), "SHA256withECDSA", caHldr));

        //
        // create our sample certificate path
        //
        CertificateFactory certFact = CertificateFactory.getInstance(
                                               "X.509", "BC");

        List<X509Certificate> chain = new ArrayList<X509Certificate>();

        chain.add(caCert);
        chain.add(eeCert);

        CertPath certPath = certFact.generateCertPath(chain);

        //
        // construct the CertStore containing our certificate set.
        //
        List certStoreList = new ArrayList();

        certStoreList.add(trustCRL);
        certStoreList.add(caCert);
        certStoreList.add(caCRL);
        certStoreList.add(eeCert);

        CertStoreParameters params =
            new CollectionCertStoreParameters(certStoreList);

        CertStore certStore = CertStore.getInstance("Collection", params, "BC");

        //
        // create the set of valid trust anchors
        //
        Set<TrustAnchor> trust = new HashSet<TrustAnchor>();
        trust.add(new TrustAnchor(trustCert, null));

        //
        // set up the parameters for the path validation
        //
        PKIXParameters param = new PKIXParameters(trust);

        X509CertSelector certSelector = new X509CertSelector();
        certSelector.setCertificate(eeCert);

        param.setTargetCertConstraints(certSelector);
        param.addCertStore(certStore);
        param.setRevocationEnabled(true);

        try
        {
            //
            // Create a validator and perform the validation.
            //
            CertPathValidator validator =
                                CertPathValidator.getInstance("PKIX", "BC");

            PKIXCertPathValidatorResult result =
                (PKIXCertPathValidatorResult)validator.validate(certPath, param);

            System.out.println("validated: " + result.getPublicKey());
        }
        catch (CertPathValidatorException e)
        {
            System.out.println("validation failed: index ("
                + e.getIndex() + "), reason \"" + e.getMessage() + "\"");
        }
    }
}
