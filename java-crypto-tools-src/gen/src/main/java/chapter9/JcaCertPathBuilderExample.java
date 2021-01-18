package chapter9;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import static chapter8.JcaX509Certificate.createEndEntity;
import static chapter8.JcaX509Certificate.createIntermediateCertificate;
import static chapter8.JcaX509Certificate.createTrustAnchor;
import static chapter9.JcaX509CRL.createEmptyCRL;

/**
 * Basic example of the use of CertPathBuilder.
 */
public class JcaCertPathBuilderExample
{
    public static void main(
        String[] args)
        throws Exception
    {
        // set up
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

        List certStoreList = new ArrayList();

        certStoreList.add(trustCRL);
        certStoreList.add(caCert);
        certStoreList.add(caCRL);
        certStoreList.add(eeCert);

        CertStoreParameters params =
            new CollectionCertStoreParameters(certStoreList);

        CertStore certStore = CertStore.getInstance("Collection", params, "BC");

        Set<TrustAnchor> trust = new HashSet<TrustAnchor>();
        trust.add(new TrustAnchor(trustCert, null));

        // build the path
        CertPathBuilder  builder = CertPathBuilder.getInstance("PKIX", "BC");
        X509CertSelector endConstraints = new X509CertSelector();
        
        endConstraints.setSerialNumber(eeCert.getSerialNumber());
        endConstraints.setIssuer(eeCert.getIssuerX500Principal().getEncoded());

        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(
                Collections.singleton(new TrustAnchor(trustCert, null)),
                endConstraints);
        
        buildParams.addCertStore(certStore);
        buildParams.setDate(new Date());
        
        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(buildParams);
        CertPath                  path = result.getCertPath();

        Iterator it = path.getCertificates().iterator();
        while (it.hasNext())
        {
            System.out.println(((X509Certificate)it.next()).getSubjectX500Principal());
        }
        
        System.out.println(result.getTrustAnchor().getTrustedCert().getSubjectX500Principal());
    }
}
