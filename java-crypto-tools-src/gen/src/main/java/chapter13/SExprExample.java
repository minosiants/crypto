package chapter13;

import java.io.ByteArrayInputStream;

import org.bouncycastle.gpg.SExprParser;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEProtectionRemoverFactory;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

public class SExprExample
{
    static final byte[] sExprKey =
        Base64.decode(
            "KDIxOnByb3RlY3RlZC1wcml2YXRlLWtleSgzOmVjYyg1OmN1cnZlMTU6YnJh"
                + "aW5wb29sUDM4NHIxKSgxOnE5NzoEi29XCqkugtlRvONnpAVMQgfecL+Gk86O"
                + "t8LnUizfHG2TqRrtqlMg1DdU8Z8dJWmhJG84IUOURCyjt8nE4BeeCfRIbTU5"
                + "7CB13OqveBdNIRfK45UQnxHLO2MPVXf4GMdtKSg5OnByb3RlY3RlZDI1Om9w"
                + "ZW5wZ3AtczJrMy1zaGExLWFlcy1jYmMoKDQ6c2hhMTg6itLEzGV4Cfg4OjEy"
                + "OTA1NDcyKTE2OgxmufENKFTZUB72+X7AwkgpMTEyOvMWNLZgaGdlTN8XCxa6"
                + "8ia0Xqqb9RvHgTh+iBf0RgY5Tx5hqO9fHOi76LTBMfxs9VC4f1rTketjEUKR"
                + "f5amKb8lrJ67kKEsny4oRtP9ejkNzcvHFqRdxmHyL10ui8M8rJN9OU8ArqWf"
                + "g22dTcKu02cpKDEyOnByb3RlY3RlZC1hdDE1OjIwMTQwNjA4VDE2MDg1MCkp"
                + "KQ==");

    public static void main(String[] args)
        throws Exception
    {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(sExprKey);

        PGPSecretKey secretKey = new SExprParser(
            new JcaPGPDigestCalculatorProviderBuilder().build()).parseSecretKey(
                        inputStream,
                        new JcePBEProtectionRemoverFactory("test".toCharArray()),
                        new JcaKeyFingerprintCalculator());
        PGPPrivateKey privateKey = secretKey.extractPrivateKey(null);
        System.err.println(Long.toHexString(privateKey.getKeyID()));
    }
}
