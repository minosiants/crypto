package chapter13;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.gpg.keybox.CertificateBlob;
import org.bouncycastle.gpg.keybox.KeyBlob;
import org.bouncycastle.gpg.keybox.KeyBox;
import org.bouncycastle.gpg.keybox.PublicKeyRingBlob;
import org.bouncycastle.gpg.keybox.jcajce.JcaKeyBoxBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

public class KeyBoxExample
{
    /**
     * Load all the key rings and certificates in a KeyBox file.
     *
     * @param keyBox the KeyBox to be loaded.
     * @return a list of the PGP public key rings and X.509 certificates
     *         found in the key box.
     */
    public static List<Object> loadKeyBoxKeys(KeyBox keyBox)
        throws Exception
    {
        List<Object> publicObjects = new ArrayList<Object>();

        for (KeyBlob keyBlob : keyBox.getKeyBlobs())
        {
            switch (keyBlob.getType())
            {
            case X509_BLOB:
                {
                byte[] certData = ((CertificateBlob)keyBlob).getEncodedCertificate();
                CertificateFactory factory = CertificateFactory.getInstance("X509");
                publicObjects.add(factory.generateCertificate(
                                                new ByteArrayInputStream(certData)));
                }
                break;
            case OPEN_PGP_BLOB:
                publicObjects.add(((PublicKeyRingBlob)keyBlob).getPGPPublicKeyRing());
                break;
            default:
                throw new IllegalStateException(
                              "Unexpected blob type: " + keyBlob.getType());
            }
        }

        return publicObjects;
    }

    private static byte[] kbxData = Base64.decode(
        "AAAAIAEBAAJLQlhmAAAAAFsDnIVbA5yFAAAAAAAAAAAAAAWXAgEAAAAAAH4A"
            + "AAUFAAIAHBNlvt79QmK2kqpORPGfU7y8bjFzAAAAIAAAAABZNSe3YNgXuI0/"
            + "OoHHqa6eEUo5PgAAADwAAAAAAAAAAQAMAAABngAAACEAAAAAAAIABAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAWwOcnQAAAACZAQ0EWwOckgEIAKcBdQvPSp8kT8HV"
            + "g2Y12kyyB/zRsFfeBA8bU4aTDwtALM+cGcdlbwbaoQMqqPPwGvEFPXJC/RPw"
            + "AY59yM1F6P6qkh9VG4jL4mfLU8qK60IVM8Z4ncYZl0zkww3eGf4s7rKMKMr5"
            + "JFl1Sp9Whhgf94h+sFC7Q5kDmiipQ1TN5x/JB+Z7HMtY/wfvxXdnZELc38nW"
            + "SiM/zp7GOCOCl2J0K8/3bFuUDiwant9LSBiL78CUtGxvEeX0jj2KXJZAbsTH"
            + "IvyF0ZsMLnHseEmDReNq2SBbq/nd24obR4eQ5R9YwnKnqfkglprBL2g5IStq"
            + "kfEGlvyB2lJYxxssWKiXd5MbLzMAEQEAAbAMAABncGcBAAAAAAAAtCFXYWx0"
            + "ZXIgTWl0dHkgPHdhbHRlckBtaXR0eS5sb2NhbD6wDAAAZ3BnAgAAAAAAAIkB"
            + "VAQTAQgAPhYhBBNlvt79QmK2kqpORPGfU7y8bjFzBQJbA5ySAhsDBQkDwmcA"
            + "BQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEPGfU7y8bjFz6VQIAI7TDq7w"
            + "7FDhjJkGzsRW3oi353m5qBY7sWX7i69KqnoEzX+8NNJ1VPwyIeZm9r8zMtbX"
            + "DwpKotNkBVblklfZ5q9x7/ElVWxLuXEnjjGs5hEXclhsuHKpEv05iB+UR0QY"
            + "fP10zpHmU0ROhj+EndHPsq6nV3GCrR7FElSqnHwWAsc5pYFhXWLR0HdGSA1T"
            + "DYgXQexjHBK2x8/zxn3CoPQDOieXdg3/EtkGMxQ71sQxrtoxNttYx+i0sOJd"
            + "xz6qYD5cOFOmpZ40BEaizpvkVP8bHomD36fYZgbMOUOLmwwUt8aCb7VFwIue"
            + "L6AXG7hsFgsVu9l8lXzZ65qVjOfqz6QuonuwBgAAZ3BnALkBDQRbA5ySAQgA"
            + "t4xyKv8cgz+BnLEZtXP6aT/NpwVe9nFrCcP07pkNX3ADoazqq6n/v79v90J+"
            + "tUGe8WwXKrJmnsUc6rDgGgGwSTCZfD4EGPL6ULIT+hNlpbrhADNx6Ycs7X2F"
            + "V4IPJqVnBSBGglXm2CDF0FDb7TJ3XWmWzNMWyvRzIX++6rVwpmuzUaYl7FVf"
            + "eu9lxhSxpmW5sZVF/yIixjkyu1QgGopjtfD1o1WLoHYEsnX2S+LuDw6bk+Bg"
            + "sBN7Yea3N75gU1DvJyhu8gERoou6wptluVULnwRoxEg1xAN95R2JgajBtGQ3"
            + "7zP42ooSc+a9w3WaUKANhXgToYr/++6pk+k36BIR0QARAQABiQE8BBgBCAAm"
            + "FiEEE2W+3v1CYraSqk5E8Z9TvLxuMXMFAlsDnJICGwwFCQPCZwAACgkQ8Z9T"
            + "vLxuMXMxwAf+NTH8asImTUzZr953QaOZEy8p4t/w7MIslKUeJgIKVwDNmt2i"
            + "oOwe0W9Cuqq5gzuGuDrQYzjx24jVtJZyuPPBuIMK8nBwOrnpB05fBghX6KH1"
            + "bbbEzFr3YAECLUl1K//63R2KyyIAcqn27Ek/OB8dsXhot9sY6PIzb3dPJH1j"
            + "wFVtY+02xNrS4rcGHsX826Bg1P83rrcwGigx6IF4FEk5i7Knytx3xuYz5pTg"
            + "O/6l6mOHYabw2D2ccSVPHKFqI9AXzG/tkv7CTUp89XF29f83E7pEJLtbNr5i"
            + "tRA5CvKsUQDvR47yG7+p09rCuvCzCoaHkgvTppjCyJOT81UgMqrAkLAGAABn"
            + "cGcALnAAc0JNca+PbE4LUM7et6F4AVQAAAOUAwEAAAAAAJIAAALuAAEAHIWg"
            + "rejphfkogokYeyxVbcnYaLaxAAAAAAAAAAAACAdrhuYkx2kVAAIADAAAAHIA"
            + "AAAQAAAAAAAAAIIAAAAQAAAAAAABAAQAAAAAAAAAAAAAAAAAAAAAWwOg0QAA"
            + "AABDTj1QZWdneSBTaGlwcGVuQ049UGVnZ3kgU2hpcHBlbjCCAuowggHSoAMC"
            + "AQICCAdrhuYkx2kVMA0GCSqGSIb3DQEBCwUAMBgxFjAUBgNVBAMTDVBlZ2d5"
            + "IFNoaXBwZW4wIBcNMTgwNTIyMDQzMzQwWhgPMjA2MzA0MDUxNzAwMDBaMBgx"
            + "FjAUBgNVBAMTDVBlZ2d5IFNoaXBwZW4wggEiMA0GCSqGSIb3DQEBAQUAA4IB"
            + "DwAwggEKAoIBAQDRcUCsSW98s9GA5Ms+AgY4YePi8lReNSWbQEPIyrL7rz1j"
            + "Jy3AWdIZvYCKBxavJ8JT7qOuwCrVnjhC/fAlTzaWqvKAmelExOgQN0TrYbVJ"
            + "IFSB1Z4E867XLlS7Y1EJllNe1pTwuB7wMZfMJZFEVZ8DKnejtSyV0+FQtN3V"
            + "REYd0SE4+jqiFAYRCGG7nfSz2lBeSVFnrrEhf+my8fx3knaqnvhhOBpOWnH2"
            + "U1v3b92pxkHDsgCiZsScdbblUq3QaKaRI8Gzqsa+EmLTJpF3iBeibuDQuClV"
            + "PNW26dhRMa2GFf86GjieBOnOM8SSdMl8ofek+iWS0nXKnEBbZt5KWtzhAgMB"
            + "AAGjNjA0MBEGCisGAQQB2kcCAgEEAwEB/zAPBgNVHRMBAf8EBTADAQH/MA4G"
            + "A1UdDwEB/wQEAwIE8DANBgkqhkiG9w0BAQsFAAOCAQEASsWgiRMQAmupI9V4"
            + "B1A6g83fD72/JLVx+yJrplH1uO1t4A2oF631CKG3C78ZjJa4eIhHAzJ9i1EO"
            + "MUO0yOfooCpC0T8zsSlCNG55aT/ZztL53MFoo12pX6TnE3ChpG5bOmqAek13"
            + "8JWjgBAyGTOA2wHw88LezZrlA0U6UTDCNAl+ck3xAZHajMrHilo7K1tmKxeD"
            + "f4/z3mJm3kG0lvN/Zj/xLz1ClZ4rLKAfguubAcXSS3CWLupoN13Ba9NiHIiD"
            + "nzCTZq+5dDKeIE0NoViidgtCdr4UG1l8nfZLEJs6dHywXK4f3BoUyx/i4zYf"
            + "ZkHYc30PZx7Kz7FdE6B2FMf9jaroVgO9HnldW+a0DypyN5PcKZr7");

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        KeyBox kbx = new JcaKeyBoxBuilder().setProvider("BC").build(kbxData);

        List<Object> kbxObjs = loadKeyBoxKeys(kbx);

        for (Object o : kbxObjs)
        {
            System.err.println(o.getClass());
        }
    }
}
