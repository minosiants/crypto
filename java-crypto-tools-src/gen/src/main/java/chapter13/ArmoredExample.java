package chapter13;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.util.Strings;

public class ArmoredExample
{
    public static void main(String[] args)
        throws Exception
    {
        byte[] msg = Strings.toByteArray("Hello, world!");

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = new ArmoredOutputStream(bOut);

        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();

        OutputStream lOut = lGen.open(aOut, PGPLiteralData.TEXT,
                            PGPLiteralData.CONSOLE, msg.length, new Date());

        lOut.write(msg);
        lOut.close();

        aOut.close();

        System.out.println(Strings.fromByteArray(bOut.toByteArray()));
    }
}
