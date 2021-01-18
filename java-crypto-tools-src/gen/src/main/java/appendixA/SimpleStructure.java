package appendixA;

import java.math.BigInteger;
import java.text.ParseException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.util.Arrays;

/**
 * Implementation of SimpleStructure - an example ASN.1 object (tagging
 * IMPLICIT).
 * <pre>
 *     SimpleStructure ::= SEQUENCE {
 *         version INTEGER DEFAULT 0,
 *         created GeneralizedTime,
 *         data OCTET STRING,
 *         comment [0] UTF8String OPTIONAL
 *     }
 * </pre>
 */
public class SimpleStructure
    extends ASN1Object
{
    private final BigInteger version;
    private final Date created;
    private final byte[] data;

    private String comment;

    /**
     * Convert, or cast, the passed in object into a SimpleStructure
     * as appropriate.
     *
     * @param obj the object of interest.
     * @return a SimpleStructure
     */
    public static SimpleStructure getInstance(
        Object  obj)
    {
        if (obj instanceof SimpleStructure)
        {
            return (SimpleStructure)obj;
        }
        else if (obj != null)
        {
            return new SimpleStructure(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * Create a structure with a default version.
     *
     * @param created creation date.
     * @param data encoded data to contain.
     */
    public SimpleStructure(Date created, byte[] data)
    {
        this(0, created, data, null);
    }

    /**
     * Create a structure with a default version and the optional comment.
     *
     * @param created creation date.
     * @param data encoded data to contain.
     * @param comment the comment to use.
     */
    public SimpleStructure(Date created, byte[] data, String comment)
    {
        this(0, created, data, comment);
    }

    /**
     * Create a structure with a specific version and the optional comment.
     *
     * @param version the version number to use.
     * @param created creation date.
     * @param data encoded data to contain.
     * @param comment the comment to use.
     */
    public SimpleStructure(int version, Date created,
                           byte[] data, String comment)
    {
        this.version = BigInteger.valueOf(version);
        this.created = new Date(created.getTime());
        this.data = Arrays.clone(data);

        if (comment != null)
        {
            this.comment = comment;
        }
        else
        {
            this.comment = null;
        }
    }

    // Note: private constructor for sequence - we want users to get
    // into the habit of using getInstance(). It's safer!
    private SimpleStructure(ASN1Sequence seq)
    {
        int index = 0;

        if (seq.getObjectAt(0) instanceof ASN1Integer)
        {
            this.version = ASN1Integer.getInstance(
                                 seq.getObjectAt(0)).getValue();
            index++;
        }
        else
        {
            this.version = BigInteger.ZERO;
        }

        try
        {
            this.created = ASN1GeneralizedTime.getInstance(
                                seq.getObjectAt(index++)).getDate();
        }
        catch (ParseException e)
        {
            throw new IllegalArgumentException(
                "exception parsing created: " + e.getMessage(), e);
        }

        this.data = Arrays.clone(
            ASN1OctetString.getInstance(seq.getObjectAt(index++)).getOctets());

        for (int i = index; i != seq.size(); i++)
        {
            ASN1TaggedObject t = ASN1TaggedObject.getInstance(
                                                     seq.getObjectAt(i));

            if (t.getTagNo() == 0)
            {
                comment = DERUTF8String.getInstance(t, false)
                                                            .getString();
            }
        }
    }

    public BigInteger getVersion()
    {
        return version;
    }

    public Date getCreated()
        throws ParseException
    {
        return new Date(created.getTime());
    }

    public byte[] getData()
    {
        return Arrays.clone(data);
    }

    public String getComment()
    {
        return comment;
    }

    /**
     * Produce a DER representation of the object.
     *
     * @return an ASN1Primitive made up of DER primitives.
     */
    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        // DER encoding rules specify that fields with
        // the value of their specified DEFAULT are left out
        // of the encoding
        if (!version.equals(BigInteger.ZERO))
        {
             v.add(new ASN1Integer(version));
        }

        v.add(new DERGeneralizedTime(created));
        v.add(new DEROctetString(data));

        if (comment != null)
        {
            v.add(new DERTaggedObject(false, 0, new DERUTF8String(comment)));
        }

        return new DERSequence(v);
    }
}
