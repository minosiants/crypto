package chapter1;

import java.security.Provider;
import java.security.Security;
import java.util.Iterator;

/**
 * Simple application to list the capabilities (including alias names)
 * of a provider.
 * <pre>
 *     usage: chapter1.ListProviderCapabilites provider_name
 * </pre>
 */
public class ListProviderCapabilities
{
    public static void main(String[] args)
    {
        if (args.length != 1)
        {
            System.err.println(
                "usage: chapter1.ListProviderCapabilites provider_name");
            System.exit(1);
        }

        Provider provider = Security.getProvider(args[0]);

        if (provider != null)
        {
            for (Iterator it = provider.keySet().iterator(); it.hasNext();)
            {
                String entry = (String)it.next();
                boolean isAlias = false;

                // an alias entry refers to another entry
                if (entry.startsWith("Alg.Alias"))
                {
                    isAlias = true;
                    entry = entry.substring("Alg.Alias".length() + 1);
                }

                String serviceName = entry.substring(
                                            0, entry.indexOf('.'));
                String name = entry.substring(serviceName.length() + 1);

                if (isAlias)
                {
                    System.out.print(serviceName + ": " + name);
                    System.out.println(" (alias for "
                              + provider.get("Alg.Alias." + entry) + ")");
                }
                else
                {
                    System.out.println(serviceName + ": " + name);
                }
            }
        }
        else
        {
            System.err.println("provider " + args[0] + " not found");
            System.exit(1);
        }
    }
}
