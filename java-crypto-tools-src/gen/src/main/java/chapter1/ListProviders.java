package chapter1;

import java.security.Provider;
import java.security.Security;

/**
 * Simple application to list installed providers and their available info.
 */
public class ListProviders
{
    public static void main(String[] args)
    {
        Provider[] installedProvs = Security.getProviders();

        for (int i = 0; i != installedProvs.length; i++)
        {
            System.out.print(installedProvs[i].getName());
            System.out.print(": ");
            System.out.print(installedProvs[i].getInfo());
            System.out.println();
        }
    }
}
