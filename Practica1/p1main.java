package Practica1;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

public class p1main {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());



    }
}
