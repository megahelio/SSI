
/* https://www.bouncycastle.org/docs/docs1.5on/index.html */
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class LaMoovi {
    public static void main(String[] args) throws Exception {
        System.out.println("Hello, World!");

        Security.addProvider(new BouncyCastleProvider());

        Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS1Padding", "BC");
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
    }
}
