
/* https://www.bouncycastle.org/docs/docs1.5on/index.html */
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class LaMoovi {
    public static void main(String[] args) throws Exception {
        System.out.println("Hello, World!");

        Security.addProvider(new BouncyCastleProvider());
    }
}
