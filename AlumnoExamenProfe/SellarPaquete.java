import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

// Valida la firma del alumno (al igual que haremos en desempaquetar examen)
// KR-privada KU-publica, Creo que la KU puede desencriptar cosas encriptadas con la clave privada

public class SellarPaquete {
    public static void main(String[] args) throws Exception {

        LocalDateTime marcaDeTiempo = LocalDateTime.now();

        if (args.length != 4) {
            System.out.println(
                    "java -cp [...] SellarPaquete <fichero examen> <nombre paquete> <clave publica alumno> <clave privada autoridad>");
        } else {

            Boolean debug = false;
            System.out.println("Debug? Y/N");
            Scanner respuesta = new Scanner(System.in);
            if (respuesta.nextLine().toUpperCase().charAt(0) == 'Y')
                debug = true;

            respuesta.close();

            String nombrePaquete = args[1];
            Paquete p = new Paquete(nombrePaquete);
            PublicKey clavePublicaAlumno = recuperaClavePublica(args[2]);
            PrivateKey clavePrivadaAutoridad = recuperarClavePrivada(args[3]);

            if (debug) {
                System.out.println("clavePrivadaAutoridad: " + clavePrivadaAutoridad.toString());
                System.out.println("ClavePublicaAlumno: " + clavePublicaAlumno.toString());
            }

            Signature firmador = Signature.getInstance("SHA1withRSA", "BC");
            firmador.initVerify(clavePublicaAlumno);
            firmador.update(p.getContenidoBloque("examenCifrado"));
            firmador.update(p.getContenidoBloque("claveSecreta"));

            if (!firmador.verify(p.getContenidoBloque("firma"))) {
                System.out.println("La firma del paquete no es correcta");
            } else {
                
                firmador.initSign(clavePrivadaAutoridad);
                firmador.update(marcaDeTiempo.toString().getBytes());
                byte[] firma = firmador.sign();

                p.anadirBloque("firmaAutoridad", firma);
                p.escribirPaquete(nombrePaquete);

            }

        }

    }

    public static void mostrarBytes(byte[] buffer) {
        System.out.println("\n-------------------------------");
        System.out.write(buffer, 0, buffer.length);
        System.out.println("\n-------------------------------");
    }

    public static PublicKey recuperaClavePublica(String stringClavePublica)
            throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");

        /*** 4 Recuperar clave PUBLICA del fichero */
        // 4.1 Leer datos binarios x809
        File ficheroClavePublica = new File(stringClavePublica);
        int tamanoFicheroClavePublica = (int) ficheroClavePublica.length();
        byte[] bufferPub = new byte[tamanoFicheroClavePublica];
        try (FileInputStream in = new FileInputStream(ficheroClavePublica)) {
            in.read(bufferPub, 0, tamanoFicheroClavePublica);
            in.close();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        // 4.2 Recuperar clave publica desde datos codificados en formato X509
        X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
        PublicKey clavePublica = keyFactoryRSA.generatePublic(clavePublicaSpec);

        return clavePublica;

    }

    public static PrivateKey recuperarClavePrivada(String stringClavePrivada) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");

        /*** 2 Recuperar clave Privada del fichero */
        // 2.1 Leer datos binarios PKCS8
        File ficheroClavePrivada = new File(stringClavePrivada);
        int tamanoFicheroClavePrivada = (int) ficheroClavePrivada.length();
        byte[] bufferPriv = new byte[tamanoFicheroClavePrivada];
        FileInputStream in = new FileInputStream(ficheroClavePrivada);
        in.read(bufferPriv, 0, tamanoFicheroClavePrivada);
        in.close();

        // 2.2 Recuperar clave privada desde datos codificados en formato PKCS8
        PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
        PrivateKey clavePrivada = keyFactoryRSA.generatePrivate(clavePrivadaSpec);

        return clavePrivada;

    }

}
