import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
// linux -cp .:provider.jar

// java-cp[...]EmpaquetarExamen <fichero examen> <nombre paquete> <clavePublicaProfesor> <ClavePrivada Alumno>

// Usado por el ALUMNO Se le pasa en línea de comandos un fichero de texto con el contenido del examen
//  a enviar,el nombre del paquete resultante y el path de los ficheros con las claves necesarias para 
//  el empaquetado(el número y tipo exacto de los ficheros de claves dependerá de que estrategia se haya 
//  decidido seguir).Genera el fichero<nombre paquete>(por ejemplo examen.paquete)con el resultado de”empaquetar”
//  los datos que conforman el Examen Empaquetado.

public class DesempaquetarExamen {
    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.out.println(
                    "java -cp [...] DesempaquetarExamen <fichero examen> <nombre paquete> <clave publica alumno> <clave privada profe>");
        } else {
            File ficheroExamen = new File(args[0]);
            int tamanhoFicheroExamen = (int) ficheroExamen.length();
            byte[] examenCifrado = new byte[tamanhoFicheroExamen]; // Cosa a encriptar
            try (FileInputStream in = new FileInputStream(ficheroExamen)) {
                in.read(examenCifrado, 0, tamanhoFicheroExamen);
                in.close();

            } catch (IOException e) {
                e.printStackTrace();
            }

            String nombrePaquete = args[1];

            PublicKey clavePublicaAlumno = recuperaClavePublica(args[2]);
            PrivateKey clavePrivadaProfesor = recuperarClavePrivada(args[3]);

            Cipher cifrador = Cipher.getInstance("RSA", "BC");
            cifrador.init(Cipher.DECRYPT_MODE, clavePrivadaProfesor); // Cifra con la clave publica

            System.out.println("Cifrar con clave publica");
            System.out.println("TEXTO CLARO");
            mostrarBytes(examenCifrado);
            System.out.println("\n-------------------------------");
            byte[] examenClaro = cifrador.doFinal(examenCifrado);
            System.out.println("TEXTO CIFRADO");
            mostrarBytes(examenClaro);
            System.out.println("\n-------------------------------");

            FileOutputStream out = new FileOutputStream("ExamenClaro");
            out.write(examenClaro);
            out.close();
        }
    }

    public static void mostrarBytes(byte[] buffer) {
        System.out.write(buffer, 0, buffer.length);
    }

    public static PublicKey recuperaClavePublica(String stringClavePublica)
            throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");

        /*** 4 Recuperar clave PUBLICA del fichero */
        // 4.1 Leer datos binarios x809
        File ficheroClavePublica = new File(stringClavePublica + ".publica");
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

        System.out.println("ClavePublicaAlumno: " + clavePublica.toString());

        return clavePublica;

    }

    public static PrivateKey recuperarClavePrivada(String stringClavePrivada) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");

        /*** 2 Recuperar clave Privada del fichero */
        // 2.1 Leer datos binarios PKCS8
        File ficheroClavePrivada = new File(stringClavePrivada + ".privada");
        int tamanoFicheroClavePrivada = (int) ficheroClavePrivada.length();
        byte[] bufferPriv = new byte[tamanoFicheroClavePrivada];
        FileInputStream in = new FileInputStream(ficheroClavePrivada);
        in.read(bufferPriv, 0, tamanoFicheroClavePrivada);
        in.close();

        // 2.2 Recuperar clave privada desde datos codificados en formato PKCS8
        PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
        PrivateKey clavePrivada = keyFactoryRSA.generatePrivate(clavePrivadaSpec);

        System.out.println("ClavePrivadaProfesor: " + clavePrivada.toString());

        return clavePrivada;

    }

}
