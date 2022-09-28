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

public class EmpaquetarExamen {
    public static void main(String[] args)
            throws Exception {
        if (args.length != 4) {
            System.out.println(
                    "Uso: java-cp[...]EmpaquetarExamen <fichero examen> <nombre paquete> <clave publica profesor> <clave privada alumno> ");

        } else {

            File ficheroExamen = new File(args[0]);
            int tamanhoFicheroExamen = (int) ficheroExamen.length();
            byte[] bufferExamen = new byte[tamanhoFicheroExamen]; // Cosa a encriptar
            try (FileInputStream in = new FileInputStream(ficheroExamen)) {
                in.read(bufferExamen, 0, tamanhoFicheroExamen);
                in.close();

            } catch (IOException e) {
                e.printStackTrace();
            }

            String nombrePaquete = args[1];

            PublicKey clavePublicaProfesor = recuperaClavePublica(args[2]);
            PrivateKey clavePrivadaAlumno = recuperarClavePrivada(args[3]);
            // PASO 2: Crear cifrador RSA
            Cipher cifrador = Cipher.getInstance("RSA", "BC"); // Hace uso del provider BC
            /************************************************************************
             * IMPORTANTE: En BouncyCastle el algoritmo RSA no funciona realmente en modo
             * ECB
             * * No divide el mensaje de entrada en bloques
             * * Solo cifra los primeros 512 bits (tam. clave)
             * * Si fuera necesario cifrar mensajes mayores (no suele
             * serlo al usar "cifrado hibrido"), habrÃ­a que hacer la
             * divisiÃ³n en bloques "a mano"
             ************************************************************************/

            // PASO 3a: Poner cifrador en modo CIFRADO
            cifrador.init(Cipher.ENCRYPT_MODE, clavePublicaProfesor); // Cifra con la clave publica

            System.out.println("Cifrar con clave publica");
            System.out.println("TEXTO CLARO");
            mostrarBytes(bufferExamen);
            System.out.println("\n-------------------------------");
            byte[] examenCifrado = cifrador.doFinal(bufferExamen);
            System.out.println("TEXTO CIFRADO");
            mostrarBytes(examenCifrado);
            System.out.println("\n-------------------------------");

            FileOutputStream out = new FileOutputStream("ExamenCifrado");
            out.write(examenCifrado);
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

        System.out.println("ClavePublicaProfesor: " + clavePublica.toString());

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

        System.out.println("ClavePrivadaAlumno: " + clavePrivada.toString());

        return clavePrivada;

    }

}
