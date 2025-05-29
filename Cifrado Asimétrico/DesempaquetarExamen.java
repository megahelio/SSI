import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

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
        if (args.length != 5) {
            System.out.println(
                    "java -cp [...] DesempaquetarExamen <fichero examen> <nombre paquete> <clave publica alumno> <clave privada profe> <clave publica autoridad>");
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
            PrivateKey clavePrivadaProfesor = recuperarClavePrivada(args[3]);
            PublicKey clavePublicaAutoridad = recuperaClavePublica(args[4]);

            if (debug) {
                System.out.println("ClavePrivadaProfesor: " + clavePrivadaProfesor.toString());
                System.out.println("ClavePublicaAlumno: " + clavePublicaAlumno.toString());
            }

            Signature firmador = Signature.getInstance("SHA1withRSA", "BC");
            firmador.initVerify(clavePublicaAlumno);
            firmador.update(p.getContenidoBloque("examenCifrado"));
            firmador.update(p.getContenidoBloque("claveSecreta"));

            if (!firmador.verify(p.getContenidoBloque("firma"))) {
                System.out.println("La firma del paquete no es correcta");
            } else {
                // se crea el cipher que desencriptará la clave
                Cipher descifradorRSA = Cipher.getInstance("RSA", "BC");
                descifradorRSA.init(Cipher.DECRYPT_MODE, clavePrivadaProfesor);
                // desencriptamos la clave secreta
                byte[] arrayClaveSecretaDES = descifradorRSA.doFinal(p.getContenidoBloque("claveSecreta"));

                // Se pasa de tener una clave secreta array de bytes a un objeto SecretKey que
                // podemos utilizar en Cipher
                SecretKeyFactory generadorDES = SecretKeyFactory.getInstance("DES");
                DESKeySpec DESspec = new DESKeySpec(arrayClaveSecretaDES);
                SecretKey claveSecretaDES = generadorDES.generateSecret(DESspec);

                // Iniciamos el cipher que desencriptará el exámen
                Cipher descifradorDES = Cipher.getInstance("DES/ECB/PKCS5Padding");
                descifradorDES.init(Cipher.DECRYPT_MODE, claveSecretaDES);

                byte[] examenCifrado = p.getContenidoBloque("EXAMENCIFRADO");
                if (debug) {
                    System.out.println("Descifrar exámen con clave privada\nTEXTO cifrado:");
                    mostrarBytes(examenCifrado);
                }
                byte[] examenClaro = descifradorDES.doFinal(examenCifrado);
                if (debug) {
                    System.out.println("TEXTO Claro:");
                    mostrarBytes(examenClaro);
                }

                FileOutputStream out = new FileOutputStream(args[0]);
                out.write(examenClaro);
                out.close();
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
