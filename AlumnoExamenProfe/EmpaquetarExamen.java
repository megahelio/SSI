import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

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
            // Boolean debug = false;
            // System.out.println("Debug? Y/N");
            // Scanner respuesta = new Scanner(System.in);
            // if (respuesta.nextLine().toUpperCase().charAt(0) == 'Y')
            // debug = true;

            // respuesta.close();

            Security.addProvider(new BouncyCastleProvider());
            String ficheroExamen = args[0];
            String nombrePaquete = args[1];
            String ficheroClavePublicaProfesor = args[2];
            String ficheroClavePrivadaAlumno = args[3];
            //// #region Cifrado examen
            // generamos clave simétrica
            KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
            generadorDES.init(56); // clave de 56 bits
            SecretKey claveSimetricaDES = generadorDES.generateKey();

            // Creamos cifrador DES para la clave que acabamos de crear
            Cipher cifradorDES = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cifradorDES.init(Cipher.ENCRYPT_MODE, claveSimetricaDES);

            // Pasamos el fichero examen a array de bytes
            byte[] bufferExamen = Files.readAllBytes(Paths.get(ficheroExamen));
            // Ciframos el examen en modo simétrico y se guardará al final en el paquete
            byte[] examenCifrado = cifradorDES.doFinal(bufferExamen);
            // #endregion Cifrado examen

            PublicKey clavePublicaProfesorRSA = recuperaClavePublica(ficheroClavePublicaProfesor);
            PrivateKey clavePrivadaAlumnoRSA = recuperarClavePrivada(ficheroClavePrivadaAlumno);

            //// #region Cifrado clave
            // Encriptamos la clave simétrica DES
            Cipher cifrador = Cipher.getInstance("RSA", "BC");
            cifrador.init(Cipher.ENCRYPT_MODE, clavePublicaProfesorRSA);
            byte[] claveCifrada = cifrador.doFinal(claveSimetricaDES.getEncoded());
            //// #endregion Cifrado clave

            //#region firma
            /* Crear funciÃ³n resumen */
            MessageDigest messageDigest = MessageDigest.getInstance("MD5"); // Usa MD5
            // MessageDigest messageDigest = MessageDigest.getInstance("SHA"); // Usar SHA-1

            /* Leer fichero de 1k en 1k y pasar fragmentos leidos a la funcion resumen */
            byte[] buffer = new byte[1000];
            
            FileInputStream in = new FileInputStream(args[0]);
            int leidos = in.read(buffer, 0, 1000);
            while (leidos != -1) {
                messageDigest.update(buffer, 0, leidos); // Pasa texto de entrada a la funciÃ³n resumen
                leidos = in.read(buffer, 0, 1000);
            }
            in.close();

            byte[] resumen = messageDigest.digest(); // Completar el resumen

            // Mostrar resumen
            System.out.println("RESUMEN:");
            mostrarBytes(resumen);
            System.out.println();
            //#endregion firma

            Paquete p = new Paquete();
            p.anadirBloque("examenCifrado", examenCifrado);
            p.anadirBloque("claveSecreta", claveCifrada);
            // p.anadirBloque("firma", firma);

            p.escribirPaquete(nombrePaquete);

        }

    }

    public static void mostrarBytes(byte[] buffer) {
        System.out.write(buffer, 0, buffer.length);
    }

    public static PublicKey recuperaClavePublica(String stringClavePublica)
            throws Exception {

        KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");

        byte[] bufferPub = Files.readAllBytes(Paths.get(stringClavePublica));
        X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
        PublicKey clavePublica = keyFactoryRSA.generatePublic(clavePublicaSpec);

        System.out.println("ClavePublicaProfesor: " + clavePublica.toString());

        return clavePublica;

    }

    public static PrivateKey recuperarClavePrivada(String stringClavePrivada) throws Exception {

        KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");

        File ficheroClavePrivada = new File(stringClavePrivada + ".privada");
        int tamanoFicheroClavePrivada = (int) ficheroClavePrivada.length();
        byte[] bufferPriv = new byte[tamanoFicheroClavePrivada];
        FileInputStream in = new FileInputStream(ficheroClavePrivada);
        in.read(bufferPriv, 0, tamanoFicheroClavePrivada);
        in.close();

        PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
        PrivateKey clavePrivada = keyFactoryRSA.generatePrivate(clavePrivadaSpec);

        System.out.println("ClavePrivadaAlumno: " + clavePrivada.toString());

        return clavePrivada;

    }

}
