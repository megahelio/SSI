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
            Security.addProvider(new BouncyCastleProvider());

            System.out.println("1. Generar clave DES");
            KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
            generadorDES.init(56); // clave de 56 bits
            SecretKey clave = generadorDES.generateKey();
            Cipher cifradorDES = Cipher.getInstance("DES/ECB/PKCS5Padding");
            System.out.println("2. Cifrar con DES el fichero " + args[0] +
                    ", dejar el resultado en " + args[0] + ".cifrado");

            cifradorDES.init(Cipher.ENCRYPT_MODE, clave);

            byte[] bufferExamen = Files.readAllBytes(Paths.get(args[0]));

            byte[] examenCifrado = cifradorDES.doFinal(bufferExamen);

            String nombrePaquete = args[1];

            PublicKey clavePublicaProfesor = recuperaClavePublica(args[2]);
            PrivateKey clavePrivadaAlumno = recuperarClavePrivada(args[3]);
            Cipher cifrador = Cipher.getInstance("RSA", "BC"); // Hace uso del provider BC
            
            cifrador.init(Cipher.ENCRYPT_MODE, clavePublicaProfesor); // Cifra con la clave publica

            byte[] claveCifrada = cifrador.doFinal(clave.getEncoded());
            Paquete p = new Paquete();
            p.anadirBloque("examenCifrado", examenCifrado);
            p.anadirBloque("claveCifrada", claveCifrada);


            p.escribirPaquete(nombrePaquete);

        }

    }

    public static void mostrarBytes(byte[] buffer) {
        System.out.write(buffer, 0, buffer.length);
    }

    public static PublicKey recuperaClavePublica(String stringClavePublica)
            throws Exception {

       
        KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");

        File ficheroClavePublica = new File(stringClavePublica + ".publica");
        int tamanoFicheroClavePublica = (int) ficheroClavePublica.length();
        byte[] bufferPub = new byte[tamanoFicheroClavePublica];
        try (FileInputStream in = new FileInputStream(ficheroClavePublica)) {
            in.read(bufferPub, 0, tamanoFicheroClavePublica);
            in.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
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
