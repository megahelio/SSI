import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

import java.io.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
// Necesario para usar el provider Bouncy Castle (BC)
//    Para compilar incluir el fichero JAR en el classpath
// 

public class EjemploRSA {
    public static void main(String[] args) throws Exception {

        // Anadir provider JCE (provider por defecto no soporta RSA)
        Security.addProvider(new BouncyCastleProvider()); // Cargar el provider BC

        System.out.println("1. Creando claves publica y privada");

        // PASO 1: Crear e inicializar el par de claves RSA DE 512 bits
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC"); // Hace uso del provider BC
        keyGen.initialize(512); // tamano clave 512 bits
        KeyPair clavesRSA = keyGen.generateKeyPair();
        PrivateKey clavePrivada = clavesRSA.getPrivate();
        PublicKey clavePublica = clavesRSA.getPublic();

        System.out.print("2. Introducir Texto Plano (max. 64 caracteres / 512 bits): ");
        byte[] bufferPlano = leerLinea(System.in);

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
        cifrador.init(Cipher.ENCRYPT_MODE, clavePublica); // Cifra con la clave publica

        System.out.println("3a. Cifrar con clave publica");
        byte[] bufferCifrado = cifrador.doFinal(bufferPlano);
        System.out.println("TEXTO CIFRADO");
        mostrarBytes(bufferCifrado);
        System.out.println("\n-------------------------------");

        // PASO 3b: Poner cifrador en modo DESCIFRADO
        cifrador.init(Cipher.DECRYPT_MODE, clavePrivada); // Descrifra con la clave privada

        System.out.println("3b. Descifrar con clave privada");
        byte[] bufferPlano2 = cifrador.doFinal(bufferCifrado);
        System.out.println("TEXTO DESCIFRADO");
        mostrarBytes(bufferPlano2);
        System.out.println("\n-------------------------------");

        // PASO 3a: Poner cifrador en modo CIFRADO
        cifrador.init(Cipher.ENCRYPT_MODE, clavePrivada); // Cifra con la clave publica

        System.out.println("4a. Cifrar con clave privada");
        bufferCifrado = cifrador.doFinal(bufferPlano);
        System.out.println("TEXTO CIFRADO");
        mostrarBytes(bufferCifrado);
        System.out.println("\n-------------------------------");

        // PASO 3b: Poner cifrador en modo DESCIFRADO
        cifrador.init(Cipher.DECRYPT_MODE, clavePublica); // Descrifra con la clave privada

        System.out.println("4b. Descifrar con clave publica");
        bufferPlano2 = cifrador.doFinal(bufferCifrado);
        System.out.println("TEXTO DESCIFRADO");
        mostrarBytes(bufferPlano2);
        System.out.println("\n-------------------------------");
    } // Fin main

    public static byte[] leerLinea(java.io.InputStream in) throws IOException {
        byte[] buffer1 = new byte[1000];
        int i = 0;
        byte c;
        c = (byte) in.read();
        while ((c != '\n') && (i < 1000)) {
            buffer1[i] = c;
            c = (byte) in.read();
            i++;
        }

        byte[] buffer2 = new byte[i];
        for (int j = 0; j < i; j++) {
            buffer2[j] = buffer1[j];
        }
        return (buffer2);
    }

    public static void mostrarBytes(byte[] buffer) {
        System.out.write(buffer, 0, buffer.length);
    }

} // Fin clase