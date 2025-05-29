package AlumnoExamenProfe;
import java.io.*;

import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

// Necesario para usar el provider Bouncy Castle (BC)
//    Para compilar incluir el fichero JAR en el classpath

public class AlmacenarClaves {
	public static void main(String[] args) throws Exception {
		if (args.length != 1) {
			mensajeAyuda();
			System.exit(1);
		}

		System.out.println("Crea los ficheros "+args[0]+".secreta, "
				+args[0]+".publica, "+args[0]+".privada");
		
		// Anadir provider  (el provider por defecto no soporta RSA)
		Security.addProvider(new BouncyCastleProvider()); // Cargar el provider BC

		/*** Crear claves RSA 512 bits  */
		KeyPairGenerator generadorRSA = KeyPairGenerator.getInstance("RSA", "BC"); // Hace uso del provider BC
		generadorRSA.initialize(512);
		KeyPair clavesRSA = generadorRSA.generateKeyPair();
		PrivateKey clavePrivada = clavesRSA.getPrivate();
		PublicKey clavePublica = clavesRSA.getPublic();

		/*** Crear KeyFactory (depende del provider) usado para las transformaciones de claves*/
		KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC"); // Hace uso del provider BC

		/*** 1 Volcar clave privada  a fichero */
		// 1.1 Recuperar de la clave su codificaciÃ³n en formato PKS8 (necesario para escribirla a disco)
		byte[] encodedPKCS8 = clavePrivada.getEncoded();

		// 1.2 Escribirla a fichero binario
		FileOutputStream out = new FileOutputStream(args[0] + ".privada");
		out.write(encodedPKCS8);
		out.close();

                // NOTA: no es estrictamente necesario crear el objeto intermedio PKCS8EncodedKeySpec
                //       para generar el byte[] con la representaciÃ³n PKCS8 de la clave, dado que la salida
                //       del metodo getEncoded() de un objeto PrivateKey ya es un byte[] con su codificacion PKCS8
                //
                //       En el ejemplo se hace asÃ­ por simetrÃ­a con el proceso de lectura de claves privadas desde 
                //       fichero, que si requiere el paso intermedio de crear un PKCS8EncodedKeySpec

		/*** 2 Recuperar clave Privada del fichero */
		// 2.1 Leer datos binarios PKCS8
		File ficheroClavePrivada = new File(args[0] + ".privada"); 
		int tamanoFicheroClavePrivada = (int) ficheroClavePrivada.length();
		byte[] bufferPriv = new byte[tamanoFicheroClavePrivada];
		FileInputStream in = new FileInputStream(ficheroClavePrivada);
		in.read(bufferPriv, 0, tamanoFicheroClavePrivada);
		in.close();

		// 2.2 Recuperar clave privada desde datos codificados en formato PKCS8
		PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
		PrivateKey clavePrivada2 = keyFactoryRSA.generatePrivate(clavePrivadaSpec);

		if (clavePrivada.equals(clavePrivada2)) {
			System.out.println("OK: clave privada guardada y recuperada");
		}

		/*** 3 Volcar clave publica  a fichero */
		// 3.1  Recuperar de la clave su codificaciÃ³n en formato X509 (necesario para escribirla a disco)
		byte[] encodedX509 = clavePublica.getEncoded();

		// 3.2 Escribirla a fichero binario
		out = new FileOutputStream(args[0] + ".publica");
		out.write(encodedX509);
		out.close();

                // NOTA: no es estrictamente necesario crear el objeto intermedio X509EncodedKeySpec
                //       para generar el byte[] con la representaciÃ³n X509 de la clave, dado que la salida
                //       del metodo getEncoded() de un objeto PublicKey ya es un byte[] con su codificacion X509
                //
                //       En el ejemplo se hace asÃ­ por simetrÃ­a con el proceso de lectura de claves publicas desde 
                //       fichero, que si requiere el paso intermedio de crear un X509EncodedKeySpec

		/*** 4 Recuperar clave PUBLICA del fichero */
		// 4.1 Leer datos binarios x809
		File ficheroClavePublica = new File(args[0] + ".publica"); 
		int tamanoFicheroClavePublica = (int) ficheroClavePublica.length();
		byte[] bufferPub = new byte[tamanoFicheroClavePublica];
		in = new FileInputStream(ficheroClavePublica);
		in.read(bufferPub, 0, tamanoFicheroClavePublica);
		in.close();

		// 4.2 Recuperar clave publica desde datos codificados en formato X509
		X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
		PublicKey clavePublica2 = keyFactoryRSA.generatePublic(clavePublicaSpec);

		if (clavePublica.equals(clavePublica2)) {
			System.out.println("OK: clave publica guardada y recuperada");
		}

		/*** Crear e inicializar clave  DES */
		KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
		generadorDES.init(56);
		SecretKey claveSecreta = generadorDES.generateKey();

		/*** Crear SecretKeyFactory usado para las transformaciones de claves secretas*/
		SecretKeyFactory secretKeyFactoryDES = SecretKeyFactory.getInstance("DES");

		/*** 5 Volcar clave secreta  a fichero */
		// 5.1 Escribirla directamente a fichero binario (vÃ¡lido para DES y 3DES)
		out = new FileOutputStream(args[0] + ".secreta");
		out.write(claveSecreta.getEncoded());  // Puede accederse al bute[] de las 
                                                       // claves secretas directamente  sin 
                                                       // requerir una codificacion intermedia
                                                       // (son numeros simples, no tienen "estructura")
		out.close();

		/*** 6 Recuperar clave secreta del fichero */
		// 6.1 Leer datos binarios directamente (vÃ¡lido para DES y 3DES)
		File ficheroClaveSecreta = new File(args[0] + ".secreta"); 
		int tamanoFicheroClaveSecreta = (int) ficheroClaveSecreta.length();	
		byte[] bufferSecr = new byte[tamanoFicheroClaveSecreta];
		in = new FileInputStream(ficheroClaveSecreta);
		in.read(bufferSecr, 0, tamanoFicheroClaveSecreta);
		in.close();

		// 6.2 Cargar clave directamente desd elos datos leidos
		DESKeySpec DESspec = new DESKeySpec(bufferSecr);
		SecretKey claveSecreta2 = secretKeyFactoryDES.generateSecret(DESspec);

		if (claveSecreta.equals(claveSecreta2)) {
			System.out.println("OK: clave secreta guardada y recuperada");
		}
	}

	public static void mensajeAyuda() {
		System.out.println("Ejemplo almacenamiento de claves");
		System.out.println("\tSintaxis:   java AlmacenarClaves prefijo");
		System.out.println();
	}
}