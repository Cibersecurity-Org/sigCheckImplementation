
import java.util.*;
import Demo.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.io.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

public class signCheckerI implements signChecker {

    @Override
    public void generateKey(String keypassword, com.zeroc.Ice.Current current) {

    }

    public KeyPair generateKeyPair(Cliente cliente, int keySize) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }

    public void guardarClavePublica (PublicKey publicKey, String path, Cliente cliente) throws Exception {
        String nombreArchivo = cliente.getNombre()+"_publica.txt";
        try(FileWriter writer = new FileWriter(nombreArchivo)) {
            String claveBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            writer.write("--- CLAVE PÚBLICA RSA ---\n");
            writer.write("Cliente: " + cliente.getNombreCompleto() + "\n");
            writer.write("Email: " + cliente.getCorreo() + "\n");
            writer.write(claveBase64);
        }
        System.out.println("Clave pública guardada: " + nombreArchivo);
    }

    public void guardarClavePrivada (PrivateKey privateKey, String path, Cliente cliente, String password) throws Exception {
        String nombreArchivo = cliente.getNombre()+"_privada.p12";

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);

        KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(
                privateKey,
                new java.security.cert.Certificate[]{
                }
        );

        KeyStore.ProtectionParameter protectionParam =
                new KeyStore.PasswordProtection(password.toCharArray());

        keyStore.setEntry(cliente.getCorreo(), privateKeyEntry, protectionParam);

        // Guardar keystore en archivo
        try (FileOutputStream fos = new FileOutputStream(nombreArchivo)) {
            keyStore.store(fos, password.toCharArray());
        }

        System.out.println("Clave privada protegida con contrasena guardada: " + nombreArchivo);

    }


    
    @Override
    public boolean verifySign(String path, String signature, String publicKey, com.zeroc.Ice.Current current){
        System.out.println("Verifying signature for file: " + path);
        return true;
    }

    @Override
    public void signFile(String path, String signaturePath, String privateKey, String keyPassword, com.zeroc.Ice.Current current){
        System.out.println("Signing file: " + path);
    }
    
}
