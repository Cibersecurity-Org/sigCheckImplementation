
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
import java.math.BigInteger;
import java.security.cert.X509Certificate;

// BouncyCastle
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

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

    private java.security.cert.X509Certificate generarCertificadoSimple(PrivateKey privateKey, PublicKey publicKey, Cliente cliente) throws Exception {
        // Añadir proveedor BouncyCastle si aún no está registrado
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // Fechas de validez
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 1000L * 60);
        Date notAfter = new Date(now + 365L * 24 * 60 * 60 * 1000); // 1 año

        // DN del sujeto/issuer (auto-firmado)
        X500Name dnName = new X500Name("CN=" + cliente.getNombreCompleto() + ", O=MiEmpresa, EmailAddress=" + cliente.getCorreo());

        BigInteger serial = BigInteger.valueOf(now);

        // Construir certificado X.509 v3 auto-firmado
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName,
                serial,
                notBefore,
                notAfter,
                dnName,
                publicKey
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(privateKey);

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certBuilder.build(signer));

        // Validar certificado (lanzará excepción si algo falla)
        cert.checkValidity(new Date());
        cert.verify(publicKey);

        return cert;
    }

    public void guardarClavePrivada (PrivateKey privateKey, PublicKey publicKey, String path, Cliente cliente, String password) throws Exception {
        String nombreArchivo = new File(path, cliente.getNombre()+"_privada.p12").getAbsolutePath();

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        
        // Generar un certificado X.509 auto-firmado para incluir en el PKCS12
        X509Certificate cert = generarCertificadoSimple(privateKey, publicKey, cliente);
        java.security.cert.Certificate[] chain = new java.security.cert.Certificate[]{cert};

        // Crear entrada con clave privada y cadena de certificados
        KeyStore.ProtectionParameter protectionParam = 
                new KeyStore.PasswordProtection(password.toCharArray());
        KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(privateKey, chain);

        // Usar el correo como alias para la entrada
        keyStore.setEntry(cliente.getCorreo(), privateKeyEntry, protectionParam);

        // Asegurar que el directorio existe
        File file = new File(nombreArchivo);
        file.getParentFile().mkdirs();

        // Guardar keystore en archivo usando la misma contraseña para el keystore
        try (FileOutputStream fos = new FileOutputStream(file)) {
            keyStore.store(fos, password.toCharArray());
        }

        System.out.println("Clave privada protegida con contrasena guardada en: " + nombreArchivo);

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
