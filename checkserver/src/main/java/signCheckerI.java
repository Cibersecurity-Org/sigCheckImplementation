
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

    // ============================================================================
    // MÉTODOS PÚBLICOS DE LA INTERFAZ ICE
    // ============================================================================

    /**
     * Firma digitalmente un archivo usando RSA con SHA-256.
     * 
     * @param path Ruta del archivo a firmar
     * @param signaturePath Ruta donde se guardará la firma digital (Base64)
     * @param privateKeyPath Ruta del archivo PKCS12 con la clave privada
     * @param keyPassword Contraseña para desbloquear la clave privada
     * @param current Contexto Ice (puede ser null en pruebas locales)
     */
    @Override
    public void signFile(String path, String signaturePath, String privateKeyPath, String keyPassword, com.zeroc.Ice.Current current) {
        try {
            // Validar parámetros
            validarParametrosSignFile(path, signaturePath, privateKeyPath, keyPassword);
            
            System.out.println("=== INICIANDO PROCESO DE FIRMA DIGITAL ===");
            System.out.println("Archivo a firmar: " + path);
            
            // 1. Verificar que el archivo existe
            File archivoAFirmar = new File(path);
            if (!archivoAFirmar.exists() || !archivoAFirmar.isFile()) {
                throw new IllegalArgumentException("El archivo no existe o no es válido: " + path);
            }
            
            // 2. Cargar la clave privada desde el archivo PKCS12
            System.out.println("Cargando clave privada desde: " + privateKeyPath);
            PrivateKey clavePrivada = cargarClavePrivadaDesdeP12(privateKeyPath, keyPassword);
            
            // 3. Calcular el hash del archivo (SHA-256)
            System.out.println("Calculando hash SHA-256 del archivo...");
            byte[] hashArchivo = calcularHashArchivo(archivoAFirmar);
            System.out.println("Hash calculado: " + bytesToHex(hashArchivo));
            
            // 4. Firmar el hash con la clave privada
            System.out.println("Firmando con algoritmo SHA256withRSA...");
            byte[] firma = firmarHash(hashArchivo, clavePrivada);
            
            // 5. Guardar la firma en formato Base64
            guardarFirma(firma, signaturePath);
            
            System.out.println("✓ FIRMA DIGITAL GENERADA EXITOSAMENTE");
            System.out.println("Firma guardada en: " + signaturePath);
            System.out.println("Tamaño de la firma: " + firma.length + " bytes");
            
        } catch (IllegalArgumentException e) {
            System.err.println("✗ ERROR DE VALIDACIÓN: " + e.getMessage());
            throw new RuntimeException("Error de validación: " + e.getMessage(), e);
        } catch (Exception e) {
            System.err.println("✗ ERROR AL FIRMAR ARCHIVO: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Error al firmar archivo: " + e.getMessage(), e);
        }
    }

    /**
     * Verifica la firma digital de un archivo.
     * 
     * @param path Ruta del archivo original
     * @param signaturePath Ruta del archivo con la firma digital en Base64
     * @param publicKeyPath Ruta del archivo con la clave pública en Base64
     * @param current Contexto Ice (puede ser null en pruebas locales)
     * @return true si la firma es válida, false en caso contrario
     */
    @Override
    public boolean verifySign(String path, String signaturePath, String publicKeyPath, com.zeroc.Ice.Current current) {
        try {
            // Validar parámetros
            validarParametrosVerifySign(path, signaturePath, publicKeyPath);
            
            System.out.println("=== INICIANDO VERIFICACIÓN DE FIRMA DIGITAL ===");
            System.out.println("Archivo: " + path);
            System.out.println("Firma: " + signaturePath);
            
            // 1. Verificar que los archivos existen
            File archivoOriginal = new File(path);
            File archivoFirma = new File(signaturePath);
            
            if (!archivoOriginal.exists() || !archivoOriginal.isFile()) {
                throw new IllegalArgumentException("El archivo original no existe: " + path);
            }
            
            if (!archivoFirma.exists() || !archivoFirma.isFile()) {
                throw new IllegalArgumentException("El archivo de firma no existe: " + signaturePath);
            }
            
            // 2. Cargar la clave pública
            System.out.println("Cargando clave pública desde: " + publicKeyPath);
            PublicKey clavePublica = cargarClavePublicaDesdeArchivo(publicKeyPath);
            
            // 3. Cargar la firma
            System.out.println("Cargando firma digital...");
            byte[] firma = cargarFirma(signaturePath);
            
            // 4. Calcular el hash del archivo original
            System.out.println("Calculando hash SHA-256 del archivo...");
            byte[] hashArchivo = calcularHashArchivo(archivoOriginal);
            System.out.println("Hash calculado: " + bytesToHex(hashArchivo));
            
            // 5. Verificar la firma
            System.out.println("Verificando firma con algoritmo SHA256withRSA...");
            boolean esValida = verificarFirmaHash(hashArchivo, firma, clavePublica);
            
            if (esValida) {
                System.out.println("✓ FIRMA VÁLIDA: El archivo es auténtico y no ha sido modificado");
            } else {
                System.out.println("✗ FIRMA INVÁLIDA: El archivo ha sido modificado o la firma no corresponde");
            }
            
            return esValida;
            
        } catch (IllegalArgumentException e) {
            System.err.println("✗ ERROR DE VALIDACIÓN: " + e.getMessage());
            return false;
        } catch (Exception e) {
            System.err.println("✗ ERROR AL VERIFICAR FIRMA: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    // ============================================================================
    // MÉTODOS AUXILIARES PRIVADOS - VALIDACIÓN
    // ============================================================================

    /**
     * Valida los parámetros del método signFile.
     */
    private void validarParametrosSignFile(String path, String signaturePath, String privateKeyPath, String keyPassword) {
        if (path == null || path.trim().isEmpty()) {
            throw new IllegalArgumentException("La ruta del archivo a firmar no puede estar vacía");
        }
        if (signaturePath == null || signaturePath.trim().isEmpty()) {
            throw new IllegalArgumentException("La ruta de la firma no puede estar vacía");
        }
        if (privateKeyPath == null || privateKeyPath.trim().isEmpty()) {
            throw new IllegalArgumentException("La ruta de la clave privada no puede estar vacía");
        }
        if (keyPassword == null || keyPassword.isEmpty()) {
            throw new IllegalArgumentException("La contraseña no puede estar vacía");
        }
    }

    /**
     * Valida los parámetros del método verifySign.
     */
    private void validarParametrosVerifySign(String path, String signaturePath, String publicKeyPath) {
        if (path == null || path.trim().isEmpty()) {
            throw new IllegalArgumentException("La ruta del archivo no puede estar vacía");
        }
        if (signaturePath == null || signaturePath.trim().isEmpty()) {
            throw new IllegalArgumentException("La ruta de la firma no puede estar vacía");
        }
        if (publicKeyPath == null || publicKeyPath.trim().isEmpty()) {
            throw new IllegalArgumentException("La ruta de la clave pública no puede estar vacía");
        }
    }

    // ============================================================================
    // MÉTODOS AUXILIARES PRIVADOS - CARGA DE CLAVES
    // ============================================================================

    /**
     * Carga una clave privada desde un archivo PKCS12.
     * 
     * @param rutaP12 Ruta del archivo PKCS12
     * @param password Contraseña para desbloquear el keystore
     * @return La clave privada
     * @throws Exception Si ocurre algún error al cargar la clave
     */
    private PrivateKey cargarClavePrivadaDesdeP12(String rutaP12, String password) throws Exception {
        File archivoP12 = new File(rutaP12);
        
        if (!archivoP12.exists()) {
            throw new FileNotFoundException("Archivo PKCS12 no encontrado: " + rutaP12);
        }
        
        // Cargar el keystore PKCS12
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        
        try (FileInputStream fis = new FileInputStream(archivoP12)) {
            keyStore.load(fis, password.toCharArray());
        }
        
        // Obtener el primer alias (generalmente el correo del cliente)
        Enumeration<String> aliases = keyStore.aliases();
        
        if (!aliases.hasMoreElements()) {
            throw new IllegalStateException("El archivo PKCS12 no contiene ninguna entrada");
        }
        
        String alias = aliases.nextElement();
        
        // Obtener la clave privada
        Key key = keyStore.getKey(alias, password.toCharArray());
        
        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        } else {
            throw new IllegalStateException("La entrada no contiene una clave privada válida");
        }
    }

    /**
     * Carga una clave pública desde un archivo en formato Base64.
     * 
     * @param rutaClavePublica Ruta del archivo con la clave pública
     * @return La clave pública
     * @throws Exception Si ocurre algún error al cargar la clave
     */
    private PublicKey cargarClavePublicaDesdeArchivo(String rutaClavePublica) throws Exception {
        File archivo = new File(rutaClavePublica);
        
        if (!archivo.exists()) {
            throw new FileNotFoundException("Archivo de clave pública no encontrado: " + rutaClavePublica);
        }
        
        // Leer todo el contenido del archivo
        StringBuilder contenido = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(archivo))) {
            String linea;
            while ((linea = reader.readLine()) != null) {
                // Ignorar líneas de encabezado y metadatos
                if (!linea.startsWith("---") && !linea.startsWith("Cliente:") && !linea.startsWith("Email:")) {
                    contenido.append(linea.trim());
                }
            }
        }
        
        if (contenido.length() == 0) {
            throw new IllegalArgumentException("El archivo de clave pública está vacío o no tiene contenido válido");
        }
        
        // Decodificar Base64
        byte[] bytesClavePublica = Base64.getDecoder().decode(contenido.toString());
        
        // Generar la clave pública
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytesClavePublica);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        
        return keyFactory.generatePublic(keySpec);
    }

    // ============================================================================
    // MÉTODOS AUXILIARES PRIVADOS - OPERACIONES CRIPTOGRÁFICAS
    // ============================================================================

    /**
     * Calcula el hash SHA-256 de un archivo.
     * 
     * @param archivo Archivo a hashear
     * @return Hash del archivo en bytes
     * @throws Exception Si ocurre algún error al leer o hashear el archivo
     */
    private byte[] calcularHashArchivo(File archivo) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        
        try (FileInputStream fis = new FileInputStream(archivo);
             BufferedInputStream bis = new BufferedInputStream(fis)) {
            
            byte[] buffer = new byte[8192]; // Buffer de 8KB para lectura eficiente
            int bytesLeidos;
            
            while ((bytesLeidos = bis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesLeidos);
            }
        }
        
        return digest.digest();
    }

    /**
     * Firma un hash usando una clave privada con el algoritmo SHA256withRSA.
     * 
     * @param hash Hash a firmar
     * @param clavePrivada Clave privada para firmar
     * @return Firma digital en bytes
     * @throws Exception Si ocurre algún error al firmar
     */
    private byte[] firmarHash(byte[] hash, PrivateKey clavePrivada) throws Exception {
        // Nota: Aunque calculamos el hash previamente, Signature.sign() lo vuelve a hashear
        // internamente cuando usamos SHA256withRSA. Para este caso, usamos NONEwithRSA
        // y firmamos directamente el hash calculado.
        
        Signature signature = Signature.getInstance("NONEwithRSA");
        signature.initSign(clavePrivada);
        signature.update(hash);
        
        return signature.sign();
    }

    /**
     * Verifica una firma digital usando una clave pública.
     * 
     * @param hash Hash original del archivo
     * @param firma Firma digital a verificar
     * @param clavePublica Clave pública para verificar
     * @return true si la firma es válida, false en caso contrario
     */
    private boolean verificarFirmaHash(byte[] hash, byte[] firma, PublicKey clavePublica) {
        try {
            Signature signature = Signature.getInstance("NONEwithRSA");
            signature.initVerify(clavePublica);
            signature.update(hash);
            
            return signature.verify(firma);
            
        } catch (Exception e) {
            System.err.println("Error al verificar firma: " + e.getMessage());
            return false;
        }
    }

    // ============================================================================
    // MÉTODOS AUXILIARES PRIVADOS - PERSISTENCIA DE FIRMAS
    // ============================================================================

    /**
     * Guarda una firma digital en un archivo en formato Base64.
     * 
     * @param firma Firma digital en bytes
     * @param rutaDestino Ruta donde guardar la firma
     * @throws Exception Si ocurre algún error al guardar
     */
    private void guardarFirma(byte[] firma, String rutaDestino) throws Exception {
        File archivo = new File(rutaDestino);
        
        // Crear directorios si no existen
        File directorioPadre = archivo.getParentFile();
        if (directorioPadre != null && !directorioPadre.exists()) {
            directorioPadre.mkdirs();
        }
        
        // Codificar firma en Base64 y guardar
        String firmaBase64 = Base64.getEncoder().encodeToString(firma);
        
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(archivo))) {
            writer.write("--- FIRMA DIGITAL RSA/SHA-256 ---\n");
            writer.write("Fecha: " + new Date() + "\n");
            writer.write("Algoritmo: SHA256withRSA\n");
            writer.write("---\n");
            writer.write(firmaBase64);
        }
    }

    /**
     * Carga una firma digital desde un archivo en formato Base64.
     * 
     * @param rutaFirma Ruta del archivo con la firma
     * @return Firma digital en bytes
     * @throws Exception Si ocurre algún error al cargar
     */
    private byte[] cargarFirma(String rutaFirma) throws Exception {
        File archivo = new File(rutaFirma);
        
        if (!archivo.exists()) {
            throw new FileNotFoundException("Archivo de firma no encontrado: " + rutaFirma);
        }
        
        // Leer el archivo y extraer la firma Base64
        StringBuilder firmaBase64 = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(archivo))) {
            String linea;
            boolean dentroFirma = false;
            
            while ((linea = reader.readLine()) != null) {
                // Detectar el inicio de la firma (después de las líneas de metadatos)
                if (linea.equals("---")) {
                    dentroFirma = true;
                    continue;
                }
                
                // Capturar la firma
                if (dentroFirma) {
                    firmaBase64.append(linea.trim());
                }
            }
        }
        
        if (firmaBase64.length() == 0) {
            throw new IllegalArgumentException("El archivo de firma está vacío o no tiene contenido válido");
        }
        
        // Decodificar Base64
        return Base64.getDecoder().decode(firmaBase64.toString());
    }

    // ============================================================================
    // MÉTODOS AUXILIARES PRIVADOS - UTILIDADES
    // ============================================================================

    /**
     * Convierte un array de bytes a su representación hexadecimal.
     * Útil para mostrar hashes de forma legible.
     * 
     * @param bytes Array de bytes
     * @return Representación hexadecimal
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
    
}
