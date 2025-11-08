# Sistema de Firma Digital RSA/SHA-256

Sistema completo de firma y verificación digital de archivos usando criptografía RSA con hashing SHA-256.

## Versiones
* Gradle 8.12.1
* Groovy: 3.0.22
* Java:  11.0.22
* ZeroC Ice: 3.7.10
* BouncyCastle: 1.70

## Construcción del Proyecto

### Compilar todo el proyecto
```bash
.\gradlew build
```

### Compilar solo el servidor
```bash
.\gradlew :checkserver:build
```

### Compilar solo el cliente
```bash
.\gradlew :client:build
```

## Ejecución

### Ejecutar el servidor Ice
```bash
java -jar checkserver/build/libs/checkserver.jar
```

### Ejecutar el cliente Ice (en construcción)
```bash
java -jar client/build/libs/client.jar
```

### Ejecutar prueba completa del sistema
```bash
cd checkserver/build/libs
java -cp checkserver.jar TestSignatureSystem
```

## Funcionalidades Implementadas ✅

### 1. Generación de Claves RSA
- Pares de claves RSA de 2048 bits
- Almacenamiento seguro en formato PKCS12 (clave privada)
- Almacenamiento en Base64 (clave pública)
- Protección con contraseña
- Certificados X.509 auto-firmados

### 2. Firma Digital de Archivos
- Algoritmo: SHA-256 con RSA
- Hash seguro del archivo completo
- Firma criptográfica con clave privada
- Formato de salida: Base64
- Validación de parámetros robusta

### 3. Verificación de Firmas
- Verificación criptográfica completa
- Detección de modificaciones en archivos
- Validación de autenticidad
- Manejo de errores exhaustivo

### 4. Arquitectura Cliente-Servidor (Ice)
- Servidor Ice funcional en puerto 11801
- Interfaz definida en Checker.ice
- Comunicación TCP
- Métodos remotos invocables

## Estructura del Proyecto

```
sigCheckImplementation/
├── Checker.ice                     # Definición de interfaces Ice
├── build.gradle                    # Configuración Gradle
├── settings.gradle                 # Subproyectos
├── checkserver/                    # Servidor de firmas
│   └── src/main/java/
│       ├── Checkserver.java        # Servidor principal Ice
│       ├── signCheckerI.java       # Implementación de firmas ⭐
│       ├── Cliente.java            # Modelo de datos
│       └── TestSignatureSystem.java # Programa de pruebas
└── client/                         # Cliente Ice (en desarrollo)
    └── main/java/
        └── Client.java
```

## Uso del Sistema

### Ejemplo: Generar Claves
```java
signCheckerI servicio = new signCheckerI();
Cliente cliente = new Cliente(1, "Juan", "Pérez", "juan@example.com");

KeyPair claves = servicio.generateKeyPair(cliente, 2048);
servicio.guardarClavePublica(claves.getPublic(), "./claves", cliente);
servicio.guardarClavePrivada(claves.getPrivate(), claves.getPublic(), 
                              "./claves", cliente, "miPassword");
```

### Ejemplo: Firmar un Archivo
```java
servicio.signFile(
    "./documento.pdf",           // Archivo a firmar
    "./documento.sig",           // Ruta de la firma
    "./clave_privada.p12",       // Clave privada PKCS12
    "miPassword",                // Contraseña
    null                         // Current (null en local)
);
```

### Ejemplo: Verificar una Firma
```java
boolean esValida = servicio.verifySign(
    "./documento.pdf",           // Archivo original
    "./documento.sig",           // Firma digital
    "./clave_publica.txt",       // Clave pública
    null                         // Current (null en local)
);

if (esValida) {
    System.out.println("✓ Firma válida: documento auténtico");
} else {
    System.out.println("✗ Firma inválida: documento modificado");
}
```

## Seguridad

- **Algoritmo de hash:** SHA-256 (256 bits)
- **Algoritmo de firma:** RSA-2048 bits
- **Formato de claves privadas:** PKCS12 protegido con contraseña
- **Certificados:** X.509 v3 auto-firmados con BouncyCastle
- **Encoding:** Base64 para portabilidad

## Arquitectura de Seguridad

1. **Generación de Claves:** KeyPairGenerator con SecureRandom
2. **Hash:** MessageDigest SHA-256 con buffer de 8KB
3. **Firma:** Signature con NONEwithRSA sobre hash pre-calculado
4. **Verificación:** Validación criptográfica completa
5. **Almacenamiento:** KeyStore PKCS12 estándar

## Estado del Proyecto

| Componente | Estado |
|------------|--------|
| Generación de claves | ✅ Completo |
| Firma digital | ✅ Completo |
| Verificación de firmas | ✅ Completo |
| Servidor Ice | ✅ Funcional |
| Cliente Ice | ⚠️ En desarrollo |
| Integración PostgreSQL | ⚠️ Pendiente |

## Autor

Sistema de Firma Digital - Implementación profesional con ZeroC Ice
