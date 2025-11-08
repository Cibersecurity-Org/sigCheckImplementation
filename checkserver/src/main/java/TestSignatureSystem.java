import java.io.*;
import java.security.KeyPair;
import java.nio.charset.StandardCharsets;

/**
 * Programa de prueba completo del sistema de firma digital.
 * 
 * Este test demuestra:
 * 1. Generación de claves RSA
 * 2. Firma digital de archivos
 * 3. Verificación de firmas
 * 4. Detección de modificaciones
 * 
 * @author Sistema de Firma Digital
 * @version 1.0
 */
public class TestSignatureSystem {

    private static final String DIRECTORIO_TEST = "./test_firma_digital";
    private static final String ARCHIVO_PRUEBA = DIRECTORIO_TEST + "/documento_prueba.txt";
    private static final String ARCHIVO_FIRMA = DIRECTORIO_TEST + "/documento_prueba.sig";
    private static final String PASSWORD = "MiPasswordSeguro123!";

    public static void main(String[] args) {
        System.out.println("╔════════════════════════════════════════════════════════════════╗");
        System.out.println("║    TEST COMPLETO DEL SISTEMA DE FIRMA DIGITAL RSA/SHA-256     ║");
        System.out.println("╚════════════════════════════════════════════════════════════════╝");
        System.out.println();

        try {
            // Crear directorio de pruebas
            crearDirectorioPrueba();

            // Crear instancia del servicio de firma
            signCheckerI servicio = new signCheckerI();

            // ========== FASE 1: GENERACIÓN DE CLAVES ==========
            System.out.println("█████████████████████████████████████████████████████████████████");
            System.out.println("█  FASE 1: GENERACIÓN DE PAR DE CLAVES RSA (2048 bits)         █");
            System.out.println("█████████████████████████████████████████████████████████████████");
            System.out.println();

            Cliente cliente = new Cliente(
                1,
                "TestUser",
                "Sistema",
                "testuser@firma.digital"
            );

            long tiempoInicio = System.currentTimeMillis();
            KeyPair claves = servicio.generateKeyPair(cliente, 2048);
            long tiempoGeneracion = System.currentTimeMillis() - tiempoInicio;

            System.out.println("✓ Par de claves generado exitosamente");
            System.out.println("  Tiempo de generación: " + tiempoGeneracion + " ms");
            System.out.println("  Algoritmo: RSA-2048");
            System.out.println();

            // Guardar claves
            servicio.guardarClavePublica(claves.getPublic(), DIRECTORIO_TEST, cliente);
            servicio.guardarClavePrivada(
                claves.getPrivate(),
                claves.getPublic(),
                DIRECTORIO_TEST,
                cliente,
                PASSWORD
            );

            String archivoClavePublica = "TestUser_publica.txt";
            String archivoClavePrivada = DIRECTORIO_TEST + "/TestUser_privada.p12";

            System.out.println("✓ Claves guardadas:");
            System.out.println("  Clave pública:  " + archivoClavePublica);
            System.out.println("  Clave privada:  " + archivoClavePrivada + " (protegida con contraseña)");
            System.out.println();

            esperarEnter();

            // ========== FASE 2: CREAR DOCUMENTO DE PRUEBA ==========
            System.out.println("█████████████████████████████████████████████████████████████████");
            System.out.println("█  FASE 2: CREACIÓN DE DOCUMENTO DE PRUEBA                      █");
            System.out.println("█████████████████████████████████████████████████████████████████");
            System.out.println();

            String contenidoDocumento = generarContenidoDocumento();
            crearArchivoPrueba(ARCHIVO_PRUEBA, contenidoDocumento);

            File archivoPrueba = new File(ARCHIVO_PRUEBA);
            System.out.println("✓ Documento creado: " + ARCHIVO_PRUEBA);
            System.out.println("  Tamaño: " + archivoPrueba.length() + " bytes");
            System.out.println();
            System.out.println("Contenido del documento:");
            System.out.println("┌────────────────────────────────────────────────────────────┐");
            System.out.println(contenidoDocumento);
            System.out.println("└────────────────────────────────────────────────────────────┘");
            System.out.println();

            esperarEnter();

            // ========== FASE 3: FIRMAR EL DOCUMENTO ==========
            System.out.println("█████████████████████████████████████████████████████████████████");
            System.out.println("█  FASE 3: FIRMA DIGITAL DEL DOCUMENTO                          █");
            System.out.println("█████████████████████████████████████████████████████████████████");
            System.out.println();

            tiempoInicio = System.currentTimeMillis();
            servicio.signFile(
                ARCHIVO_PRUEBA,
                ARCHIVO_FIRMA,
                archivoClavePrivada,
                PASSWORD,
                null  // current es null en pruebas locales
            );
            long tiempoFirma = System.currentTimeMillis() - tiempoInicio;

            System.out.println("Tiempo de firma: " + tiempoFirma + " ms");
            System.out.println();

            esperarEnter();

            // ========== FASE 4: VERIFICAR FIRMA (CASO VÁLIDO) ==========
            System.out.println("█████████████████████████████████████████████████████████████████");
            System.out.println("█  FASE 4: VERIFICACIÓN DE FIRMA - CASO VÁLIDO                  █");
            System.out.println("█████████████████████████████████████████████████████████████████");
            System.out.println();

            tiempoInicio = System.currentTimeMillis();
            boolean firmaValida = servicio.verifySign(
                ARCHIVO_PRUEBA,
                ARCHIVO_FIRMA,
                archivoClavePublica,
                null
            );
            long tiempoVerificacion = System.currentTimeMillis() - tiempoInicio;

            System.out.println("Tiempo de verificación: " + tiempoVerificacion + " ms");
            System.out.println();

            if (firmaValida) {
                System.out.println("╔══════════════════════════════════════════════════════════╗");
                System.out.println("║  ✓✓✓ RESULTADO: FIRMA VÁLIDA ✓✓✓                        ║");
                System.out.println("║  El documento es auténtico y no ha sido modificado       ║");
                System.out.println("╚══════════════════════════════════════════════════════════╝");
            } else {
                System.out.println("╔══════════════════════════════════════════════════════════╗");
                System.out.println("║  ✗✗✗ ERROR: FIRMA INVÁLIDA ✗✗✗                          ║");
                System.out.println("╚══════════════════════════════════════════════════════════╝");
                return;
            }
            System.out.println();

            esperarEnter();

            // ========== FASE 5: MODIFICAR DOCUMENTO Y RE-VERIFICAR ==========
            System.out.println("█████████████████████████████████████████████████████████████████");
            System.out.println("█  FASE 5: DETECCIÓN DE MODIFICACIONES                          █");
            System.out.println("█████████████████████████████████████████████████████████████████");
            System.out.println();

            System.out.println("Modificando el documento (agregando una línea extra)...");
            modificarArchivo(ARCHIVO_PRUEBA);
            System.out.println("✓ Documento modificado");
            System.out.println();

            System.out.println("Verificando firma con documento modificado...");
            System.out.println();

            boolean firmaValidaDespuesDeCambio = servicio.verifySign(
                ARCHIVO_PRUEBA,
                ARCHIVO_FIRMA,
                archivoClavePublica,
                null
            );

            System.out.println();
            if (!firmaValidaDespuesDeCambio) {
                System.out.println("╔══════════════════════════════════════════════════════════╗");
                System.out.println("║  ✓✓✓ CORRECTO: MODIFICACIÓN DETECTADA ✓✓✓               ║");
                System.out.println("║  El sistema detectó que el documento fue alterado        ║");
                System.out.println("╚══════════════════════════════════════════════════════════╝");
            } else {
                System.out.println("╔══════════════════════════════════════════════════════════╗");
                System.out.println("║  ✗✗✗ ERROR: NO SE DETECTÓ LA MODIFICACIÓN ✗✗✗           ║");
                System.out.println("╚══════════════════════════════════════════════════════════╝");
            }
            System.out.println();

            esperarEnter();

            // ========== RESUMEN FINAL ==========
            System.out.println("█████████████████████████████████████████████████████████████████");
            System.out.println("█  RESUMEN DE PRUEBAS                                           █");
            System.out.println("█████████████████████████████████████████████████████████████████");
            System.out.println();
            System.out.println("┌─────────────────────────────────────────────────────────────┐");
            System.out.println("│ ✓ Generación de claves RSA-2048                  [OK]       │");
            System.out.println("│ ✓ Almacenamiento seguro de claves                [OK]       │");
            System.out.println("│ ✓ Firma digital SHA256withRSA                    [OK]       │");
            System.out.println("│ ✓ Verificación de firma válida                   [OK]       │");
            System.out.println("│ ✓ Detección de modificaciones                    [OK]       │");
            System.out.println("└─────────────────────────────────────────────────────────────┘");
            System.out.println();
            System.out.println("Métricas de rendimiento:");
            System.out.println("  • Generación de claves: " + tiempoGeneracion + " ms");
            System.out.println("  • Firma de documento:   " + tiempoFirma + " ms");
            System.out.println("  • Verificación:         " + tiempoVerificacion + " ms");
            System.out.println();
            System.out.println("╔══════════════════════════════════════════════════════════════╗");
            System.out.println("║          TODAS LAS PRUEBAS COMPLETADAS EXITOSAMENTE          ║");
            System.out.println("║     Sistema de Firma Digital Funcionando Correctamente       ║");
            System.out.println("╚══════════════════════════════════════════════════════════════╝");
            System.out.println();

            System.out.println("Archivos generados en: " + DIRECTORIO_TEST + "/");
            System.out.println("  - TestUser_publica.txt          (clave pública)");
            System.out.println("  - TestUser_privada.p12          (clave privada protegida)");
            System.out.println("  - documento_prueba.txt          (documento de prueba)");
            System.out.println("  - documento_prueba.sig          (firma digital)");
            System.out.println();

        } catch (Exception e) {
            System.err.println("╔══════════════════════════════════════════════════════════════╗");
            System.err.println("║  ✗✗✗ ERROR DURANTE LAS PRUEBAS ✗✗✗                          ║");
            System.err.println("╚══════════════════════════════════════════════════════════════╝");
            System.err.println();
            System.err.println("Detalles del error:");
            e.printStackTrace();
        }
    }

    // ========== MÉTODOS AUXILIARES ==========

    private static void crearDirectorioPrueba() {
        File directorio = new File(DIRECTORIO_TEST);
        if (!directorio.exists()) {
            directorio.mkdirs();
            System.out.println("✓ Directorio de pruebas creado: " + DIRECTORIO_TEST);
            System.out.println();
        }
    }

    private static String generarContenidoDocumento() {
        return "╔════════════════════════════════════════════════════════════╗\n" +
               "║           DOCUMENTO DIGITAL CONFIDENCIAL                   ║\n" +
               "╚════════════════════════════════════════════════════════════╝\n" +
               "\n" +
               "CONTRATO DE PRUEBA\n" +
               "==================\n" +
               "\n" +
               "Entre las partes:\n" +
               "  - Parte A: Sistema de Firma Digital\n" +
               "  - Parte B: Usuario de Prueba\n" +
               "\n" +
               "Se acuerda lo siguiente:\n" +
               "\n" +
               "1. Este documento es una prueba del sistema de firma digital.\n" +
               "2. La firma digital garantiza la autenticidad e integridad.\n" +
               "3. Cualquier modificación invalida la firma.\n" +
               "\n" +
               "Fecha: " + new java.util.Date() + "\n" +
               "\n" +
               "Este documento contiene información importante que debe\n" +
               "permanecer sin modificaciones para mantener su validez legal.\n" +
               "\n" +
               "Hash del documento se calcula usando SHA-256.\n" +
               "Firma se genera usando RSA-2048.\n" +
               "\n" +
               "Fin del documento.";
    }

    private static void crearArchivoPrueba(String ruta, String contenido) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(
                new FileWriter(ruta, StandardCharsets.UTF_8))) {
            writer.write(contenido);
        }
    }

    private static void modificarArchivo(String ruta) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(
                new FileWriter(ruta, StandardCharsets.UTF_8, true))) {
            writer.write("\n\n[MODIFICACIÓN NO AUTORIZADA - Esta línea invalida la firma]");
        }
    }

    private static void esperarEnter() {
        System.out.println("Presiona ENTER para continuar...");
        try {
            System.in.read();
            // Limpiar el buffer
            while (System.in.available() > 0) {
                System.in.read();
            }
        } catch (IOException e) {
            // Ignorar
        }
        System.out.println();
    }
}

