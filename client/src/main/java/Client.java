import Demo.*;
import java.io.*;
import java.util.Scanner;

/**
 * Cliente del Sistema de Firma Digital RSA/SHA-256
 * 
 * Este cliente implementa las mejores prácticas de seguridad:
 * - FIRMA LOCALMENTE: La clave privada NUNCA sale de esta máquina
 * - VERIFICA FLEXIBLE: Puede verificar local o remotamente
 * - Manejo robusto de errores
 * - Interfaz de usuario intuitiva
 * 
 * Arquitectura de Seguridad:
 * - Las operaciones de firma usan signCheckerI localmente (sin Ice)
 * - Las verificaciones pueden ser locales o remotas según necesidad
 * - La clave privada permanece siempre en la máquina del cliente
 * 
 * @author Sistema de Firma Digital
 * @version 1.0
 */
public class Client {

    private static final Scanner scanner = new Scanner(System.in);
    private static signCheckerI firmadorLocal;
    private static com.zeroc.Ice.Communicator communicator;
    private static Demo.signCheckerPrx servidorRemoto;
    private static boolean conectadoAlServidor = false;

    public static void main(String[] args) {
        System.out.println("╔════════════════════════════════════════════════════════════════╗");
        System.out.println("║       CLIENTE DE FIRMA DIGITAL RSA/SHA-256                     ║");
        System.out.println("║       Sistema Seguro de Gestión de Firmas Digitales           ║");
        System.out.println("╚════════════════════════════════════════════════════════════════╝");
        System.out.println();

        // Inicializar firmador local (para operaciones seguras sin Ice)
        firmadorLocal = new signCheckerI();
        System.out.println("✓ Módulo de firma local inicializado");

        // Intentar conectar al servidor Ice (opcional)
        conectarServidor(args);

        // Menú principal
        boolean continuar = true;
        while (continuar) {
            continuar = mostrarMenuPrincipal();
        }

        // Limpieza
        cerrarConexiones();
        System.out.println("\n¡Hasta luego!");
    }

    // ============================================================================
    // MENÚ PRINCIPAL
    // ============================================================================

    /**
     * Muestra el menú principal y procesa la opción seleccionada.
     * @return true para continuar, false para salir
     */
    private static boolean mostrarMenuPrincipal() {
        System.out.println("\n═══════════════════════════════════════════════════════════════");
        System.out.println("                    MENÚ PRINCIPAL");
        System.out.println("═══════════════════════════════════════════════════════════════");
        System.out.println("  1. Generar par de claves RSA");
        System.out.println("  2. Firmar un archivo (LOCAL - Seguro)");
        System.out.println("  3. Verificar firma (LOCAL)");
        System.out.println("  4. Verificar firma (REMOTO - vía servidor)");
        System.out.println("  5. Información del sistema");
        System.out.println("  6. Conectar/Reconectar al servidor");
        System.out.println("  0. Salir");
        System.out.println("═══════════════════════════════════════════════════════════════");
        System.out.print("Seleccione una opción: ");

        try {
            int opcion = Integer.parseInt(scanner.nextLine().trim());
            System.out.println();

            switch (opcion) {
                case 1:
                    generarClaves();
                    break;
                case 2:
                    firmarArchivo();
                    break;
                case 3:
                    verificarFirmaLocal();
                    break;
                case 4:
                    verificarFirmaRemoto();
                    break;
                case 5:
                    mostrarInformacionSistema();
                    break;
                case 6:
                    reconectarServidor();
                    break;
                case 0:
                    return false;
                default:
                    System.out.println("❌ Opción inválida. Intente nuevamente.");
            }
        } catch (NumberFormatException e) {
            System.out.println("❌ Por favor ingrese un número válido.");
        } catch (Exception e) {
            System.err.println("❌ Error inesperado: " + e.getMessage());
            e.printStackTrace();
        }

        return true;
    }

    // ============================================================================
    // OPERACIÓN 1: GENERAR CLAVES RSA
    // ============================================================================

    /**
     * Genera un par de claves RSA y las guarda de forma segura.
     */
    private static void generarClaves() {
        System.out.println("╔════════════════════════════════════════════════════════════════╗");
        System.out.println("║              GENERACIÓN DE PAR DE CLAVES RSA                   ║");
        System.out.println("╚════════════════════════════════════════════════════════════════╝");
        System.out.println();

        try {
            // Solicitar datos del usuario
            System.out.print("Nombre: ");
            String nombre = scanner.nextLine().trim();
            
            System.out.print("Apellido: ");
            String apellido = scanner.nextLine().trim();
            
            System.out.print("Correo electrónico: ");
            String correo = scanner.nextLine().trim();

            // Validar datos
            if (nombre.isEmpty() || apellido.isEmpty() || correo.isEmpty()) {
                System.out.println("❌ Todos los campos son obligatorios.");
                return;
            }

            if (!correo.contains("@")) {
                System.out.println("❌ El correo electrónico no es válido.");
                return;
            }

            // Solicitar contraseña para proteger la clave privada
            System.out.print("Contraseña para proteger la clave privada (mínimo 8 caracteres): ");
            String password = scanner.nextLine().trim();

            if (password.length() < 8) {
                System.out.println("❌ La contraseña debe tener al menos 8 caracteres.");
                return;
            }

            System.out.print("Confirme la contraseña: ");
            String passwordConfirm = scanner.nextLine().trim();

            if (!password.equals(passwordConfirm)) {
                System.out.println("❌ Las contraseñas no coinciden.");
                return;
            }

            // Solicitar directorio de salida
            System.out.print("Directorio donde guardar las claves (Enter para usar './claves'): ");
            String directorio = scanner.nextLine().trim();
            if (directorio.isEmpty()) {
                directorio = "./claves";
            }

            // Crear directorio si no existe
            File dir = new File(directorio);
            if (!dir.exists()) {
                dir.mkdirs();
            }

            // Crear objeto Cliente
            Cliente cliente = new Cliente(1, nombre, apellido, correo);

            // Generar claves
            System.out.println("\n⏳ Generando par de claves RSA-2048... (esto puede tomar unos segundos)");
            long inicio = System.currentTimeMillis();
            
            java.security.KeyPair claves = firmadorLocal.generateKeyPair(cliente, 2048);
            
            long tiempoGeneracion = System.currentTimeMillis() - inicio;

            // Guardar claves
            System.out.println("💾 Guardando claves...");
            firmadorLocal.guardarClavePublica(claves.getPublic(), directorio, cliente);
            firmadorLocal.guardarClavePrivada(
                claves.getPrivate(),
                claves.getPublic(),
                directorio,
                cliente,
                password
            );

            System.out.println();
            System.out.println("╔════════════════════════════════════════════════════════════════╗");
            System.out.println("║              ✓ CLAVES GENERADAS EXITOSAMENTE                   ║");
            System.out.println("╚════════════════════════════════════════════════════════════════╝");
            System.out.println();
            System.out.println("📊 Detalles:");
            System.out.println("  • Algoritmo: RSA-2048 bits");
            System.out.println("  • Tiempo de generación: " + tiempoGeneracion + " ms");
            System.out.println("  • Clave pública: " + nombre + "_publica.txt");
            System.out.println("  • Clave privada: " + directorio + "/" + nombre + "_privada.p12");
            System.out.println("  • Formato: PKCS12 (protegido con contraseña)");
            System.out.println();
            System.out.println("🔐 Seguridad:");
            System.out.println("  • La clave privada está cifrada con su contraseña");
            System.out.println("  • NUNCA comparta su clave privada ni su contraseña");
            System.out.println("  • La clave pública puede compartirse libremente");

        } catch (Exception e) {
            System.err.println("❌ Error al generar claves: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // ============================================================================
    // OPERACIÓN 2: FIRMAR ARCHIVO (LOCAL - SEGURO)
    // ============================================================================

    /**
     * Firma un archivo de forma LOCAL (la clave privada nunca sale de esta máquina).
     * Esta es la forma SEGURA de firmar documentos.
     */
    private static void firmarArchivo() {
        System.out.println("╔════════════════════════════════════════════════════════════════╗");
        System.out.println("║                FIRMA DIGITAL DE ARCHIVO                        ║");
        System.out.println("║                    (Operación LOCAL - Segura)                  ║");
        System.out.println("╚════════════════════════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("🔒 Seguridad: Su clave privada permanece en esta máquina");
        System.out.println();

        try {
            // Solicitar ruta del archivo a firmar
            System.out.print("Ruta del archivo a firmar: ");
            String archivoAFirmar = scanner.nextLine().trim();

            if (archivoAFirmar.isEmpty()) {
                System.out.println("❌ Debe especificar un archivo.");
                return;
            }

            File archivo = new File(archivoAFirmar);
            if (!archivo.exists() || !archivo.isFile()) {
                System.out.println("❌ El archivo no existe o no es válido: " + archivoAFirmar);
                return;
            }

            // Solicitar ruta de la clave privada
            System.out.print("Ruta de su clave privada (.p12): ");
            String rutaClavePrivada = scanner.nextLine().trim();

            if (rutaClavePrivada.isEmpty()) {
                System.out.println("❌ Debe especificar la ruta de la clave privada.");
                return;
            }

            File archivoClavePrivada = new File(rutaClavePrivada);
            if (!archivoClavePrivada.exists()) {
                System.out.println("❌ El archivo de clave privada no existe: " + rutaClavePrivada);
                return;
            }

            // Solicitar contraseña
            System.out.print("Contraseña de la clave privada: ");
            String password = scanner.nextLine().trim();

            if (password.isEmpty()) {
                System.out.println("❌ Debe ingresar la contraseña.");
                return;
            }

            // Determinar nombre del archivo de firma
            String archivoFirma = archivoAFirmar + ".sig";
            System.out.println("📝 La firma se guardará en: " + archivoFirma);
            System.out.println();

            // FIRMAR LOCALMENTE (sin Ice - la clave privada NO sale de aquí)
            System.out.println("⏳ Firmando archivo...");
            long inicio = System.currentTimeMillis();

            firmadorLocal.signFile(
                archivoAFirmar,
                archivoFirma,
                rutaClavePrivada,
                password,
                null  // null = operación local, sin Ice
            );

            long tiempoFirma = System.currentTimeMillis() - inicio;

            System.out.println();
            System.out.println("╔════════════════════════════════════════════════════════════════╗");
            System.out.println("║           ✓ ARCHIVO FIRMADO EXITOSAMENTE                      ║");
            System.out.println("╚════════════════════════════════════════════════════════════════╝");
            System.out.println();
            System.out.println("📊 Detalles:");
            System.out.println("  • Archivo firmado: " + archivoAFirmar);
            System.out.println("  • Firma digital: " + archivoFirma);
            System.out.println("  • Tamaño del archivo: " + archivo.length() + " bytes");
            System.out.println("  • Tiempo de firma: " + tiempoFirma + " ms");
            System.out.println("  • Algoritmo: SHA-256 con RSA");
            System.out.println();
            System.out.println("✉️  Puede enviar el archivo y la firma a cualquier persona");
            System.out.println("🔑 También necesitarán su clave PÚBLICA para verificar");

        } catch (RuntimeException e) {
            System.err.println("❌ Error al firmar archivo: " + e.getMessage());
            if (e.getMessage().contains("password")) {
                System.err.println("💡 Verifique que la contraseña sea correcta");
            }
        } catch (Exception e) {
            System.err.println("❌ Error inesperado: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // ============================================================================
    // OPERACIÓN 3: VERIFICAR FIRMA (LOCAL)
    // ============================================================================

    /**
     * Verifica una firma de forma LOCAL (sin necesidad del servidor).
     * Útil para verificación offline y privada.
     */
    private static void verificarFirmaLocal() {
        System.out.println("╔════════════════════════════════════════════════════════════════╗");
        System.out.println("║              VERIFICACIÓN DE FIRMA DIGITAL                     ║");
        System.out.println("║                    (Operación LOCAL)                           ║");
        System.out.println("╚════════════════════════════════════════════════════════════════╝");
        System.out.println();

        try {
            // Solicitar archivo original
            System.out.print("Ruta del archivo original: ");
            String archivoOriginal = scanner.nextLine().trim();

            if (archivoOriginal.isEmpty()) {
                System.out.println("❌ Debe especificar el archivo original.");
                return;
            }

            File archivo = new File(archivoOriginal);
            if (!archivo.exists()) {
                System.out.println("❌ El archivo no existe: " + archivoOriginal);
                return;
            }

            // Solicitar archivo de firma
            System.out.print("Ruta del archivo de firma (.sig): ");
            String archivoFirma = scanner.nextLine().trim();

            if (archivoFirma.isEmpty()) {
                System.out.println("❌ Debe especificar el archivo de firma.");
                return;
            }

            File firma = new File(archivoFirma);
            if (!firma.exists()) {
                System.out.println("❌ El archivo de firma no existe: " + archivoFirma);
                return;
            }

            // Solicitar clave pública
            System.out.print("Ruta de la clave pública del firmante (.txt): ");
            String rutaClavePublica = scanner.nextLine().trim();

            if (rutaClavePublica.isEmpty()) {
                System.out.println("❌ Debe especificar la clave pública.");
                return;
            }

            File clavePublica = new File(rutaClavePublica);
            if (!clavePublica.exists()) {
                System.out.println("❌ La clave pública no existe: " + rutaClavePublica);
                return;
            }

            // VERIFICAR LOCALMENTE
            System.out.println("\n⏳ Verificando firma...");
            long inicio = System.currentTimeMillis();

            boolean esValida = firmadorLocal.verifySign(
                archivoOriginal,
                archivoFirma,
                rutaClavePublica,
                null  // null = operación local
            );

            long tiempoVerificacion = System.currentTimeMillis() - inicio;

            System.out.println();
            if (esValida) {
                System.out.println("╔════════════════════════════════════════════════════════════════╗");
                System.out.println("║              ✓✓✓ FIRMA VÁLIDA ✓✓✓                            ║");
                System.out.println("║                                                                ║");
                System.out.println("║  El archivo es AUTÉNTICO y NO ha sido modificado              ║");
                System.out.println("║  Puede confiar en la integridad del documento                 ║");
                System.out.println("╚════════════════════════════════════════════════════════════════╝");
            } else {
                System.out.println("╔════════════════════════════════════════════════════════════════╗");
                System.out.println("║              ✗✗✗ FIRMA INVÁLIDA ✗✗✗                          ║");
                System.out.println("║                                                                ║");
                System.out.println("║  ADVERTENCIA: El archivo ha sido MODIFICADO                   ║");
                System.out.println("║  o la firma NO corresponde al archivo                         ║");
                System.out.println("║                                                                ║");
                System.out.println("║  ⚠️  NO CONFÍE en este documento                              ║");
                System.out.println("╚════════════════════════════════════════════════════════════════╝");
            }

            System.out.println();
            System.out.println("📊 Detalles de verificación:");
            System.out.println("  • Tiempo: " + tiempoVerificacion + " ms");
            System.out.println("  • Algoritmo: SHA-256 con RSA");
            System.out.println("  • Modo: Verificación local (offline)");

        } catch (Exception e) {
            System.err.println("❌ Error al verificar firma: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // ============================================================================
    // OPERACIÓN 4: VERIFICAR FIRMA (REMOTO VÍA SERVIDOR)
    // ============================================================================

    /**
     * Verifica una firma usando el servidor remoto vía Ice.
     * Útil para auditoría centralizada.
     */
    private static void verificarFirmaRemoto() {
        System.out.println("╔════════════════════════════════════════════════════════════════╗");
        System.out.println("║              VERIFICACIÓN DE FIRMA DIGITAL                     ║");
        System.out.println("║                  (Operación REMOTA vía Servidor)               ║");
        System.out.println("╚════════════════════════════════════════════════════════════════╝");
        System.out.println();

        if (!conectadoAlServidor) {
            System.out.println("❌ No hay conexión con el servidor.");
            System.out.println("💡 Use la opción 6 para conectarse al servidor.");
            return;
        }

        try {
            // Solicitar datos (igual que verificación local)
            System.out.print("Ruta del archivo original: ");
            String archivoOriginal = scanner.nextLine().trim();

            System.out.print("Ruta del archivo de firma (.sig): ");
            String archivoFirma = scanner.nextLine().trim();

            System.out.print("Ruta de la clave pública (.txt): ");
            String rutaClavePublica = scanner.nextLine().trim();

            // Validaciones básicas
            if (archivoOriginal.isEmpty() || archivoFirma.isEmpty() || rutaClavePublica.isEmpty()) {
                System.out.println("❌ Todos los campos son obligatorios.");
                return;
            }

            // VERIFICAR REMOTAMENTE VÍA ICE
            System.out.println("\n⏳ Enviando solicitud al servidor...");
            long inicio = System.currentTimeMillis();

            boolean esValida = servidorRemoto.verifySign(
                archivoOriginal,
                archivoFirma,
                rutaClavePublica
            );

            long tiempoVerificacion = System.currentTimeMillis() - inicio;

            System.out.println();
            if (esValida) {
                System.out.println("╔════════════════════════════════════════════════════════════════╗");
                System.out.println("║         ✓✓✓ FIRMA VÁLIDA (Verificado por servidor) ✓✓✓       ║");
                System.out.println("╚════════════════════════════════════════════════════════════════╝");
            } else {
                System.out.println("╔════════════════════════════════════════════════════════════════╗");
                System.out.println("║        ✗✗✗ FIRMA INVÁLIDA (Verificado por servidor) ✗✗✗      ║");
                System.out.println("╚════════════════════════════════════════════════════════════════╝");
            }

            System.out.println();
            System.out.println("📊 Detalles:");
            System.out.println("  • Tiempo total: " + tiempoVerificacion + " ms (incluye red)");
            System.out.println("  • Modo: Verificación remota (servidor)");

        } catch (Exception e) {
            System.err.println("❌ Error al verificar firma remotamente: " + e.getMessage());
            System.err.println("💡 Verifique que el servidor esté funcionando correctamente.");
        }
    }

    // ============================================================================
    // OPERACIÓN 5: INFORMACIÓN DEL SISTEMA
    // ============================================================================

    /**
     * Muestra información sobre el sistema y el estado de las conexiones.
     */
    private static void mostrarInformacionSistema() {
        System.out.println("╔════════════════════════════════════════════════════════════════╗");
        System.out.println("║              INFORMACIÓN DEL SISTEMA                           ║");
        System.out.println("╚════════════════════════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("📋 Cliente de Firma Digital RSA/SHA-256");
        System.out.println();
        System.out.println("🔐 Capacidades de Seguridad:");
        System.out.println("  • Firma digital LOCAL (clave privada no sale de aquí)");
        System.out.println("  • Verificación LOCAL (offline, privada)");
        System.out.println("  • Verificación REMOTA (auditoría centralizada)");
        System.out.println("  • Algoritmo: RSA-2048 con SHA-256");
        System.out.println();
        System.out.println("🔗 Estado de Conexiones:");
        System.out.println("  • Módulo local: ✓ Activo");
        System.out.println("  • Servidor remoto: " + (conectadoAlServidor ? "✓ Conectado" : "✗ Desconectado"));
        
        if (conectadoAlServidor && servidorRemoto != null) {
            // Mostrar la dirección efectiva desde la configuración
            com.zeroc.Ice.Properties props = communicator.getProperties();
            String proxy = props.getProperty("Checker.Proxy");
            if (proxy == null || proxy.trim().isEmpty()) {
                String host = props.getPropertyWithDefault("Checker.Host",
                        props.getPropertyWithDefault("Ice.Default.Host", "localhost"));
                String port = props.getPropertyWithDefault("Checker.Port", "11801");
                System.out.println("  • Dirección servidor: " + host + ":" + port);
            } else {
                System.out.println("  • Proxy servidor: " + proxy);
            }
        }
        
        System.out.println();
        System.out.println("💻 Entorno:");
        System.out.println("  • Java: " + System.getProperty("java.version"));
        System.out.println("  • OS: " + System.getProperty("os.name"));
        System.out.println("  • Directorio actual: " + System.getProperty("user.dir"));
        System.out.println();
        System.out.println("📚 Operaciones Disponibles:");
        System.out.println("  1. Generar claves RSA (siempre disponible)");
        System.out.println("  2. Firmar archivos LOCAL (siempre disponible, SEGURO)");
        System.out.println("  3. Verificar firmas LOCAL (siempre disponible)");
        System.out.println("  4. Verificar firmas REMOTO (requiere servidor)");
    }

    // ============================================================================
    // GESTIÓN DE CONEXIONES
    // ============================================================================

    /**
     * Intenta conectar con el servidor Ice.
     */
    private static void conectarServidor(String[] args) {
        try {
            System.out.println("⏳ Intentando conectar con el servidor...");
            
            // Inicializar comunicador Ice
            communicator = com.zeroc.Ice.Util.initialize(args, "config.client");
            
            // Construir proxy desde configuración (permite host/puerto remotos)
            com.zeroc.Ice.Properties props = communicator.getProperties();
            String proxy = props.getProperty("Checker.Proxy");
            if (proxy == null || proxy.trim().isEmpty()) {
                String host = props.getPropertyWithDefault("Checker.Host",
                        props.getPropertyWithDefault("Ice.Default.Host", "localhost"));
                String port = props.getPropertyWithDefault("Checker.Port", "11801");
                proxy = "simpleChecker:tcp -h " + host + " -p " + port;
            }

            // Obtener proxy al servidor
            com.zeroc.Ice.ObjectPrx base = communicator.stringToProxy(proxy);
            
            // Hacer cast al tipo correcto
            servidorRemoto = Demo.signCheckerPrx.checkedCast(base);
            
            if (servidorRemoto == null) {
                throw new Error("Proxy inválido - no se pudo conectar al servidor");
            }
            
            conectadoAlServidor = true;
            System.out.println("✓ Conectado al servidor en " + proxy);
            System.out.println("  (Las operaciones remotas están disponibles)");
            
        } catch (Exception e) {
            conectadoAlServidor = false;
            System.out.println("⚠️  No se pudo conectar al servidor remoto");
            System.out.println("  Razón: " + e.getMessage());
            System.out.println("  (Las operaciones locales siguen disponibles)");
        }
    }

    /**
     * Reconecta al servidor Ice.
     */
    private static void reconectarServidor() {
        System.out.println("╔════════════════════════════════════════════════════════════════╗");
        System.out.println("║                RECONEXIÓN AL SERVIDOR                          ║");
        System.out.println("╚════════════════════════════════════════════════════════════════╝");
        System.out.println();

        // Cerrar conexión actual si existe
        if (communicator != null) {
            try {
                communicator.destroy();
            } catch (Exception e) {
                // Ignorar errores al cerrar
            }
            communicator = null;
            servidorRemoto = null;
            conectadoAlServidor = false;
        }

        // Intentar nueva conexión
        conectarServidor(new String[0]);
    }

    /**
     * Cierra todas las conexiones activas.
     */
    private static void cerrarConexiones() {
        if (communicator != null) {
            try {
                System.out.println("\n⏳ Cerrando conexiones...");
                communicator.destroy();
                System.out.println("✓ Conexiones cerradas correctamente");
            } catch (Exception e) {
                System.err.println("⚠️  Error al cerrar conexiones: " + e.getMessage());
            }
        }
        scanner.close();
    }
}
