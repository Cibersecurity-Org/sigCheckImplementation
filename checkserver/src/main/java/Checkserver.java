import java.security.KeyPair;
import java.util.Scanner;
import java.io.*;

public class Checkserver {

    private final static Scanner scanner = new java.util.Scanner(System.in);
    private static com.zeroc.Ice.Communicator communicator;


    public static void main(String[] args) {
        System.out.println("╔════════════════════════════════════════════════════════════════╗");
        System.out.println("║   SERVIDOR DE FIRMA DIGITAL RSA/SHA-256 - Fase 1 MVP          ║");
        System.out.println("╚════════════════════════════════════════════════════════════════╝");
        System.out.println();

        java.util.List<String> extraArgs = new java.util.ArrayList<>();
        try
        {
            communicator = com.zeroc.Ice.Util.initialize(
                args, "config.server", extraArgs
            );

            //crear adaptador con nombre "Checker". Debe coincidir con el nombre de la configuración en config.server
            com.zeroc.Ice.ObjectAdapter adapter=communicator.createObjectAdapter("Checker");

            //Asignar la instancia del objeto signCheckerI a un objeto Ice
            com.zeroc.Ice.Object object = new signCheckerI();

            //Añadir el objeto al adaptador con el identificador "simpleChecker"
            adapter.add(object, com.zeroc.Ice.Util.stringToIdentity("simpleChecker"));
            adapter.activate();

            //Mostrar mensaje de que el servidor está listo
            System.out.println("═══════════════════════════════════════════════════════════════");
            System.out.println("           ✓ SERVIDOR INICIADO CORRECTAMENTE");
            System.out.println("═══════════════════════════════════════════════════════════════");
            System.out.println("  🌐 Puerto: 11801");
            System.out.println("  🔐 Servicio: signChecker");
            System.out.println("  📋 Funcionalidades:");
            System.out.println("     • Firma digital RSA/SHA-256");
            System.out.println("     • Verificación de firmas");
            System.out.println("     • Gestión de usuarios (Fase 1 MVP)");
            System.out.println("     • Repositorio de claves públicas");
            System.out.println("═══════════════════════════════════════════════════════════════");
            System.out.println();
            signCheckerI.mostrarEstadisticas();
            System.out.println("Presiona Enter para cerrar el servidor...");

            //Esperar a que el usuario presione Enter para cerrar el servidor
            scanner.nextLine();

            signCheckerI sig = new signCheckerI();

            // Datos del cliente
            Cliente cliente = new Cliente(1,"Juan", "Plaza", "juan.perez@empresa.com");
            String password = "MiContrasenaSegura123";
            String directorioSalida = "./claves_generadas";

            // Crear directorio si no existe
            new File(directorioSalida).mkdirs();

            // Generar claves
            KeyPair claves = sig.generateKeyPair(cliente, 2048);
            // Guardar claves en archivos
            sig.guardarClavePublica(claves.getPublic(), directorioSalida, cliente);
            sig.guardarClavePrivada(claves.getPrivate(), claves.getPublic(), directorioSalida, cliente, password);

            System.out.println("\n Proceso completado para: " + cliente.getNombreCompleto());
            System.out.println(" La clave privada esta protegida con contraseña en formato PKCS12");


        }catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (communicator != null) {
                communicator.destroy();
            }
            scanner.close();
            System.out.println("Cerrando servidor...");
        }
    }
}