import java.util.Scanner;

public class Checkserver {

    private static java.util.Scanner scanner = new java.util.Scanner(System.in);
    private static com.zeroc.Ice.Communicator communicator;


    public static void main(String[] args) {
        System.out.println("Server is running...");

        java.util.List<String> extraArgs = new java.util.ArrayList<String>();
        try
        {
            communicator = com.zeroc.Ice.Util.initialize(
                args, "config.server", extraArgs
            );

            //crear adaptador con nombre "Checker". Debe coincidir con el nombre de la configuración en config.server
            com.zeroc.Ice.ObjectAdapter adapter=communicator.createObjectAdapter("Checker");

            //Asignar la instancia del objeto signCheckerI a un objeto Ice
            signCheckerI signChecker= new signCheckerI();
            com.zeroc.Ice.Object object = signChecker;

            //Añadir el objeto al adaptador con el identificador "simpleChecker"
            adapter.add(object, com.zeroc.Ice.Util.stringToIdentity("simpleChecker"));
            adapter.activate();

            //Mostrar mensaje de que el servidor está listo
            System.out.println("Servicio signChecker disponible en puerto 11801");
            System.out.println("Presiona Enter para cerrar el servidor...");

            //Esperar a que el usuario presione Enter para cerrar el servidor
            scanner.nextLine();

        }catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (communicator != null) {
                communicator.destroy();
            }
            if (scanner != null) {
                scanner.close();
            }
            System.out.println("Cerrando servidor...");
        }
    }
}