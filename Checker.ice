module Demo
{
    // Secuencia de bytes para transferir archivos
    sequence<byte> ByteSeq;

    // Estructura para representar un usuario
    struct Usuario {
        string email;
        string nombre;
        string apellido;
        bool conectado;
        string fechaRegistro;
        string ultimaConexion;
    }
    
    // Secuencia de usuarios
    sequence<Usuario> ListaUsuarios;
    
    interface signChecker
    {
        // ===== MÉTODOS ORIGINALES =====
        void generateKey(string keypassword);
        bool verifySign(string path, string signature, string publicKey);
        void signFile(string path, string signaturePath, string privateKey, string keyPassword);

        // ===== NUEVO: Verificación enviando archivos (datos) =====
        // Permite al cliente subir el archivo original, la firma (.sig) y la clave pública (.txt)
        // para que el servidor verifique sin depender de rutas locales del servidor.
        bool verifySignData(ByteSeq originalData, ByteSeq signatureFileData, ByteSeq publicKeyFileData);
        
        // ===== GESTIÓN DE USUARIOS (Fase 1 - MVP) =====
        
        // Registrar usuario con su clave pública
        string registerUser(string nombre, string apellido, string email, string publicKey);
        
        // Obtener clave pública de un usuario por email
        string getPublicKey(string email);
        
        // Obtener lista de usuarios conectados
        ListaUsuarios getConnectedUsers();
        
        // Obtener lista de todos los usuarios registrados
        ListaUsuarios getAllUsers();
        
        // Verificar firma usando email del usuario (sin necesidad de enviar clave pública)
        bool verifySignByUser(string path, string signaturePath, string userEmail);
        
        // Notificar desconexión de usuario
        void notifyDisconnect(string email);
    }
}