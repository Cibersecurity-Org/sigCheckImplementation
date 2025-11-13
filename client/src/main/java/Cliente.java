public class Cliente {

    private int id;
    private String nombre;
    private String apellido;
    private String correo;

    public Cliente(int id, String nombre, String apellido, String correo) {
        this.id = id;
        this.nombre = nombre;
        this.apellido = apellido;
        this.correo = correo;
    }

    public String getNombreCompleto(){
        return nombre+"_"+apellido;
    }

    public int getId() { return id; }
    public String getNombre() { return nombre; }
    public String getApellido() { return apellido; }
    public String getCorreo() { return correo; }
}

