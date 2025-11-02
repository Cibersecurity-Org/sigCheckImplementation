# Version
* Gradle 8.12.1
* Groovy: 3.0.22
* Java:  11.0.22

# Construir proyecto y subproyectos
.\gradlew build
## Compilar el servidor
  .\gradlew :checkserver:build
## Compilar el cliente
  .\gradlew :client:build

# Ejecución de subproyectos
  ## Ejecutar el servidor
  java -jar checkserver/build/libs/checkserver.jar
  ## Ejecutar el cliente
  java -jar client/build/libs/client.jar
  
# Funcionalidades del Servidor
**En Construcción**
👷🏗️

