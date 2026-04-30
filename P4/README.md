# Práctica 4: protocolo de autenticación

## 1. Compilación
Para compilar los programas, debemos ejecutar e siguiente comando puesto que he hecho un
Makefile. Tenemos que estar en el directorio de la práctica y ejecutar en la terminal:

    $>make

Esto compilará los archivos fuente usando el Makefile y generará los ejecutables
`authserver` y `authclient`. Si necesitamos borrar los binarios generados para hacer una
compilación limpia, ejecutamos en terminal:

    $>make clean

## 2. Ejecución del Servidor
El servidor debe arrancarse primero. Recibe como parámetros el fichero de cuentas y,
de forma opcional, el puerto en el que va a escuchar (si no se pone puerto, usa el 9999
por defecto)

- Formato --> ./authserver fichero_cuentas puerto

- Ejemplo de ejecución --> ./authserver accounts.txt 9999

## 3. Ejecución del Cliente

Con el servidor ya corriendo, abrimos una nueva terminal para ejecutar el cliente

- Formato --> `./authclient usuario clave_hexadecimal ip_servidor puerto`

- Ejemplo de ejecución --> `./authclient pepe 3f786850e387550fdab836ed7e6dc881de23001b 127.0.0.1 9999`