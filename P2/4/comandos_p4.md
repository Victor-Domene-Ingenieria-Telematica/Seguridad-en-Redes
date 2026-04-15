# Pregunta 4

## Firmar la clave
Antes de firmarla debemos de comprobar el finguerprint de Enrique Soriano.
1. Debemos de abrir el **editor interativo de GPG** con el comando:
    - `$> gpg --edit-key enrique.soriano@gmail.com`

*Debemos poner enrique.soriano@gmail.com en el comando anterior debido a
que tenemos su clave importada en el anillo de claves publicas y tambien los
UIDs asociados a ella*

2. Una vez dentro del editor tenemos que escribir el comando `sign` para firmarla,
nos pide la passphrase para poder poder firmarla.

3. Despues para acabara y guardar los cambios tenemos que poner el comando `save` 
el cual guardará los cambios.


## Subir la clave al servidor GPG de Ubuntu

1. Tenemos que ver cual es el KeyID con el comando `$> gpg --list-keys` y buscar la
firmada.

2. Ahora con el KeyID ya podemos subirla al servidor con el comando:
    - `$> gpg --keyserver keyserver.ubuntu.com --send-keys 29C532C0EE857DCE384E362726930ACAF90A5363`
