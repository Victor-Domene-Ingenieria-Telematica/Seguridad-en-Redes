# Práctica 1: César
## Caesar / Breakcaesar
Programas para cifrar y descifrar textos usando el cifrado César.

### Programas
- **caesar**: Cifra un texto con una clave pasada como argumento
- **breakcaesar**: Rompe el cifrado César mediante fuerza bruta

### Compilar caesar.c
```sh
$> gcc -g -c -Wall -Wshadow -Wvla caesar.c
$> gcc -g -o caesar caesar.o
$> 
```

### Uso
- #### Cifrar
    ```sh
    $> echo 'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG'| ./caesar 23
    $> QEB NRFZH YOLTK CLU GRJMP LSBO QEB IXWV ALD
    $> 
    ```

### Compilar breakcaesar.c
Al enlazar el programa breakcaesar.c, tenemos que enlazar con la biblioteca *math* usando la opcion `-lm`

```sh
$> gcc -g -c -Wall -Wshadow -Wvla breakcaesar.c
$> gcc -g -o breakcaesar breakcaesar.o -lm
```

### Uso
- #### Descifrar
    ```sh
    $> echo 'QEB NRFZH YOLTK CLU GRJMP LSBO QEB IXWV ALD' | ./breakcaesar
    23: 0.13080, 6, 2
    $> cat  key-23.txt
    THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG
    $>
    ```

### Ejemplo completo
```sh
$> echo 'THE QUICK BROWN FOX' | ./caesar 23 > cifrado.txt
$> ./breakcaesar < cifrado.txt
$> cat key-23.txt
23: 0.11356, 2, 1
$> 
```

### Salida
- Breakcaesar muestra los candidatos más probables basandose en la frecuencia de aparicion, la cantidad de diagramas y la 
cantidad de trigramas y genera archivos `key-N.txt` con el texto descifrado.
