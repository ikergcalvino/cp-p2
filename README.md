# Práctica 2 – MD5

En sistemas que necesitan autenticar usando passwords es frecuente que en vez de almacenarlos
directamente se guarde un hash. Cuando hay que comprobar si un password es correcto, se aplica
la misma función de hash y se compara con el hash almacenado. En caso de un problema de
seguridad que permita acceder a los hash los passwords no quedan expuestos porque la función no
es fácilmente invertible.

Si asumiendo ciertas restricciones en la generación de passwords podemos rompelos por fuerza bruta. Vamos a partir de un programa que, a partir de un hash md5, recupere el password
suponiendo:

- Los passwords tienen 6 caracteres.

- Cada carácter solo puede ser una letra minúscula distinta de la ñ.

Como excluyendo la ñ hay 26 letras, esto permite 26<sup>6</sup> passwords distintos. En el programa
hay dos funciones (pass_to_long y long_to_pass) que establecen una correspondencia entre un
número entre 0 y 26<sup>6</sup> y un password. Para romper el hash el programa itera entre 0 y 26<sup>6</sup>
, genera
el password correspondiente, calcula su hash md5, y lo compara con el hash que queremos romper.

Para probarlo, si tenemos un password podemos generar su hash de la siguiente forma:

```
$ echo -n "passwd" | md5sum
76a2173be6393254e72ffa4d6df1030a -
```

Y romperíamos ese hash llamando al programa y pasándolo:

```
$ ./break_md5 76a2173be6393254e72ffa4d6df1030a
76a2173be6393254e72ffa4d6df1030a: passwd
```

Para compilar el programa, hay que tener instaladas las cabeceras de desarrollo de openssl (en
ubuntu o debian están en el paquete libssl-dev)

Partiendo de este código se pide:

## Ejercicio 1 (Haga el programa multithread)
Ahora mismo se usa un único thread para
romper el hash. Como el programa prueba de forma exhaustiva, podríamos dividir los posibles
passwords entre varios threads y acelerar el cálculo. Añade threads para realizar los cálculos. Al
obtener el resultado en cualquiera de ellos deberíamos parar al resto.

## Ejercicio 2 (Añada una barra de progreso)
El programa trabaja sin mostrar información
sobre los casos que lleva probados. Partiendo del ejericio1, crea un thread que se encargue de
imprimir una barra de progreso. Los threads que están haciéndo cálculos deberían informar de
cuantos casos llevan probados, y el thread que imprime la barra debería usar esta información
para calcular que proporción de los casos totales llevamos.

Para imprimir una barra que vaya creciendo se puede usar el código \r en printf para devolver
el cursor al principio de una linea. De esta forma podemos sobreescribir la información de progreso.

## Ejercicio 3 (Probar varias claves a la vez)
Al romper el password por fuerza bruta estamos
generando posibles password, calculando su hash md5, y comparándolo con el que queremos romper. El paso que más carga implica es el cálculo del hash, por lo que si queremos romper varios
passwords es más eficiente calcular el hash asociado a uno de los posibles passwords, y compararlo
con todos los hashes que queremos romper.

Modifica el programa para que acepte un número arbitrario de password por línea de comandos:

```
$ ./break_md5 76a2173be6393254e72ffa4d6df1030a 35bc8cec895861697a0243c1304c7789
```

En el momento en que se rompa un hash se imprime, y en todos los threads se deja de comparar
contra él.
