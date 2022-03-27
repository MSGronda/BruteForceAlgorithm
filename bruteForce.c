#include "bruteForce.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "SHA256 Library/sha-256.h"

int char_to_hex(char c, int base){
    int resp=0;
    if(c>='0' && c<='9'){
        resp += (c- '0') * base;
    }
    else{
        resp += (c - 'a' + 10) * base;
    }
    return resp;
}

int dualchar_to_hex(const char * dualChar){
    int resp=0;

    resp += char_to_hex(dualChar[0], 16);
    resp += char_to_hex(dualChar[1],1);

    return resp;
}
/*
 * Convierte un cypher en ASCII a sus
 * valores hexa correspondientes.
 */

uint8_t * string_to_hash(char * cypher){
    uint8_t * resp = malloc( 32 * sizeof(uint8_t) );
    for(int i=0, j=0; i<32; j+=2,i++){
        resp[i] = dualchar_to_hex(cypher + j * sizeof(char));
    }
    return resp;
}

/*
 * Da positivo si la cifra y la palabra son
 * equivalentes. En este caso, solo se usa
 * string compare. Aca hiria la funcion de
 * encriptacion.
 */
char compare(uint8_t * cypherHash, char * word){
    uint8_t wordHash[32];
    calc_sha_256(wordHash, word, strlen(word));

    for(int i=0; i<32;i++){
        if(cypherHash[i] != wordHash[i]){
            return NO_MATCH_FOUND;
        }
    }
    return MATCH_FOUND;
}

/*
 * Uso: Deja todos los valores anteriores de pos en startingLetter
 * Complejidad temporal: O(n) = n
 */
void setPreviousLettersToStart(char * word, int pos, char startingLetter, int * letterPosInChars){
    for(int i=0; i<pos; i++){
        word[i]=startingLetter;
        letterPosInChars[i]=0;
    }
}

/*
 * Uso: genera un puntero a la palabra que despues se va a usar
 * al generar todas las permutaciones.
 * Complejidad temporal: O(n) = n
 */
char * createWord(char firstLetter, int dimOfWord){
    char * word = malloc(sizeof(char) * (dimOfWord + 1));
    word[dimOfWord] = 0;
    for(int i=0; i<dimOfWord; i++){
        word[i] = firstLetter;
    }
    return word;
}

/*
 * Uso: genera todas las permutacion de n caracteres dado un vector
 * de caracteres posibles.
 * Complejidad temporal: ?????
 */
int testAllWordPermutations(char * cypher, int dimCypher,char * characters, int dimOfCharacters,
                             int dimOfWord, char ** decryptedText, int * dimDecryptedText){

    char lastLetter = characters[dimOfCharacters-1];
    char firstLetter = characters[0];

    /*
     * Setup de la palabra y del vector de caracteres.
     * Ej: Si los carcteres validos son [a,b,c]
     *    Palabra: a b a c
     *    Vector:  0 1 0 2
     */

    char * currentWord = createWord(characters[0], dimOfWord);
    int * letterPosInChars = calloc(dimOfCharacters,sizeof(int));

    uint8_t * cypherHash = string_to_hash(cypher);

    for(int i=0; i < dimOfWord; ){
        /*
         * Testeamos si la palabra actual es la
         * que buscamos. Si lo es, corta la ejecucion.
         */
        if(compare(cypherHash,currentWord)==MATCH_FOUND){
            *decryptedText = currentWord;
            *dimDecryptedText = dimOfWord;
            return MATCH_FOUND;
        }
        /*
         * Si la letra actual no es final, pasa a la proxima letra.
         * El vector se aumenta junto al cambio de letra.
         */
        if(currentWord[i]!=lastLetter){
            currentWord[i] = characters[++letterPosInChars[i]];
        }
            /*
             * Si es la letra mas grande, pasa a la proxima posicion
             * en la palabra y resetea todas las anteriores. Ocurre lo
             * mismo con el vector.
             * Ej: caracteres = [a,b,c]
             *      a a -c- c   =>   a -b- a a
             */
        else{
            while(currentWord[i]==lastLetter){
                i++;
            }
            if(i != dimOfWord){
                currentWord[i] = characters[++letterPosInChars[i]];
                setPreviousLettersToStart(currentWord, i,firstLetter, letterPosInChars);
                i=0;
            }
        }
    }

    free(letterPosInChars);
    free(currentWord);
    free(cypherHash);
    return NO_MATCH_FOUND;
}

/*
 * Testea para un cierto rango, todas las permutaciones de un
 * diccionario contra un elemento cifrado. Si la encuentra,
 * deja la respuesta en el decryptedText y devuelve MATCH_FOUND.
 * Complejidad temporal: ?????
 */
int bruteForceAttack(char * cypher, int dimCypher, char * characters, int dimCharacters,
                      int minLength, int maxLength, char ** decryptedText, int * dimDecryptedText){
    /*
     * Chequeos necesarios.
     */
    if(minLength <=0 || maxLength <=0 || maxLength < minLength || dimCypher <= 0 || dimCharacters <= 0){
        return INVALID_INPUT;
    }

    int found = NO_MATCH_FOUND;

    for(int wordLength = minLength; wordLength <= maxLength && found==NO_MATCH_FOUND; wordLength++) {
        found = testAllWordPermutations(cypher,dimCypher,characters,dimCharacters,
                                        wordLength,decryptedText,dimDecryptedText);
    }

    return found;
}


/*-----------DEMOSTRATIVO------------*/
void printAllWordPermutations(char * characters, int dimOfCharacters, int dimOfWord){
    char lastLetter = characters[dimOfCharacters-1];
    char firstLetter = characters[0];
    char * currentWord = createWord(characters[0], dimOfWord);
    int * letterPosInChars = calloc(dimOfCharacters,sizeof(int));
    for(int i=0; i < dimOfWord; ){
        printf("%s\n",currentWord);
        if(currentWord[i]!=lastLetter){
            currentWord[i] = characters[++letterPosInChars[i]];
        }
        else{
            while(currentWord[i]==lastLetter){
                i++;
            }
            if(i != dimOfWord){
                currentWord[i] = characters[++letterPosInChars[i]];
                setPreviousLettersToStart(currentWord, i,firstLetter, letterPosInChars);
                i=0;
            }
        }
    }
    printf("Last word: %s\n", currentWord);
    free(letterPosInChars);
    free(currentWord);
}




