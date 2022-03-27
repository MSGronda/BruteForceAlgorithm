//
// Created by mbox_2 on 3/12/2022.
//

#ifndef MISC_BRUTEFORCE_H
#define MISC_BRUTEFORCE_H

#include <stdint.h>

#define INVALID_INPUT 2
#define MATCH_FOUND 0
#define NO_MATCH_FOUND 1

void printAllWordPermutations(char * characters, int dimOfCharacters, int dimOfWord);
int bruteForceAttack(char * cypher, int dimCypher, char * characters, int dimCharacters,
                     int minLength, int maxLength, char ** decryptedText, int * dimDecryptedText);

#endif //MISC_BRUTEFORCE_H
