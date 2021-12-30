#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcrypt.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>


int decrypt(void* buffer, int buffer_len, char* IV, char* key, int key_len) {
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);

  if( buffer_len % blocksize != 0 ){ 
    return 1;
  }
  
  mcrypt_generic_init(td, key, key_len, IV);
  mdecrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);
  
  return 0;
}

int main(int argc, char* argv[]) // gcc src.c -o dec -lmcrypt -ggdb
{

  // Setting up values
  char* IV = "AAAAAAAAAAAAAAAA";
  char *key = "VXISlqY>Ve6D<{#F";
  int keysize = 16;
  char* buffer;
  int buffer_len = 16;

  // Open and reading file content to buffer
  FILE *fileptr;

  fileptr = fopen("core", "rb");
  fseek(fileptr, 0, SEEK_END);
  int filelen = ftell(fileptr);
  fseek(fileptr, 0, SEEK_SET);

  int i;
  for (i = 0; i < filelen; i += 16) {
    void* ciphertext = malloc(buffer_len);
    fread(ciphertext, 1, 16, fileptr);

    // Try to decrypt current 16 bytes
    decrypt(ciphertext, buffer_len, IV, key, keysize);

    if (strncmp(ciphertext, "HTB{", 4) == 0) {
      printf("Decrypted contents: %s\n", ciphertext);
      return 0;
    }
  }

  return 0;
}

