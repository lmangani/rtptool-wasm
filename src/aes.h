/*
  From Joshua Davies: Implementing SSL / TLS Using Cryptography and PKI at www.wiley.com/go/implementingssl
*/

#ifndef AES_H
#define AES_H

void aes_128_encrypt( const unsigned char *plaintext,
           const int plaintext_len,
           unsigned char ciphertext[],
           void *iv,
           const unsigned char *key );
void aes_128_decrypt( const unsigned char *ciphertext,
           const int ciphertext_len,
           unsigned char plaintext[],
           void *iv,
           const unsigned char *key );
void aes_256_encrypt( const unsigned char *plaintext,
           const int plaintext_len,
           unsigned char ciphertext[],
           void *iv,
           const unsigned char *key );
void aes_256_decrypt( const unsigned char *ciphertext,
           const int ciphertext_len,
           unsigned char plaintext[],
           void *iv,
           const unsigned char *key );
void xor( unsigned char *target,
		   const unsigned char *src,
		   int len );
void aes_block_encrypt( const unsigned char *input_block,
           unsigned char *output_block,
           const unsigned char *key,
           int key_size );

#endif
