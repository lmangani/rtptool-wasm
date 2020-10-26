/*
  From Joshua Davies: Implementing SSL / TLS Using Cryptography and PKI at www.wiley.com/go/implementingssl
*/

#ifndef HEX_H
#define HEX_H

int hex_decode( const unsigned char *input, unsigned char **decoded );
void show_hex( const unsigned char *array, int length );

#endif
