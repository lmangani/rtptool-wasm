/*
  From Joshua Davies: Implementing SSL / TLS Using Cryptography and PKI at www.wiley.com/go/implementingssl
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "hex.h"

/** 
 * Check to see if the input starts with "0x"; if it does, return the decoded
 * bytes of the following data (presumed to be hex coded). If not, just return
 * the contents. This routine allocates memory, so has to be free'd.
 */
int hex_decode( const unsigned char *input, unsigned char **decoded )
{  
  int i;
  int len;
    
  if ( strncmp( "0x", input, 2 ) )
  {
    len = strlen( input ) + 1;
    *decoded = malloc( len );
    strcpy( *decoded, input );
    len--;
  }
  else
  {
    len = ( strlen( input ) >> 1 ) - 1;
    *decoded = malloc( len );
    for ( i = 2; i < strlen( input ); i += 2 )
    {
      (*decoded)[ ( ( i / 2 ) - 1 ) ] =
        ( ( ( input[ i ] <= '9' ) ? input[ i ] - '0' : 
        ( ( tolower( input[ i ] ) ) - 'a' + 10 ) ) << 4 ) |
        ( ( input[ i + 1 ] <= '9' ) ? input[ i + 1 ] - '0' : 
        ( ( tolower( input[ i + 1 ] ) ) - 'a' + 10 ) );
    }
  } 
 
  return len;
}

void show_hex( const unsigned char *array, int length )
{
  while ( length-- )
  {
    printf( "%.02x", *array++ );
  }
  printf( "\n" );
}
