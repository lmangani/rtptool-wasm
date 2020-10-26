#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "file.h"


void write_memory_to_file( char *filename, char *binary_data, int buffer_length )
{
  FILE *outfile;
  int bytes_written;

  if ( ( outfile = fopen( filename, "wb" ) ) == NULL )
  {
    perror( "\n\nUnable to open file for writing\n" );
    return;
  }
 
  bytes_written = fwrite( ( void * ) binary_data, 1, buffer_length, outfile );

  fclose( outfile );
}