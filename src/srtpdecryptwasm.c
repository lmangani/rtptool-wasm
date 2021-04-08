/*
 * srtpdecrypt
 *
 * Written in 2016
 *
 * To the extent possible under law, the author has dedicated all copyright
 * and related and neighboring rights to this software to the public domain worldwide.
 * This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along with this software.
 * If not, see <http://creativecommons.org/publicdomain/zero/1.0/>. 
 *
*/



/*
  Main: processes arguments and calls main functions
*/

#include "emscripten.h"
#include <string.h>
#include "analyze.h"
#include "decrypt.h"
#include "extract.h"
#include "usage-and-help.h"
#include <stdlib.h>
#include <stdint.h>
#include <emscripten.h>

/* Wasm exports */
EMSCRIPTEN_KEEPALIVE
int add(int a, int b) {
  return a + b;
}

EMSCRIPTEN_KEEPALIVE
uint8_t* create_buffer(int width, int height) {
  return malloc(width * height * 4 * sizeof(uint8_t));
}

EMSCRIPTEN_KEEPALIVE
void destroy_buffer(uint8_t* p) {
  free(p);
}


/* original functions */

int main(int argc, char **argv)
{
/* process arguments */

if(argc == 1){

	usage( argv[0] );
    return -1;
}
if(strcmp( argv[1], "analyze") && strcmp( argv[1], "decrypt") && strcmp( argv[1], "extract") && strcmp( argv[1], "help")){

	usage( argv[0] );
    return -1;
}
if(!strcmp(argv[1], "help" ) && argc < 3){

	usage( argv[0] );
    return -1;
}
if(!strcmp(argv[1], "help" ) && strcmp( argv[2], "analyze") && strcmp( argv[2], "decrypt") && strcmp( argv[2], "info")){

	usage( argv[0] );
    return -1;
}
if(!strcmp(argv[1], "help" ))
{
	help( argv[0], argv[2] );
	return 0;
}
if(!strcmp(argv[1], "analyze" ))
{
	int r;
	if ( argc < 3 ) {
		usage ( argv[0] );
		return -1;
	}
	r = analyze( argv[2] );
	return r;
}
if(!strcmp(argv[1], "decrypt" ))
{
	int r;
	if ( argc < 5 ) {
		usage ( argv[0] );
		return -1;
	}
	r = decrypt( argv[2], argv[3], argv[4], 1, 10 ); /* MKI = 1, MAC length = 10 by default */
	return r;
}
if(!strcmp(argv[1], "extract" ))
{
	int r;
	if ( argc < 4 ) {
		usage ( argv[0] );
		return -1;
	}
	r = extract( argv[2], argv[3] );
	return r;
}
    
return 0;
}
