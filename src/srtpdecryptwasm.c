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
#include "extract.h"
#include "usage-and-help.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <emscripten.h>
#include <pcap/pcap.h>
#include "hex.h"

/* Wasm exports */

EMSCRIPTEN_KEEPALIVE
void version() {
  printf("WASM\n");
}

EMSCRIPTEN_KEEPALIVE
int analyze_pcap(const char *filename) {
  int r;
  r = analyze( filename );
  return r;
}

EMSCRIPTEN_KEEPALIVE
int extract_pcap(const char *ssrc, const char *filename) {
  int r;
  r = extract( ssrc, filename );
  return r;
}

/*
EMSCRIPTEN_KEEPALIVE
int decrypt_pcap(char **ssrc, char **key, char **filename) {
  int r;
  r = decrypt( ssrc, key, filename, 1, 10 );
  return r;
}
*/

EMSCRIPTEN_KEEPALIVE
uint8_t* create_buffer(int width, int height) {
  return malloc(width * height * 4 * sizeof(uint8_t));
}

EMSCRIPTEN_KEEPALIVE
void destroy_buffer(uint8_t* p) {
  free(p);
}


/* original functions */

/*
int main(int argc, char **argv)
{

if(argc == 1){

	usage( argv[0] );
    return -1;
}
if(!strcmp(argv[1], "help" ) && argc < 3){

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
*/
