/*
 * srtpdecrypt
 *
 * Written in 2016
 * Refactored in 2021
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
#include "decrypt.h"
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
  MAIN_THREAD_EM_ASM({
     var filename = UTF8ToString($0);
     var read = FS.readFile(filename, { encoding: 'utf8' });
  }, filename);
  int r;
  r = analyze( filename );
  return r;
}

EMSCRIPTEN_KEEPALIVE
int extract_pcap(const char *ssrc, const char *filename) {
  MAIN_THREAD_EM_ASM({
     var filename = UTF8ToString($1);
     var ssrc = UTF8ToString($0);
     var read = FS.readFile(filename, { encoding: 'utf8' });
  }, ssrc, filename);
  int r;
  r = extract( ssrc, filename );
  MAIN_THREAD_EM_ASM({
     var filename = UTF8ToString($0)+".wav";
     var ssrc = UTF8ToString($0);
     var read = FS.readFile(filename, { encoding: 'utf8' });
  }, ssrc, filename);

  return r;
}

EMSCRIPTEN_KEEPALIVE
int decrypt_pcap(const char *ssrc, const char *key, const char *filename) {
  MAIN_THREAD_EM_ASM({
     var filename = UTF8ToString($1);
     var ssrc = UTF8ToString($0);
     var read = FS.readFile(filename, { encoding: 'utf8' });
  }, ssrc, filename);
  int r;
  r = decrypt( ssrc, key, filename, 1, 10 );
  MAIN_THREAD_EM_ASM({
     var filename = UTF8ToString($0)+".wav";
     var ssrc = UTF8ToString($0);
     var read = FS.readFile(filename, { encoding: 'utf8' });
  }, ssrc, filename);

  return r;
}

EMSCRIPTEN_KEEPALIVE
uint8_t* create_buffer(int width, int height) {
  return malloc(width * height * 4 * sizeof(uint8_t));
}

EMSCRIPTEN_KEEPALIVE
void destroy_buffer(uint8_t* p) {
  free(p);
}


void emscripten_wget_data(const char* url, void** pbuffer, int* pnum, int *perror);


int main() {
  EM_ASM(
        // Make a directory other than '/'
        FS.mkdir('/pcap');
        // Then mount with IDBFS type
        FS.mount(MEMFS, {}, '/pcap');
        FS.syncfs(true, function (err) {
            // Error
        });
  );

  emscripten_exit_with_live_runtime();
  return 0;
}
