#include <stdio.h>
#include <string.h>

void usage( const char *filename )
{
  printf("\n\n");
  printf("usage:\n");
  printf("%s analyze <input file>\n", filename);
  printf("%s decrypt <ssrc> <key> <input file>\n", filename);
  printf("%s extract <ssrc> <input file>\n", filename);
  printf("%s help [analyze|decrypt|extract|info]\n", filename);
  printf("\n");
}

int help( const char *filename, const char *helpselection )
{
  if (!strcmp( "analyze", helpselection ))
  {
	printf("\n\n");
	printf("Provide a pcap file as second argument.\n");
	printf("%s will try to find RTP media streams in the pcap file and display some info including the SSRC value.\n", filename);
	printf("\n");
	printf("Example:\n%s analyze file.pcap\n", filename);
	printf("\n");
	return 0;
  }
  if (!strcmp( "decrypt", helpselection ))
  {
	printf("\n\n");
	printf("Provide the SSRC value of the SRTP stream to decrypt as second argument in Hex notation with leading 0x.\n");
	printf("Provide the key material to be used for decryption as third argument as 40 character base64 value.\n");
	printf("Provide the pcap file that contains the SRTP stream as fourth argument.\n\n");
	printf("%s will create an output file that contains the decrypted audio data.\n", filename);
	printf("For further information run %s help info.\n\n", filename);
	printf("Example:\n%s decrypt 0x72c4827b CXL0YTLiYrsKYDAsxAJKTWqQaBg1PQhUH9iFwPAp file.pcap\n", filename);
	printf("\n");
	return 0;
  }
  if (!strcmp( "info", helpselection ))
  {
	printf("\n\n");
	printf("To decrypt an SRTP audio stream you need the key material that was used to encrypt it. ");
	printf("Get it from a SIP trace or from a log file. ");
	printf("The key material is a 40 byte character string, for example CXL0YTLiYrsKYDAsxAJKTWqQaBg1PQhUH9iFwPAp.\n");
	printf("You also need the SSRC value of the SRTP audio stream. One way of doing this is by running %s analyze.\n\n\n\n\n", filename);

	printf("For a G.711 RTP stream (PCMU or PCMA) %s creates a .wav file that can be played directly.\n\n\n", filename);
	printf("For a G.722 RTP stream %s creates a RAW file with .g722 extension. Use ffmpeg to convert:\n", filename);
	printf("ffmpeg -i file.g722 file.wav\n\n\n");
	printf("For a SILK 8KHz RTP stream %s creates a SILK SDK file with .bin extension. To convert use:\n", filename);
	printf("decoder.exe file-SILK8000.bin help.pcm -Fs_API 8000\n");
	printf("ffmpeg.exe -f s16le -ar 8000 -i help.pcm out.wav\n\n\n");
	printf("For a SILK 16KHz RTP stream %s creates a SILK SDK file with .bin extension. To convert use:\n", filename);
	printf("decoder.exe file-SILK16000.bin help.pcm -Fs_API 16000\n");
	printf("ffmpeg.exe -f s16le -ar 16000 -i help.pcm out.wav\n\n\n\n");
	printf("Codecs other than G.711, G.722, SILK/8000 and SILK/16000 are not supported.\n");
	printf("\n");

	return 0;
  }
  return -1;
}
