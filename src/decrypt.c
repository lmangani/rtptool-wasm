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
  Decrypts SRTP audio stream
  Input: SSRC, key material, .pcap file
  Output file format depends on audio codec
*/



#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"
#include "hex.h"
#include "base64.h"
#include "file.h"



int decrypt( const char *input_ssrc, const char *key, const char *filename, const int MKI_length, const int MAC_length ) {

pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
struct pcap_pkthdr *header;
const u_char *pkt_data;

u_char *wav_file_content;
u_char wav_file_skeleton_header[71] = { 
	0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45, 0x66, 0x6D, 0x74, 0x20,
	0x12, 0x00, 0x00, 0x00, 0x07, 0x00, 0x01, 0x00, 0x40, 0x1F, 0x00, 0x00, 0x40, 0x1F, 0x00, 0x00,
	0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x66, 0x61, 0x63, 0x74, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x00, 0x54, 0xE3, 0x68, 0x63, 0x60, 0x17,
	0x51, 0x6E, 0x60, 0x6D, 0x63, 0x59, 0x65
};
u_char silkbin_file_skeleton_header[9] = { 
	0x23, 0x21, 0x53, 0x49, 0x4C, 0x4B, 0x5F, 0x56, 0x33
};
int wav_file_size;
int riff_chunk_size, fact_sample_length, data_chunk_size;
char wav_file_name[256];

u_int i=0;
int res;
int frame_number = 0;
int rtp_offset;
int rtp_payload_type;
int rtp_pt_found;
int rtp_payload_size;
int cmdline_ssrc_length;
unsigned char *cmdline_ssrc;
unsigned char sequence_number[ 2 ];
unsigned char ssrc[ 4 ];

unsigned char *key_info;
unsigned char key_info_base64decoded[ 30 ];
int key_info_len;
int key_info_len_base64decoded;

unsigned char master_key[ 16 ];
unsigned char master_salt[ 14 ];

unsigned char cipher_key[ 16 ];
unsigned char cipher_salt[ 14 ];

unsigned char temp[ 16 ];
unsigned char temp1[ 16 ];

unsigned char counter[ 16 ];
unsigned char keystream[ 16 ];
unsigned char increment;

int bytes_to_decrypt;
int first_packet_found = 0;


key_info_len = hex_decode( key, &key_info );
if ( !( key_info_len == 40 ) )
{
fprintf( stderr, "Unsupported key info length: %d\n", key_info_len );
exit( -1 );
}

cmdline_ssrc_length = hex_decode( input_ssrc, &cmdline_ssrc );
if ( !( cmdline_ssrc_length == 4 ) )
{
fprintf( stderr, "Unsupported synchronization source identifier length: %d\n", cmdline_ssrc_length );
exit( -1 );
}

/* extract master key and master salt from key info */ 
key_info_len_base64decoded = base64_decode( key_info, 40, key_info_base64decoded );
memcpy( ( void * ) master_key, ( void * ) key_info_base64decoded, 16 ); 
/* printf( "\nMaster Key:\t" );
show_hex( master_key, 16 ); */
memcpy( ( void * ) master_salt, ( void * ) ( key_info_base64decoded + 16 ), 14 );
/* printf( "Master Salt:\t" ); 
show_hex( master_salt, 14 ); */

/* compute cipher key from master key and master salt according to RFC3711 */
memcpy( ( void * ) (temp), ( void * ) master_salt, 14 );
temp[ 14 ] = 0x00;
temp[ 15 ] = 0x00;
aes_block_encrypt( temp, cipher_key, master_key, 16 );
/* printf( "Cipher Key:\t" );
show_hex( cipher_key, 16 ); */

/* compute cipher salt from master key and master salt according to RFC3711 */
temp[7] ^= 0x02;
aes_block_encrypt( temp, temp1, master_key, 16 );
memcpy( ( void * ) (cipher_salt), ( void * ) temp1, 14 );
/* printf( "Cipher Salt:\t" );
show_hex( cipher_salt, 14 );
printf( "\n" ); */



/* Open the capture file */
if ( (fp = pcap_open_offline(filename, errbuf) ) == NULL) {
	fprintf(stderr,"\nPCAP: Unable to open %s\nError: %s\n", filename, errbuf);
	return -1;
}



/* Find the first packet from the stream with supported payload type */
while( ( ( res = pcap_next_ex( fp, &header, &pkt_data ) ) >= 0 ) && !first_packet_found )
{
	frame_number = frame_number + 1;

	/* RTP Offset = Ethernet Header (14 bytes) +
	                IP Header length (found in lower 4 bits of first IP byte) +
					UDP Header (8 bytes)
    */
	rtp_offset = ( int )( pkt_data[ 14 ] & 0x0F ) * 4 + 22;

	/* RTP Payload Type starts 9 bits after RTP Offset and is 7 bits long */
	rtp_payload_type = (int) ( pkt_data[ rtp_offset + 1 ] & 0x7F );

	/* RTP Sequence Number starts 2 bytes after RTP Offset and is 2 bytes long */
	sequence_number[ 0 ] = pkt_data[ rtp_offset + 2 ];
	sequence_number[ 1 ] = pkt_data[ rtp_offset + 3 ];

	/* RTP SSRC starts 8 bytes after RTP Offset and is 4 bytes long */
	ssrc[ 0 ] = pkt_data[ rtp_offset + 8 ];
	ssrc[ 1 ] = pkt_data[ rtp_offset + 9 ];
	ssrc[ 2 ] = pkt_data[ rtp_offset + 10 ];
	ssrc[ 3 ] = pkt_data[ rtp_offset + 11 ];

	/* Does SSRC from command line match SSRC from packet? Does first byte after UDP Header equal 0x80? */
	/* This check is also used to eliminate packets that have nothing to do with this RTP stream */
	if ( ( pkt_data[ rtp_offset ] == 0x80 ) &&
		 ( ssrc[ 0 ] == cmdline_ssrc[ 0 ] ) &&
		 ( ssrc[ 1 ] == cmdline_ssrc[ 1 ] ) &&
		 ( ssrc[ 2 ] == cmdline_ssrc[ 2 ] ) &&
		 ( ssrc[ 3 ] == cmdline_ssrc[ 3 ] ) &&
	/* and is RTP Payload Type 0 (PCMU) or 8 (PCMA) or 9 (G.722) or 103 (SILK8000) or 104 (SILK16000)? */
		 ( ( rtp_payload_type == 0 ) || ( rtp_payload_type == 8 ) || ( rtp_payload_type == 9 ) || ( rtp_payload_type == 103 ) || ( rtp_payload_type == 104 ) ) )
	{
		/* First packet was found */
		first_packet_found = 1;
		rtp_pt_found = rtp_payload_type;

		/* If RTP Payload Type is PCMU, use skeleton (PCMU is already in wav_file_skeleton_header) */
		if ( rtp_payload_type == 0 ) {
			wav_file_size = 58; /* 58 bytes in wav file before payload begins */
			wav_file_content = malloc( wav_file_size );
			memcpy( ( void * ) wav_file_content, ( void * ) wav_file_skeleton_header, wav_file_size );
		}

		/* If RTP Payload Type is PCMA, use skeleton and tell the wav file */
		if ( rtp_payload_type == 8 ) {
			wav_file_size = 58; /* 58 bytes in wav file before payload begins */
			wav_file_content = malloc( wav_file_size );
			memcpy( ( void * ) wav_file_content, ( void * ) wav_file_skeleton_header, wav_file_size );
			wav_file_content[ 20 ] = 0x06;
		}

		/* If RTP Payload Type is G.722, use Raw file */
		if ( rtp_payload_type == 9 ) {
			wav_file_size = 0; 
			wav_file_content = malloc( wav_file_size );
		}

		/* If RTP Payload Type is SILK8000 or SILK16000, use SILK bin file */
		if ( ( rtp_payload_type == 103 ) || ( rtp_payload_type == 104 ) ) {
			wav_file_size = 9; /* SILK bin file with 9 byte header */
			wav_file_content = malloc( wav_file_size );
			memcpy( ( void * ) wav_file_content, ( void * ) silkbin_file_skeleton_header, wav_file_size );
		}

		printf( "*");
		/* printf( "Frame %d: RTP Seq: %.2x%.2x RTP SSRC: %.2x%.2x%.2x%.2x decrypting...\n", frame_number, sequence_number[ 0 ], sequence_number[ 1 ], ssrc[ 0 ], ssrc[ 1 ], ssrc[ 2 ], ssrc[ 3 ] ); */
		
		memcpy( ( void * ) (counter), ( void * ) cipher_salt, 14 );
		counter[ 14 ] = 0x00;
		counter[ 15 ] = 0x00;
		xor( counter + 4, ssrc, 4 );
		xor( counter + 12, sequence_number, 2 );

		/* RTP Payload starts 12 bytes after RTP Offset and ends at header->caplen - MKI_length - MAC_length */
		/* increase memory by the amount of payload data */
		/* (add another 2 bytes if SILK bin file) */
		rtp_payload_size = header->caplen - rtp_offset - 12 - MKI_length - MAC_length;
		wav_file_size = wav_file_size + rtp_payload_size;
		if ( ( rtp_payload_type == 103 ) || ( rtp_payload_type == 104 ) ) wav_file_size = wav_file_size + 2;
		wav_file_content = realloc( wav_file_content, wav_file_size );

		/* add payload size to SILK bin file */
		if ( ( rtp_payload_type == 103 ) || ( rtp_payload_type == 104 ) ) {
			memcpy( ( void * ) ( wav_file_content + wav_file_size - rtp_payload_size - 2 ), ( void * ) ( &rtp_payload_size ), 2 ); /* it's little endian anyway */
		}

		/* Walk through the RTP payload 16 bytes at a time and decrypt and write to file content */
		increment = 0x00; 
		for( i = rtp_offset + 12; i < header->caplen - MKI_length - MAC_length; i = i + 16 ) {
			counter[ 15 ] = increment;
			aes_block_encrypt( counter, keystream, cipher_key, 16 );
			bytes_to_decrypt = ( header->caplen - MKI_length - MAC_length - i < 16 ) ? header->caplen - MKI_length - MAC_length - i : 16;
			memcpy( ( void * ) (temp), ( void * ) ( pkt_data + i ), bytes_to_decrypt );
			xor( temp, keystream, bytes_to_decrypt );
			memcpy( ( void * ) ( wav_file_content + wav_file_size - rtp_payload_size - rtp_offset - 12 + i ), ( void * ) (temp), bytes_to_decrypt );
			increment++; 
		}
	}
}


if (!first_packet_found) {
	printf("\nCould not find an RTP packet with this SSRC and a supported payload type.\n");
}


/* Retrieve the remaining packets from the file */
while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0)
{
	frame_number = frame_number + 1;

	/* RTP Offset = Ethernet Header (14 bytes) +
	                IP Header length (found in lower 4 bits of first IP byte) +
					UDP Header (8 bytes)
    */
	rtp_offset = ( int )( pkt_data[ 14 ] & 0x0F ) * 4 + 22;

	/* RTP Payload Type starts 9 bits after RTP Offset and is 7 bits long */
	rtp_payload_type = (int) ( pkt_data[ rtp_offset + 1 ] & 0x7F ); 

	/* RTP Sequence Number starts 2 bytes after RTP Offset and is 2 bytes long */
	sequence_number[ 0 ] = pkt_data[ rtp_offset + 2 ];
	sequence_number[ 1 ] = pkt_data[ rtp_offset + 3 ];

	/* RTP SSRC starts 8 bytes after RTP Offset and is 4 bytes long */
	ssrc[ 0 ] = pkt_data[ rtp_offset + 8 ];
	ssrc[ 1 ] = pkt_data[ rtp_offset + 9 ];
	ssrc[ 2 ] = pkt_data[ rtp_offset + 10 ];
	ssrc[ 3 ] = pkt_data[ rtp_offset + 11 ];

	/* Does SSRC from command line match SSRC from packet? Does first byte after UDP Header equal 0x80? */
	/* This check is also used to eliminate packets that have nothing to do with this RTP stream */
	if ( ( pkt_data[ rtp_offset ] == 0x80 ) &&
		 ( ssrc[ 0 ] == cmdline_ssrc[ 0 ] ) &&
		 ( ssrc[ 1 ] == cmdline_ssrc[ 1 ] ) &&
		 ( ssrc[ 2 ] == cmdline_ssrc[ 2 ] ) &&
		 ( ssrc[ 3 ] == cmdline_ssrc[ 3 ] ) &&
	/* and is RTP Payload Type identical to the RTP Payload Type we found in the first packet? */
		 ( rtp_payload_type == rtp_pt_found )
		 )
	{
		printf( "*");
		/* printf( "Frame %d: RTP Seq: %.2x%.2x RTP SSRC: %.2x%.2x%.2x%.2x decrypting...\n", frame_number, sequence_number[ 0 ], sequence_number[ 1 ], ssrc[ 0 ], ssrc[ 1 ], ssrc[ 2 ], ssrc[ 3 ] ); */
		
		memcpy( ( void * ) (counter), ( void * ) cipher_salt, 14 );
		counter[ 14 ] = 0x00;
		counter[ 15 ] = 0x00;
		xor( counter + 4, ssrc, 4 );
		xor( counter + 12, sequence_number, 2 );

		/* RTP Payload starts 12 bytes after RTP Offset and ends at header->caplen - MKI_length - MAC_length */
		/* increase memory by the amount of payload data */
		/* (add another 2 bytes if SILK bin file) */
		rtp_payload_size = header->caplen - rtp_offset - 12 - MKI_length - MAC_length;
		wav_file_size = wav_file_size + rtp_payload_size;
		if ( ( rtp_payload_type == 103 ) || ( rtp_payload_type == 104 ) ) wav_file_size = wav_file_size + 2;
		wav_file_content = realloc( wav_file_content, wav_file_size );

		/* add payload size to SILK bin file */
		if ( ( rtp_payload_type == 103 ) || ( rtp_payload_type == 104 ) ) {
			memcpy( ( void * ) ( wav_file_content + wav_file_size - rtp_payload_size - 2 ), ( void * ) ( &rtp_payload_size ), 2 ); /* it's little endian anyway */
		}

		/* Walk through the RTP payload 16 bytes at a time and decrypt and write to file content */
		increment = 0x00; 
		for( i = rtp_offset + 12; i < header->caplen - MKI_length - MAC_length; i = i + 16 ) {
			counter[ 15 ] = increment;
			aes_block_encrypt( counter, keystream, cipher_key, 16 );
			bytes_to_decrypt = ( header->caplen - MKI_length - MAC_length - i < 16 ) ? header->caplen - MKI_length - MAC_length - i : 16;
			memcpy( ( void * ) (temp), ( void * ) ( pkt_data + i ), bytes_to_decrypt );
			xor( temp, keystream, bytes_to_decrypt );
			memcpy( ( void * ) ( wav_file_content + wav_file_size - rtp_payload_size - rtp_offset - 12 + i ), ( void * ) (temp), bytes_to_decrypt );
			increment++; 
		}
	}
}

if (res == -1)
{
    printf("Error reading the packets: %s\n", pcap_geterr(fp));
}

/* if something was decrypted, write the file */
if ( wav_file_size > 0 )
{
	if ( ( rtp_pt_found == 0 ) || ( rtp_pt_found == 8 ) ) {
		riff_chunk_size = wav_file_size - 8;
		fact_sample_length = wav_file_size - 58;
		data_chunk_size = wav_file_size - 58;
		memcpy( ( void * ) ( wav_file_content + 4 ), ( void * ) &riff_chunk_size, 4 );
		memcpy( ( void * ) ( wav_file_content + 46 ), ( void * ) &fact_sample_length, 4 );
		memcpy( ( void * ) ( wav_file_content + 54 ), ( void * ) &data_chunk_size, 4 );
		strcpy( wav_file_name, input_ssrc );	
		strcat( wav_file_name, ".wav" );
		write_memory_to_file( wav_file_name, wav_file_content, wav_file_size );
	}

	if ( rtp_pt_found == 9 ) {
		strcpy( wav_file_name, input_ssrc );	
		strcat( wav_file_name, ".g722" );
		write_memory_to_file( wav_file_name, wav_file_content, wav_file_size );
		printf("\nRun the following command:\n\n");
		printf("ffmpeg.exe -i %s out.wav\n", wav_file_name);
	}
	if ( rtp_pt_found == 103 ) {
		strcpy( wav_file_name, input_ssrc );	
		strcat( wav_file_name, "-SILK8000.bin" );
		write_memory_to_file( wav_file_name, wav_file_content, wav_file_size );
		printf("\nRun the following commands:\n\n");
		printf("decoder.exe %s help.pcm -Fs_API 8000\n", wav_file_name);
		printf("ffmpeg.exe -f s16le -ar 8000 -i help.pcm out.wav\n");
	}
	if ( rtp_pt_found == 104 ) {
		strcpy( wav_file_name, input_ssrc );	
		strcat( wav_file_name, "-SILK16000.bin" );
		write_memory_to_file( wav_file_name, wav_file_content, wav_file_size );
		printf("\nRun the following commands:\n\n");
		printf("decoder.exe %s help.pcm -Fs_API 16000\n", wav_file_name);
		printf("ffmpeg.exe -f s16le -ar 16000 -i help.pcm out.wav\n");
	}
}

printf( "\n");
return 0;
}
