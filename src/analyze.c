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
  Shows information about RTP Audio streams in a given .pcap file
  Primary use is to display the Synchronization Source (SSRC) identifier
*/



#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include "hex.h"


int analyze( const char *filename ) {

pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
struct pcap_pkthdr *header;
const u_char *pkt_data;
u_int i=0;
int res;
int frame_number = 0;
int rtp_offset;

struct RTP_Stream_Data {
	unsigned char ssrc[ 4 ];
	unsigned char pt[ 1 ];
	unsigned char sip[ 4 ];
	unsigned char sport[ 2 ];
	unsigned char dip[ 4 ];
	unsigned char dport[ 2 ];
	int numberofpackets;
	struct RTP_Stream_Data *next;
};


struct RTP_Stream_Data *RTP_Streams;
struct RTP_Stream_Data *Current_RTP_Stream;
struct RTP_Stream_Data *New_RTP_Stream;


/* Open the capture file */
if ( (fp = pcap_open_offline(filename, errbuf) ) == NULL) {
	fprintf(stderr,"\nPCAP: Unable to open %s\nError: %s\n", filename, errbuf);
	return -1;
}


/* Retrieve the packets from the file */
RTP_Streams = 0;
while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0)
{
	frame_number = frame_number + 1;
	
	/* IP Packet denoted by 0x0800 at respective offset in Ethernet header; UDP denoted by 0x11 at respective offset in IP header */
	if( pkt_data[ 12 ] == 0x08 && pkt_data[ 13 ] == 0x00 && pkt_data[ 23 ] == 0x11 ) {

		/* RTP Offset = Ethernet Header (14 bytes) + IP Header length (found in lower 4 bits of first IP byte) + UDP Header (8 bytes) */
		rtp_offset = ( int )( pkt_data[ 14 ] & 0x0F ) * 4 + 22;

		/* The first byte after this offset being 0x80 means RFC 1889 version 2, no padding, no extension, no CSRC */
		/* The second byte after this offset being 0xc8 or 0xc9 means it is most likely RTCP */
		/* And neither do we want stuff like CN, RED or DTMF */
		if( pkt_data[ rtp_offset ] == 0x80 && !(pkt_data[ rtp_offset + 1 ] == 0xc8) && !(pkt_data[ rtp_offset + 1 ] == 0xc9) &&
			!(( pkt_data[ rtp_offset + 1 ] & 0x7F ) == 0x0d) &&
			!(( pkt_data[ rtp_offset + 1 ] & 0x7F ) == 0x61) &&
			!(( pkt_data[ rtp_offset + 1 ] & 0x7F ) == 0x65) &&
			!(( pkt_data[ rtp_offset + 1 ] & 0x7F ) == 0x76) ) { 

			Current_RTP_Stream = RTP_Streams;
			while( !(Current_RTP_Stream == 0) ) { /* Do we know this packet's stream? */
				if( (Current_RTP_Stream->ssrc[ 0 ] == pkt_data[ rtp_offset + 8 ]) &&
					(Current_RTP_Stream->ssrc[ 1 ] == pkt_data[ rtp_offset + 9 ]) &&
					(Current_RTP_Stream->ssrc[ 2 ] == pkt_data[ rtp_offset + 10 ]) &&
					(Current_RTP_Stream->ssrc[ 3 ] == pkt_data[ rtp_offset + 11 ]) &&
					(Current_RTP_Stream->pt[ 0 ] == ( pkt_data[ rtp_offset + 1 ] & 0x7F)) ) break; /* Yes, we know it. */
				else Current_RTP_Stream = Current_RTP_Stream->next;
			}

			if( Current_RTP_Stream == 0) { /* No, we don't know it. */

				New_RTP_Stream = (struct RTP_Stream_Data *) malloc( sizeof( struct RTP_Stream_Data) );
				
				New_RTP_Stream->ssrc[ 0 ] = pkt_data[ rtp_offset + 8 ];
				New_RTP_Stream->ssrc[ 1 ] = pkt_data[ rtp_offset + 9 ];
				New_RTP_Stream->ssrc[ 2 ] = pkt_data[ rtp_offset + 10 ];
				New_RTP_Stream->ssrc[ 3 ] = pkt_data[ rtp_offset + 11 ];
				New_RTP_Stream->pt[ 0 ] = ( pkt_data[ rtp_offset + 1 ] & 0x7F );
				New_RTP_Stream->sip[ 0 ] = pkt_data[ 26 ];
				New_RTP_Stream->sip[ 1 ] = pkt_data[ 27 ];
				New_RTP_Stream->sip[ 2 ] = pkt_data[ 28 ];
				New_RTP_Stream->sip[ 3 ] = pkt_data[ 29 ];
				New_RTP_Stream->sport[ 0 ] = pkt_data[ rtp_offset - 8 ];
				New_RTP_Stream->sport[ 1 ] = pkt_data[ rtp_offset - 7 ];
				New_RTP_Stream->dip[ 0 ] = pkt_data[ 30 ];
				New_RTP_Stream->dip[ 1 ] = pkt_data[ 31 ];
				New_RTP_Stream->dip[ 2 ] = pkt_data[ 32 ];
				New_RTP_Stream->dip[ 3 ] = pkt_data[ 33 ];
				New_RTP_Stream->dport[ 0 ] = pkt_data[ rtp_offset - 6 ];
				New_RTP_Stream->dport[ 1 ] = pkt_data[ rtp_offset - 5 ];
				New_RTP_Stream->numberofpackets = 1;
				New_RTP_Stream->next = RTP_Streams;

				RTP_Streams = New_RTP_Stream;
			}
			else {
				Current_RTP_Stream->numberofpackets = Current_RTP_Stream->numberofpackets + 1; /* Yes, we know it. */
			}
		}
	}
}

if( res == -1 ) {
	fprintf(stderr,"PCAP: Error reading the packets: %s\n", pcap_geterr(fp));
	return -1;
}

if( RTP_Streams == 0 ) {
	printf("\nNo RTP Streams found.\n");
	return -1;
}

printf("\n");
Current_RTP_Stream = RTP_Streams;
while ( !( Current_RTP_Stream == 0 ) ) {
	if( Current_RTP_Stream->numberofpackets < 50 ) { /* ignore false positives and short lived RTP streams, 50 seems a reasoable threshold */
		Current_RTP_Stream = Current_RTP_Stream->next;
		continue;
	}
	printf("SSRC:\t\t%.2x%.2x%.2x%.2x\n", Current_RTP_Stream->ssrc[ 0 ], Current_RTP_Stream->ssrc[ 1 ], Current_RTP_Stream->ssrc[ 2 ], Current_RTP_Stream->ssrc[ 3 ]);
	printf("Payload Type:\t%d", Current_RTP_Stream->pt[ 0 ]);
	switch( (int)Current_RTP_Stream->pt[ 0 ] ) {
		case 0: printf(" (PCMU)\n"); break;
		case 8: printf(" (PCMA)\n"); break;
		case 9: printf(" (G722)\n"); break;
		case 103: printf(" (SILK/8000)\n"); break;
		case 104: printf(" (SILK/16000)\n"); break;
		default: printf("\n"); break;
	}
	printf("Src IP:\t\t%d.%d.%d.%d\n", Current_RTP_Stream->sip[ 0 ], Current_RTP_Stream->sip[ 1 ], Current_RTP_Stream->sip[ 2 ], Current_RTP_Stream->sip[ 3 ]);
	printf("Src Port:\t%d\n", (((int)Current_RTP_Stream->sport[ 0 ]) << 8) + (int)Current_RTP_Stream->sport[ 1 ]);
	printf("Dst IP:\t\t%d.%d.%d.%d\n", Current_RTP_Stream->dip[ 0 ], Current_RTP_Stream->dip[ 1 ], Current_RTP_Stream->dip[ 2 ], Current_RTP_Stream->dip[ 3 ]);
	printf("Dst Port:\t%d\n", (((int)Current_RTP_Stream->dport[ 0 ]) << 8) + (int)Current_RTP_Stream->dport[ 1 ]);
	printf("Packets:\t%d\n\n", Current_RTP_Stream->numberofpackets);
	Current_RTP_Stream = Current_RTP_Stream->next;
}

return 0;
}
