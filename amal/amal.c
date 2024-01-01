/*----------------------------------------------------------------------------
PA-04:  Part Two Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   amal.c

Written By: 
     1- Zoe Zinn
	 2- Josh Kuesters
Submitted on: 
     12/04/2023
----------------------------------------------------------------------------*/

#include <linux/random.h>
#include <time.h>
#include <stdlib.h>

#include "../myCrypto.h"

// Generate random nonces for Amal
void  getNonce4Amal( int which , Nonce_t  value )
{
	// Normally we generate random nonces using
	// RAND_bytes( (unsigned char *) value , NONCELEN  );
	// However, for grading purpose, we will use fixed values

	switch ( which ) 
	{
		case 1:		// the first nonce
			value[0] = 0x11223344 ;
			break ;

		case 2:		// the second nonce
			value[0] = 0xaabbccdd ;		
			break ;

		default:	// Invalid agrument. Must be either 1 or 2
			fprintf( stderr , "\n\nAmal trying to create an Invalid nonce\n exiting\n\n");
			exit(-1);
	}
}
	
//*************************************
// The Main Loop
//*************************************
int main ( int argc , char * argv[] )
{
    int      fd_A2K , fd_K2A , fd_A2B , fd_B2A  ;
    FILE    *log ;

    char *developerName = "Code by Josh and Zoe" ;

    fprintf( stdout , "Starting Amal's      %s.\n" , developerName  ) ;
    
    if( argc < 5 )
    {
        printf("\nMissing command-line file descriptors: %s <getFr. KDC> <sendTo KDC> "
               "<getFr. Basim> <sendTo Basim>\n\n" , argv[0]) ;
        exit(-1) ;
    }
    fd_K2A    = atoi(argv[1]);  // Read from KDC    File Descriptor
    fd_A2K    = atoi(argv[2]);  // Send to   KDC    File Descriptor
    fd_B2A    = atoi(argv[3]);  // Read from Basim  File Descriptor
    fd_A2B    = atoi(argv[4]);  // Send to   Basim  File Descriptor

    log = fopen("amal/logAmal.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "\nAmal's  %s. Could not create my log file\n" , developerName  ) ;
        exit(-1) ;
    }

    BANNER( log ) ;
    fprintf( log , "Starting Amal\n" ) ;
    BANNER( log ) ;

    fprintf( log , "\n<readFr. KDC> FD=%d , <sendTo KDC> FD=%d , "
                   "<readFr. Basim> FD=%d , <sendTo Basim> FD=%d\n" , 
                   fd_K2A , fd_A2K , fd_B2A , fd_A2B );

    // Get Amal's master key with the KDC
    myKey_t  Ka ;  // Amal's master key with the KDC


    // Use  getKeyFromFile( "amal/amalKey.bin" , .... ) )
	// On failure, print "\nCould not get Amal's Masker key & IV.\n" to both  stderr and the Log file
	// and exit(-1)
	// On success, print "Amal has this Master Ka { key , IV }\n" to the Log file
	// BIO_dump the Key IV indented 4 spaces to the righ
    if (getKeyFromFile("amal/amalKey.bin", &Ka) != 1)
    {
        fprintf(stderr, "\nCould not get Amal's Masker key & IV.\n");
        fprintf(log, "\nCould not get Amal's Masker key & IV.\n");
        exit(-1);
    }
    fprintf( log , "\n" );
	// BIO_dump the IV indented 4 spaces to the right
    fprintf( log , "Amal has this Master Ka { key , IV }\n" );
    BIO_dump_indent_fp(log, (const char *)Ka.key, SYMMETRIC_KEY_LEN, 4);
    fprintf( log , "\n" );
    BIO_dump_indent_fp(log, (const char *)Ka.iv, INITVECTOR_LEN, 4);
    

    // Get Amal's pre-created Nonces: Na and Na2
	Nonce_t   Na , Na2; 
    fprintf( log , "\nAmal will use these Nonces:  Na  and Na2\n"  ) ;
	// Use getNonce4Amal () to get Amal's 1st and second nonces into Na and Na2, respectively
    getNonce4Amal(1, Na);
    getNonce4Amal(2, Na2);
    
	// BIO_dump Na indented 4 spaces to the right
    BIO_dump_indent_fp(log, (const char *)Na, NONCELEN, 4);
    fprintf( log , "\n" );
	// BIO_dump Na2 indented 4 spaces to the right
    BIO_dump_indent_fp(log, (const char *)Na2, NONCELEN, 4);
    fprintf( log , "\n") ; 

    fflush( log ) ;

    //*************************************
    // Construct & Send    Message 1
    //*************************************
    BANNER( log ) ;
    fprintf( log , "         MSG1 New\n");
    BANNER( log ) ;

    char *IDa = "Amal is Hope", *IDb = "Basim is Smily" ;
    unsigned  LenMsg1 ;
    uint8_t  *msg1 ;
    LenMsg1 = MSG1_new( log , &msg1 , IDa , IDb , Na ) ;
    
    // Send MSG1 to KDC via the appropriate pipe
    if (write(fd_A2K, msg1, LenMsg1) != LenMsg1)
    {
        fprintf(stderr, "\nCould not write MSG1 to KDC.\n");
        fprintf(log, "\nCould not write MSG1 to KDC.\n");
        exit(-1);
    }

   fprintf( log , "Amal sent message 1 ( %d bytes ) to the KDC with:\n    "
                   "IDa ='%s'\n    "
                   "IDb = '%s'\n" , LenMsg1 , IDa , IDb ) ;
    fprintf( log , "    Na ( %lu Bytes ) is:\n" , NONCELEN ) ;
    // BIO_dump the nonce Na
    BIO_dump_indent_fp(log, (const char *)Na, NONCELEN, 4);
    fprintf( log , "\n") ; 
    fflush( log ) ;

    // Deallocate any memory allocated for msg1
    free(msg1);

    //*************************************
    // Receive   &   Process Message 2
    //*************************************
	// PA-04 Part Two
    BANNER ( log ) ;
    fprintf( log , "         MSG2 Receive\n");
    BANNER ( log ) ;
    fflush ( log ) ;

    // Get MSG2 from KDC
    myKey_t  Ks ;

    unsigned LenTktCiph = 0;
    uint8_t *tktCipher ;

    MSG2_receive( log , fd_K2A, &Ka, &Ks, &IDb, &Na, &LenTktCiph, &tktCipher ) ;

    // Print the message 2 components
    fprintf(log, "Amal received the following in message 2 from the KDC\n") ;
    fflush(log) ;

    // Dump Ks
    fprintf(log, "    Ks { Key , IV } (%lu Bytes ) is:\n" , sizeof(myKey_t) ) ;
    BIO_dump_indent_fp(log, &Ks, sizeof(myKey_t), 4);
    fflush(log) ;

    // Dump IDb
    fprintf(log, "\n    IDb (%lu Bytes):   ..... MATCH\n" ,  strlen(IDb) + 1) ;
    BIO_dump_indent_fp(log, IDb, strlen(IDb) + 1, 4); fprintf( log , "\n" );
    fflush(log) ;

    // Dump nonce
    fprintf(log, "    Received Copy of Na (%lu bytes):    >>>> VALID\n" , NONCELEN ) ;
    BIO_dump_indent_fp(log, Na, NONCELEN, 4); fprintf( log , "\n" );
    fflush(log) ;

    // Dump encrypted ticket
    fprintf(log, "    Encrypted Ticket (%u bytes):\n" , LenTktCiph ) ;
    BIO_dump_indent_fp(log, tktCipher, LenTktCiph, 4); fprintf( log , "\n" );
    fflush(log) ;

    //*************************************
    // Construct & Send    Message 3
    //*************************************
	// PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG3 New\n");
    BANNER( log ) ;

    // Print info to the log
    fprintf(log, "Amal is sending this nonce Na2 in Message 3:\n");
    BIO_dump_indent_fp (log, &Na2, NONCELEN, 4);

    // Create MSG3: Encrypted Ticket + Nonce2
    uint8_t *msg3;

    unsigned msg3Len = MSG3_new(log, &msg3, LenTktCiph, tktCipher, &Na2);

    if (write(fd_A2B, msg3, msg3Len) != msg3Len)
    {
        fprintf(stderr, "\nCould not write MSG3 to Basim.\n");
        fprintf(log, "\nCould not write MSG3 to Basim.\n");
        exit(-1);
    } 

    fprintf(log, "Amal Sent the above Message 3 ( %u bytes ) to Basim\n", msg3Len) ;
    fprintf(log, "\n"); fflush(log) ;

    free(msg3) ;

    //*************************************
    // Receive   & Process Message 4
    //*************************************
	// PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG4 Receive\n");
    BANNER( log ) ;

    Nonce_t fNa2;
    fNonce(fNa2, Na2);


    // Get MSG4 from Basim
    Nonce_t Nb;
    MSG4_receive(log, fd_B2A, &Ks, &fNa2, &Nb);


    //*************************************
    // Construct & Send    Message 5
    //*************************************
	// PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG5 New\n");
    BANNER( log ) ;

    Nonce_t fNb;
    fNonce(fNb, Nb) ;

    fprintf(log, "Amal is sending this f( Nb ) in MSG5:\n");
    BIO_dump_indent_fp(log, &fNb, NONCELEN, 4);
    fprintf(log, "\n"); fflush(log) ;

    // Create MSG5: f( Nb )
    uint8_t *msg5;
    unsigned msg5Len = MSG5_new(log, &msg5, &Ks, &fNb);

    // Concat MSG5's length to the message
    uint8_t *newMSG5ptr = (uint8_t *) malloc(msg5Len + LENSIZE) ;
    uint8_t *m = newMSG5ptr ;

    memcpy(m, &msg5Len, LENSIZE);
    m += LENSIZE ;

    memcpy(m, msg5, msg5Len) ;
    m += msg5Len;

    if (write(fd_A2B, newMSG5ptr, (msg5Len + LENSIZE)) != (msg5Len + LENSIZE))
    {
        fprintf(stderr, "Amal could not send MSG5 to Basim\n");
        fprintf(log, "Amal could not send MSG5 to Basim\n");
        exit(-1);
    }

    fprintf(log, "Amal sent the above Message 5 ( %u bytes ) to Basim\n", msg5Len) ;
    fflush(log) ;

    free(msg5) ;

    //*************************************   
    // Final Clean-Up
    //*************************************
   
    fprintf( log , "\nAmal has terminated normally. Goodbye\n" ) ;  
    fflush( log ) ;
    fclose( log ) ;
    return 0 ;
}

