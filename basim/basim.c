/*----------------------------------------------------------------------------
PA-04:  Part Two Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   basim.c

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

// Generate random nonces for Basim
void  getNonce4Basim( int which , Nonce_t  value )
{
	// Normally we generate random nonces using
	// RAND_bytes( (unsigned char *) value , NONCELEN  );
	// However, for grading purpose, we will use fixed values

	switch ( which ) 
	{
		case 1:		// the first and Only nonce
			value[0] = 0x66778899 ;
			break ;

		default:	// Invalid agrument. Must be either 1 or 2
			fprintf( stderr , "\n\nBasim trying to create an Invalid nonce\n exiting\n\n");
			exit(-1);
	}
}

//*************************************
// The Main Loop
//*************************************
int main ( int argc , char * argv[] )
{
    int       fd_A2B , fd_B2A   ;
    FILE     *log ;

    char *developerName = "Code by Josh and Zoe" ;

    fprintf( stdout , "Starting Basim's     %s\n" , developerName ) ;

    if( argc < 3 )
    {
        printf("\nMissing command-line file descriptors: %s <getFr. Amal> "
               "<sendTo Amal>\n\n", argv[0]) ;
        exit(-1) ;
    }

    fd_A2B    = atoi(argv[1]);  // Read from Amal   File Descriptor
    fd_B2A    = atoi(argv[2]);  // Send to   Amal   File Descriptor

    log = fopen("basim/logBasim.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "Basim's %s. Could not create log file\n" , developerName ) ;
        exit(-1) ;
    }

    BANNER( log ) ;
    fprintf( log , "Starting Basim\n"  ) ;
    BANNER( log ) ;

    fprintf( log , "\n<readFr. Amal> FD=%d , <sendTo Amal> FD=%d\n\n" , fd_A2B , fd_B2A );

    // Get Basim's master keys with the KDC
    myKey_t   Kb ;    // Basim's master key with the KDC    

    // Use  getKeyFromFile( "basim/basimKey.bin" , .... ) )
	// On failure, print "\nCould not get Basim's Masker key & IV.\n" to both  stderr and the Log file
	// and exit(-1)
	// On success, print "Basim has this Master Ka { key , IV }\n" to the Log file
	// BIO_dump the Key IV indented 4 spaces to the righ
    if (getKeyFromFile("basim/basimKey.bin", &Kb) != 1)
    {
        fprintf(stderr, "\nCould not get Basim's Masker key & IV.\n");
        fprintf(log, "\nCould not get Basim's Masker key & IV.\n");
        exit(-1);
    }
    // fprintf( log , "\n" );
	// BIO_dump the IV indented 4 spaces to the right
    fprintf( log , "Basim has this Master Kb { key , IV }\n" );
    BIO_dump_indent_fp(log, (const char *)Kb.key, SYMMETRIC_KEY_LEN, 4);
    fprintf( log , "\n" );
    BIO_dump_indent_fp(log, (const char *)Kb.iv, INITVECTOR_LEN, 4);

    // Get Basim's pre-created Nonces: Nb
	Nonce_t   Nb;  

	// Use getNonce4Basim () to get Basim's 1st and only nonce into Nb
    getNonce4Basim(1, Nb);
    fprintf( log , "\nBasim will use this Nonce:  Nb\n"  ) ;
	// BIO_dump Nb indented 4 spaces to the right
    BIO_dump_indent_fp(log, (const char *) Nb, NONCELEN, 4);
    fprintf( log , "\n" );

    fflush( log ) ;

    //*************************************
    // Receive  & Process   Message 3
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG3 Receive\n");
    BANNER( log ) ;

    myKey_t Ks;
    char   *IDa;
    Nonce_t Na2;

    // Get the message 3
    MSG3_receive(log, fd_A2B, &Kb, &Ks, &IDa, &Na2);

    // Print the message components
    fprintf(log, "Basim received Message 3 from Amal with the following:\n") ;
    fflush(log) ;

    fprintf(log, "    Ks { Key , IV } (%lu Bytes ) is:\n", sizeof(myKey_t));
    BIO_dump_indent_fp(log, &Ks, sizeof(myKey_t), 4); fprintf(log, "\n") ;
    fflush(log) ;

    fprintf(log, "    IDa = '%s'", IDa) ;
    fflush(log) ;

    fprintf(log, "\n    Na2 ( %lu Bytes ) is:\n", NONCELEN) ;
    BIO_dump_indent_fp(log, &Na2, NONCELEN, 4); fprintf(log, "\n");

    fflush(log) ;


    //*************************************
    // Construct & Send    Message 4
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG4 New\n");
    BANNER( log ) ;

    unsigned  LenMsg4 ;
    uint8_t  *msg4 ;

    LenMsg4 = MSG4_new( log , &msg4 , &Ks , &Na2 , &Nb ) ;

    // Concat MSG4's length to the message
    uint8_t *newMSG4ptr = (uint8_t *) malloc(LenMsg4 + LENSIZE) ;
    uint8_t *m = newMSG4ptr ;

    memcpy(m, &LenMsg4, LENSIZE);
    m += LENSIZE ;

    memcpy(m, msg4, LenMsg4) ;
    m += LenMsg4 ;

    if (write(fd_B2A, newMSG4ptr, (LenMsg4 + LENSIZE)) != (LenMsg4 + LENSIZE))
    {
        fprintf(stderr, "Basim could not send MSG4 to Amal\n");
        fprintf(log, "Basim could not send MSG4 to Amal\n");
        exit(-1);
    }

    fprintf(log, "Basim Sent the above MSG4 to Amal\n") ;
    fprintf(log, "\n");
    fflush(log) ;

    free(msg4) ;

    //*************************************
    // Receive   & Process Message 5
    //*************************************
    // PA-04 Part Two
    BANNER( log ) ;
    fprintf( log , "         MSG5 Receive\n");
    BANNER( log ) ;

    Nonce_t fNb;

    // Get MSG5 from Amal
    MSG5_receive(log, fd_A2B, &Ks, &fNb);

    fprintf(log, "Basim received Message 5 from Amal with this f( Nb ): >>>> VALID\n") ;
    BIO_dump_indent_fp(log, &fNb, NONCELEN, 4); fprintf(log, "\n");
    fflush(log) ;

    //*************************************   
    // Final Clean-Up
    //*************************************

    fprintf( log , "\nBasim has terminated normally. Goodbye\n" ) ;
    fflush( log ) ;
    fclose( log ) ;  

    return 0 ;
}
