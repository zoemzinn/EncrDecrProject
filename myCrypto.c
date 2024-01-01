/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c

Written By: 
     1- Zoe Zinn
	 2- Josh Kuesters
Submitted on: 
     12/04/2023
	 
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//***********************************************************************
// pLAB-01
//***********************************************************************

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    abort();
}

//-----------------------------------------------------------------------------
// Encrypt the plain text stored at 'pPlainText' into the 
// caller-allocated memory at 'pCipherText'
// Caller must allocate sufficient memory for the cipher text
// Returns size of the cipher text in bytes

unsigned   encrypt( uint8_t *pPlainText, unsigned plainText_len, 
                    const uint8_t *key, const uint8_t *iv, uint8_t *pCipherText )
{
    int status;
    unsigned len = 0, encrypted_len = 0;

    /* Create and initialize the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        handleErrors("encrypt: failed to create CTX");
    }

    // Initialize the encryption operation
    status = EVP_EncryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if (status == -1)
    {
        handleErrors("encrypt: failed to EncryptInit_ex");
    }

    // Call EncryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular encryption
    status = EVP_EncryptUpdate(ctx, pCipherText, &len, pPlainText, plainText_len);
    if (status == -1)
    {
        handleErrors("encrypt: failed to EncryptUpdate");
    }
    encrypted_len += len;

    // If additional ciphertext may still be generated,
    // the pCipherText pointer must be first advanced forward
    pCipherText += len;

    // Finalize the encryption
    status = EVP_EncryptFinal_ex(ctx, pCipherText, &len);
    if (status == -1)
    {
        handleErrors("encrypt: failed to EncryptFinal_ex");
    }
    encrypted_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return encrypted_len;
}

//-----------------------------------------------------------------------------
// Decrypt the cipher text stored at 'pCipherText' into the 
// caller-allocated memory at 'pDecryptedText'
// Caller must allocate sufficient memory for the decrypted text
// Returns size of the decrypted text in bytes

unsigned   decrypt( uint8_t *pCipherText, unsigned cipherText_len, 
                    const uint8_t *key, const uint8_t *iv, uint8_t *pDecryptedText)
{
    int status;
    unsigned len = 0, decryptedLen = 0;

    /* Create and initialize the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        handleErrors("decrypt: failed to create CTX");
    }

    // Initialize the decryption operation.
    status = EVP_DecryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if (status == -1)
    {
        handleErrors("decrypt: failed to DecryptInit_ex");
    }

    // Call DecryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular decryption
    status = EVP_DecryptUpdate(ctx, pDecryptedText, &len, pCipherText, cipherText_len);
    if (status == -1)
    {
        handleErrors("decrypt: failed to DecryptUpdate");
    }
    decryptedLen += len;

    // If additional plaintext may still be generated,
    // the pDecryptedText pointer must be first advanced forward
    pDecryptedText += len;

    // Finalize the decryption
    status = EVP_DecryptFinal_ex(ctx, pDecryptedText, &len);
    if (status == -1)
    {
        handleErrors("decrypt: failed to DecryptFinal_ex");
    }
    decryptedLen += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return decryptedLen;
}

//***********************************************************************
// PA-01
//***********************************************************************

static unsigned char   plaintext [ PLAINTEXT_LEN_MAX ] , // Temporarily store plaintext
                       ciphertext[ CIPHER_LEN_MAX    ] , // Temporarily store outcome of encryption
                       decryptext[ DECRYPTED_LEN_MAX ] ; // Temporarily store decrypted text

// above arrays being static to resolve runtime stack size issue. 
// However, that makes the code non-reentrant for multithreaded application

//-----------------------------------------------------------------------------

int    encryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{
    int status;
    unsigned plaintext_len;
    unsigned encrypted_len = 0, len = 0;

    /* Create and initialize the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        handleErrors("encrypt: failed to create CTX");
    }

    // Initialize the encryption operation
    status = EVP_EncryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if (status == -1)
    {
        handleErrors("encrypt: failed to EncryptInit_ex");
    }

    // Call EncryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular encryption
    while ((plaintext_len = read(fd_in, plaintext, PLAINTEXT_LEN_MAX)) != 0)
    {
        status = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
        if (status == -1)
        {
            handleErrors("encrypt: failed to EncryptUpdate");
        }
        encrypted_len += len;

        // If additional ciphertext may still be generated,
        // the ciphertext pointer must be first advanced forward
        write(fd_out, ciphertext, len);
    }

    // Finalize the encryption
    status = EVP_EncryptFinal_ex(ctx, ciphertext, &len);
    if (status == -1)
    {
        handleErrors("encrypt: failed to EncryptFinal_ex");
    }
    encrypted_len += len;
    write(fd_out, ciphertext, len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return encrypted_len;
}

//-----------------------------------------------------------------------------
int    decryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{
    int status;
    unsigned ciphertext_len;
    unsigned decrypted_len = 0, len = 0;

    /* Initialize the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        handleErrors("decrypt: failed to create CTX");
    }

    // Initialize the decryption operation
    status = EVP_DecryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if (status == -1)
    {
        handleErrors("decrypt: failed to DecryptInit_ex");
    }

    // Call DecryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular decryption
    while ((ciphertext_len = read(fd_in, ciphertext, CIPHER_LEN_MAX)) != 0)
    {
        status = EVP_DecryptUpdate(ctx, decryptext, &len, ciphertext, ciphertext_len);
        if (status == -1)
        {
            handleErrors("decrypt: failed to DecryptUpdate");
        }
        decrypted_len += len;

        // If additional plaintext may still be generated,
        // the plaintext pointer must be first advanced forward
        write(fd_out, decryptext, len);
    }

    // Finalize the decryption
    status = EVP_DecryptFinal_ex(ctx, decryptext, &len);
    if (status == -1)
    {
        handleErrors("decrypt: failed to DecryptFinal_ex");
    }
    decrypted_len += len;
    write(fd_out, decryptext, len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return decrypted_len;
}



//***********************************************************************
// pLAB-02
//***********************************************************************

RSA *getRSAfromFile(char * filename, int public)
{
    FILE * fp = fopen(filename,"rb");
    if (fp == NULL)
    {
        fprintf( stderr , "getRSAfromFile: Unable to open RSA key file %s \n",filename);
        return NULL;    
    }

    RSA *rsa = RSA_new() ;
    if ( public )
        rsa = PEM_read_RSA_PUBKEY( fp, &rsa , NULL , NULL );
    else
        rsa = PEM_read_RSAPrivateKey( fp , &rsa , NULL , NULL );
 
    fclose( fp );

    return rsa;
}

//***********************************************************************
// PA-02
//***********************************************************************

size_t fileDigest( int fd_in , int fd_out , uint8_t *digest )
// Read all the incoming data stream from 'fd_in' file descriptor
// Compute the SHA256 hash value of this incoming data into the array 'digest'
// If the file descriptor 'fd_out' is > 0, write a copy of the incoming data stream
// file to 'fd_out'
// Returns actual size in bytes of the computed hash (a.k.a. digest value)
{
    unsigned mdLen = 0;
	// Use EVP_MD_CTX_create() to create new hashing context
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_create();
    if (!mdCtx)
    {
        handleErrors("fileDigest: failed to create CTX");
    }

    // Initialize the context using EVP_DigestInit() so that it deploys 
	// the EVP_sha256() hashing function
    if (EVP_DigestInit(mdCtx, EVP_sha256()) != 1)
    {
        handleErrors("fileDigest: failed to DigestInit");
    }

    int nBytes;
    uint8_t buffer[PLAINTEXT_LEN_MAX];

    while ((nBytes = read(fd_in, buffer, PLAINTEXT_LEN_MAX)) > 0)
    {
		// Use EVP_DigestUpdate() to hash the data you read
        if (EVP_DigestUpdate(mdCtx, buffer, nBytes) != 1)
        {
            handleErrors("fileDigest: failed to DigestUpdate");
        }

        if ( fd_out > 0 )
        {
            // write the data you just read to fd_out
            if (write(fd_out, buffer, nBytes) != nBytes)
            {
                handleErrors("fileDigest: failed to write to fd_out");
            }
        }
    }

    // Finialize the hash calculation using EVP_DigestFinal() directly
	// into the 'digest' array
    if (EVP_DigestFinal(mdCtx, digest, &mdLen) != 1)
    {
        handleErrors("fileDigest: failed to DigestFinal");
    }

    // Use EVP_MD_CTX_destroy() to clean up the context
    EVP_MD_CTX_destroy(mdCtx);

    // return the length of the computed digest in bytes ;
    //print the mdLen
    return mdLen;
}

//***********************************************************************
// PA-04  Part  One
//***********************************************************************

void exitError( char *errText )
{
    fprintf( stderr , "%s\n" , errText ) ;
    exit(-1) ;
}

//-----------------------------------------------------------------------------
// Utility to read Key/IV from a file
// Return:  1 on success, or 0 on failure

int getKeyFromFile( char *keyF , myKey_t *x )
{
    int   fd_key  ;
    
    fd_key = open( keyF , O_RDONLY )  ;
    if( fd_key == -1 ) 
    { 
        fprintf( stderr , "\nCould not open key file '%s'\n" , keyF ); 
        return 0 ; 
    }

    // first, read the symmetric encryption key
	if( SYMMETRIC_KEY_LEN  != read ( fd_key , x->key , SYMMETRIC_KEY_LEN ) ) 
    { 
        fprintf( stderr , "\nCould not read key from file '%s'\n" , keyF ); 
        return 0 ; 
    }

    // Next, read the Initialialzation Vector
    if ( INITVECTOR_LEN  != read ( fd_key , x->iv , INITVECTOR_LEN ) ) 
    { 
        fprintf( stderr , "\nCould not read the IV from file '%s'\n" , keyF ); 
        return 0 ; 
    }
	
    close( fd_key ) ;
    
    return 1;  //  success
}

//-----------------------------------------------------------------------------
// Allocate & Build a new Message #1 from Amal to the KDC 
// Where Msg1 is:  Len(IDa)  ||  IDa  ||  Len(IDb)  ||  IDb  ||  Na
// All Len(*) fields are unsigned integers
// Set *msg1 to point at the newly built message
// Msg1 is not encrypted
// Returns the size (in bytes) of Message #1 

unsigned MSG1_new ( FILE *log , uint8_t **msg1 , const char *IDa , const char *IDb , const Nonce_t Na )
{

    //  Check against any NULL pointers in the arguments
    if (msg1 == NULL || IDa == NULL || IDb == NULL || Na == NULL)
    {
        fprintf( stderr , "MSG1_new: NULL pointer argument\n" ) ;
        exit(-1) ;
    }

    unsigned  LenA    = strlen(IDa) + 1;                                                  //  number of bytes in IDa ;
    unsigned  LenB    = strlen(IDb) + 1;                                                  //  number of bytes in IDb ;
    unsigned  LenMsg1 = sizeof(unsigned) + LenA + sizeof(unsigned) + LenB +  NONCELEN ;   //  number of bytes in the completed MSG1 ;
    unsigned *lenPtr  = &LenMsg1; 
    uint8_t  *p ;

    // Allocate memory for msg1. MUST always check malloc() did not fail
    *msg1 = (uint8_t *) malloc(LenMsg1) ;
    if (*msg1 == NULL)
    {
        return 0; // Return 0 bytes if malloc() fails
    }

    // Fill in Msg1:  Len( IDa )  ||  IDa   ||  Len( IDb )  ||  IDb   ||  Na
    p = *msg1;

    // Store the length of IDa
    *((unsigned *)p) = LenA;
    p += sizeof(unsigned);

    // Copy the characters of IDa
    strcpy(p, IDa);
    p += LenA;

    // Store the length of IDb
    *((unsigned *)p) = LenB;
    p += sizeof(unsigned);

    // Copy the characters of IDb 
    strcpy(p, IDb);
    p += LenB;

    // Copy the nonce
    memcpy(p, Na, NONCELEN) ;

    fprintf( log , "The following new MSG1 ( %u bytes ) has been created by MSG1_new ():\n" , LenMsg1 ) ;
    // BIO_dumpt the completed MSG1 indented 4 spaces to the right
    BIO_dump_indent_fp(log, *msg1, LenMsg1, 4);
    fprintf( log , "\n" ) ;
    
    return LenMsg1;
}

//-----------------------------------------------------------------------------
// Receive Message #1 by the KDC from Amal via the pipe's file descriptor 'fd'
// Parse the incoming msg1 into the values IDa, IDb, and Na

void  MSG1_receive( FILE *log , int fd , char **IDa , char **IDb , Nonce_t Na )
{

    //  Check against any NULL pointers in the arguments
    if (IDa == NULL || IDb == NULL || Na == NULL)
    {
        fprintf( stderr , "MSG1_receive: NULL pointer argument\n" ) ;
        exit(-1) ;
    }

    unsigned LenMsg1 = 0, LenA , lenB ;
	// Throughout this function, don't forget to update LenMsg1 as you receive its components
 
    // Read in the components of Msg1:  L(A)  ||  A   ||  L(B)  ||  B   ||  Na
    // 1) Read Len(ID_A)  from the pipe
    // On failure to read Len(IDa):
    if (read(fd, &LenA, sizeof(LenA)) != sizeof(LenA))
    {
        fprintf( log , "Unable to receive all %lu bytes of Len(IDA) "
                       "in MSG1_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes LenA in MSG1_receive()" );
    }
    LenMsg1 += sizeof(LenA) ;

    
    // 2) Allocate memory for ID_A 
	// On failure to allocate memory:
    *IDa = (char *) malloc(LenA) ;
    if (*IDa == NULL)
    {
        fprintf( log , "Out of Memory allocating %u bytes for IDA in MSG1_receive() "
                       "... EXITING\n" , LenA );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDA in MSG1_receive()" );
    }

 	// On failure to read ID_A from the pipe
    if (read(fd, *IDa, LenA) != LenA)
    {
        fprintf( log , "Unable to receive all %u bytes of IDA in MSG1_receive() "
                       "... EXITING\n" , LenA );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Unable to receive all bytes of IDA in MSG1_receive()" );
    }
    LenMsg1 += LenA ;

    // 3) Read Len( ID_B )  from the pipe
    // On failure to read Len( ID_B ):
    if (read(fd, &lenB, sizeof(lenB)) != sizeof(lenB))
    {
        fprintf( log , "Unable to receive all %lu bytes of Len(IDB) "
                       "in MSG1_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes of LenB in MSG1_receive()" );
    }
    LenMsg1 += sizeof(lenB) ;

    // 4) Allocate memory for ID_B
	// On failure to allocate memory:
    *IDb = (char *) malloc(lenB);
    if (*IDb == NULL)
    {
        fprintf( log , "Out of Memory allocating %u bytes for IDB in MSG1_receive() "
                       "... EXITING\n" , lenB );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDB in MSG1_receive()" );
    }

 	// On failure to read ID_B from the pipe
    if (read(fd, *IDb, lenB) != lenB)
    {
        fprintf( log , "Unable to receive all %u bytes of IDB in MSG1_receive() "
                       "... EXITING\n" , lenB );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Unable to receive all bytes of IDB in MSG1_receive()" );
    }
    LenMsg1 += lenB ;
    
    // 5) Read Na
 	// On failure to read Na from the pipe
    if (read(fd, Na, NONCELEN) != NONCELEN)
    {
        fprintf( log , "Unable to receive all %lu bytes of Na "
                       "in MSG1_receive() ... EXITING\n" , NONCELEN );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes of Na in MSG1_receive()" );
    }
    LenMsg1 += NONCELEN ;
 
    fprintf( log , "MSG1 ( %u bytes ) has been received"
                   " on FD %d by MSG1_receive():\n" ,  LenMsg1 , fd  ) ;   
    fflush( log ) ;

    return ;
}


//***********************************************************************
// PA-04   Part  TWO
//***********************************************************************

static unsigned char   ciphertext2[ CIPHER_LEN_MAX    ] ; // Temporarily store outcome of encryption

//-----------------------------------------------------------------------------
// Build a new Message #2 from the KDC to Amal
// Where Msg2 before encryption:  Ks || L(IDb) || IDb  || Na || L(TktCipher) || TktCipher
// All L() fields are unsigned integers
// Set *msg2 to point at the newly built message
// Log milestone steps to the 'log' file for debugging purposes
// Returns the size (in bytes) of the encrypted (using Ka) Message #2  

unsigned MSG2_new( FILE *log , uint8_t **msg2, const myKey_t *Ka , const myKey_t *Kb , 
                   const myKey_t *Ks , const char *IDa , const char *IDb  , Nonce_t *Na )
{

    //  Check against any NULL pointers in the arguments
    if (msg2 == NULL || Ka == NULL || Kb == NULL || Ks == NULL || IDa == NULL || IDb == NULL || Na == NULL)
    {
        fprintf( stderr , "MSG2_new: NULL pointer argument\n" ) ;
        exit(-1) ;
    }

    //---------------------------------------------------------------------------------------
    // Construct TktPlain = { Ks  || L(IDa)  || IDa }
    // in the global scratch buffer plaintext[]

    // Build the ticket
    unsigned  LenA    = strlen(IDa) + 1;                                                  //  number of bytes in IDa ;
    unsigned LenTick  = sizeof(myKey_t) + sizeof(unsigned) + LenA ;                       //  number of bytes in the ticket before encryption ;
    uint8_t *t ;
    t = plaintext ;

    // Copy the session key into the temporary plaintext buffer
    memcpy(t, Ks, sizeof(myKey_t)) ;
    t += sizeof(myKey_t) ;

    // Copy the length of IDa into the temporary plaintext buffer
    memcpy(t, &LenA, sizeof(unsigned)) ;
    t += sizeof(unsigned) ;

    // Copy IDa into the temporary plaintext buffer
    strcpy(t, IDa) ;
    t += LenA ;

    fprintf( log ,"Plaintext Ticket (%u Bytes) is\n" , LenTick);
    BIO_dump_indent_fp ( log , plaintext, LenTick, 4 ) ;  fprintf( log , "\n") ; 

    // Use that global array as a scratch buffer for building the plaintext of the ticket
    // Compute its encrypted version in the global scratch buffer ciphertext[]

    // Now, set TktCipher = encrypt( Kb , plaintext );
    // Store the result in the global scratch buffer ciphertext[]
    unsigned TktCipher = encrypt(plaintext, LenTick, Kb->key, Kb->iv, ciphertext) ;

    //---------------------------------------------------------------------------------------
    // Construct the rest of Message 2 then encrypt it using Ka
    // MSG2 plain = {  Ks || L(IDb) || IDb  ||  Na || L(TktCipher) || TktCipher }

    unsigned  LenB    = strlen(IDb) + 1;                                                      //  number of bytes in IDb ;
    unsigned  LenN    = NONCELEN ;                                                            //  number of bytes in the nonce struct ;
    unsigned  LenMsg2 = sizeof(myKey_t) + LENSIZE + LenB + LenN + LENSIZE + TktCipher ;       //  number of bytes in the completed MSG2 ;
    unsigned *lenPtr  = &LenMsg2; 
    uint8_t  *p ;

    // Allocate memory for msg1. MUST always check malloc() did not fail
    *msg2 = (uint8_t *) malloc(LenMsg2) ;
    if (*msg2 == NULL)
    {
        fprintf( stderr , "MSG2_new: message could not be allocated\n" ) ;
        exit(-1) ;
    }

    // Fill in Msg2 Plaintext:  Ks || L(IDb) || IDb || Na || len(TktCipher) || TktCipher
    // Reuse that global array plaintext[] as a scratch buffer for building the plaintext of the MSG2
    memset(plaintext, 0, PLAINTEXT_LEN_MAX) ;
    p = plaintext;

    // Copy the session key into the temporary plaintext buffer
    memcpy(p, Ks, sizeof(myKey_t)) ;
    p += sizeof(myKey_t) ;

    // Copy the length of IDb into the temporary plaintext buffer
    memcpy(p, &LenB, sizeof(unsigned)) ;
    p += sizeof(unsigned) ;

    // Copy IDb into the temporary plaintext buffer
    strcpy(p, IDb) ;
    p += LenB ;

    // Copy the nonce into the temporary plaintext buffer
    memcpy(p, Na, NONCELEN) ;
    p += NONCELEN ;

    // Copy the length of the ticket cipher text into the temporary plaintext buffer
    memcpy(p, &TktCipher, sizeof(unsigned)) ;
    p += sizeof(unsigned) ;

    // Copy the ticket cipher text into the temporary plaintext buffer
    memcpy(p, ciphertext, TktCipher) ;

    // Now, encrypt Message 2 using Ka. 
    // Use the global scratch buffer ciphertext2[] to collect the results

    // // TESTING PURPOSES
    // fprintf( log ,"This is the plaintext MSG2 before Encryption:\n");  
    // BIO_dump_indent_fp ( log , plaintext, LenMsg2, 4) ;  fprintf( log , "\n") ;
    // // END TESTING PURPOSES

    unsigned Msg2CipherLen = encrypt(plaintext, LenMsg2, Ka->key, Ka->iv, ciphertext2) ;

    fprintf( log ,"This is the new MSG2 ( %u Bytes ) before Encryption:\n" , LenMsg2);  
    fprintf( log ,"    Ks { key + IV } (%lu Bytes) is:\n" , sizeof(myKey_t) );
    BIO_dump_indent_fp ( log , Ks, sizeof(myKey_t), 4) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    IDb (%u Bytes) is:\n" , LenB );
    BIO_dump_indent_fp ( log , IDb, LenB, 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    Na (%lu Bytes) is:\n" , NONCELEN);
    BIO_dump_indent_fp ( log , Na, NONCELEN, 4) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    Encrypted Ticket (%u Bytes) is\n" , TktCipher );
    BIO_dump_indent_fp ( log , ciphertext, TktCipher, 4 ) ;  fprintf( log , "\n") ; 

    // Copy the encrypted ciphertext to Caller's msg2 buffer.
    memcpy(*msg2, ciphertext2, Msg2CipherLen) ;

    fprintf( log , "The following new Encrypted MSG2 ( %u bytes ) has been"
                   " created by MSG2_new():  \n" , Msg2CipherLen ) ;
    BIO_dump_indent_fp( log , *msg2 , Msg2CipherLen , 4 ) ;    fprintf( log , "\n" ) ;    

    fflush( log ) ;    
    
    return Msg2CipherLen ;    

}

//-----------------------------------------------------------------------------
// Receive Message #2 by Amal from by the KDC
// Parse the incoming msg2 into the component fields 
// *Ks, *IDb, *Na and TktCipher = Encr{ Ks  || L(IDb)  || IDb }

void MSG2_receive( FILE *log , int fd , const myKey_t *Ka , myKey_t *Ks, char **IDb , 
                       Nonce_t *Na , unsigned *lenTktCipher , uint8_t **tktCipher )
{

    //  Check against any NULL pointers in the arguments
    if (Ka == NULL || Ks == NULL || IDb == NULL || Na == NULL || log == NULL)
    {
        fprintf( stderr , "MSG2_receive: NULL pointer argument\n" ) ;
        exit(-1) ;
    }

    unsigned LenMsg2 = 0, LenB = 0, LenMsg2Encr = 0 ;
    uint8_t *p;
 
    // Read in the components of Msg2: Encr{ Ks  || L(IDb)  || IDb || Na || L(Tkt) Encr{ Tkt } }
    // 1) Read the message length from the pipe
    if (read(fd, &LenMsg2Encr, LENSIZE) != LENSIZE)
    {
        fprintf( log , "Unable to receive all %lu bytes of Len(Msg2Encr) "
                       "in MSG2_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes LenMsg2Encr in MSG2_receive()" );
    }

    // 2) Read the whole encrypted message2 from the pipe
    if (read(fd, ciphertext2, LenMsg2Encr) != LenMsg2Encr)
    {

        fprintf( log , "Unable to receive all %u bytes of Msg2Encr "
                       "in MSG2_receive() ... EXITING\n" , LenMsg2Encr );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes Msg2Encr in MSG2_receive()" );
    }

    memset(plaintext, 0, PLAINTEXT_LEN_MAX) ;

    // 3) Decrypt the entire message2
    LenMsg2 = decrypt(ciphertext2, LenMsg2Encr, Ka->key, Ka->iv, plaintext) ;
    
    // 4) Read in the Ks from the plaintext buffer
    p = plaintext;

    memcpy(Ks, p, sizeof(myKey_t));
    p += sizeof(myKey_t) ;
    
    // 5) Read in the Len(IDb) from the plaintext buffer
    memcpy(&LenB, p, sizeof(unsigned));
    p += sizeof(unsigned) ;

    // 6) Read in the IDb from the plaintext buffer
    *IDb = (char *) malloc(LenB) ;
    if (*IDb == NULL)
    {
        fprintf( log , "Out of Memory allocating %u bytes for IDB in MSG2_receive() "
                       "... EXITING\n" , LenB );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDB in MSG2_receive()" );
    }

    memcpy(*IDb, p, LenB);
    p += LenB ;

    // 7) Read in the Nonce from the plaintext buffer
    memcpy(Na, p, NONCELEN);
    p += NONCELEN ;

    // 8) Read in the Len(Tkt) from the plaintext buffer
    memcpy(lenTktCipher, p, sizeof(unsigned)) ;
    p += sizeof(unsigned) ;

    // 9) Read in the Tkt from the plaintext buffer
    *tktCipher = (uint8_t *) malloc(*lenTktCipher) ;
    if (*tktCipher == NULL)
    {
        fprintf( log , "Out of Memory allocating %u bytes for tktCipher in MSG2_receive() "
                       "... EXITING\n" , *lenTktCipher );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating tktCipher in MSG2_receive()" );
    }
    memcpy(*tktCipher, p, *lenTktCipher) ;
    p += *lenTktCipher ;

    fprintf( log ,"MSG2_receive() got the following Encrypted MSG2 ( %u bytes ) Successfully\n" 
                 , LenMsg2Encr );
    BIO_dump_indent_fp( log , ciphertext2, LenMsg2Encr , 4 ) ; fprintf( log , "\n" ) ;
    fflush( log ) ;


}

//-----------------------------------------------------------------------------
// Build a new Message #3 from Amal to Basim
// MSG3 = {  L(TktCipher)  || TktCipher  ||  Na2  }
// No further encryption is done on MSG3
// Returns the size of Message #3  in bytes

unsigned MSG3_new( FILE *log , uint8_t **msg3 , const unsigned lenTktCipher , const uint8_t *tktCipher,  
                   const Nonce_t *Na2 )
{

    if (msg3 == NULL || tktCipher == NULL || Na2 == NULL)
    {
        fprintf( stderr , "MSG3_new: NULL pointer argument\n" ) ;
        exit(-1) ;
    }

    // Allocate memory for msg3
    unsigned LenMsg3 = LENSIZE + lenTktCipher + NONCELEN ;
    *msg3 = (uint8_t *) malloc(LenMsg3) ;

    // Write values into the msg3 pointer
    uint8_t *m = *msg3;

    memcpy(m, &lenTktCipher, LENSIZE) ;
    m += LENSIZE ;

    memcpy(m, tktCipher, lenTktCipher);
    m += lenTktCipher ;

    memcpy(m, Na2, NONCELEN) ;
    m += NONCELEN ;

    // Print info to the log
    fprintf( log , "\nThe following new MSG3 ( %u bytes ) has been created by "
                   "MSG3_new ():\n" , LenMsg3 ) ;
    BIO_dump_indent_fp( log , *msg3 , LenMsg3 , 4 ) ;    fprintf( log , "\n" ) ;    
    fflush( log ) ;    

    return LenMsg3 ;

}

//-----------------------------------------------------------------------------
// Receive Message #3 by Basim from Amal
// Parse the incoming msg3 into its components Ks , IDa , and Na2
// The buffers for Kb, Ks, and Na2 are pre-created by the caller
// The value of Kb is set by the caller
// The buffer for IDA is to be allocated here into *IDa

void MSG3_receive( FILE *log , int fd , const myKey_t *Kb , myKey_t *Ks , char **IDa , Nonce_t *Na2 )
{

    if (Kb == NULL || Ks == NULL || IDa == NULL || Na2 == NULL)
    {
        fprintf( stderr , "MSG3_receive: NULL pointer argument\n" ) ;
        exit(-1) ;
    }

    // Read the length of the ticket cipher first
    unsigned LenTktCiph = 0;
    if (read(fd, &LenTktCiph, LENSIZE) != LENSIZE)
    {
        fprintf( log , "Unable to receive all %lu bytes of LenTktCiph "
                       "in MSG3_receive() ... EXITING\n" , LENSIZE );
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes LenTktCiph in MSG3_receive()" );
    }

    // Read the ticket cipher into the ciphertext buffer
    if (read(fd, ciphertext, LenTktCiph) != LenTktCiph)
    {
        fprintf( log , "Unable to receive all %u bytes of TktCiph "
                       "in MSG3_receive() ... EXITING\n" , LenTktCiph );
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes TktCiph in MSG3_receive()" );
    }

    // Read the Nonce2 into the nonce struct
    if (read(fd, Na2, NONCELEN) != NONCELEN)
    {
        fprintf( log , "Unable to receive all %lu bytes of Na2 "
                       "in MSG3_receive() ... EXITING\n" , NONCELEN );
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes Na2 in MSG3_receive()" );
    }

    // Print the ticket cipher info
    fprintf( log ,"The following Encrypted TktCipher ( %u bytes ) was received by MSG3_receive()\n" 
                 , LenTktCiph );
    BIO_dump_indent_fp( log , ciphertext, LenTktCiph, 4) ;   fprintf( log , "\n");

    // Decrypt the ticket cipher
    unsigned LenTkt = decrypt(ciphertext, LenTktCiph, Kb->key, Kb->iv, plaintext) ;

    // Print the decrypted ticket info
    fprintf( log ,"Here is the Decrypted Ticket ( %u bytes ) in MSG3_receive():\n" , LenTkt ) ;
    BIO_dump_indent_fp( log , plaintext, LenTkt, 4) ;   fprintf( log , "\n");
    fflush( log ) ;

    // Get Ks from the plaintext
    uint8_t *p = plaintext;

    memcpy(Ks, p, sizeof(myKey_t)) ;
    p += sizeof(myKey_t);

    // Get Len(IDa) from the plaintext
    unsigned LenA = 0;

    memcpy(&LenA, p, LENSIZE) ;
    p += LENSIZE;

    // Allocate memory for IDa using LenA
    *IDa = (char *) malloc(LenA) ;
    if (*IDa == NULL)
    {
        fprintf( log , "Out of Memory allocating %u bytes for IDA in MSG3_receive() "
                       "... EXITING\n" , LenA );
        fflush( log ) ;  fclose( log ) ;
        exitError( "Out of Memory allocating IDA in MSG3_receive()" );
    }

    memcpy(*IDa, p, (LenA)) ;
    p += (LenA) ;

}

//-----------------------------------------------------------------------------
// Build a new Message #4 from Basim to Amal
// MSG4 = Encrypt( Ks ,  { fNa2 ||  Nb }   )
// A new buffer for *msg4 is allocated here
// All other arguments have been initialized by caller

// Returns the size of Message #4 after being encrypted by Ks in bytes

unsigned MSG4_new( FILE *log , uint8_t **msg4, const myKey_t *Ks , Nonce_t *fNa2 , Nonce_t *Nb )
{

    if (msg4 == NULL || Ks == NULL || fNa2 == NULL || Nb == NULL)
    {
        fprintf( stderr , "MSG4_new: NULL pointer argument\n" ) ;
        exit(-1) ;
    }

    // Construct MSG4 Plaintext = { f(Na2)  ||  Nb }
    // Use the global scratch buffer plaintext[] for MSG4 plaintext and fill it in with component values
    unsigned LenNb = NONCELEN;
    unsigned LenMsg4 = NONCELEN + NONCELEN;
    
    // Compute f(Na2)
    Nonce_t result;
    fNonce(result, *fNa2);

    memset(plaintext, 0, PLAINTEXT_LEN_MAX) ;
    uint8_t *p = plaintext;

    // Copy f(Na2) into the plaintext buffer
    memcpy(p, result, NONCELEN) ;
    p += NONCELEN;

    // Copy Nb into the plaintext buffer
    memcpy(p, Nb, NONCELEN) ;
    p += NONCELEN;


    fprintf(log, "Basim is sending this f( Na2 ) in MSG4:\n");
    BIO_dump_indent_fp(log, result, NONCELEN, 4);   fprintf(log, "\n");

    fprintf(log, "Basim is sending this nonce Nb in MSG4:\n");
    BIO_dump_indent_fp(log, Nb, NONCELEN, 4);   fprintf(log, "\n");

    // Now, encrypt MSG4 plaintext using the session key Ks;
    // Use the global scratch buffer ciphertext[] to collect the result. Make sure it fits.
    unsigned LenMSG4cipher = encrypt(plaintext, LenMsg4, Ks->key, Ks->iv, ciphertext2) ;

    // Now allocate a buffer for the caller, and copy the encrypted MSG4 to it
    *msg4 = malloc( LenMSG4cipher ) ;
    if (*msg4 == NULL)
    {
        fprintf( stderr , "MSG4_new: message could not be allocated\n" ) ;
        exit(-1) ;
    }

    memcpy(*msg4, ciphertext2, LenMSG4cipher) ;

    fprintf( log , "The following new Encrypted MSG4 ( %u bytes ) has been"
                   " created by MSG4_new ():  \n" , LenMSG4cipher ) ;
    BIO_dump_indent_fp( log , *msg4 , LenMSG4cipher , 4 ) ;    fprintf( log , "\n" ) ;

    return LenMSG4cipher;  
}

//-----------------------------------------------------------------------------
// Receive Message #4 by Amal from Basim
// Parse the incoming encrypted msg4 into the values rcvd_fNa2 and Nb

void  MSG4_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *rcvd_fNa2 , Nonce_t *Nb )
{
    if (Ks == NULL || rcvd_fNa2 == NULL || Nb == NULL)
    {
        fprintf( stderr , "MSG4_receive: NULL pointer argument\n" ) ;
        exit(-1) ;
    }

    unsigned LenMsg4Encr = 0, LenMsg4 = 0;
    if (read(fd, &LenMsg4Encr, LENSIZE) != LENSIZE)
    {
        fprintf( log , "Unable to receive all %lu bytes of Len(Msg4Encr) "
                                          "in MSG4_receive() ... EXITING\n" , LENSIZE );
        
            fflush( log ) ;  fclose( log ) ;   
            exitError( "Unable to receive all bytes LenMsg4Encr in MSG4_receive()" );
    }

    memset(ciphertext2, 0, CIPHER_LEN_MAX) ;
    if (read (fd, ciphertext2, LenMsg4Encr) != LenMsg4Encr)
    {
        fprintf( log , "Unable to receive all %u bytes of Msg4Encr "
                            "in MSG4_receive() ... EXITING\n" , LenMsg4Encr );
        
            fflush( log ) ;  fclose( log ) ;   
            exitError( "Unable to receive all bytes Msg4Encr in MSG4_receive()" );
    }

    fprintf( log ,"The following Encrypted MSG4 ( %u bytes ) was received:\n" , LenMsg4Encr );
    BIO_dump_indent_fp(log, ciphertext2, LenMsg4Encr, 4); fprintf(log, "\n");
    fflush(log);

    fprintf(log, "\nAmal is expecting back this f( Na2 ) in MSG4:\n") ;
    BIO_dump_indent_fp(log, rcvd_fNa2, NONCELEN, 4); fprintf( log , "\n" );
    fflush(log) ;

    memset(plaintext, 0, PLAINTEXT_LEN_MAX);
    LenMsg4 = decrypt(ciphertext2, LenMsg4Encr, Ks->key, Ks->iv, plaintext);

    uint8_t *p;
    p = plaintext;

    memcpy(rcvd_fNa2, p, NONCELEN);
    p += NONCELEN;

    memcpy(Nb, p, NONCELEN);
    p += NONCELEN;

    fprintf(log, "Basim returned the following f( Na2 )   >>>> VALID\n") ;
    BIO_dump_indent_fp(log, rcvd_fNa2, NONCELEN, 4); fprintf( log , "\n" );
    fflush(log) ;

    fprintf(log, "Amal also received this Nb :\n") ;
    BIO_dump_indent_fp(log, Nb, NONCELEN, 4); fprintf( log , "\n" );
    fflush(log) ;
}

//-----------------------------------------------------------------------------
// Build a new Message #5 from Amal to Basim
// A new buffer for *msg5 is allocated here
// MSG5 = Encr( Ks  ,  { fNb }  )
// All other arguments have been initialized by caller
// Returns the size of Message #5  in bytes

unsigned MSG5_new( FILE *log , uint8_t **msg5, const myKey_t *Ks ,  Nonce_t *fNb )
{

    if (msg5 == NULL || Ks == NULL || fNb == NULL)
    {
        fprintf( stderr , "MSG5_new: NULL pointer argument\n" ) ;
        exit(-1) ;
    }

    // Construct MSG5 Plaintext  = {  f(Nb)  }
    // Use the global scratch buffer plaintext[] for MSG5 plaintext. Make sure it fits 
    unsigned LenMsg5 = NONCELEN;
    memset(plaintext, 0, PLAINTEXT_LEN_MAX) ;
    uint8_t *p = plaintext;

    // Copy f(Nb) into the plaintext buffer
    memcpy(p, fNb, NONCELEN) ;
    p += NONCELEN;

    // Now, encrypt( Ks , {plaintext} );
    // Use the global scratch buffer ciphertext[] to collect result. Make sure it fits.
    unsigned LenMSG5cipher = encrypt(plaintext, LenMsg5, Ks->key, Ks->iv, ciphertext2) ;

    // Now allocate a buffer for the caller, and copy the encrypted MSG5 to it
    *msg5 = (uint8_t *) malloc( LenMSG5cipher ) ;
    if (*msg5 == NULL)
    {
        fprintf( stderr , "MSG5_new: message could not be allocated\n" ) ;
        exit(-1) ;
    }

    memcpy(*msg5, ciphertext2, LenMSG5cipher) ;

    fprintf( log , "The following new Encrypted MSG5 ( %u bytes ) has been"
                   " created by MSG5_new ():  \n" , LenMSG5cipher ) ;
    BIO_dump_indent_fp( log , *msg5 , LenMSG5cipher , 4 ) ;    fprintf( log , "\n" ) ;    
    fflush( log ) ;    

    return LenMSG5cipher;
}

//-----------------------------------------------------------------------------
// Receive Message 5 by Basim from Amal
// Parse the incoming msg5 into the value fNb

void  MSG5_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *fNb )
{

    if (Ks == NULL || fNb == NULL)
    {
        fprintf( stderr , "MSG5_receive: NULL pointer argument\n" ) ;
        exit(-1) ;
    }

    // Read Len( Msg5 ) followed by reading Msg5 itself
    // Always make sure read() and write() succeed
    // Use the global scratch buffer ciphertext[] to receive encrypted MSG5.
    // Make sure it fits.
    unsigned LenMSG5cipher = 0;
    if (read(fd, &LenMSG5cipher, LENSIZE) != LENSIZE)
    {
        fprintf( log , "Unable to receive all %lu bytes of Len(MSG5cipher) "
                       "in MSG5_receive() ... EXITING\n" , LENSIZE );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes LenMSG5cipher in MSG5_receive()" );
    }

    if (read(fd, ciphertext2, LenMSG5cipher) != LenMSG5cipher)
    {
        fprintf( log , "Unable to receive all %u bytes of MSG5cipher "
                       "in MSG5_receive() ... EXITING\n" , LenMSG5cipher );
        
        fflush( log ) ;  fclose( log ) ;   
        exitError( "Unable to receive all bytes MSG5cipher in MSG5_receive()" );
    }

    // Now, Decrypt MSG5 using Ks
    // Use the global scratch buffer decryptext[] to collect the results of decryption
    // Make sure it fits
    unsigned LenMSG5 = decrypt(ciphertext2, LenMSG5cipher, Ks->key, Ks->iv, decryptext) ;


    // Parse MSG5 into its components f( Nb )
    uint8_t *p = decryptext;

    memcpy(fNb, p, NONCELEN);
    p += NONCELEN;
    
    fprintf( log, "Basim is expecting back this f( Nb ) in MSG5:\n") ;
    BIO_dump_indent_fp(log, fNb, NONCELEN, 4); fprintf( log , "\n" );
    fflush(log) ;

    fprintf( log ,"The following Encrypted MSG5 ( %u bytes ) has been received:\n" , LenMSG5cipher );
    BIO_dump_indent_fp(log, ciphertext2, LenMSG5cipher, 4); fprintf(log, "\n");
    fflush(log);
}

//-----------------------------------------------------------------------------
// Utility to compute r = F( n ) for Nonce_t objects
// For our purposes, F( n ) = ( n + 1 ) mod  2^b  
// where b = number of bits in a Nonce_t object
// The value of the nonces are interpretted as BIG-Endian unsigned integers
void     fNonce( Nonce_t r , Nonce_t n )
{
    // Note that the nonces are stored in Big-Endian byte order
    // This affects how you do arithmetice on the nonces, e.g. when you add 1

    // Define b
    int b = 8 * NONCELEN ;

    // Convert nonce n to little endian
    uint32_t little_n = ntohl(n[0]);

    // compute the F( n )
    uint32_t fNonce = (little_n + 1);

    // Convert back to big endian
    r[0] = htonl(fNonce) ;
    }