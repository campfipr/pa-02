/*----------------------------------------------------------------------------
PA-02: Messaage Digest & Signature using Pipes

FILE:   myCrypto.c

Written By: 
     1- Patrick Campfield
     2-
     
Submitted on: 
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//***********************************************************************
// pLAB-01
//***********************************************************************

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    exit(-1);
}

//-----------------------------------------------------------------------------
// Encrypt the plaint text stored at 'pPlainText' into the 
// caller-allocated memory at 'pCipherText'
// Caller must allocate sufficient memory for the cipher text
// Returns size of the cipher text in bytes

// For the following Encryption/Decryption, 
// use a 256-bit key and AES in CBC mode (with a 128-bit IV)
// Ensure the (key,IV) being used match the specified algorithm

unsigned encrypt( uint8_t *pPlainText, unsigned plainText_len, 
             uint8_t *key, uint8_t *iv, uint8_t *pCipherText )
{
    int status;
	int len = 0; 
	int encryptedLen = 0;
	
	// Create and initialise the context
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if(!ctx)
		handleErrors("encrypt: failed to creat CTX");
	// Initialise the encryption operation.
	status = EVP_EncryptInit_ex( ctx, ALGORITHM(), NULL, key, iv );
	if( status != 1 )
		handleErrors("encrypt: failed to EncryptInit_ex");
	// Call EncryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular encryption
	status = EVP_EncryptUpdate(ctx, pCipherText, &len, pPlainText, plainText_len);
	if( status != 1 )
		handleErrors("encrypt: failed to EncryptUpdate");
	encryptedLen += len;// If additional ciphertext may still be generated,

	// the pCipherText pointer must be first advanced forward
	pCipherText += len;
	// Finalize the encryption.
	status = EVP_EncryptFinal_ex( ctx, pCipherText , &len ) ;
	if( status != 1 )
		handleErrors("encrypt: failed to EncryptFinal_ex");
	encryptedLen += len; // len could be 0 if no additional cipher text was generated

	EVP_CIPHER_CTX_free(ctx);

	return encryptedLen;
}

//-----------------------------------------------------------------------------
// Decrypt the cipher text stored at 'pCipherText' into the 
// caller-allocated memory at 'pDecryptedText'
// Caller must allocate sufficient memory for the decrypted text
// Returns size of the decrypted text in bytes

unsigned decrypt( uint8_t *pCipherText, unsigned cipherText_len, 
                  uint8_t *key, uint8_t *iv, uint8_t *pDecryptedText)
{
    int status ;
	unsigned len=0 , decryptedLen=0 ;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new() ;
	if( ! ctx )
	    handleErrors("decrypt: failed to creat CTX");

	// Initialise the decryption operation.
	status = EVP_DecryptInit_ex( ctx, ALGORITHM(), NULL, key, iv ) ;
	if( status != 1 )
	    handleErrors("decrypt: failed to DecryptInit_ex");

	// Call DecryptUpdate as many times as needed (e.g. inside a loop)
	// to perform regular decryption
	status = EVP_DecryptUpdate( ctx, pDecryptedText, &len, pCipherText, cipherText_len) ;
	if( status != 1 )
		handleErrors("decrypt: failed to DecryptUpdate");
	decryptedLen += len;

	// If additionl decrypted text may still be generated,
	// the pDecryptedText pointer must be first advanced forward
	pDecryptedText += len ;

	status = EVP_DecryptFinal_ex( ctx, pDecryptedText , &len ) ;
	if( status != 1 )
	    handleErrors("decrypt: failed to DecryptFinal_ex");
	decryptedLen += len;

	EVP_CIPHER_CTX_free(ctx);
	
	return decryptedLen;
}

//***********************************************************************
// PA-01
//***********************************************************************
static unsigned char    plaintext [ PLAINTEXT_LEN_MAX ] ,
                        ciphertext[ CIPHER_LEN_MAX    ] ,
                        decryptext[ DECRYPTED_LEN_MAX ] ;
int encryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv )
{
    int status;
    int readIn = 0;
    unsigned len = 0;
    unsigned encryptedLen = 0;
	
	// Create and initialise the context
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if(!ctx)
		handleErrors("encrypt: failed to creat CTX");
	// Initialise the encryption operation.
	status = EVP_EncryptInit_ex( ctx, ALGORITHM(), NULL, key, iv );
	if( status != 1 )
		handleErrors("encrypt: failed to EncryptInit_ex");
 
    while(1){
        readIn = read(fd_in, plaintext, PLAINTEXT_LEN_MAX);
        if(readIn == 0)
            break;
        if(readIn == -1)
            handleErrors("Error in reading in file to Encrypt");
        
        
        status = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, readIn);
	    if( status != 1 )
		    handleErrors("encrypt: failed to EncryptUpdate");
        
        encryptedLen += len;

        write(fd_out, ciphertext, len);

    }
    status = EVP_EncryptFinal_ex(ctx, ciphertext, &len);

    if( status != 1 )
	    handleErrors("encrypt: failed to EncryptFinal_ex");
    
    write(fd_out, ciphertext, len);

	encryptedLen += len; 

	EVP_CIPHER_CTX_free(ctx);
    return encryptedLen;
}
//-----------------------------------------------------------------------------
int decryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv )
{
   int status;
    int readIn = 0;
    unsigned len = 0;
    unsigned decryptedLen = 0;

    // Create and initialise the context
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if(!ctx)
		handleErrors("Decrypt: failed to creat CTX");
	// Initialise the decryption operation.
    status = EVP_DecryptInit_ex( ctx, ALGORITHM(), NULL, key, iv );
	if( status != 1 )
		handleErrors("Decrypt: failed to DecryptInit_ex");
    while(1){
        readIn = read(fd_in, ciphertext, CIPHER_LEN_MAX);
        if(readIn == 0)
            break;
        if(readIn == -1)
            handleErrors("Error in reading in file to Decrypt");

        status = EVP_DecryptUpdate(ctx, decryptext, &len, ciphertext, readIn);
        if( status != 1 )
		    handleErrors("Decrypt: failed to DecryptUpdate");

        decryptedLen += len;
        write(fd_out, decryptext, len);
    }
    status = EVP_DecryptFinal_ex(ctx, ciphertext, &len);
    if( status != 1 )
	    handleErrors("Decrypt: failed to DecryptFinal_ex");
    
    write(fd_out, ciphertext, len);

	decryptedLen += len; 

	EVP_CIPHER_CTX_free(ctx);
    return decryptedLen;
}

//***********************************************************************
// pLAB-02
//***********************************************************************

RSA *getRSAfromFile(char * filename, int public)
{
    // open the binary file whose name if 'filename' for reading
    // Create a new RSA object using RSA_new() ;
    // To read a public RSA key, use PEM_read_RSA_PUBKEY()
    // To read a public RSA key, use PEM_read_RSAPrivateKey()
    // close the binary file 'filename'
	FILE * fp = fopen(filename,"rb");
    if (fp == NULL)
    {
        fprintf( stderr , "getRSAfromFile: Unable to open RSA key file %s \n",filename);
        return NULL;    
    }
    RSA *rsa = RSA_new() ;
    if ( public ){
        rsa = PEM_read_RSA_PUBKEY( fp, &rsa , NULL , NULL );
	}
    else{
        rsa = PEM_read_RSAPrivateKey( fp , &rsa , NULL , NULL );
	}
    fclose( fp );
    return rsa;
}

//-----------------------------------------------------------------------------


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
	// Use EVP_MD_CTX_create() to create new hashing context

    // Initialize the context using EVP_DigestInit() so that it deploys 
	// the EVP_sha256() hashing function 

    while ( /* Loop until end-of input file */ )
    {
        // read( fd_in, ...  , INPUT_CHUNK );

		// Use EVP_DigestUpdate() to hash the data you read

        if ( fd_out > 0 )
            // write the data you just read to fd_out
    }

    // Finialize the hash calculation using EVP_DigestFinal() directly
	// into the 'digest' array

    // Use EVP_MD_CTX_destroy( ) to clean up the context

    // return the length of the computed digest in bytes ;
}


