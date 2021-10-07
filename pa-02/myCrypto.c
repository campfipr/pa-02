/*----------------------------------------------------------------------------
PA-02: Messaage Digest & Signature using Pipes

FILE:   myCrypto.c

Written By: 
     1- 
     2-
     
Submitted on: 
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//***********************************************************************
// LAB-01
//***********************************************************************

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    abort();
}

//-----------------------------------------------------------------------------
// Encrypt the plaint text stored at 'pPlainText' into the 
// caller-allocated memory at 'pCipherText'
// Caller must allocate sufficient memory for the cipher text
// Returns size of the cipher text in bytes

unsigned encrypt( uint8_t *pPlainText, unsigned plainText_len, 
             uint8_t *key, uint8_t *iv, uint8_t *pCipherText )
{
	// ....
	// Your previous code MUST be here
	// ....
}

//-----------------------------------------------------------------------------
// Decrypt the cipher text stored at 'pCipherText' into the 
// caller-allocated memory at 'pDecryptedText'
// Caller must allocate sufficient memory for the decrypted text
// Returns size of the decrypted text in bytes

unsigned decrypt( uint8_t *pCipherText, unsigned cipherText_len, 
                  uint8_t *key, uint8_t *iv, uint8_t *pDecryptedText)
{
	// ....
	// Your previous code MUST be here
	// ....
}

//***********************************************************************
// PA-01
//***********************************************************************

int encryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv )
{
	// ....
	// Your previous code MUST be here
	// ....
}

//-----------------------------------------------------------------------------
int decryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv )
{
	// ....
	// Your previous code MUST be here
	// ....
}

//***********************************************************************
// LAB-02
//***********************************************************************

RSA *getRSAfromFile(char * filename, int public)
{
	// ....
	// Your previous code MUST be here
	// ....
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


