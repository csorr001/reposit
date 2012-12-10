//----------------------------------------------------------------------------
// File: ssl_server.cpp
// Description: Implementation of an SSL-secured server that performs
//              secure file transfer to a single client over a single
//              connection.
//----------------------------------------------------------------------------
#include <string>
#include <time.h>
#include <iostream>
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>

#include "utils.h"

//-----------------------------------------------------------------------------
// Function: main()
//-----------------------------------------------------------------------------
int main(int argc, char** argv)
{
    //-------------------------------------------------------------------------
    // initialize
	ERR_load_crypto_strings();
	SSL_load_error_strings();
    SSL_library_init();
    
    setbuf(stdout, NULL); // disables buffered output

	// Handle commandline arguments
	// Useage: client -server serveraddress -port portnumber filename
	if (argc < 2)
	{
		printf("Useage: server portnumber\n");
		exit(EXIT_FAILURE);
	}
	char* port = argv[1];

	printf("------------\n");
	printf("-- SERVER --\n"); 
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Allow for a client to establish an SSL connection
	printf("1. Allowing for client SSL connection...");

	// Setup DH object and generate Diffie-Helman Parameters
	DH* dh = DH_generate_parameters(128, 5, NULL, NULL);
	int dh_err;
	DH_check(dh, &dh_err);
	if (dh_err != 0)
	{
		printf("Error during Diffie-Helman parameter generation.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup server context
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
	SSL_CTX_set_tmp_dh(ctx, dh);
	if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the BIO
	BIO* server = BIO_new(BIO_s_accept());
	BIO_set_accept_port(server, port);
	BIO_do_accept(server);

	// Setup the SSL
	SSL* ssl = SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	SSL_set_accept_state(ssl);
	SSL_set_bio(ssl, server, server);
	if (SSL_accept(ssl) <= 0)
	{
		printf("Error doing SSL_accept(ssl).\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	printf("DONE.\n");
	printf("    (Now listening on port: %s)\n", port);

    //-------------------------------------------------------------------------
	// 2. Receive a random number (the challenge) from the client
	printf("2. Waiting for client to connect and send challenge...");
    
	int bufflen=0;
	unsigned char buff[1024];
	memset(buff,0,sizeof(buff));
	bufflen=SSL_read(ssl,buff,1024);

    //SSL_read;
    
	printf("DONE.\n");
	printf("    (Challenge: \"%s\")\n", buff);

    //-------------------------------------------------------------------------
	// 3. Generate the SHA1 hash of the challenge
	printf("3. Generating SHA1 hash...");
	//int mdlen=0;
	//int writelen=0;
	unsigned char hashWrite[1024];
	BIO *fp=BIO_new_file("rsaprivatekey.pem","r");
	RSA *x;
	x=PEM_read_bio_RSAPrivateKey(fp,NULL,0,0);
	BIO *fpp=BIO_new_file("rsapublickey.pem","r");
	RSA *xx;
	xx=PEM_read_bio_RSA_PUBKEY(fpp,NULL,0,0);
	unsigned char unencrypted[128];
	memset(unencrypted,0,sizeof(unencrypted));
	RSA_private_decrypt(128,buff,unencrypted,x,RSA_NO_PADDING);
	//unsigned char hashRead[SHA_DIGEST_LENGTH];
	SHA1(unencrypted,bufflen,hashWrite);
	//BIO *mem=BIO_new(BIO_s_mem());
	//BIO *md=BIO_new(BIO_f_md());
	//BIO_set_md(md,EVP_sha1());
	//mem=BIO_push(md,mem);
	//writelen=BIO_write(mem,hashWrite,bufflen);
	//mdlen=BIO_read(mem,hashRead,BUFFER_SIZE);
	

	printf("SUCCESS.\n");
	printf("    (SHA1 hash: \"%s\" (%d bytes))\n", hashWrite, SHA_DIGEST_LENGTH);

    //-------------------------------------------------------------------------
	// 4. Sign the key using the RSA private key specified in the
	//     file "rsaprivatekey.pem"
	printf("4. Signing the key...");
	unsigned char sigret[1024];
	unsigned int siglen[1024];
	int s=128;
	//long sig=0;
	RSA_sign(NID_sha1,hashWrite,102,sigret,siglen,x);
	RSA_verify(NID_sha1,hashWrite,102,sigret,s,xx);
	//char errbuf[128];
	//sig=ERR_get_error();
	//ERR_error_string(sig,errbuf);
	//cout << endl << errbuf << endl;
    printf("DONE.\n");
    printf("    (Signed key length: %d bytes)\n", s);
    printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)sigret, s).c_str(), s);

    //-------------------------------------------------------------------------
	// 5. Send the signature to the client for authentication
	printf("5. Sending signature to client for authentication...");
	
	int sigWriteLen=0;
	sigWriteLen=SSL_write(ssl,sigret,128);
	printf("DONE.\n");
    
    //-------------------------------------------------------------------------
	// 6. Receive a filename request from the client
	printf("6. Receiving file request from client...");
    //SSL_read
    unsigned char file[BUFFER_SIZE];
    memset(file,0,sizeof(file));
    bufflen=SSL_read(ssl,file,BUFFER_SIZE);
    printf("RECEIVED.\n");
    printf("    (File requested: \"%s\"\n", file);

    //-------------------------------------------------------------------------
	// 7. Send the requested file back to the client (if it exists)
	printf("7. Attempting to send requested file to client...");

	PAUSE(2);
	//BIO_flush
	//BIO_new_file
	//BIO_puts(server, "fnf");
    //BIO_read(bfile, buffer, BUFFER_SIZE)) > 0)
	//SSL_write(ssl, buffer, bytesRead);

    int bytesSent=0;
    
    printf("SENT.\n");
    printf("    (Bytes sent: %d)\n", bytesSent);

    //-------------------------------------------------------------------------
	// 8. Close the connection
	printf("8. Closing connection...");

	//SSL_shutdown
    //BIO_reset
    printf("DONE.\n");

    printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
	
    //-------------------------------------------------------------------------
	// Freedom!
    
	BIO_free_all(server);
	//BIO_free_all(mem);
	return EXIT_SUCCESS;
}
