/*
Ssl Smtp Server with c++ openssl sockets
All rights reservered Marcin Łukaszewski <hello@breakermind.com>
*/
#include "starttls.h"

Ssl::Ssl(){

}

void Ssl::init_openssl()
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    ERR_load_crypto_strings();
}

void Ssl::cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *Ssl::create_context()
{
    SSL_CTX *ctx;
    auto method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void Ssl::configure_context(SSL_CTX *ctx, std::string Certificate, std::string CertificateKey)
{
    // SSL_CTX_set_ecdh_auto(ctx, 1);
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, Certificate.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, CertificateKey.c_str(), SSL_FILETYPE_PEM) <= 0 ) {
      ERR_print_errors_fp(stderr);
      exit(EXIT_FAILURE);
    }
}

void Ssl::Start(string Certificate, string CertificateKey, SOCK client)
{
    cout << "Starting server ..." << endl;

    int sock;
    SSL_CTX *ctx;

    init_openssl();
    ctx = create_context();
    configure_context(ctx, Certificate, CertificateKey);

    SSL *ssl;
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);
    // ShowCerts(ssl);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        const char reply00[] = "220 TLS working, go ahead \r\n";
        SSL_write(ssl, reply00, strlen(reply00));
    }
// magic 
// SSL_set_accept_state(ssl);
// SSL_set_connect_state(ssl);
X509 * peercert = SSL_get_peer_certificate(ssl);

    std::string ClientIP = "";
	ServerLoop(ssl,ClientIP);

    printf("SSL pid %i", getpid());
    SSL_free(ssl);
#ifdef _WIN32
    closesocket(client);
#else
    close(client);
#endif
}

void  Ssl::ServerLoop(SSL *ssl, string ipAddress){

	char buffer[8192] = {0};
	std::string cmsg ="";
	try{
		//EHLO
		memset(buffer,0,sizeof(buffer));
		buffer[0] = '\0';
			int received = SSL_read(ssl,buffer,sizeof(buffer)-1);
		    cmsg = std::string(buffer);
		    cout << "HELO CLIENT <<<< " << cmsg << endl; 
		    const char reply1[] = "250-qflash.pl at your service\r\n250-SIZE 20286400\r\n250 SMTPUTF8\r\n";
		    int wr = SSL_write(ssl, reply1, strlen(reply1));
			cout << "Write " << wr << endl;
			sslError(ssl,received);
			cout<<"ERROR:"<<strerror(errno)<<endl;			
		//MAIL FROM
		memset(buffer,0,sizeof(buffer));
		buffer[0] = '\0';
			received = SSL_read (ssl, buffer, sizeof(buffer) - 1);
			if(received == 0)cout<<"Error input"<<endl;
		    cmsg = std::string(buffer);
		    cout << "FROM CLIENT <<<< " << cmsg << endl; 
		    const char reply2[] = "250 2.1.0 OK\r\n";
		    wr = SSL_write(ssl, reply2, strlen(reply2));
		    cout << "Write " << wr << endl;
		    sslError(ssl,received);
		    cout<<"ERROR:"<<strerror(errno)<<endl;
		// RCPTTO    
		memset(buffer,0,sizeof(buffer));
		buffer[0] = '\0';
		    received = SSL_read (ssl, buffer, sizeof(buffer) - 1);
		    if(received == 0)cout<<"Error input"<<endl;
		    cmsg = std::string(buffer);
		    cout << "RCPT CLIENT <<<< " << cmsg << endl; 
		    const char reply3[] = "250 2.1.5 OK\r\n";
		    wr = SSL_write(ssl, reply3, strlen(reply3));
		    cout << "Write " << wr << endl;
		    sslError(ssl,received);
		    cout<<"ERROR:"<<strerror(errno)<<endl;
		// DATA    
		memset(buffer,0,sizeof(buffer));
		buffer[0] = '\0';
		    received = SSL_read (ssl, buffer, sizeof(buffer) - 1);
		    if(received == 0)cout<<"Error input"<<endl;
		    cmsg = std::string(buffer);
		    cout << "DATA CLIENT <<<< " << cmsg << endl; 
		    const char d4[] = "354 Go ahead\r\n";
		    wr = SSL_write(ssl, d4, strlen(d4));
		    cout << "Write " << wr << endl;
		    sslError(ssl,received);
		    cout<<"ERROR:"<<strerror(errno)<<endl;
		// MIME
		memset(buffer,0,sizeof(buffer));    
		buffer[0] = '\0';
		    while(!m_aborted){
		    	received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
		    	if(received <= 0){
		    		break;
		    	}
		    	cmsg = std::string(buffer);
			    cout << "MIME RECEIVED <<<  " << cmsg << endl;	   
			    if(Contain(cmsg, "\r\n.\r\n") || Contain(cmsg, ".\r\n") || Contain(cmsg, ".\r\n") || Contain(cmsg, ".\n")){                 
			        cout << "MESSAGES HAS BEEN SENT [OK]" << endl;
			        // reply_send + std::string("|") + wassendto;
			        const char reply5[] = "250 OK message: queued as 123\r\n";
			        wr = SSL_write(ssl, (const void *)reply5, strlen(reply5));
			        cout << "Write " << wr << endl;
			        //c4 = 1;                    
			        break;
			    }
			    memset(buffer,0,sizeof(buffer));
			    buffer[0] = '\0';
			}
		// QUIT
		memset(buffer,0,sizeof(buffer));
		buffer[0] = '\0';
			received = SSL_read (ssl, buffer, sizeof(buffer) - 1);
		    cmsg = std::string(buffer);
		    cout << "QUIT CLIENT <<<< " << cmsg << endl; 
		    const char reply6[] = "221 Bye\r\n";
		    wr = SSL_write(ssl, (const void *)reply6, strlen(reply6));
		    cout << "Write " << wr << endl;
		    sslError(ssl,received);
		    cout<<"ERROR:"<<strerror(errno)<<endl;

		    SSL_shutdown(ssl);
        m_aborted = true;
#ifndef _WIN32    
	      kill(getpid(), SIGKILL);
#endif
		}catch(std::exception &e){
			e.what();
		}
}

void Ssl::sslError(SSL *ssl, int received){
    const int err = SSL_get_error(ssl, received);
    // const int st = ERR_get_error();
    if (err == SSL_ERROR_NONE) {
        std::cout<<"SSL_ERROR_NONE:"<<SSL_ERROR_NONE<<std::endl;
        // SSL_shutdown(ssl);
    } else if (err == SSL_ERROR_WANT_READ ) {
        std::cout<<"SSL_ERROR_WANT_READ:"<<SSL_ERROR_WANT_READ<<std::endl;
        SSL_shutdown(ssl);
        m_aborted = true;
#ifndef _WIN32    
        kill(getpid(), SIGKILL);
#endif
    } else if (SSL_ERROR_SYSCALL) {
      cout << errno << " Received " << received << endl;
        std::cout<<"SSL_ERROR_SYSCALL:"<<SSL_ERROR_SYSCALL<<std::endl;
        SSL_shutdown(ssl);
        m_aborted = true;
#ifndef _WIN32    
        kill(getpid(), SIGKILL);
#endif
    }
}

bool Ssl::Contain(std::string str,std::string search){
	std::size_t found = str.find(search);
	if(found!=std::string::npos){
		return 1;
	}
	return 0;
}
