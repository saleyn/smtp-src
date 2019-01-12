//=====================================================================
// BaracudaSMTP - smtp server example 
// Ssl Smtp Server with c++ openssl sockets and STARTTLS
// (multiple connections/process - fork())
// All rights reservered Marcin Łukaszewski <hello@breakermind.com>
//=====================================================================
// Install
// apt-get install openssl libssl-dev g++
//
// Compile
// g++ -o BaracudaSMTP main.cpp starttls.cpp starttls.h -lssl -lcrypto -L. -I.
//
// Create TLS certs (very simple): 
// https://www.sslforfree.com/
//
// Add certificate to main folder 
// (create .pem - copy all certs,keys,ca_bundle to one file)
// certificate.pem, private.key - without password
//=====================================================================
// Known problem
// Gmail does not send ssl emails (maybe only on my domain)
// It is only sample without saving emails to file 
// and without validating data.
//=====================================================================

#include <string>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// fork, getpid
#include <sys/types.h>
// 
#include <algorithm>
#include <limits.h>
// add class
#include <starttls.h>

#ifdef _WIN32
#include <io.h>
#define SOCK SOCKET

FILE _iob[] = { *stdin, *stdout, *stderr };
extern "C" FILE * __cdecl __iob_func(void) { return _iob; }

#else
#include <unistd.h>
// sockets
#include <sys/socket.h>
#include <netinet/in.h>
// inet_ntoa
#include <arpa/inet.h>
// pid kill
#include <signal.h>
#include <sys/stat.h>
#define SOCK int
#define INVALID_SOCKET -1
#endif

using namespace std;

#define PORT 25

bool Contain(std::string str,std::string search){
	std::size_t found = str.find(search);
	if(found!=std::string::npos){
		return 1;
	}
	return 0;
}

int create_socket(int port)
{
    SOCK s;
    int opt = 1;

#ifdef _WIN32
    SOCKADDR_IN addr;

    LPHOSTENT lpHost = gethostbyname("localhost");

    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr   = *(LPIN_ADDR)(lpHost->h_addr_list[0]);
#else
    struct sockaddr_in addr;

    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
#endif

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
      perror("Unable to create socket");
      exit(EXIT_FAILURE);
    }


    //set master socket to allow multiple connections , this is just a good habit, it will work without this
#ifdef _WIN32
    int opts = SO_REUSEADDR;
#else
    int opts = SO_REUSEADDR | SO_REUSEPORT;
#endif
    if( setsockopt(s, SOL_SOCKET, opts, (char*)&opt, sizeof(opt)) < 0 )
    {
      perror("setsockopt");
      exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
      perror("Unable to bind");
      exit(EXIT_FAILURE);
    }

    if (listen(s, 5) < 0) {
      perror("Unable to listen");
      exit(EXIT_FAILURE);
    }
    return s;
}

int main(int argc, char const *argv[])
{
#ifdef _WIN32
  WSADATA wsaData;
  auto err = WSAStartup(MAKEWORD(2, 2), &wsaData);

  if (err != 0) {
    printf("Error in  initializing.\nQuiting with error code: %d\n", WSAGetLastError());
    Sleep(5000);
    exit(WSAGetLastError());
  }
#endif

  int port = argc > 1 ? atoi(argv[1]) : 25;

  SOCK sock = create_socket(port);

  char *welcome = (char*)"220 example.com SMTP\r\n";
  // z tls
  char *ehlo = (char*)"250-example.com at your service\r\n250-SIZE 157286400\r\n250-STARTTLS\r\n250 SMTPUTF8\r\n";
  // bez tls
  // char *ehlo = (char*)"250-example.com at your service\r\n250-SIZE 157286400\r\n250 SMTPUTF8\r\n";
  char *ok   = (char*)"250 Ok\r\n";
  char *data = (char*)"354 send data\r\n";
  char *end  = (char*)"250 email was send\r\n";
  char *bye  = (char*)"221 Bye...\r\n";
  char *tls  = (char*)"220 2.0.0 Ready to start TLS\r\n";    

  char buffer[8192] = {0};

  while(1) {
    int valread = 0;
    int valsend = 0;

    struct sockaddr_in addr;
    int len = sizeof(addr);
        
    cout << "Waiting for connections on port " << port << "..." << endl;
    SOCK client = accept(sock, (struct sockaddr*)&addr, &len);
    if(client == INVALID_SOCKET){
      perror("Unable accept client");
      exit(EXIT_FAILURE);
      //continue;
      //exit(0);
    }
    std::string ClientIP = inet_ntoa(addr.sin_addr);
    printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    // new thread proccess
    int currpid = 0;
#ifdef _WIN32
    int pid = 0;
#else
    pid_t pid;
    // create child proccess with fork();
    pid = fork();            
#endif
    if (pid > 0) {
      currpid = pid;
      fprintf(stderr, "Mam mowego klienta, pid=%d\n", currpid);
      continue;
      //exit(0);
    }

    // Clear buffer            	
    //memset(buffer,0,sizeof(buffer));
    buffer[0] = '\0';

    // socket 220 Welcome
    send(client , welcome , strlen(welcome) , 0 );
    // printf("Hello message sent %s\n",hello1);

    // ehlo 250 OK            
    valread = recv(client,buffer,sizeof(buffer), 0);
    printf("Client send %s\n",buffer );
    memset(buffer,0,sizeof(buffer));
    char e1[] = "250-example.com\r\n250-STARTTLS\r\n250 SMTPUTF8\r\n";           
    send(client,e1,strlen(e1),0);

    // client send    
    memset(buffer,0,sizeof(buffer));
    valread = recv(client,buffer, sizeof(buffer),0);
    printf("Client send %s\n",buffer);

    if(Contain(std::string(buffer),"STARTTLS") || Contain(std::string(buffer),"starttls")){
      char tls1[] = "220 Ready to start TLS\r\n";
      send(client, tls1, strlen(tls1), 0);                

      // Start tls here
      Ssl t = Ssl();
      t.Start("certificate.pem","private.key",client);

    } else { 
      // mail from:
      // valread = read( client , buffer, 8192);
      // printf("Client send %s\n",buffer );
      memset(buffer,0,sizeof(buffer));
      send(client,ok,strlen(ok),0);
      // printf("Hello message sent %s\n",hello1);

      // rcpt to:
      valread = recv(client,buffer, sizeof(buffer),0);
      printf("Client send %s\n",buffer);
      memset(buffer,0,sizeof(buffer));
      send(client,ok,strlen(ok),0);
      // printf("Hello message sent %s\n",hello1);

      // DATA
      valread = recv(client,buffer, sizeof(buffer), 0);
      printf("Client send %s\n",buffer );
      memset(buffer,0,sizeof(buffer));
      send(client , data , strlen(data) , 0 );
      // printf("Hello message sent %s\n",hello1);
                
      // DATA CONTENT    
      while(1){
        valread = recv( client , buffer, sizeof(buffer), 0);
        printf("Client send %s\n",buffer);
        if(valread == 0||Contain(std::string(buffer),".\r\n") || Contain(std::string(buffer),"\r\n.\r\n")||Contain(std::string(buffer),".\n")||Contain(std::string(buffer),"\n.\n"))
          break;
      }
      memset(buffer,0,sizeof(buffer));
      send(client,end,strlen(end), 0);
                
      // QUIT
      valread = recv( client , buffer, sizeof(buffer), 0);
      printf("Client send %s\n",buffer );
      memset(buffer,0,sizeof(buffer));
      int err = send(client , bye , strlen(bye) , 0 );
      // printf("Hello message sent %s\n",hello1);
                            
      // close socket
#ifdef _WIN32  
      closesocket(client);
#else
      close(client);
      shutdown(client,SHUT_RDWR);
      kill(getpid(), SIGKILL);
      kill(currpid, SIGKILL);
#endif
      // exit(0);
    }
  }    
}
