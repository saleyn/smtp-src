#include <iostream>
#include <string>
#include <stdio.h>
#include <sys/types.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/wait.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <fstream>
#include "../KLSmtp/mailsession.h"

#ifdef _WIN32
# define bzero(b,len) (memset((b), '\0', (len)), (void) 0)
#endif

#define TMP_LENGTH 1024
using namespace std;

void receiveFromClient();
void processQuit();
bool heloAccepted, fromAccepted, toAccepted, dataAccepted, quit;
char* fname;
int flag = 0;


#ifdef _WIN32
SOCKET serverSd;
SOCKET newSd;
#else
int serverSd;
int newSd;
#endif

void writeToFile(char content[], char* target);
void closeConnection();
char* extractName(const char* msg);

void sendStatusCode(string code)
{
  char buf[TMP_LENGTH];

  bzero(buf, TMP_LENGTH);
  strcpy(buf, code.c_str());
  strcat(buf, "\n");
  send(newSd, (char*)&buf, strlen(buf), 0);
}

bool doesFileExist(const char* name)
{
  //strcat(name, ".txt");
  if (freopen(name, "r", stdin))
    return true;
  else
    return false;
}

void checkClientMessage(char msg[])
{
  char buf[TMP_LENGTH];

  if (strstr(msg, "HELO") || strstr(msg, "helo")) {
    heloAccepted = true;
    sendStatusCode("220   Service ready");

  } else if (strstr(msg, "MAIL FROM") || strstr(msg, "mail from")) {
    if (!heloAccepted) {
      sendStatusCode("503	 Bad sequence of commands");
      return;
    }
    fromAccepted = true;
    sendStatusCode("250    Requested mail action okay completed");
    string duplicate = buf;
    cout << duplicate << "\n";
    checkClientMessage(buf);
    //fname = extractName(duplicate.c_str());
    fname = "user";


  } else if (strstr(msg, "RCPT TO") || strstr(msg, "rcpt to")) {
    if (!fromAccepted) {
      sendStatusCode("503	 Bad sequence of commands");
      heloAccepted = false;
      return;
    }
    strtok(msg, ":");
    char* targetUserName = strtok(NULL, "@");
    strcat(targetUserName, ".txt");
    if (doesFileExist(targetUserName)) {
      toAccepted = true;
      sendStatusCode("250    Requested mail action okay, completed");
    } else {
      //mailbox unavailable
      toAccepted = false;
      sendStatusCode("450    Requested mail action not taken: mailbox unavailable");
    }


  } else if (strstr(msg, "DATA") || strstr(msg, "data")) {
    if (!toAccepted) {
      sendStatusCode("503	 Bad sequence of commands");
      heloAccepted = false;
      return;
    }

    sendStatusCode("354  Start mail input; end with <CRLF>.<CRLF>");
    //header
    bzero(buf, TMP_LENGTH);
    recv(newSd, (char*)&buf, sizeof(buf), 0);
    writeToFile(buf, fname);
    cout << buf << "\n";

    //msg-body
    bzero(buf, TMP_LENGTH);
    recv(newSd, (char*)&buf, sizeof(buf), 0);
    cout << buf << "\n";
    writeToFile(buf, fname);
    sendStatusCode("250	    Requested mail action okay, completed");

    bzero(buf, TMP_LENGTH);
    recv(newSd, (char*)&buf, sizeof(buf), 0);
    writeToFile(buf, fname);
    cout << buf << "\n";

  } else {
    //sendStatusCode("500  Command not implemented");
  }

}

//Server side
int main(int argc, char *argv[])
{

  //for the server, we only need to specify a port number
  if (argc > 2) {
    cerr << "Usage: port" << endl;
    exit(0);
  }
  //grab the port number
  int port = argc == 2 ? atoi(argv[1]) : 25;

  //buffer to send and receive messages with
  char msg[1500];

#ifdef _WIN32
  WSADATA wsaData;
  auto err = WSAStartup(MAKEWORD(2, 2), &wsaData);

  if (err != 0) {
    printf("Error in  initializing.\nQuiting with error code: %d\n", WSAGetLastError());
    Sleep(5000);
    exit(WSAGetLastError());
  }

  SOCKADDR_IN servAddr;

  LPHOSTENT lpHost = gethostbyname("localhost");

  servAddr.sin_family = AF_INET;
  servAddr.sin_port   = htons(port);
  servAddr.sin_addr   = *(LPIN_ADDR)(lpHost->h_addr_list[0]);
#else
  //setup a socket and connection tools
  sockaddr_in servAddr;
  bzero((char*)&servAddr, sizeof(servAddr));
  servAddr.sin_family = AF_INET;
  servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servAddr.sin_port = htons(port);
#endif

  //open stream oriented socket with internet address
  //also keep track of the socket descriptor
  auto serverSd = socket(AF_INET, SOCK_STREAM, 0);
  if (serverSd < 0) {
    cerr << "Error establishing the server socket" << endl;
    exit(0);
  }
  //bind the socket to its local address
  int bindStatus = bind(serverSd, (struct sockaddr*) &servAddr,
    sizeof(servAddr));
  if (bindStatus < 0) {
    cerr << "Error binding socket to local address" << endl;
    exit(0);
  }
  cout << "Server listening on port " << port << "..." << endl;
listening:
  listen(serverSd, 5);
  //receive a request from client using accept
  //we need a new address to connect with the client
  sockaddr_in newSockAddr;
  auto newSockAddrSize = int(sizeof(newSockAddr));
  //accept, create a new socket descriptor to
  //handle the new connection with client
  newSd = accept(serverSd, (sockaddr *)&newSockAddr, &newSockAddrSize);
  if (newSd < 0) {
    cerr << "Error accepting request from client!" << endl;
    exit(1);
  }
  cout << "Connected with client" << endl;
  receiveFromClient();
  if (flag != 3370) {
    goto listening;
  }
  cout << "Connection closed..." << endl;
  return 0;
}

void receiveFromClient()
{

  char buf[TMP_LENGTH];
  char msg[TMP_LENGTH];

  while (1) {

    memset(&msg, 0, sizeof(msg));//clear the buffer
    int n = recv(newSd, (char*)&msg, sizeof(msg), 0);
    cout << "Client: " << msg << endl;
    cout << ">";
    if (strstr(msg, "QUIT") || strstr(msg, "quit")) {
      processQuit();
      break;
    } else
      checkClientMessage(msg);
  }
  /*
  //receiving MAIL FROM
  bzero(buf,TMP_LENGTH);
  recv(newSd, (char*)&buf, sizeof(buf), 0);
  cout<<buf <<"\n";
  checkClientMessage(buf);

  // RCPT TO
  bzero(buf,TMP_LENGTH);
  recv(newSd, (char*)&buf, sizeof(buf), 0);
  cout<<buf <<"\n";
  string duplicate = buf;
  cout<<duplicate<<"\n";
  checkClientMessage(buf);
  char* fname = extractName(duplicate.c_str());
  //char* fname = "nobody.txt";

  //DATA
  bzero(buf,TMP_LENGTH);
  recv(newSd, (char*)&buf, sizeof(buf), 0);
  cout<<buf <<"\n";
  checkClientMessage(buf);


  //header
  bzero(buf,TMP_LENGTH);
  recv(newSd, (char*)&buf, sizeof(buf), 0);
  writeToFile(buf, fname);
  cout<<buf <<"\n";

  //msg-body
  bzero(buf,TMP_LENGTH);
  recv(newSd, (char*)&buf, sizeof(buf), 0);
  cout<<buf <<"\n";
  writeToFile(buf, fname);
  sendStatusCode("250	    Requested mail action okay, completed");

  bzero(buf,TMP_LENGTH);
  recv(newSd, (char*)&buf, sizeof(buf), 0);
  writeToFile(buf, fname);
  cout<<buf <<"\n";

  //QUIT
  bzero(buf,TMP_LENGTH);
  recv(newSd, (char*)&buf, sizeof(buf), 0);
  cout<<buf <<"\n";
  checkClientMessage(buf);

  */

}

void writeToFile(char content[], char* target)
{
  ofstream outfile;
  outfile.open(target, std::ios_base::app);
  outfile << content << endl << endl;
}

char* extractName(const char* msg)
{
  char* msg2 = (char*)msg;
  strtok(msg2, ":");
  char* targetUserName = strtok(NULL, "@");
  strcat(targetUserName, ".txt");
  cout << targetUserName << endl;
  return targetUserName;
}

void processQuit()
{
  heloAccepted = false;
  fromAccepted = false;
  toAccepted = false;
  dataAccepted = false;


  sendStatusCode("221	  Service closing transmission channel");
  closeConnection();

}

void closeConnection()
{
#ifdef _WIN32
  closesocket(newSd);
#else
  close(newSd);
#endif
  flag = 1000;
  cout << "Done processing this client, closed connection" << "\n";
}