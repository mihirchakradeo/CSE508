#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<stdlib.h>
#include<openssl/aes.h>
#include<openssl/rand.h>
#include<openssl/opensslconf.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<errno.h>
#include<pthread.h>
#include<netdb.h>

#define BUF_SIZE 4096

AES_KEY AESkey;
//######################COUNTER MODE RELATED#################################
//cite stackoverflow: https://stackoverflow.com/questions/3141860/aes-ctr-256-encryption-mode-of-operation-on-openssl
struct ctr_state {
    unsigned char ivec[AES_BLOCK_SIZE];  /* ivec[0..7] is the IV, ivec[8..15] is the big-endian counter */
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};

int init_ctr(struct ctr_state *state, const unsigned char iv[16])
{
    /* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
     * first call. */
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);

    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);

    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
}
//#####################COUNTER RELATED END###################################

//######################ENCRYPTION AND DECRYPTION############################

void encrypt(unsigned char *MBlock, unsigned char *CBlock, unsigned char* Key, unsigned char *iv, int len)
{
  struct ctr_state state;
  AES_set_encrypt_key((const unsigned char *) Key, 128, &AESkey);
  init_ctr(&state, iv);
  AES_ctr128_encrypt((const unsigned char *) MBlock, CBlock, len, &AESkey, state.ivec, state.ecount, &state.num);
  int i = 0;
}

void decrypt(unsigned char *testBuff, unsigned char *CBlock, unsigned char* Key, unsigned char *iv, int len)
{
  struct ctr_state state;
  int i;
  init_ctr(&state, iv);
  AES_set_encrypt_key((const unsigned char *) Key, 128, &AESkey);
  AES_ctr128_encrypt((const unsigned char *) CBlock, testBuff, len, &AESkey, state.ivec, state.ecount, &state.num);
}
//######################ENCRYPTION AND DECRYPTION END########################

void *serverThreadFunction(void *args);
void *clientReadThreadFunction(void *args);
void *clientWriteThreadFunction(void *args);
void *serverWriteThreadFunction(void *args);
void *serverReadThreadFunction(void *args);

//Structure for passing args to server thread function
struct threadInfo
{
  unsigned char *Key;
  unsigned char *destination;
  int destPort;
  int sockfd;
  int sockfd2;
};

//Structure for passing args to client read and write functions
struct clientInfo
{
  int sockfd;
  int sockfd2;
  unsigned char *Key;
};


//Reading key from file
//Cite: https://stackoverflow.com/questions/174531/easiest-way-to-get-files-contents-in-c
unsigned char *readKey(char *fileName)
{
  FILE *fp;
  unsigned char *Key = NULL;
  fp = fopen(fileName, "r");
  if(fp == NULL)
  {
    return NULL;
  }
  if(fp)
  {
    fseek(fp, 0, SEEK_END);
    int length = ftell (fp);
    fseek(fp, 0, SEEK_SET);
    Key = malloc (length);
    if(Key)
    {
      fread(Key, 1, length, fp);
    }
    fclose(fp);
  }
  return Key;
}


//Server code
//Cite: http://www.geeksforgeeks.org/socket-programming-cc/
void serverStart(unsigned char *Key, int portArg, unsigned char *destination, int destPort)
{

  int server_fd, new_socket, valread;
  struct sockaddr_in s_address, c_address;
  struct threadInfo *args = malloc(sizeof(struct threadInfo));
  int c_addr_len;
  int opt = 1;
  unsigned char buffer[BUF_SIZE] = {0};
  pthread_t tid;
  int pid;

  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
  {
      perror("socket failed");
      exit(EXIT_FAILURE);
  }

  s_address.sin_family = AF_INET;
  s_address.sin_addr.s_addr = INADDR_ANY;
  s_address.sin_port = htons(portArg);

  if (bind(server_fd, (struct sockaddr *)&s_address, sizeof(s_address))<0)
  {
      perror("bind failed");
      exit(EXIT_FAILURE);
  }

  if (listen(server_fd, 3) < 0)
  {
      perror("listen");
      exit(EXIT_FAILURE);
  }

  c_addr_len = sizeof(c_address);

  unsigned char recvBuff[BUF_SIZE] = {0};
  while(1)
  {
    new_socket = accept(server_fd, (struct sockaddr *)&c_address, (socklen_t*)&c_addr_len);
    if (new_socket < 0)
    {
      perror("accept error");
      close(server_fd);
      exit(EXIT_FAILURE);
    }

    //for passing values to thread
    args->Key = Key;
    args->destination = destination;
    args->destPort = destPort;
    args->sockfd = new_socket;

    int serverTheadReturn = pthread_create(&tid, NULL, serverThreadFunction, args);
    if(serverTheadReturn)
    {
      printf("pbproxy server thread error\n");
      exit(EXIT_FAILURE);
    }
  }

  pthread_join(tid, NULL);

  close(server_fd);
  close(new_socket);

  free(args);
}



//Client code

void clientStart(unsigned char *Key, unsigned char *destination, int destPort)
{

  int sockfd;
  struct sockaddr_in s_address;
  struct hostent *h;
  pthread_t readThread, writeThread;


  h = gethostbyname(destination);
  if(h == NULL)
  {
    fprintf(stderr, "Invalid Host\n");
  }

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
  {
      perror("socket failed");
      exit(EXIT_FAILURE);
  }

  s_address.sin_family = AF_INET;
  memcpy((unsigned char *)&s_address.sin_addr.s_addr, (unsigned char *)h->h_addr, h->h_length);
  s_address.sin_port = htons(destPort);

  if(connect(sockfd, (struct sockaddr *)&s_address, sizeof(s_address)) < 0)
  {
     printf("\n Error : Connection Failed \n");
     exit(EXIT_FAILURE);
  }

  int n;
  unsigned char recvBuff[BUF_SIZE] = {0};
  unsigned char sendBuff[BUF_SIZE] = {0};
  unsigned char CBlock[128];
  //Connection is now established to pbproxy

  struct clientInfo *args = malloc(sizeof(struct clientInfo));
  int readReturn, writeReturn;

  args->sockfd = sockfd;
  args->Key = Key;
  writeReturn = pthread_create(&writeThread, NULL, clientWriteThreadFunction, args);
  if(writeReturn)
  {
    printf("Read thread error");
    exit(EXIT_FAILURE);
  }

  readReturn = pthread_create(&readThread, NULL, clientReadThreadFunction, args);
  if(readReturn)
  {
    printf("Read thread error");
    exit(EXIT_FAILURE);
  }


  pthread_join(writeThread, NULL);
  pthread_join(readThread, NULL);
  close(sockfd);

}


//Client thread function to read the incoming data
void *clientWriteThreadFunction(void *args)
{
  struct clientInfo *args1 = args;
  int n;
  int sockfd = args1->sockfd;
  unsigned char *Key = args1->Key;

  //Send the IV first
  unsigned char iv[8];
  if (!RAND_bytes(iv, 8))
  {
    printf("Rand error\n");
  }
  n = write(sockfd, iv, 8);
  if(n <= 0)
  {
    printf("Error sending IV\n");
    close(sockfd);
    exit(0);
  }
  while(1)
  {
    unsigned char recvBuff[BUF_SIZE] = {0};
    unsigned char testBuff[BUF_SIZE] = {0};
    unsigned char CBlock[BUF_SIZE] = {0};
    while ((n = read(STDIN_FILENO, recvBuff, BUF_SIZE)) > 0) {
    //encrypt data

      encrypt(recvBuff, CBlock, Key, iv, n);
      //send encrypted data to pbproxy
      n = write(sockfd, CBlock, n);

      if(n <= 0)
      {
        printf("Error sending msg\n");
        close(sockfd);
        exit(0);
      }
    }

  }


}


void *clientReadThreadFunction(void *args)
{
  struct clientInfo *args1 = args;
  int sockfd = args1->sockfd;
  int n;
  unsigned char iv[8];

  //read incoming iv
  n = read(sockfd, iv, 8);
  if(n <= 0)
  {
    printf("Error reading iv\n");
    close(sockfd);
    exit(0);
  }
  while(1)
  {
    unsigned char recvBuff[BUF_SIZE] = {0};
    unsigned char plaintext[BUF_SIZE] = {0};
    while((n = read(sockfd, recvBuff, BUF_SIZE))>0){
    if(n <= 0)
    {
      printf("Error reading data\n");
      close(sockfd);
      exit(0);
    }

    decrypt(plaintext, recvBuff, args1->Key, iv, n);
    write(STDOUT_FILENO, plaintext, n);
    }
  }

}

//pbproxy server calls this function after creating a thread
void *serverThreadFunction(void *args)
{
    struct threadInfo *args1 = args;
    pthread_t serverReadThread, serverWriteThread;
    sleep(1);

    //Connect to destination and destPort as client
    //*****************************************************
    int sockfd;
    struct sockaddr_in s_address;
    struct hostent *h;
    h = gethostbyname(args1->destination);
    if(h == NULL)
    {
      fprintf(stderr, "Invalid Host\n");
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    s_address.sin_family = AF_INET;
    memcpy((unsigned char *)&s_address.sin_addr.s_addr, (unsigned char *)h->h_addr, h->h_length);
    s_address.sin_port = htons(args1->destPort);


    if(connect(sockfd, (struct sockaddr *)&s_address, sizeof(s_address)) < 0)
    {
       printf("\n Error : Connection Failed \n");
       exit(EXIT_FAILURE);
    }

    int n;
    unsigned char recvBuff[BUF_SIZE] = {0};

    //Connection is now established to dest server

    struct clientInfo *args2 = malloc(sizeof(struct clientInfo));
    args2->sockfd = sockfd;
    args2->sockfd2 = args1->sockfd;
    args2->Key = args1->Key;

    int writeReturn = pthread_create(&serverWriteThread, NULL, serverWriteThreadFunction, args2);
    if(writeReturn)
    {
      printf("Error creating readThread\n");
    }

    int readReturn = pthread_create(&serverReadThread, NULL, serverReadThreadFunction, args2);
    if(readReturn)
    {
      printf("Error creating readThread\n");
    }

    pthread_join(serverWriteThread, NULL);
    pthread_join(serverReadThread, NULL);
    return 0;

}

void *serverWriteThreadFunction(void *args)
{
  unsigned char iv[8];
  struct clientInfo *args1 = args;
  unsigned char *Key = args1->Key;
  //socket to sshd
  int sockfd = args1->sockfd;
  //socket to client
  int sockfd2 = args1->sockfd2;
  int n;
  //reading iv sent by client
  n = read(sockfd2, iv, 8);
  if(n <= 0)
  {
    printf("Error reading iv\n");
    close(sockfd2);
    close(sockfd);
    exit(0);
  }
  int i;
  while(1)
  {
    unsigned char recvBuff[BUF_SIZE] = {0};
    unsigned char plaintext[BUF_SIZE] = {0};
    while((n = read(sockfd2, recvBuff, BUF_SIZE)) > 0){
      if(n <= 0)
      {
        printf("Error reading encrypted data\n");
        close(sockfd2);
        close(sockfd);
        exit(0);
      }
      decrypt(plaintext, recvBuff, Key, iv, n);
      //write to sshd
      n = write(sockfd, plaintext, n);
      if(n <= 0)
      {
        printf("Error writing to sshd\n");
        close(sockfd);
        close(sockfd2);
        exit(0);
      }
    }
  }
}

void *serverReadThreadFunction(void *args)
{
  struct clientInfo *args1 = args;
  //socket to sshd
  int sockfd = args1->sockfd;
  //socket to client
  int sockfd2 = args1->sockfd2;
  int n;

  //send iv to client
  unsigned char iv[8];
  if (!RAND_bytes(iv, 8))
  {
    printf("Rand error\n");
  }
  n = write(sockfd2, iv, 8);
  if(n <= 0)
  {
    printf("Error sending IV\n");
    close(sockfd2);
    exit(0);
  }


  while(1)
  {
    unsigned char recvBuff[BUF_SIZE] = {0};
    unsigned char CBlock[BUF_SIZE] = {0};
    //read from sshd
    while((n = read(sockfd, recvBuff, BUF_SIZE)) > 0){

      //write to client
      encrypt(recvBuff, CBlock, args1->Key, iv, n);
      n = write(sockfd2, CBlock, n);
      if(n <= 0)
      {
        printf("Error writing to client\n");
        close(sockfd2);
        close(sockfd);
        exit(0);
      }
    }
  }
}


int main(int argc, char **argv) {

  char c;
  unsigned char *fileName = NULL;
  unsigned char *Key = malloc(16);
  unsigned char *destination;
  int portArg;
  int destPort;
  int serverFlag;

  //Parsing command line arguments
  while ((c = getopt(argc, argv, "l:k:")) != -1)
  {
    switch (c) {

      case 'l':
        portArg = atoi(optarg);
        serverFlag = 1;
        break;

      case 'k':
        fileName = malloc(sizeof(optarg));
        strcpy(fileName, optarg);
        Key = readKey(fileName);
        if(Key == NULL)
        {
          printf("File does not exist\n");
          exit(0);
        }
        break;

      case '?':
        if(optopt == 'l' || optopt == 'k')
        {
          fprintf(stderr, "Option -%c needs an argument\n", optopt);
        }
        else
        {
          fprintf(stderr, "Usage: pbproxy [-l port] -k keyfile destination port\n");
        }
        break;

      default:
  				fprintf(stderr, "Usage: pbproxy [-l port] -k keyfile destination port\n");
          exit(EXIT_FAILURE);
    }

  }

  //If dest and port not entered
  if(optind != argc-2)
  {
    printf("Invalid number of arguments\nUsage: pbproxy [-l port] -k keyfile destination port\n");
    exit(EXIT_FAILURE);
  }

  //reading destination and destPort (last argument)
  destination = argv[argc-2];
  destPort = atoi(argv[argc-1]);

  //check if server or client
  if(serverFlag == 1)
  {
    //Server reverse pbproxy
    serverStart(Key, portArg, destination, destPort);
  }

  //Client pbproxy
  else
  {
    clientStart(Key, destination, destPort);
  }

  return 0;
}
