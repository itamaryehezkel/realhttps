#define DEBUG_LEVEL 0

#define TOKEN_DUMP if(DEBUG_LEVEL & 1)
#define TRACE_PARSER if(DEBUG_LEVEL & 2)
#define TRACE_AST if(DEBUG_LEVEL & 4)
#define VAR_DUMP if(DEBUG_LEVEL & 8)
#define TRACE_VARS if(DEBUG_LEVEL & 16)
#define DUMP_PATHS if(DEBUG_LEVEL & 32)
#define DUMP_SQL_GETTER if(DEBUG_LEVEL & 64)
#define TRACE_SYS_FILE_READ_CALLS if(DEBUG_LEVEL & 128)

#define HTTPS_PORT 443
#define HTTP_PORT 80
#define DEFAULT_DOMAIN "https://localhost"
#define BACKLOG 10

#define LIST_2D(...) (char *[]){__VA_ARGS__}

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
//#include "SSL.h"

void   https_start(char * bind_addr, int https_port, int http_port, char * domain);
void * handle_http(void *arg);

char * domain;
char * bind_addr;
int https_port;

int main(int argc, char *argv[]) {

    bind_addr = malloc(16*sizeof(char));
    domain = malloc(256*sizeof(char));
    strcpy(domain, DEFAULT_DOMAIN);
    https_port = HTTPS_PORT;
    strcpy(bind_addr, "0.0.0.0");
    
    for (int i = 1; i < argc; i++) { 
     // printf("arg %d: %s\n", i, argv[i]);
      if(argc - i >= 1)
        switch(argv[i][1]){
         case 'b':
          strcpy(bind_addr, argv[i+1]);
          i++;
          break;
         case 'p':
           https_port = atoi(argv[i+1]);
           i++;
           break;
         case 'd':
           memset(domain, '\0', 256*sizeof(char));
           strcpy(domain, argv[i+1]);
           i++;
           break;
         default:
          printf("ERROR: unknown parameter: %s\n", argv[i]);
          exit(1);
        }
      else
        printf("Invalid Parameters\n");
    }
    
    
    //bind_signal_handlers();
    //printf("Bind address (%s)\n", bind_addr);
    https_start(bind_addr, https_port, HTTP_PORT, domain);
  
    return 0;
}

void* handle_http(void *arg) {

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }


    struct sockaddr_in https;
    https.sin_family = AF_INET;
    https.sin_port = htons(80);
    https.sin_addr.s_addr = inet_addr(bind_addr); //INADDR_ANY;

    int reuse = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt failed");
        close(s);
        exit(EXIT_FAILURE);
    }

    if (listen(s, BACKLOG) < 0) {
        perror("Listen failed");
        close(s);
        exit(EXIT_FAILURE);
    }


  while (1) {
        struct sockaddr_storage addr;

        socklen_t addr_len = sizeof(addr);

        int client_fd = accept(s, (struct sockaddr*)&addr, &addr_len);
        if (client_fd < 0) {
            perror("accept failed");
            continue;
        }

        // Always redirect HTTP → HTTPS
        char *redirect = malloc(1024*(sizeof(char)));
        sprintf(redirect,"HTTP/1.1 301 Moved Permanently\r\nLocation: https://%s/\r\nConnection: close\r\n\r\n", domain);
         //sprintf(redirect, DOMAIN);
        send(client_fd, redirect, strlen(redirect), 0);
        close(client_fd);
    }

    return NULL;
}



void https_start(char * bind_addr, int https_port, int http_port, char * domain){
  printf("Starting HTTPS services: (%s:%d)\nHTTP listening on: %d\nHTTP redirection to: %s\n", bind_addr, https_port, http_port, domain);
}
 /* 
void https_start(){

    //load_program();

    //files = getAllFilePaths(HOME);

    
    DUMP_PATHS for (int i = 0; i < files.count; i++)
      fprintf(stdout,"\e[94m%s\e[0m\n", files.paths[i]);
    
    SSL_CTX *ctx = create_ssl_context();
    configure_ssl_context(ctx);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Socket creation failed");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(BIND_ADDR); //INADDR_ANY;

    int reuse = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt failed");
        close(s);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }


    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        close(s);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (listen(s, BACKLOG) < 0) {
        perror("Listen failed");
        close(s);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    fprintf(stdout,"\e[0;93mHTTPS Server is listening on \e[96m%s\e[97m:\e[92m%d\e[0m\n", BIND_ADDR, PORT);
    
       pthread_t thread;
    if (pthread_create(&thread, NULL, handle_http, NULL) != 0) {
      perror("Thread creation failed");
    } else {
      pthread_detach(thread);
    }

    while (1) {
        connection_t *connection = malloc(sizeof(connection_t));
        if (!connection) {
            perror("Memory allocation failed");
            continue;
        }

        socklen_t client_len = sizeof(connection->address);
        connection->sock = accept(s, (struct sockaddr *)&connection->address, &client_len);
        connection->ctx = ctx;

        if (connection->sock < 0) {
            perror("Accept failed");
            free(connection);
            continue;
        }

        // Spawn a new thread for handling the client
        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, connection) != 0) {
            perror("Thread creation failed");
            close(connection->sock);
            free(connection);
        } else {
            pthread_detach(thread); // Detach the thread to avoid memory leaks
        }
    }

    fprintf(stdout,"SERVER CRASHED\n");
    close(s);
    SSL_CTX_free(ctx);
    for (int i = 0; i < files.count; i++)
        free(files.paths[i]);
    free(files.paths);
   

} */
