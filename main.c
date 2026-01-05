#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ctype.h>


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
#define INET_ADDRSTRLEN 16
#define BUFFER_SIZE 8192
#define READ_TIMEOUT_SECS 3
#define READ_MAX_RETRIES 3


#define CERT_FILE "./certs/cert.pem"
#define KEY_FILE "./certs/key.pem"
#define MAX_URI_LENGTH 2048
#include "functions.h"



#define LIST_2D(...) (char *[]){__VA_ARGS__}





//SSL.h
SSL_CTX *create_ssl_context();
void configure_ssl_context(SSL_CTX *ctx);

void   https_start(char * bind_addr, int https_port, int http_port, char * domain);
void * handle_http(void *arg);
void * handle_https(void *arg);
void handle_traffic(Request * req);


char * domain;
char * bind_addr;
int https_port;

int main(int argc, char *argv[]) {

    bind_addr = malloc(16*sizeof(char));
    domain = malloc(256*sizeof(char));
    strcpy(domain, DEFAULT_DOMAIN);
    https_port = HTTPS_PORT;
    strcpy(bind_addr, "0.0.0.0");
    
    int arg = 0;
    
    for (int i = 1; i < argc && argv[i+1]; i++) { 
      printf("arg %d: %s %s\n", arg, argv[i], argv[i+1]);
      arg++;
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
    //HTTP P P P P P P P P P P P P P P P P P P P P P P P P P P P
    pthread_t thread;
    if (pthread_create(&thread, NULL, handle_http, NULL) != 0) {
      perror("Thread creation failed");
    } else {
      pthread_detach(thread);
    }
    
    //START HTTPS S S S S S S S S S S S S S S S S S S S  S
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
    https.sin_port = htons(HTTP_PORT);
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
        sprintf(redirect,"HTTP/1.1 301 Moved Permanently\r\nLocation: http://%s/\r\nConnection: close\r\n\r\n", domain);
         //sprintf(redirect, DOMAvoid * handle_https(void *arg)IN);
        send(client_fd, redirect, strlen(redirect), 0);
        close(client_fd);
    }

    return NULL;
}



/* ssl_write_all: writes full buffer, returns bytes written or -1 on fatal error */
int ssl_write_all(SSL *ssl, const char *buf, int len)
{
    if (!ssl || !buf || len <= 0)
        return -1;

    int total = 0;

    for (;;) {
        int remaining = len - total;
        if (remaining <= 0)
            return total;  // all bytes written

        int w = SSL_write(ssl, buf + total, remaining);

        if (w > 0) {
            total += w;
            continue;
        }

        int err = SSL_get_error(ssl, w);

        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            // Non-blocking retry
            continue;
        }

        if (err == SSL_ERROR_ZERO_RETURN) {
            // Peer performed clean shutdown
            return total;
        }

        if (err == SSL_ERROR_SYSCALL) {
            // Socket closed or syscall error
            return total > 0 ? total : -1;
        }

        // Fatal SSL error
        return -1;
    }
}


char * resp = "HTTP/1.1 200 OK\r\n\r\nHello";
// ---------------------------------------------------------------------------------------------------
int ssl_read_request(SSL *ssl, Request *req, int buffer_size)
{
    if (!ssl || !req || !req->buffer || buffer_size <= 0)
        return -1;

    req->buffer_size = buffer_size;
    req->total_read  = 0;

    for (;;) {
        int space = buffer_size - req->total_read;
        if (space <= 0)
            return req->total_read;

        int r = SSL_read(ssl, req->buffer + req->total_read, space);

        if (r > 0) {
            req->total_read += r;

            // NEW: detect end of headers
            if (req->total_read >= 4) {
                char *b = req->buffer;
                int n = req->total_read;

                if (b[n-4] == '\r' && b[n-3] == '\n' &&
                    b[n-2] == '\r' && b[n-1] == '\n') {

                    return req->total_read;
                }
            }

            continue;
        }

        int err = SSL_get_error(ssl, r);

        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {

            int fd = SSL_get_fd(ssl);
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);

            struct timeval tv;
            tv.tv_sec = READ_TIMEOUT_SECS;
            tv.tv_usec = 0;

            int sel = select(fd + 1, &rfds, NULL, NULL, &tv);

            if (sel <= 0) {
                return req->total_read > 0 ? req->total_read : -1;
            }

            continue;
        }

        if (err == SSL_ERROR_ZERO_RETURN)
            return req->total_read;

        if (err == SSL_ERROR_SYSCALL)
            return req->total_read > 0 ? req->total_read : -1;

        return -1;
    }
}



// ---------------------------------------------------------------------------------------------------


void *handle_https(void *arg) {
    connection_t *con = (connection_t *)arg;

    Request *req = malloc(sizeof(Request));
    if (!req) {
        // best-effort cleanup
        SSL_shutdown(con->ssl);
        SSL_free(con->ssl);
        close(con->sock);
        free(con);
        return NULL;
    }

    req->con = con;
    req->buffer = malloc(BUFFER_SIZE + 1);
    if (!req->buffer) {
        SSL_shutdown(con->ssl);
        SSL_free(con->ssl);
        close(con->sock);
        free(con);
        free(req);
        return NULL;
    }

    inet_ntop(AF_INET, &con->address.sin_addr, req->ip, INET_ADDRSTRLEN);
    

    int rr = ssl_read_request(con->ssl, req, BUFFER_SIZE);
    if (rr < 0) {
        fprintf(stderr, "ssl_read_request failed\n");
        SSL_shutdown(req->con->ssl);
        SSL_free(req->con->ssl);
        close(req->con->sock);

        free(req->buffer);
        free(req);
        free(req->con);
    }

    //printf("%s: %s\n", req->ip, req->buffer);
    handle_traffic(req);

    return NULL;
}






void https_start(char * bind_addr, int https_port, int http_port, char * domain){

    //load_program();

    //files = getAllFilePaths(HOME);

    
   /* DUMP_PATHS for (int i = 0; i < files.count; i++)
      fprintf(stdout,"\e[94m%s\e[0m\n", files.paths[i]);
    */
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
    addr.sin_port = htons(https_port);
    addr.sin_addr.s_addr = inet_addr(bind_addr); //INADDR_ANY;

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

    fprintf(stdout,"\e[0;93mHTTPS Server is listening on \e[96m%s\e[97m:\e[92m%d\e[0m\n", bind_addr, https_port);
    
    

    while (1) {
    connection_t *connection = malloc(sizeof(connection_t));
    if (!connection) {
        perror("Memory allocation failed1");
        continue;
    }

    socklen_t client_len = sizeof(connection->address);
    connection->sock = accept(s, (struct sockaddr *)&connection->address, &client_len);
    connection->ctx  = ctx;

    if (connection->sock < 0) {
        perror("Accept failed");
        free(connection);
        continue;
    }

    // --- NEW: create SSL object and do handshake ---
    connection->ssl = SSL_new(ctx);
    if (!connection->ssl) {
        ERR_print_errors_fp(stderr);
        close(connection->sock);
        free(connection);
        continue;
    }

    if (SSL_set_fd(connection->ssl, connection->sock) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(connection->ssl);
        close(connection->sock);
        free(connection);
        continue;
    }

    if (SSL_accept(connection->ssl) <= 0) {
        // Handshake failed
        ERR_print_errors_fp(stderr);
        SSL_shutdown(connection->ssl);
        SSL_free(connection->ssl);
        close(connection->sock);
        free(connection);
        continue;
    }
    // --- END NEW ---

    pthread_t thread;
    if (pthread_create(&thread, NULL, handle_https, connection) != 0) {
        perror("Thread creation failed");
        SSL_shutdown(connection->ssl);
        SSL_free(connection->ssl);
        close(connection->sock);
        free(connection);
    } else {
        pthread_detach(thread);
    }
}


    fprintf(stdout,"SERVER CRASHED\n");
    close(s);
    SSL_CTX_free(ctx);
    /*for (int i = 0; i < files.count; i++)
        free(files.paths[i]);
    free(files.paths);*/
   

} 





int detect_uri(Request * req){
  void * ptr =  memchr(req->buffer, ' ', MAX_URI_LENGTH);
  if (ptr != NULL) {
        // Calculate the position using pointer arithmetic
        int position = (int)((char*)ptr - req->buffer);
        req->uri = calloc(position+10, sizeof(char));
        
        strncpy(req->uri, req->buffer, position);
        if(strcmp(req->uri, "/") == 0 ){
          strcat(req->uri, "index.html");
        }
        if(strnstr(req->buffer, "..", position) != NULL)
          return 0;
        req->buffer += position+1;
        return position;
    } else {
      return 0;
    }
}
int detect_version(Request * req){
   void * ptr =  memchr(req->buffer, '\n', 15);
  if (ptr != NULL) {
        // Calculate the position using pointer arithmetic
        int position = (int)((char*)ptr - req->buffer);
        char * version = calloc(position+15, sizeof(char));
        
        strncpy(version, req->buffer, position);
        version[position] = '\0';
        if(strcmp("HTTP/1.1\r", version) != 0 || strcmp("HTTP/1.1", version) != 0 )
          return 0;
       
        req->buffer += position+1;
        return position;
    } else {
      return 0;
    }
}

// ================================================================================================================




void handle_traffic(Request *req) {
    char *buf = req->buffer;

    // ---- Parse request line ----
    if (!parse_request_line(req)) {
        goto finish;
    }

    // ---- Parse headers into map ----
    header_map *headers = parse_headers(req); 
    if (!headers) goto finish; // Example: read Host header 
    const char *host = header_map_get(headers, "Host"); 
    
  
    // Example: read Host header
    
    printf("%s: %s %s %s\n", req->ip, req_method_str(req), req->uri, host);

    // ---- Build response ----
    
    //TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT
    
      //run_itl(req);
    
    //IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII
    char *response_headers = calloc(BUFFER_SIZE, sizeof(char));
    char * folder = calloc(256, sizeof(char));
    strcpy(folder,"../");
    strcat(folder, host);
    FileInfo file = get_file(folder,req->uri);
    if (!file.data) {
        sprintf(response_headers,
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: 11\r\n"
                "Connection: close\r\n\r\n"
                "Not Found");
        ssl_write_all(req->con->ssl, response_headers, strlen(response_headers));
        goto finish;
    }

    sprintf(response_headers,
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %ld\r\n"
            "Connection: close\r\n\r\n",
            get_content_type(get_extension(req->uri)),
            file.size);

    ssl_write_all(req->con->ssl, response_headers, strlen(response_headers));
    ssl_write_all(req->con->ssl, file.data, file.size);

    free(file.data);
    free(response_headers);
    header_map_free(headers);
    free(headers);

finish:
    SSL_shutdown(req->con->ssl);
    SSL_free(req->con->ssl);
    close(req->con->sock);

    if (req->uri) free(req->uri);
    free(buf);
    free(req->con);
    free(req);
}
