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

typedef enum {
    M_OPTIONS,
    M_DELETE,
    M_CONNECT,
    M_GET,
    M_PUT,
    M_PATCH,
    M_TRACE,
    M_HEAD,
    M_POST,
    M_UNSUPPORTED
} Method;

typedef struct {
    int sock;
    SSL_CTX *ctx;
    SSL *ssl;
    struct sockaddr_in address;
} connection_t;


typedef struct {
    connection_t *con;
    Method method;
    char ip[INET_ADDRSTRLEN];

    /* buffer holding request-line + headers + body (no copies) */
    char *buffer;
    int buffer_size;
    int total_read;

    /* request-line parts */
    int reqline_start; /* always 0 */
    int reqline_len;

    /* version */
    int version_start;
    int version_len;

    /* URI */
    char * uri;
    char * query; /* 0 if no query */

    /* headers block */
    int headers_start;
    int headers_len; /* includes final CRLFCRLF */

    /* body */
    int body_start;
    int body_len;
    char * host;

} Request;

typedef struct {
    size_t size;
    char *data;
} FileInfo;

const char *req_method_str(const Request *req) {
    if (!req) return "UNSUPPORTED";
    switch (req->method) {
        case M_GET: return "GET";
        case M_POST: return "POST";
        case M_PUT: return "PUT";
        case M_DELETE: return "DELETE";
        case M_PATCH: return "PATCH";
        case M_OPTIONS: return "OPTIONS";
        case M_CONNECT: return "CONNECT";
        case M_TRACE: return "TRACE";
        case M_HEAD: return "HEAD";
        default: return "UNSUPPORTED";
    }
}

// Detect HTTP method from req->buffer
void detect_method(Request *req) {
    char *p = req->buffer;   // working pointer

    switch (*p) {

        case 'O': case 'o':
            if (strncasecmp(p, "OPTIONS ", 8) == 0) {
                req->method = M_OPTIONS;
                p += 8;  // skip "OPTIONS "
            } else req->method = M_UNSUPPORTED;
            break;

        case 'D': case 'd':
            if (strncasecmp(p, "DELETE ", 7) == 0) {
                req->method = M_DELETE;
                p += 7;  // skip "DELETE "
            } else req->method = M_UNSUPPORTED;
            break;

        case 'C': case 'c':
            if (strncasecmp(p, "CONNECT ", 8) == 0) {
                req->method = M_CONNECT;
                p += 8;  // skip "CONNECT "
            } else req->method = M_UNSUPPORTED;
            break;

        case 'G': case 'g':
            if (strncasecmp(p, "GET ", 4) == 0) {
                req->method = M_GET;
                p += 4;  // skip "GET "
            } else req->method = M_UNSUPPORTED;
            break;

        case 'P': case 'p':
            if (strncasecmp(p, "PUT ", 4) == 0) {
                req->method = M_PUT;
                p += 4;
            }
            else if (strncasecmp(p, "PATCH ", 6) == 0) {
                req->method = M_PATCH;
                p += 6;
            }
            else if (strncasecmp(p, "POST ", 5) == 0) {
                req->method = M_POST;
                p += 5;
            }
            else req->method = M_UNSUPPORTED;
            break;

        case 'T': case 't':
            if (strncasecmp(p, "TRACE ", 6) == 0) {
                req->method = M_TRACE;
                p += 6;
            } else req->method = M_UNSUPPORTED;
            break;

        case 'H': case 'h':
            if (strncasecmp(p, "HEAD ", 5) == 0) {
                req->method = M_HEAD;
                p += 5;
            } else req->method = M_UNSUPPORTED;
            break;

        default:
            req->method = M_UNSUPPORTED;
            break;
    }

    // Advance req->buffer to the start of the URI
    req->buffer = p;
}


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
        SSL_shutdown(con->ssl);
        SSL_free(con->ssl);
        close(con->sock);

        free(req->buffer);
        free(req);
        free(con);
    }

    //printf("%s: %s\n", req->ip, req->buffer);
    handle_traffic(req);

    return NULL;
}

//char * resp2 = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHello";



   
    // --- begin: read+parse request (place after SSL_set_fd and SSL_accept) --- 
/*
int rr = ssl_read_request(req->con->ssl, req, BUFFER_SIZE);
if (rr < 0) {
    // fatal read error: terminate and return 
    fprintf(stderr, "ssl_read_request failed\n");
  //  terminate_con(req);
    return NULL;
}
if (rr == 0) {
    // peer closed without sending data 
    fprintf(stderr, "Client closed during read\n");
    terminate_con(req);
    return NULL;
}

   //At this point ssl_read_request populated:
   //req->total_read, req->reqline_len, req->headers_start, req->headers_len,
   //req->body_start, req->body_len
   //Now populate method, uri, version offsets as done in the merged example.


// Parse request-line fields (METHOD SP URI SP VERSION\r\n) 
//int rl_end = req->reqline_len;             /* index of '\r' in first CRLF 
if (rl_end <= 0 || rl_end >= req->total_read) {
    fprintf(stderr, "invalid request-line length\n");
    terminate_con(req);
    return NULL;
}

// find method end (space) 
int p = 0;
while (p < rl_end && req->buffer[p] != ' ') p++;
if (p >= rl_end) {
    fprintf(stderr, "malformed request-line (no space after method)\n");
    terminate_con(req);
    return NULL;
}

// set URI start (after method + space) 
int uri_s = p + 1;
int uri_e = uri_s;
int saw_q = 0;
int qlen = 0;

// scan URI until space 
while (uri_e < rl_end && req->buffer[uri_e] != ' ') {
    if (!saw_q && req->buffer[uri_e] == '?') {
        req->uri_len = uri_e - uri_s; // length of path before ? 
        saw_q = 1;
        uri_e++; // continue to count query chars 
        continue;
    }
    if (saw_q) qlen++;
    uri_e++;
}
if (!saw_q) req->uri_len = uri_e - uri_s;
req->uri_start = uri_s;
req->uri_query_len = qlen;

// version starts after the space following URI 
if (uri_e >= rl_end) {
    fprintf(stderr, "malformed request-line (no space before version)\n");
    terminate_con(req);
    return NULL;
}
int version_s = uri_e + 1;
int version_len = rl_end - version_s;
if (version_len < 0) version_len = 0;
req->version_start = version_s;
req->version_len = version_len;

// Set request-line fields (reqline_start is 0) 
req->reqline_start = 0;
req->reqline_len = rl_end;

// Determine Method enum (fast match against known methods) 
req->method = M_UNSUPPORTED;
if (p == 3 && (match_token(req->buffer, req->reqline_len, 0, "GET"))) req->method = M_GET;
else if (p == 4 && (match_token(req->buffer, req->reqline_len, 0, "POST"))) req->method = M_POST;
else if (p == 3 && (match_token(req->buffer, req->reqline_len, 0, "PUT"))) req->method = M_PUT;
else if (p == 6 && (match_token(req->buffer, req->reqline_len, 0, "DELETE"))) req->method = M_DELETE;
else if (p == 5 && (match_token(req->buffer, req->reqline_len, 0, "PATCH"))) req->method = M_PATCH;
else if (p == 7 && (match_token(req->buffer, req->reqline_len, 0, "OPTIONS"))) req->method = M_OPTIONS;
else if (p == 7 && (match_token(req->buffer, req->reqline_len, 0, "CONNECT"))) req->method = M_CONNECT;
else if (p == 5 && (match_token(req->buffer, req->reqline_len, 0, "TRACE"))) req->method = M_TRACE;
else if (p == 4 && (match_token(req->buffer, req->reqline_len, 0, "HEAD"))) req->method = M_HEAD;

// Sanity checks 
if (req->uri_len < 0 || req->uri_len > MAX_URI_LENGTH || req->uri_query_len > MAX_URI_LENGTH) {
    //send_error(req, 414);
    // send_error will call terminate_con(req)
    return NULL;
}

*/





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
        perror("Memory allocation failed");
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




SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    // After creating SSL_CTX
    SSL_CTX_set_alpn_protos(ctx, (const unsigned char *)"\x08http/1.1", 9); // length-prefixed "http/1.1"

// Also disable NPN if enabled.
// Ensure you are NOT setting ALPN to include "h2".

    if (!ctx) {
        perror("Failed to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Enable session caching for better performance
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
    return ctx;
}

void configure_ssl_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        perror("Failed to load certificate file");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        perror("Failed to load private key file");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
}

char *strnstr(const char *haystack, const char *needle, size_t len) { size_t needle_len = strlen(needle); if (needle_len == 0) return (char *)haystack; for (size_t i = 0; i + needle_len <= len; i++) { if (haystack[i] == needle[0] && memcmp(haystack + i, needle, needle_len) == 0) { return (char *)(haystack + i); } } return NULL; }

int detect_uri(Request * req){
  void * ptr =  memchr(req->buffer, ' ', MAX_URI_LENGTH);
  if (ptr != NULL) {
        // Calculate the position using pointer arithmetic
        int position = (int)((char*)ptr - req->buffer);
        req->uri = calloc(position+1, sizeof(char));
        strncpy(req->uri, req->buffer, position);  
        if(strnstr(req->buffer, "..", position) != NULL)
          return 0;
        req->buffer += position+1;
        return position;
    } else {
      return 0;
    }
}
int detect_version(Request * req){
  
}

// ================================================================================================================

FileInfo get_file(const char* filename) {
    FileInfo result;
    result.data = NULL;
    result.size = 0;
    char path[1024];
    strcpy(path, "../www/");
    strcat(path, filename);
    // printf("%s\n", path);
    FILE* file = fopen(path, "r");
    if (!file) {
        perror("Failed to open file");
        return result;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        perror("fseek failed");
        fclose(file);
        return result;
    }

    long size = ftell(file);
    if (size < 0) {
        perror("ftell failed");
        fclose(file);
        return result;
    }
    rewind(file);

    unsigned char* buffer = (unsigned char*)calloc(size/sizeof(unsigned char), sizeof(unsigned char));
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(file);
        return result;
    }

    size_t read = fread(buffer, 1, size, file);
    fclose(file);

    if (read != (size_t)size) {
        fprintf(stderr, "Only read %zu of %ld bytes\n", read, size);
        free(buffer);
        return result;
    }

    result.data = buffer;
    result.size = read;
    //itlc = result;
    return result;
}


void handle_traffic(Request * req){
  //printf("%s\n", req->buffer);
  char * buf = req->buffer;
  detect_method(req);
  int pos = detect_uri(req);
  if(!pos)
    goto finish;
    
  detect_version(req);
  
  printf("%s: %s %s\n", req->ip, req_method_str(req), req->uri);
  
  char * headers = calloc(BUFFER_SIZE, sizeof(char));
  
  FileInfo file = get_file(req->uri);
  if(file.data == NULL){
      sprintf(headers, "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %ld\r\nConnection: close\r\n\r\nNot Found", "404 Not Found", "text/html", 11);
      goto finish;
  }else
    sprintf(headers, "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %ld\r\nConnection: close\r\n\r\n", "200 OK", "text/html", file.size);
  ssl_write_all(req->con->ssl, headers, strlen(headers));
  
  //char * body = calloc(BUFFER_SIZE, sizeof(char));
  //strcpy(body, "Hello World");
  ssl_write_all(req->con->ssl, file.data, file.size);

finish:
  SSL_shutdown(req->con->ssl);
  SSL_free(req->con->ssl);
  close(req->con->sock);

  free(buf);
  free(req->con);
  free(req);
}
