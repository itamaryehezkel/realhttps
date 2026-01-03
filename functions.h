#ifndef SETTINGS_H
#define SETTINGS_H


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


// ----------------------
// Simple Hashmap for Headers
// ----------------------

#define HEADER_BUCKETS 64

typedef struct header_node {
    char *key;
    char *value;
    struct header_node *next;
} header_node;

typedef struct {
    header_node *buckets[HEADER_BUCKETS];
} header_map;

unsigned int hash_key(const char *key) {
    unsigned int h = 5381;
    while (*key)
        h = ((h << 5) + h) + tolower(*key++);
    return h % HEADER_BUCKETS;
}

void header_map_init(header_map *map) {
    memset(map->buckets, 0, sizeof(map->buckets));
}

void header_map_put(header_map *map, const char *key, const char *value) {
    unsigned int h = hash_key(key);

    header_node *node = malloc(sizeof(header_node));
    node->key = strdup(key);
    node->value = strdup(value);
    node->next = map->buckets[h];
    map->buckets[h] = node;
}

const char *header_map_get(header_map *map, const char *key) {
    unsigned int h = hash_key(key);
    header_node *node = map->buckets[h];

    while (node) {
        if (strcasecmp(node->key, key) == 0)
            return node->value;
        node = node->next;
    }
    return NULL;
}

void header_map_free(header_map *map) {
    for (int i = 0; i < HEADER_BUCKETS; i++) {
        header_node *node = map->buckets[i];
        while (node) {
            header_node *next = node->next;
            free(node->key);
            free(node->value);
            free(node);
            node = next;
        }
    }
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


FileInfo get_file(const char* from, const char* filename) {
    FileInfo result;
    result.data = NULL;
    result.size = 0;
    char path[1024];
    strcpy(path, from);
    strcat(path, filename);
     printf("%s\n", path);
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
        perror("Memory allocation failed2");
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


const char *get_extension(const char *uri) {
    if (!uri)
        return NULL;

    const char *filename = uri;
    const char *slash = strrchr(uri, '/');

    if (slash && *(slash + 1) != '\0')
        filename = slash + 1;

    const char *dot = strrchr(filename, '.');

    if (!dot || dot == filename)
        return NULL;

    return dot + 1;
}

const char *get_content_type(const char *ext) {
    if (!ext)
        return "application/octet-stream";

    // normalize to lowercase for comparison
    char lower[32];
    size_t i = 0;
    for (; ext[i] && i < sizeof(lower) - 1; i++)
        lower[i] = tolower((unsigned char)ext[i]);
    lower[i] = '\0';

    // common MIME types (HTTP standard + widely used)
    if (strcmp(lower, "html") == 0 || strcmp(lower, "htm") == 0)
        return "text/html";
    if (strcmp(lower, "css") == 0)
        return "text/css";
    if (strcmp(lower, "js") == 0)
        return "application/javascript";
    if (strcmp(lower, "json") == 0)
        return "application/json";
    if (strcmp(lower, "txt") == 0)
        return "text/plain";
    if (strcmp(lower, "xml") == 0)
        return "application/xml";

    // images
    if (strcmp(lower, "jpg") == 0 || strcmp(lower, "jpeg") == 0)
        return "image/jpeg";
    if (strcmp(lower, "png") == 0)
        return "image/png";
    if (strcmp(lower, "gif") == 0)
        return "image/gif";
    if (strcmp(lower, "svg") == 0)
        return "image/svg+xml";
    if (strcmp(lower, "webp") == 0)
        return "image/webp";

    // fonts
    if (strcmp(lower, "woff") == 0)
        return "font/woff";
    if (strcmp(lower, "woff2") == 0)
        return "font/woff2";
    if (strcmp(lower, "ttf") == 0)
        return "font/ttf";
    if (strcmp(lower, "otf") == 0)
        return "font/otf";

    // binary / downloads
    if (strcmp(lower, "pdf") == 0)
        return "application/pdf";
    if (strcmp(lower, "zip") == 0)
        return "application/zip";

    // default fallback (RFC 2046)
    return "application/octet-stream";
}
int parse_request_line(Request *req) {
    char *buf = req->buffer;

    // Find end of request line
    char *end = strstr(buf, "\r\n");
    if (!end)
        return 0;

    int line_len = end - buf;
    if (line_len <= 0 || line_len >= 2048)
        return 0;

    // Copy request line into a safe local buffer
    char line[2048];
    memcpy(line, buf, line_len);
    line[line_len] = '\0';

    // METHOD URI VERSION
    char method[16], uri[1024], version[16];

    if (sscanf(line, "%15s %1023s %15s", method, uri, version) != 3)
        return 0;

    // Parse method
    if      (!strcasecmp(method, "GET"))    req->method = M_GET;
    else if (!strcasecmp(method, "POST"))   req->method = M_POST;
    else if (!strcasecmp(method, "PUT"))    req->method = M_PUT;
    else if (!strcasecmp(method, "DELETE")) req->method = M_DELETE;
    else if (!strcasecmp(method, "PATCH"))  req->method = M_PATCH;
    else if (!strcasecmp(method, "HEAD"))   req->method = M_HEAD;
    else if (!strcasecmp(method, "OPTIONS"))req->method = M_OPTIONS;
    else req->method = M_UNSUPPORTED;

    // Normalize URI
    if (strcmp(uri, "/") == 0)
        strcpy(uri, "/index.html");

    req->uri = strdup(uri);
    if (!req->uri)
        return 0;

    // Validate version
    if (strcmp(version, "HTTP/1.1") != 0)
        return 0;

    // Advance buffer to start of headers
    req->buffer = end + 2;

    return 1;
}
header_map *parse_headers(Request *req) {
    if (!req || !req->buffer)
        return NULL;

    header_map *map = malloc(sizeof(header_map));
    if (!map)
        return NULL;

    header_map_init(map);

    char *p = req->buffer;

    while (1) {
        char *end = strstr(p, "\r\n");
        if (!end) {
            header_map_free(map);
            free(map);
            return NULL;
        }

        int len = end - p;

        // blank line = end of headers
        if (len == 0) {
            req->buffer = end + 2;   // move pointer to body
            return map;
        }

        if (len >= 2048) {
            header_map_free(map);
            free(map);
            return NULL;
        }

        char line[2048];
        memcpy(line, p, len);
        line[len] = '\0';

        char *colon = strchr(line, ':');
        if (!colon) {
            header_map_free(map);
            free(map);
            return NULL;
        }

        *colon = '\0';
        char *key = line;
        char *value = colon + 1;

        while (*value == ' ') value++;

        header_map_put(map, key, value);

        p = end + 2;
    }
}




#endif
