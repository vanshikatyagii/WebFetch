#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <sys/select.h>
#include <fcntl.h>
#include <time.h>

#define PORT 8080
#define BUFFER_SIZE 4096
#define MAX_RESPONSE_SIZE (1024 * 1024)  // 1MB max response
#define MAX_URL_LENGTH 2048
#define MAX_HOST_LENGTH 256
#define MAX_PATH_LENGTH 1024
#define CONNECTION_TIMEOUT 30
#define MAX_THREADS 100

// Thread-safe counters
static volatile int active_threads = 0;
static pthread_mutex_t thread_count_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int shutdown_server = 0;

// Allowed domains whitelist (for security)
static const char* allowed_domains[] = {
    "httpbin.org",
    "jsonplaceholder.typicode.com",
    "api.github.com",
    "www.example.com",
    NULL  // Null-terminated list
};

typedef struct {
    int client_socket;
    struct sockaddr_in client_addr;
} client_data_t;

typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} response_buffer_t;

// Thread-safe logging
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void safe_log(const char *format, ...) {
    pthread_mutex_lock(&log_mutex);
    
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    printf("[%s] ", timestamp);
    
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    
    fflush(stdout);
    pthread_mutex_unlock(&log_mutex);
}

void print_ssl_error() {
    unsigned long err_code;
    while ((err_code = ERR_get_error())) {
        char *err_msg = ERR_error_string(err_code, NULL);
        safe_log("SSL error: %s\n", err_msg);
    }
}

int is_domain_allowed(const char *host) {
    if (!host) return 0;
    
    for (int i = 0; allowed_domains[i] != NULL; i++) {
        if (strcasecmp(host, allowed_domains[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

response_buffer_t* create_response_buffer() {
    response_buffer_t *buf = malloc(sizeof(response_buffer_t));
    if (!buf) return NULL;
    
    buf->capacity = BUFFER_SIZE;
    buf->data = malloc(buf->capacity);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    
    buf->size = 0;
    buf->data[0] = '\0';
    return buf;
}

void free_response_buffer(response_buffer_t *buf) {
    if (buf) {
        free(buf->data);
        free(buf);
    }
}

int append_to_response(response_buffer_t *buf, const char *data, size_t len) {
    if (!buf || !data || len == 0) return 0;
    
    // Check size limits
    if (buf->size + len + 1 > MAX_RESPONSE_SIZE) {
        safe_log("Response size limit exceeded\n");
        return 0;
    }
    
    // Resize buffer if needed
    if (buf->size + len + 1 > buf->capacity) {
        size_t new_capacity = buf->capacity * 2;
        while (new_capacity < buf->size + len + 1) {
            new_capacity *= 2;
        }
        
        char *new_data = realloc(buf->data, new_capacity);
        if (!new_data) {
            safe_log("Memory allocation failed\n");
            return 0;
        }
        
        buf->data = new_data;
        buf->capacity = new_capacity;
    }
    
    memcpy(buf->data + buf->size, data, len);
    buf->size += len;
    buf->data[buf->size] = '\0';
    
    return 1;
}

int set_socket_timeout(int sock, int timeout_sec) {
    struct timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;
    
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        return -1;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        return -1;
    }
    return 0;
}

int validate_and_parse_url(const char *url, char *host, char *path, int *port, int *use_ssl) {
    if (!url || !host || !path || !port || !use_ssl) {
        return 0;
    }
    
    // Initialize output parameters
    *use_ssl = 0;
    *port = 80;
    strcpy(path, "/");
    host[0] = '\0';
    
    // Check URL length
    if (strlen(url) >= MAX_URL_LENGTH) {
        safe_log("URL too long: %zu bytes\n", strlen(url));
        return 0;
    }
    
    // Parse HTTPS URLs
    if (strncmp(url, "https://", 8) == 0) {
        *use_ssl = 1;
        *port = 443;
        
        const char *url_part = url + 8;
        const char *path_start = strchr(url_part, '/');
        
        if (path_start) {
            size_t host_len = path_start - url_part;
            if (host_len >= MAX_HOST_LENGTH) {
                safe_log("Host name too long\n");
                return 0;
            }
            strncpy(host, url_part, host_len);
            host[host_len] = '\0';
            
            if (strlen(path_start) >= MAX_PATH_LENGTH) {
                safe_log("Path too long\n");
                return 0;
            }
            strcpy(path, path_start);
        } else {
            if (strlen(url_part) >= MAX_HOST_LENGTH) {
                safe_log("Host name too long\n");
                return 0;
            }
            strcpy(host, url_part);
        }
    }
    // Parse HTTP URLs
    else if (strncmp(url, "http://", 7) == 0) {
        const char *url_part = url + 7;
        const char *path_start = strchr(url_part, '/');
        
        if (path_start) {
            size_t host_len = path_start - url_part;
            if (host_len >= MAX_HOST_LENGTH) {
                safe_log("Host name too long\n");
                return 0;
            }
            strncpy(host, url_part, host_len);
            host[host_len] = '\0';
            
            if (strlen(path_start) >= MAX_PATH_LENGTH) {
                safe_log("Path too long\n");
                return 0;
            }
            strcpy(path, path_start);
        } else {
            if (strlen(url_part) >= MAX_HOST_LENGTH) {
                safe_log("Host name too long\n");
                return 0;
            }
            strcpy(host, url_part);
        }
    } else {
        safe_log("Unsupported URL scheme\n");
        return 0;
    }
    
    // Validate host name (basic checks)
    if (strlen(host) == 0) {
        safe_log("Empty host name\n");
        return 0;
    }
    
    // Check for malicious characters
    for (int i = 0; host[i]; i++) {
        if (host[i] < 32 || host[i] > 126) {
            safe_log("Invalid characters in host name\n");
            return 0;
        }
    }
    
    return 1;
}

int fetch_url_content(const char *url, response_buffer_t *response) {
    char host[MAX_HOST_LENGTH], path[MAX_PATH_LENGTH];
    int port, use_ssl;
    
    if (!validate_and_parse_url(url, host, path, &port, &use_ssl)) {
        append_to_response(response, "Error: Invalid URL format\n", 26);
        return 0;
    }
    
    // Security check: verify domain is allowed
    if (!is_domain_allowed(host)) {
        safe_log("Access denied for host: %s\n", host);
        append_to_response(response, "Error: Access denied for this domain\n", 37);
        return 0;
    }
    
    safe_log("Fetching %s from %s:%d (SSL: %s)\n", path, host, port, use_ssl ? "yes" : "no");
    
    // Resolve hostname
    struct hostent *server = gethostbyname(host);
    if (!server) {
        safe_log("Failed to resolve host: %s\n", host);
        char error_msg[512];
        snprintf(error_msg, sizeof(error_msg), "Error: Failed to resolve host '%s'\n", host);
        append_to_response(response, error_msg, strlen(error_msg));
        return 0;
    }
    
    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        safe_log("Failed to create socket: %s\n", strerror(errno));
        append_to_response(response, "Error: Failed to create socket\n", 31);
        return 0;
    }
    
    // Set socket timeout
    if (set_socket_timeout(sock, CONNECTION_TIMEOUT) < 0) {
        safe_log("Failed to set socket timeout\n");
    }
    
    // Setup server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    
    // Connect to server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        safe_log("Failed to connect to %s:%d - %s\n", host, port, strerror(errno));
        char error_msg[512];
        snprintf(error_msg, sizeof(error_msg), "Error: Failed to connect to host '%s'\n", host);
        append_to_response(response, error_msg, strlen(error_msg));
        close(sock);
        return 0;
    }
    
    // Prepare HTTP request
    char request[BUFFER_SIZE];
    int request_len = snprintf(request, sizeof(request),
                              "GET %s HTTP/1.1\r\n"
                              "Host: %s\r\n"
                              "User-Agent: SecureProxy/1.0\r\n"
                              "Connection: close\r\n"
                              "Accept: text/html,application/json,text/plain\r\n\r\n",
                              path, host);
    
    if (request_len >= sizeof(request)) {
        safe_log("Request too large\n");
        append_to_response(response, "Error: Request too large\n", 25);
        close(sock);
        return 0;
    }
    
    int success = 0;
    
    if (use_ssl) {
        // SSL connection
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            safe_log("Failed to create SSL context\n");
            append_to_response(response, "Error: Failed to create SSL context\n", 36);
            close(sock);
            return 0;
        }
        
        // Set SSL options for security
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); // For demo purposes
        
        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            safe_log("Failed to create SSL structure\n");
            append_to_response(response, "Error: Failed to create SSL structure\n", 37);
            SSL_CTX_free(ctx);
            close(sock);
            return 0;
        }
        
        SSL_set_fd(ssl, sock);
        
        if (SSL_connect(ssl) <= 0) {
            safe_log("Failed to establish SSL connection\n");
            print_ssl_error();
            append_to_response(response, "Error: Failed to establish SSL connection\n", 42);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sock);
            return 0;
        }
        
        // Send request
        int bytes_sent = SSL_write(ssl, request, request_len);
        if (bytes_sent <= 0) {
            safe_log("Failed to send SSL request\n");
            append_to_response(response, "Error: Failed to send request\n", 30);
        } else {
            // Read response
            char buffer[BUFFER_SIZE];
            int bytes_read;
            
            while ((bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
                if (!append_to_response(response, buffer, bytes_read)) {
                    safe_log("Response buffer full, truncating\n");
                    break;
                }
            }
            success = 1;
        }
        
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    } else {
        // Regular HTTP connection
        int bytes_sent = send(sock, request, request_len, 0);
        if (bytes_sent <= 0) {
            safe_log("Failed to send request: %s\n", strerror(errno));
            append_to_response(response, "Error: Failed to send request\n", 30);
        } else {
            // Read response
            char buffer[BUFFER_SIZE];
            int bytes_read;
            
            while ((bytes_read = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
                if (!append_to_response(response, buffer, bytes_read)) {
                    safe_log("Response buffer full, truncating\n");
                    break;
                }
            }
            success = 1;
        }
    }
    
    close(sock);
    return success;
}

void *handle_client(void *arg) {
    client_data_t *data = (client_data_t *)arg;
    int client_socket = data->client_socket;
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &data->client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    
    free(data);
    
    // Increment thread counter
    pthread_mutex_lock(&thread_count_mutex);
    active_threads++;
    pthread_mutex_unlock(&thread_count_mutex);
    
    safe_log("New connection from %s\n", client_ip);
    
    // Set socket timeout for client
    set_socket_timeout(client_socket, CONNECTION_TIMEOUT);
    
    char url_buffer[MAX_URL_LENGTH];
    memset(url_buffer, 0, sizeof(url_buffer));
    
    // Read URL from client with bounds checking
    int bytes_received = recv(client_socket, url_buffer, sizeof(url_buffer) - 1, 0);
    if (bytes_received <= 0) {
        safe_log("Failed to receive data from client %s: %s\n", client_ip, strerror(errno));
        close(client_socket);
        goto cleanup;
    }
    
    // Ensure null termination and remove newlines
    url_buffer[bytes_received] = '\0';
    char *newline = strchr(url_buffer, '\n');
    if (newline) *newline = '\0';
    newline = strchr(url_buffer, '\r');
    if (newline) *newline = '\0';
    
    safe_log("Client %s requested: %s\n", client_ip, url_buffer);
    
    // Create response buffer
    response_buffer_t *response = create_response_buffer();
    if (!response) {
        safe_log("Failed to create response buffer\n");
        const char *error_msg = "Error: Memory allocation failed\n";
        send(client_socket, error_msg, strlen(error_msg), 0);
        close(client_socket);
        goto cleanup;
    }
    
    // Fetch the URL
    fetch_url_content(url_buffer, response);
    
    // Send response to client
    size_t total_sent = 0;
    while (total_sent < response->size) {
        int bytes_sent = send(client_socket, response->data + total_sent, 
                             response->size - total_sent, 0);
        if (bytes_sent <= 0) {
            safe_log("Failed to send response to client %s: %s\n", client_ip, strerror(errno));
            break;
        }
        total_sent += bytes_sent;
    }
    
    safe_log("Sent %zu bytes to client %s\n", total_sent, client_ip);
    
    free_response_buffer(response);
    close(client_socket);
    
cleanup:
    // Decrement thread counter
    pthread_mutex_lock(&thread_count_mutex);
    active_threads--;
    pthread_mutex_unlock(&thread_count_mutex);
    
    safe_log("Connection closed for %s\n", client_ip);
    pthread_exit(NULL);
}

void signal_handler(int signum) {
    safe_log("Received signal %d, shutting down gracefully...\n", signum);
    shutdown_server = 1;
}

int main() {
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Create server socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // Allow socket reuse
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Setsockopt failed");
        exit(EXIT_FAILURE);
    }
    
    // Setup server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    
    // Bind socket
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }
    
    // Listen for connections
    if (listen(server_socket, 10) < 0) {
        perror("Listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }
    
    safe_log("Secure proxy server started on port %d\n", PORT);
    safe_log("Allowed domains: ");
    for (int i = 0; allowed_domains[i]; i++) {
        printf("%s%s", allowed_domains[i], allowed_domains[i+1] ? ", " : "\n");
    }
    
    // Main server loop
    while (!shutdown_server) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        // Accept connections
        int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            if (shutdown_server) break;
            perror("Accept failed");
            continue;
        }
        
        // Check thread limit
        pthread_mutex_lock(&thread_count_mutex);
        int current_threads = active_threads;
        pthread_mutex_unlock(&thread_count_mutex);
        
        if (current_threads >= MAX_THREADS) {
            safe_log("Maximum thread limit reached, rejecting connection\n");
            const char *error_msg = "Error: Server busy, try again later\n";
            send(client_socket, error_msg, strlen(error_msg), 0);
            close(client_socket);
            continue;
        }
        
        // Create client data structure
        client_data_t *data = malloc(sizeof(client_data_t));
        if (!data) {
            safe_log("Memory allocation failed for client data\n");
            const char *error_msg = "Error: Server memory allocation failed\n";
            send(client_socket, error_msg, strlen(error_msg), 0);
            close(client_socket);
            continue;
        }
        
        data->client_socket = client_socket;
        data->client_addr = client_addr;
        
        // Create thread to handle client
        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, data) != 0) {
            safe_log("Thread creation failed: %s\n", strerror(errno));
            free(data);
            close(client_socket);
            continue;
        }
        
        // Detach thread
        pthread_detach(thread);
    }
    
    safe_log("Server shutting down...\n");
    
    // Wait for active threads to finish
    while (1) {
        pthread_mutex_lock(&thread_count_mutex);
        int threads = active_threads;
        pthread_mutex_unlock(&thread_count_mutex);
        
        if (threads == 0) break;
        
        safe_log("Waiting for %d active threads to finish...\n", threads);
        sleep(1);
    }
    
    close(server_socket);
    
    // Cleanup OpenSSL
    EVP_cleanup();
    ERR_free_strings();
    
    safe_log("Server shutdown complete\n");
    return 0;
}
