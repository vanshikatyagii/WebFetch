#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>

#define PROXY_HOST "127.0.0.1"  // Proxy server address
#define PROXY_PORT 8080         // Proxy server port
#define BUFFER_SIZE 4096
#define MAX_URL_LENGTH 2048
#define MAX_RESPONSE_SIZE (10 * 1024 * 1024)  // 10MB max response

// Structure to hold response data
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} response_buffer_t;

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
        printf("Warning: Response size limit exceeded, truncating\n");
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
            printf("Error: Memory allocation failed\n");
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

int validate_url(const char *url) {
    if (!url || strlen(url) == 0) {
        printf("Error: Empty URL\n");
        return 0;
    }
    
    if (strlen(url) >= MAX_URL_LENGTH) {
        printf("Error: URL too long (max %d characters)\n", MAX_URL_LENGTH);
        return 0;
    }
    
    // Check if URL starts with http:// or https://
    if (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0) {
        printf("Error: URL must start with http:// or https://\n");
        return 0;
    }
    
    // Basic character validation
    for (int i = 0; url[i]; i++) {
        if (url[i] < 32 || url[i] > 126) {
            printf("Error: Invalid characters in URL\n");
            return 0;
        }
    }
    
    return 1;
}

int connect_to_proxy() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("Error: Failed to create socket: %s\n", strerror(errno));
        return -1;
    }
    
    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = 30;  // 30 second timeout
    timeout.tv_usec = 0;
    
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        printf("Warning: Failed to set receive timeout\n");
    }
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        printf("Warning: Failed to set send timeout\n");
    }
    
    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(PROXY_PORT);
    
    // Convert IP address
    if (inet_pton(AF_INET, PROXY_HOST, &proxy_addr.sin_addr) <= 0) {
        printf("Error: Invalid proxy address\n");
        close(sock);
        return -1;
    }
    
    // Connect to proxy server
    if (connect(sock, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) {
        printf("Error: Failed to connect to proxy server at %s:%d: %s\n", 
               PROXY_HOST, PROXY_PORT, strerror(errno));
        printf("Make sure the proxy server is running!\n");
        close(sock);
        return -1;
    }
    
    printf("Connected to proxy server at %s:%d\n", PROXY_HOST, PROXY_PORT);
    return sock;
}

int fetch_via_proxy(const char *url, response_buffer_t *response) {
    int sock = connect_to_proxy();
    if (sock < 0) {
        return 0;
    }
    
    printf("Sending URL to proxy: %s\n", url);
    
    // Send URL to proxy server
    int bytes_sent = send(sock, url, strlen(url), 0);
    if (bytes_sent <= 0) {
        printf("Error: Failed to send URL to proxy: %s\n", strerror(errno));
        close(sock);
        return 0;
    }
    
    printf("Waiting for response from proxy...\n");
    
    // Receive response from proxy
    char buffer[BUFFER_SIZE];
    int total_bytes = 0;
    int bytes_received;
    
    while ((bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        if (!append_to_response(response, buffer, bytes_received)) {
            printf("Warning: Response truncated due to size limit\n");
            break;
        }
        total_bytes += bytes_received;
        printf("Received %d bytes (total: %d bytes)\r", bytes_received, total_bytes);
        fflush(stdout);
    }
    
    printf("\nTotal bytes received: %d\n", total_bytes);
    
    if (bytes_received < 0) {
        printf("Error: Failed to receive data from proxy: %s\n", strerror(errno));
        close(sock);
        return 0;
    }
    
    close(sock);
    return 1;
}

char* extract_html_content(const response_buffer_t *response, size_t *content_length) {
    if (!response || !response->data || response->size == 0) {
        *content_length = 0;
        return NULL;
    }
    
    // Look for the end of HTTP headers (double CRLF)
    char *header_end = strstr(response->data, "\r\n\r\n");
    if (!header_end) {
        // Try with just LF (some servers might use this)
        header_end = strstr(response->data, "\n\n");
        if (!header_end) {
            printf("Warning: Could not find end of HTTP headers, saving full response\n");
            *content_length = response->size;
            char *content = malloc(response->size + 1);
            if (content) {
                memcpy(content, response->data, response->size);
                content[response->size] = '\0';
            }
            return content;
        }
        header_end += 2; // Skip the \n\n
    } else {
        header_end += 4; // Skip the \r\n\r\n
    }
    
    // Calculate content length
    *content_length = response->size - (header_end - response->data);
    
    if (*content_length <= 0) {
        printf("Warning: No content found after HTTP headers\n");
        *content_length = 0;
        return NULL;
    }
    
    // Allocate memory for content
    char *content = malloc(*content_length + 1);
    if (!content) {
        printf("Error: Failed to allocate memory for content\n");
        *content_length = 0;
        return NULL;
    }
    
    // Copy content
    memcpy(content, header_end, *content_length);
    content[*content_length] = '\0';
    
    return content;
}

int save_html_to_file(const response_buffer_t *response, const char *filename) {
    size_t content_length;
    char *html_content = extract_html_content(response, &content_length);
    
    if (!html_content || content_length == 0) {
        printf("Error: No HTML content to save\n");
        return 0;
    }
    
    FILE *output_file = fopen(filename, "w");  // Use text mode for HTML
    if (!output_file) {
        printf("Error: Could not open file '%s' for writing: %s\n", 
               filename, strerror(errno));
        free(html_content);
        return 0;
    }
    
    size_t bytes_written = fwrite(html_content, 1, content_length, output_file);
    fclose(output_file);
    free(html_content);
    
    if (bytes_written != content_length) {
        printf("Error: Failed to write complete HTML content to file\n");
        return 0;
    }
    
    printf("Successfully saved HTML content (%zu bytes) to '%s'\n", bytes_written, filename);
    return 1;
}

void print_response_info(const response_buffer_t *response) {
    if (!response || response->size == 0) {
        printf("No response data received\n");
        return;
    }
    
    printf("\n=== Response Information ===\n");
    printf("Total response size: %zu bytes\n", response->size);
    
    // Extract and show HTTP status
    char *status_line_end = strstr(response->data, "\r\n");
    if (!status_line_end) {
        status_line_end = strstr(response->data, "\n");
    }
    
    if (status_line_end) {
        size_t status_len = status_line_end - response->data;
        if (status_len < 100) {  // Reasonable status line length
            printf("Status: %.*s\n", (int)status_len, response->data);
        }
    }
    
    // Extract content size
    size_t content_length;
    char *html_content = extract_html_content(response, &content_length);
    if (html_content) {
        printf("HTML content size: %zu bytes\n", content_length);
        
        // Detect content type
        if (strstr(html_content, "<html") || strstr(html_content, "<HTML") || 
            strstr(html_content, "<!DOCTYPE html") || strstr(html_content, "<!doctype html")) {
            printf("Content type: HTML document\n");
        } else if (strstr(html_content, "{") && strstr(html_content, "}")) {
            printf("Content type: JSON data\n");
        } else if (strstr(html_content, "<") && strstr(html_content, ">")) {
            printf("Content type: XML/HTML content\n");
        } else {
            printf("Content type: Plain text\n");
        }
        
        free(html_content);
    } else {
        printf("HTML content size: 0 bytes\n");
        printf("Content type: No content found\n");
    }
    
    printf("============================\n\n");
}

void show_help() {
    printf("Proxy Client - Fetch URLs through the secure proxy server\n\n");
    printf("Supported domains (as configured in proxy server):\n");
    printf("  - httpbin.org\n");
    printf("  - jsonplaceholder.typicode.com\n");
    printf("  - api.github.com\n");
    printf("  - www.example.com\n\n");
    printf("Example URLs:\n");
    printf("  https://httpbin.org/get\n");
    printf("  https://jsonplaceholder.typicode.com/posts/1\n");
    printf("  http://www.example.com\n\n");
}

int main() {
    char input_url[MAX_URL_LENGTH];
    char output_filename[256] = "output.html";
    
    printf("=== Secure Proxy Client ===\n\n");
    show_help();
    
    // Get URL from user
    printf("Enter the URL (http:// or https://): ");
    if (!fgets(input_url, sizeof(input_url), stdin)) {
        printf("Error: Failed to read input\n");
        return 1;
    }
    
    // Remove trailing newline
    input_url[strcspn(input_url, "\n")] = '\0';
    
    // Validate URL
    if (!validate_url(input_url)) {
        return 1;
    }
    
    // Ask for output filename
    printf("Enter output filename (default: %s): ", output_filename);
    char filename_input[256];
    if (fgets(filename_input, sizeof(filename_input), stdin)) {
        filename_input[strcspn(filename_input, "\n")] = '\0';
        if (strlen(filename_input) > 0) {
            strncpy(output_filename, filename_input, sizeof(output_filename) - 1);
            output_filename[sizeof(output_filename) - 1] = '\0';
        }
    }
    
    // Create response buffer
    response_buffer_t *response = create_response_buffer();
    if (!response) {
        printf("Error: Failed to allocate response buffer\n");
        return 1;
    }
    
    printf("\n=== Fetching URL via Proxy ===\n");
    
    // Fetch URL through proxy
    if (!fetch_via_proxy(input_url, response)) {
        printf("Failed to fetch URL through proxy\n");
        free_response_buffer(response);
        return 1;
    }
    
    // Print response information
    print_response_info(response);
    
    // Save HTML content to file
    if (!save_html_to_file(response, output_filename)) {
        printf("Failed to save HTML content to file\n");
        free_response_buffer(response);
        return 1;
    }
    
    printf("Operation completed successfully!\n");
    
    // Cleanup
    free_response_buffer(response);
    return 0;
}
