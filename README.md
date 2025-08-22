# Secure HTTP/HTTPS Proxy Server

A secure proxy server implementation in C with corresponding client, featuring domain whitelisting, SSL/TLS support, and comprehensive security measures.

## Features

- **Security**: Domain whitelist to prevent abuse
- **SSL/TLS Support**: Handles both HTTP and HTTPS requests
- **Thread Safety**: Multi-threaded with proper synchronization
- **Memory Management**: Dynamic buffers with overflow protection
- **Error Handling**: Comprehensive error checking and logging

## Files

- `sever_side.c` - The main proxy server implementation
- `client_side.c` - Client application to test the proxy
- `README.md` - This documentation

## Compilation

### Proxy Server
```bash
gcc -o secure_proxy secure_proxy.c -lssl -lcrypto -lpthread

###Client 
```bash
gcc -o proxy_client proxy_client.c



