#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <unistd.h>

#define KEY_SIZE 32  // AES-256 key size
#define BLOCK_SIZE 16
#define BUFFER_SIZE 1024
#define TRANSFER_PORT 5512

unsigned char key[KEY_SIZE];

void generate_key() {
    RAND_bytes(key, KEY_SIZE);  // Generate key only once and share it
}

// 🔹 **Encryption Function**
void encrypt_file(const char *input_filename, const char *output_filename) {
    FILE *in = fopen(input_filename, "rb");
    FILE *out = fopen(output_filename, "wb");

    if (!in || !out) {
        perror("File opening failed");
        return;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[BLOCK_SIZE];
    RAND_bytes(iv, BLOCK_SIZE);  // Generate IV
    fwrite(iv, 1, BLOCK_SIZE, out);  // Write IV to output file

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char buffer[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE + BLOCK_SIZE];
    int bytes_read, encrypted_len;

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, in)) > 0) {
        EVP_EncryptUpdate(ctx, encrypted, &encrypted_len, buffer, bytes_read);
        fwrite(encrypted, 1, encrypted_len, out);
    }

    EVP_EncryptFinal_ex(ctx, encrypted, &encrypted_len);
    fwrite(encrypted, 1, encrypted_len, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    printf("File encrypted successfully: %s\n", output_filename);
}

// 🔹 **Decryption Function**
void decrypt_file(const char *input_filename, const char *output_filename) {
    FILE *in = fopen(input_filename, "rb");
    FILE *out = fopen(output_filename, "wb");

    if (!in || !out) {
        perror("File opening failed");
        return;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[BLOCK_SIZE];

    fread(iv, 1, BLOCK_SIZE, in); // Read IV from file
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char buffer[BUFFER_SIZE];
    unsigned char decrypted[BUFFER_SIZE + BLOCK_SIZE];
    int bytes_read, decrypted_len;

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, in)) > 0) {
        EVP_DecryptUpdate(ctx, decrypted, &decrypted_len, buffer, bytes_read);
        fwrite(decrypted, 1, decrypted_len, out);
    }

    EVP_DecryptFinal_ex(ctx, decrypted, &decrypted_len);
    fwrite(decrypted, 1, decrypted_len, out);
    fflush(out);  // 🔹 Ensure all data is written to disk

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    printf("File decrypted successfully: %s\n", output_filename);
}

// 🔹 **Sending File Function**
void send_file(const char *filename, const char *server_ip) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(TRANSFER_PORT);
    inet_pton(AF_INET, server_ip, &server.sin_addr);

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        perror("Connection failed");
        return;
    }

    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Error opening file!\n");
        return;
    }

    send(sock, filename, strlen(filename) + 1, 0);  // Send filename first
    send(sock, key, KEY_SIZE, 0);  // Send key

    char buffer[BUFFER_SIZE];
    int bytes_read;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        send(sock, buffer, bytes_read, 0);
    }

    fclose(file);
    close(sock);
    printf("File sent successfully!\n");
}

// 🔹 **Receiving File Function**
void receive_file(const char *output_filename) {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server, client;
    int opt = 1;

    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    server.sin_family = AF_INET;
    server.sin_port = htons(TRANSFER_PORT);
    server.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        perror("Bind failed");
        return;
    }

    listen(server_sock, 1);
    int client_sock = accept(server_sock, NULL, NULL);
    if (client_sock < 0) {
        perror("Accept failed");
        return;
    }

    char filename[256];
    recv(client_sock, filename, sizeof(filename), 0);  // Receive filename
    recv(client_sock, key, KEY_SIZE, 0);  // Receive key

    FILE *file = fopen(output_filename, "wb");
    if (!file) {
        perror("File creation failed");
        return;
    }

    char buffer[BUFFER_SIZE];
    int bytes_received;
    while ((bytes_received = recv(client_sock, buffer, BUFFER_SIZE, 0)) > 0) {
        fwrite(buffer, 1, bytes_received, file);
    }

    fflush(file);  // 🔹 Ensure file is written properly
    fclose(file);
    close(client_sock);
    close(server_sock);
    printf("File '%s' received successfully!\n", output_filename);
}

// 🔹 **Menu for Selection**
void menu() {
    int choice;
    char input_file[256], output_file[256], server_ip[20];

    while (1) {
        printf("\nSecure File Transfer Menu (Port: %d):\n", TRANSFER_PORT);
        printf("1. Encrypt and Send File\n");
        printf("2. Receive and Decrypt File\n");
        printf("3. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);
        getchar();  // Clear newline from input buffer

        switch (choice) {
            case 1:
                generate_key();  // Generate key before encryption
                printf("Enter input filename: ");
                scanf("%s", input_file);
                printf("Enter output encrypted filename: ");
                scanf("%s", output_file);
                encrypt_file(input_file, output_file);
                
                printf("Enter receiver IP: ");
                scanf("%s", server_ip);
                send_file(output_file, server_ip);
                break;

            case 2:
                printf("Enter filename to save received file: ");
                scanf("%s", output_file);
                receive_file(output_file);
                
                printf("Enter filename for decrypted output: ");
                scanf("%s", input_file);
                decrypt_file(output_file, input_file);
                break;

            case 3:
                printf("Exiting...\n");
                return;

            default:
                printf("Invalid choice. Try again.\n");
        }
    }
}

// 🔹 **Main Function**
int main() {
    menu();
    return 0;
}

