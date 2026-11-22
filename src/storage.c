#include "kryptos.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

struct Credential vault[MAX_ENTRIES];
int entryCount = 0;
uint32_t vaultSalt = 0;
uint32_t storedPinHash = 0;
char activePin[32];

void readLine(char *buffer, int size) {
    if (fgets(buffer, size, stdin) != NULL) {
        buffer[strcspn(buffer, "\n")] = '\0';
    }
}

void readMasked(char *buffer, int size) {
    int i = 0;
    int ch;
#ifdef _WIN32
    while ((ch = _getch()) != '\r' && ch != '\n' && ch != EOF) {
        if ((ch == '\b' || ch == 127) && i > 0) {
            i--;
            printf("\b \b");
        } else if (isprint(ch) && i < size - 1) {
            buffer[i++] = (char)ch;
            printf("*");
        }
    }
    printf("\n");
#else
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    while ((ch = getchar()) != '\n' && ch != '\r' && ch != EOF) {
        if ((ch == 127 || ch == '\b') && i > 0) {
            i--;
            printf("\b \b");
            fflush(stdout);
        } else if (isprint(ch) && i < size - 1) {
            buffer[i++] = (char)ch;
            printf("*");
            fflush(stdout);
        }
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
#endif
    buffer[i] = '\0';
}

void saveVault(void) {
    FILE *fp = fopen(VAULT_FILE, "w");
    if (fp == NULL) {
        printf("[Error] Failed to open %s for writing.\n", VAULT_FILE);
        return;
    }

    uint32_t checksum = computeVaultChecksum();
    fprintf(fp, "KRYPTOS_HDR|%u|%u|%u\n", vaultSalt, storedPinHash, checksum);

    for (int i = 0; i < entryCount; i++) {
        char encPass[64];
        strcpy(encPass, vault[i].password);
        applyStreamCipher(encPass, activePin, vaultSalt);

        fprintf(fp, "%d|%s|%s|%s|%d\n",
                vault[i].id,
                vault[i].service,
                vault[i].username,
                encPass,
                vault[i].strength);
        secureWipe(encPass, sizeof(encPass));
    }
    fclose(fp);
}

int authenticateUser(void) {
    FILE *fp = fopen(VAULT_FILE, "r");
    char pinInput[32];

    if (fp == NULL) {
        printf("[Setup] No vault found. Create a new Master PIN (min 4 chars): ");
        readMasked(pinInput, sizeof(pinInput));
        if (strlen(pinInput) < 4) {
            printf("[!] PIN must be at least 4 characters.\n");
            return 0;
        }
        vaultSalt = (uint32_t)time(NULL) ^ (uint32_t)rand();
        storedPinHash = hashPin(pinInput, vaultSalt);
        strcpy(activePin, pinInput);
        secureWipe(pinInput, sizeof(pinInput));
        saveVault();
        printf("[+] New encrypted Kryptos vault initialized (%s).\n", VAULT_FILE);
        return 1;
    }

    char headerLine[128];
    uint32_t fileChecksum = 0;
    if (fgets(headerLine, sizeof(headerLine), fp) == NULL ||
        sscanf(headerLine, "KRYPTOS_HDR|%u|%u|%u", &vaultSalt, &storedPinHash, &fileChecksum) != 3) {
        printf("[CRITICAL] Vault header corrupted or invalid format!\n");
        fclose(fp);
        return 0;
    }

    for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        printf("Enter Master PIN (%d/%d): ", attempt, MAX_ATTEMPTS);
        readMasked(pinInput, sizeof(pinInput));

        if (hashPin(pinInput, vaultSalt) == storedPinHash) {
            strcpy(activePin, pinInput);
            secureWipe(pinInput, sizeof(pinInput));

            entryCount = 0;
            char line[256];
            while (fgets(line, sizeof(line), fp) != NULL && entryCount < MAX_ENTRIES) {
                line[strcspn(line, "\n")] = '\0';
                if (sscanf(line, "%d|%47[^|]|%47[^|]|%63[^|]|%d",
                           &vault[entryCount].id,
                           vault[entryCount].service,
                           vault[entryCount].username,
                           vault[entryCount].password,
                           &vault[entryCount].strength) == 5) {
                    applyStreamCipher(vault[entryCount].password, activePin, vaultSalt);
                    entryCount++;
                }
            }
            fclose(fp);

            if (computeVaultChecksum() != fileChecksum) {
                printf("\n[WARNING] TAMPER ALERT: %s was modified outside Kryptos!\n", VAULT_FILE);
            } else {
                printf("[+] Authentication & Integrity Verification Passed.\n");
            }
            return 1;
        }
        printf("[!] Incorrect Master PIN.\n");
    }

    secureWipe(pinInput, sizeof(pinInput));
    fclose(fp);
    printf("[LOCKED] Maximum failed attempts reached. Exiting.\n");
    return 0;
}