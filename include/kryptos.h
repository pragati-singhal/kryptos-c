#ifndef KRYPTOS_H
#define KRYPTOS_H

#include <stddef.h>
#include <stdint.h>

#define MAX_ENTRIES 200
#define VAULT_FILE "kryptos_vault.dat"
#define AUDIT_FILE "kryptos_audit.txt"
#define MAX_ATTEMPTS 3

struct Credential {
    int id;
    char service[48];
    char username[48];
    char password[64];
    int strength;       // 1 = Weak, 2 = Fair, 3 = Strong, 4 = Very Strong
};

// Shared vault state across modules
extern struct Credential vault[MAX_ENTRIES];
extern int entryCount;
extern uint32_t vaultSalt;
extern uint32_t storedPinHash;
extern char activePin[32];

// crypto.c functions
void secureWipe(void *ptr, size_t len);
uint32_t hashPin(const char *pin, uint32_t salt);
uint32_t computeVaultChecksum(void);
void applyStreamCipher(char *text, const char *pin, uint32_t salt);
int evaluateStrength(const char *pass);
const char* getStrengthLabel(int s);
void generateStrongPassword(char *out, int length);

// storage.c functions
void readLine(char *buffer, int size);
void readMasked(char *buffer, int size);
void saveVault(void);
int authenticateUser(void);

#endif