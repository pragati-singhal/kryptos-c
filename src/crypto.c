#include "kryptos.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Overwrite sensitive RAM buffers using a volatile pointer
void secureWipe(void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

// Salted DJB2 Hash for Master PIN verification
uint32_t hashPin(const char *pin, uint32_t salt) {
    uint32_t hash = 5381 ^ salt;
    for (int i = 0; pin[i] != '\0'; i++) {
        hash = ((hash << 5) + hash) + (unsigned char)pin[i];
    }
    return hash;
}

// FNV-1a Checksum for Vault File Tamper Detection
uint32_t computeVaultChecksum(void) {
    uint32_t hash = 2166136261u ^ vaultSalt ^ storedPinHash;
    for (int i = 0; i < entryCount; i++) {
        hash ^= (uint32_t)vault[i].id;
        hash *= 16777619u;
        for (int j = 0; vault[i].service[j] != '\0'; j++) {
            hash ^= (unsigned char)vault[i].service[j];
            hash *= 16777619u;
        }
        for (int j = 0; vault[i].password[j] != '\0'; j++) {
            hash ^= (unsigned char)vault[i].password[j];
            hash *= 16777619u;
        }
    }
    return hash;
}

// Symmetric Keystream XOR Cipher (preserves printable ASCII & avoids '|')
void applyStreamCipher(char *text, const char *pin, uint32_t salt) {
    size_t pinLen = strlen(pin);
    if (pinLen == 0) return;

    for (size_t i = 0; text[i] != '\0'; i++) {
        if (text[i] >= 33 && text[i] <= 126 && text[i] != '|') {
            uint8_t keyByte = (uint8_t)((pin[i % pinLen] + (salt >> ((i % 4) * 8)) + i * 7) % 93) + 1;
            int offset = text[i] - 33;
            int transformedOffset = (offset ^ keyByte) % 94;
            char candidate = (char)(transformedOffset + 33);

            int reverseCheck = (transformedOffset ^ keyByte) % 94;
            if (reverseCheck == offset && candidate != '|' && candidate >= 33 && candidate <= 126) {
                text[i] = candidate;
            }
        }
    }
}

// Password Strength Evaluator (1 to 4)
int evaluateStrength(const char *pass) {
    int hasUpper = 0, hasLower = 0, hasDigit = 0, hasSymbol = 0;
    int len = (int)strlen(pass);

    for (int i = 0; i < len; i++) {
        if (isupper((unsigned char)pass[i])) hasUpper = 1;
        else if (islower((unsigned char)pass[i])) hasLower = 1;
        else if (isdigit((unsigned char)pass[i])) hasDigit = 1;
        else hasSymbol = 1;
    }

    int classes = hasUpper + hasLower + hasDigit + hasSymbol;
    if (len < 8) return 1;
    if (len >= 12 && classes == 4) return 4;
    if (len >= 8 && classes >= 3) return 3;
    if (classes >= 2) return 2;
    return 1;
}

const char* getStrengthLabel(int s) {
    switch (s) {
        case 1: return "Weak";
        case 2: return "Fair";
        case 3: return "Strong";
        case 4: return "Very Strong";
        default: return "Unknown";
    }
}

// High-Entropy Random Password Generator
void generateStrongPassword(char *out, int length) {
    const char upper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char lower[] = "abcdefghijklmnopqrstuvwxyz";
    const char digits[] = "0123456789";
    const char symbols[] = "!@#$%^&*_-+=?";
    const char all[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*_-+=?";

    if (length < 12) length = 16;
    out[0] = upper[rand() % (sizeof(upper) - 1)];
    out[1] = lower[rand() % (sizeof(lower) - 1)];
    out[2] = digits[rand() % (sizeof(digits) - 1)];
    out[3] = symbols[rand() % (sizeof(symbols) - 1)];

    for (int i = 4; i < length; i++) {
        out[i] = all[rand() % (sizeof(all) - 1)];
    }
    out[length] = '\0';

    for (int i = length - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        char tmp = out[i];
        out[i] = out[j];
        out[j] = tmp;
    }
}