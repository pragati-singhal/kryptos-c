#include "kryptos.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

int findById(int id) {
    for (int i = 0; i < entryCount; i++) {
        if (vault[i].id == id) return i;
    }
    return -1;
}

void addEntry(void) {
    if (entryCount >= MAX_ENTRIES) {
        printf("\n[!] Vault storage limit reached.\n");
        return;
    }

    struct Credential item;
    char buf[64];

    printf("\n--- Add New Credential ---\n");
    printf("Entry ID (numeric, e.g., 101): ");
    readLine(buf, sizeof(buf));
    item.id = atoi(buf);

    if (item.id <= 0 || findById(item.id) != -1) {
        printf("[!] Invalid or duplicate ID.\n");
        return;
    }

    printf("Service / Platform (e.g., GitHub, AWS): ");
    readLine(item.service, sizeof(item.service));

    printf("Username / Email: ");
    readLine(item.username, sizeof(item.username));

    printf("Auto-generate 16-char strong password? (y/n): ");
    readLine(buf, sizeof(buf));
    if (tolower((unsigned char)buf[0]) == 'y') {
        generateStrongPassword(item.password, 16);
        printf("[*] Generated Password: %s\n", item.password);
    } else {
        printf("Enter Password / Secret: ");
        readMasked(item.password, sizeof(item.password));
    }

    item.strength = evaluateStrength(item.password);
    vault[entryCount++] = item;
    saveVault();

    printf("[+] Encrypted & saved '%s' (Strength: %s).\n",
           item.service, getStrengthLabel(item.strength));
    secureWipe(&item, sizeof(item));
}

void viewEntries(void) {
    printf("\n======================================================================================\n");
    printf("%-6s | %-20s | %-24s | %-18s | %-11s\n",
           "ID", "Service", "Username", "Password", "Strength");
    printf("======================================================================================\n");

    if (entryCount == 0) {
        printf("Vault is empty.\n");
    } else {
        for (int i = 0; i < entryCount; i++) {
            printf("%-6d | %-20s | %-24s | %-18s | %-11s\n",
                   vault[i].id,
                   vault[i].service,
                   vault[i].username,
                   vault[i].password,
                   getStrengthLabel(vault[i].strength));
        }
    }
    printf("======================================================================================\n");
}

void searchEntries(void) {
    char query[48];
    printf("\nEnter keyword to search (Service or Username): ");
    readLine(query, sizeof(query));

    int found = 0;
    printf("\n--- Search Results for '%s' ---\n", query);
    for (int i = 0; i < entryCount; i++) {
        if (strstr(vault[i].service, query) != NULL || strstr(vault[i].username, query) != NULL) {
            printf("#%d | %s | %s | Password: %s [%s]\n",
                   vault[i].id, vault[i].service, vault[i].username,
                   vault[i].password, getStrengthLabel(vault[i].strength));
            found++;
        }
    }
    if (found == 0) printf("No matching entries found.\n");
}

void modifyEntry(void) {
    char buf[32];
    printf("\nEnter Entry ID to update password: ");
    readLine(buf, sizeof(buf));
    int id = atoi(buf);

    int idx = findById(id);
    if (idx == -1) {
        printf("[!] Entry ID #%d not found.\n", id);
        return;
    }

    printf("Updating '%s' (%s)\n", vault[idx].service, vault[idx].username);
    printf("Auto-generate new 16-char password? (y/n): ");
    readLine(buf, sizeof(buf));

    secureWipe(vault[idx].password, sizeof(vault[idx].password));
    if (tolower((unsigned char)buf[0]) == 'y') {
        generateStrongPassword(vault[idx].password, 16);
        printf("[*] New Generated Password: %s\n", vault[idx].password);
    } else {
        printf("Enter New Password: ");
        readMasked(vault[idx].password, sizeof(vault[idx].password));
    }

    vault[idx].strength = evaluateStrength(vault[idx].password);
    saveVault();
    printf("[+] Credential #%d updated & re-encrypted (Strength: %s).\n",
           id, getStrengthLabel(vault[idx].strength));
}

void deleteEntry(void) {
    char buf[32];
    printf("\nEnter Entry ID to delete: ");
    readLine(buf, sizeof(buf));
    int id = atoi(buf);

    int idx = findById(id);
    if (idx == -1) {
        printf("[!] Entry ID #%d not found.\n", id);
        return;
    }

    secureWipe(&vault[idx], sizeof(struct Credential));
    for (int i = idx; i < entryCount - 1; i++) {
        vault[i] = vault[i + 1];
    }
    secureWipe(&vault[entryCount - 1], sizeof(struct Credential));
    entryCount--;

    saveVault();
    printf("[-] Entry #%d wiped from memory and deleted from disk.\n", id);
}

void analyseVault(void) {
    if (entryCount == 0) {
        printf("\n[!] Vault is empty. Add credentials first.\n");
        return;
    }

    int weakCount = 0, strongCount = 0, reusedCount = 0;

    for (int i = 0; i < entryCount; i++) {
        if (vault[i].strength <= 2) weakCount++;
        else strongCount++;

        for (int j = i + 1; j < entryCount; j++) {
            if (strcmp(vault[i].password, vault[j].password) == 0) {
                reusedCount++;
                break;
            }
        }
    }

    float health = ((float)strongCount / entryCount) * 100.0f - (reusedCount * 12.5f);
    if (health < 0.0f) health = 0.0f;

    printf("\n================ KRYPTOS SECURITY HYGIENE AUDIT ================\n");
    printf("Total Credentials Stored : %d\n", entryCount);
    printf("Strong / Very Strong     : %d\n", strongCount);
    printf("Weak / Fair Passwords    : %d\n", weakCount);
    printf("Duplicate/Reused Secrets : %d\n", reusedCount);
    printf("Vault Security Score     : %.1f / 100.0\n", health);
    printf("================================================================\n");

    FILE *rep = fopen(AUDIT_FILE, "w");
    if (rep != NULL) {
        fprintf(rep, "KRYPTOS-C - SECURITY HYGIENE AUDIT REPORT\n");
        fprintf(rep, "Total Credentials : %d\n", entryCount);
        fprintf(rep, "Strong Passwords  : %d\n", strongCount);
        fprintf(rep, "Weak Passwords    : %d\n", weakCount);
        fprintf(rep, "Reused Passwords  : %d\n", reusedCount);
        fprintf(rep, "Overall Score     : %.1f%%\n\n", health);
        fprintf(rep, "Entry Breakdown (Redacted):\n");
        for (int i = 0; i < entryCount; i++) {
            fprintf(rep, "- ID #%d | %s (%s) -> Strength: %s\n",
                    vault[i].id, vault[i].service, vault[i].username,
                    getStrengthLabel(vault[i].strength));
        }
        fclose(rep);
        printf("[+] Redacted audit report exported to '%s'.\n", AUDIT_FILE);
    }
}

int main(void) {
    srand((unsigned int)time(NULL));
    char input[16];
    int choice = 0;

    printf("====================================================\n");
    printf("   KRYPTOS-C v1.0 - Encrypted CLI Secret Manager    \n");
    printf("====================================================\n");

    if (!authenticateUser()) {
        return 1;
    }

    while (1) {
        printf("\n--- KRYPTOS MENU (Stored: %d | File: %s) ---\n", entryCount, VAULT_FILE);
        printf("1. Add Credential (Manual / Auto-Generate)\n");
        printf("2. View Decrypted Vault\n");
        printf("3. Search Credentials\n");
        printf("4. Modify Password\n");
        printf("5. Delete Credential\n");
        printf("6. Run Security Audit & Export Report\n");
        printf("7. Lock Vault & Exit\n");
        printf("Select option (1-7): ");

        readLine(input, sizeof(input));
        choice = atoi(input);

        switch (choice) {
            case 1: addEntry(); break;
            case 2: viewEntries(); break;
            case 3: searchEntries(); break;
            case 4: modifyEntry(); break;
            case 5: deleteEntry(); break;
            case 6: analyseVault(); break;
            case 7:
                secureWipe(vault, sizeof(vault));
                secureWipe(activePin, sizeof(activePin));
                printf("[Locked] Memory wiped & encrypted vault saved to %s.\n", VAULT_FILE);
                return 0;
            default:
                printf("[!] Invalid option. Choose 1-7.\n");
        }
    }
    return 0;
}