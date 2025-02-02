#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define NUM_PMP 64

//to load the PMP configuration from file.
// config.txt file 128 lines: first 64 for pmpcfg and next 64 for pmpaddr.
int read_config(const char *filename, uint8_t *pmpcfg, uint64_t *pmpaddr) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen");
        return 1;
    }
    char line[256];
    // read first 64 lines
    for (int i = 0; i < NUM_PMP; i++) {
        if (!fgets(line, sizeof(line), fp)) {
            fprintf(stderr, "Error reading pmpcfg line %d\n", i+1);
            fclose(fp);
            return 1;
        }
        line[strcspn(line, "\r\n")] = 0;
        pmpcfg[i] = (uint8_t)strtoul(line, NULL, 16);
    }
    // read next 64 lines
    for (int i = 0; i < NUM_PMP; i++) {
        if (!fgets(line, sizeof(line), fp)) {
            fprintf(stderr, "Error reading pmpaddr line %d\n", i+1);
            fclose(fp);
            return 1;
        }
        line[strcspn(line, "\r\n")] = 0;
        pmpaddr[i] = strtoull(line, NULL, 16);
    }
    fclose(fp);
    return 0;
}

// count consecutive ones in  LSBs.
int trailing_one_counter(uint64_t value) {
    int count = 0;
    while (value & 1ULL) {
        count++;
        value >>=1;
    }
    return count;
    }

// to check access for a given physical address, priv mode, and op.
// Returns 0 if access is allowed, 1 if there is an access fault.

int access(uint8_t *pmpcfg, uint64_t *pmpaddr, uint64_t phys_addr, char priv_mod, char op) {
    uint64_t prev_addr = 0;
    int anyPMPEnabled = 0;

    // Loop over each of the 64 PMP entries.
    for (int i = 0; i < NUM_PMP; i++) {
        uint8_t cfg = pmpcfg[i];
        // Extract addressing mode (bits 3-4).
        uint8_t A = (cfg >> 3) & 0x3;
        if (A == 0) { // entry is disabled.
            continue;
        }
        anyPMPEnabled = 1;

        uint64_t region_start = 0, region_end = 0;

        if (A == 1) {                            // TOR mode.
            region_start = prev_addr;
            region_end = pmpaddr[i];            // region is [prev_addr, current_pmpaddr)
        } else if (A == 2) {                    // NA4 mode
            region_start = pmpaddr[i];
            region_end = pmpaddr[i] + 4;
        } else if (A == 3) {                    // NAPOT mode.
            // trailing ones to find region size.
            int n = trailing_one_counter(pmpaddr[i]);
            // The region size is 2^(n+3) bytes.
            uint64_t region_size = 1ULL << (n + 3);
            // Base address is obtained by clearing the n+1 LSBs.
            uint64_t base = pmpaddr[i] & ~(region_size - 1);
            region_start = base;
            region_end = base + region_size;
        }
        // Update prev_addr
        prev_addr = pmpaddr[i];

        // if address falls in this region.
        if (phys_addr >= region_start && phys_addr < region_end) {
            // find whether the access is permitted.
            int permit = 0;
            // Extract permission bits.
            int r = (cfg >> 0) & 0x1;
            int w = (cfg >> 1) & 0x1;
            int x = (cfg >> 2) & 0x1;
            int locked = (cfg >> 7) & 0x1;

            // If the PMP-entry-locked, the permission bits are enforced for all modes.
            if (locked) {
                if (op == 'R' && r) permit = 1;
                else if (op == 'W' && w) permit = 1;
                else if (op == 'X' && x) permit = 1;
            }
           else {
            // For unlocked-PMP-entries, machine mode bypasses the permission bits.
                if (priv_mod == 'M') {
                    permit = 1;
                } else {
                    if (op == 'R' && r) permit = 1;
                    else if (op == 'W' && w) permit = 1;
                    else if (op == 'X' && x) permit = 1;
                }
            }
            return permit ? 0 : 1;
        }
    }
    // If no PMP entry matches, then machine mode is allowed,
    // but S/U-mode access faults if any PMP entry is enabled.
    if (priv_mod == 'M')
        return 0;
    else
        return anyPMPEnabled ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <pmp_config_file> <0xaddress> <privilege mode (M/S/U)> <operation (R/W/X)>\n", argv[0]);
        return 1;
    }

    const char *config_file = argv[1];
    const char *addr_str = argv[2];
    char priv_mod = argv[3][0];     // 'M', 'S', or 'U'
    char op = argv[4][0];         // 'R', 'W', or 'X'

    // Check physical address format.
    if (strncmp(addr_str, "0x", 2) != 0) {
        fprintf(stderr, "Address must start with '0x'\n");
        return 1;
    }
    uint64_t phys_addr = strtoull(addr_str, NULL, 16);

    // Check priv mode.
    if (!(priv_mod == 'M' || priv_mod == 'S' || priv_mod == 'U')) {
        fprintf(stderr, "Priv Mode must be M, S, or U\n");
        return 1;
    }
    // Check op.
    if (!(op == 'R' || op == 'W' || op == 'X')) {
        fprintf(stderr, "Op should be R, W, or X\n");
        return 1;}

    uint8_t pmpcfg[NUM_PMP];
    uint64_t pmpaddr[NUM_PMP];

    if (read_config(config_file, pmpcfg, pmpaddr) != 0) {
        fprintf(stderr, "Failure to load config.txt from %s\n", config_file);
        return 1;
    }

    int fault = access(pmpcfg, pmpaddr, phys_addr, priv_mod, op);
    if (fault)
        printf("Access fault\n");
    else
        printf("Access Allowed\n");

    return 0;
}
