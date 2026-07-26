#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../src/proto.h"

static int failures = 0;

// print PASS/FAIL for a test result and tally failures
static void check(const char *label, int ok) {
    printf("[%s] %s\n", ok ? "PASS" : "FAIL", label);
    if (!ok) failures++;
}

int main(void) {
    char tmpdir[600];

    // get pid for each test -> make directory named with specific pid
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/test_proto_%d", (int)getpid());
    if (mkdir(tmpdir, 0755) != 0) { perror("mkdir(tmpdir)"); return 1; }   // 0755: permission (rwxr-xr-x)

    // make certs folder in tmpdir to use certs/hmac.key from here
    char certs_dir[700];
    snprintf(certs_dir, sizeof(certs_dir), "%s/certs", tmpdir);
    mkdir(certs_dir, 0755);
    
    // build the full path to the key file: <tmpdir>/certs/hmac.key
    char key_path[720];
    snprintf(key_path, sizeof(key_path), "%s/hmac.key", certs_dir);

    // known (not random) key bytes, so it can be verified what was loaded later
    uint8_t expected[HMAC_KEY_LEN];
    for (int i = 0; i < HMAC_KEY_LEN; i++) expected[i] = (uint8_t)i; // 0x00, 0x01, ..., 0x1f

    // write the key data in the created certs folder
    FILE *fp = fopen(key_path, "wb");
    fwrite(expected, 1, HMAC_KEY_LEN, fp);
    fclose(fp);

    // chdir == cd
    if (chdir(tmpdir) != 0) { perror("chdir"); return 1; }

    // success case: verify the loaded key matches the expected data
    uint8_t got[HMAC_KEY_LEN];
    int result = load_hmac_key(got);

    check("load_hmac_key returns 0 on success", result == 0);
    check("loaded key matches file contents",
          memcmp(got, expected, HMAC_KEY_LEN) == 0);

    // fail case: hmac.key file does not exist
    remove("certs/hmac.key");
    uint8_t dummy[HMAC_KEY_LEN];
    int missing_result = load_hmac_key(dummy);
    check("load_hmac_key returns -1 when file is missing", missing_result == -1);

    // fail case: key file exists but is shorter than HMAC_KEY_LEN
    fp = fopen("certs/hmac.key", "wb");
    uint8_t short_key[10] = {0};
    fwrite(short_key, 1, sizeof(short_key), fp);
    fclose(fp);
    int short_result = load_hmac_key(dummy);
    check("load_hmac_key returns -1 when key file is too short", short_result == -1);

    if (failures == 0) {
        printf("\nAll tests passed.\n");
        return 0;
    } else {
        printf("\n%d test(s) failed.\n", failures);
        return 1;
    }
}
