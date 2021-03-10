#include <sys/types.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define PASS_LEN 6

struct break_md5
{
    char *md5;
    unsigned char res[MD5_DIGEST_LENGTH];
    char hex_res[MD5_DIGEST_LENGTH * 2 + 1];
    unsigned char *pass;
    long bound;
    pthread_mutex_t *mutex;
};

long ipow(long base, int exp)
{
    long res = 1;
    for (;;)
    {
        if (exp & 1)
            res *= base;
        exp >>= 1;
        if (!exp)
            break;
        base *= base;
    }

    return res;
}

long pass_to_long(char *str) {
    long res = 0;

    for(int i=0; i < PASS_LEN; i++)
        res = res * 26 + str[i]-'a';

    return res;
};

void long_to_pass(long n, unsigned char *str) {  // str should have size PASS_SIZE+1
    for(int i=PASS_LEN-1; i >= 0; i--) {
        str[i] = n % 26 + 'a';
        n /= 26;
    }
    str[PASS_LEN] = '\0';
}

void to_hex(unsigned char *res, char *hex_res) {
    for(int i=0; i < MD5_DIGEST_LENGTH; i++) {
        snprintf(&hex_res[i*2], 3, "%.2hhx", res[i]);
    }
    hex_res[MD5_DIGEST_LENGTH * 2] = '\0';
}

void *cracking(void *ptr) {
    struct break_md5 *args = ptr;
    
    for(long i=0; i < args->bound; i++) {
        long_to_pass(i, args->pass);

        MD5(args->pass, PASS_LEN, args->res);

        to_hex(args->res, args->hex_res);

        if(!strcmp(args->hex_res, args->md5)) break; // Found it!
    }

    return NULL;
}

char *break_pass(char *md5) {
    struct break_md5 *args;
    pthread_t *threads;
    char *psswd;

    args = malloc(sizeof(struct break_md5));
    args->mutex = malloc(sizeof(pthread_mutex_t));
    threads = malloc(sizeof(pthread_t) * 2);

    if (args == NULL || args->mutex == NULL || threads == NULL)
    {
        printf("Not enough memory\n");
        exit(1);
    }

    pthread_mutex_init(args->mutex, NULL);

    args->md5 = md5;
    args->pass = malloc((PASS_LEN + 1) * sizeof(char));
    args->bound = ipow(26, PASS_LEN); // we have passwords of PASS_LEN
                                     // lowercase chars =>
                                    //     26 ^ PASS_LEN  different cases

    //call *cracking in different threads

    psswd = (char *) args->pass;

    pthread_mutex_destroy(args->mutex);
    free(args->mutex);
    free(threads);
    free(args);
    return psswd;
}

int main(int argc, char *argv[]) {
    if(argc < 2) {
        printf("Use: %s string\n", argv[0]);
        exit(0);
    }

    char *pass = break_pass(argv[1]);

    printf("%s: %s\n", argv[1], pass);
    free(pass);
    return 0;
}
