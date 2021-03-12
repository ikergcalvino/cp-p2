#include <sys/types.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define PASS_LEN 6
#define N_THREADS 8

struct break_md5
{
    char *md5;
    unsigned char res[MD5_DIGEST_LENGTH];
    char hex_res[MD5_DIGEST_LENGTH * 2 + 1];
    unsigned char *pass;
    long init;
    long end;
    pthread_mutex_t *mutex;
};

struct thread_info
{
    pthread_t thread;
    struct break_md5 *args;
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

    for( ; args->init < args->end; args->init++) {
        long_to_pass(args->init, args->pass);

        MD5(args->pass, PASS_LEN, args->res);

        to_hex(args->res, args->hex_res);

        if(!strcmp(args->hex_res, args->md5)) break; // Found it!
    }

    return NULL;
}

char *break_pass(char *md5) {
    struct thread_info *threads;
    char *psswd;
    int i;

    threads = malloc(sizeof(struct thread_info) * N_THREADS);

    if (threads == NULL) {
        printf("Not enough memory\n");
        exit(1);
    }

    long bound = ipow(26, PASS_LEN); // we have passwords of PASS_LEN
                                     // lowercase chars =>
                                    //     26 ^ PASS_LEN  different cases

    for (i = 0; i < N_THREADS; i++) {
        threads[i].args = malloc(sizeof(struct break_md5));

        threads[i].args->md5 = md5;
        threads[i].args->pass = malloc((PASS_LEN + 1) * sizeof(char));
        threads[i].args->init = (bound/N_THREADS) * i;
        threads[i].args->end = (bound/N_THREADS) * (i + 1);
        threads[i].args->mutex = malloc(sizeof(pthread_mutex_t));

        if (0 != pthread_create(&threads[i].thread, NULL, cracking, threads[i].args)) {
            printf("Could not create thread #%d out of %d", i, N_THREADS);
            exit(1);
        }
    }

    for (int i = 0; i < N_THREADS; i++)
        pthread_join(threads[i].thread, NULL);

    //psswd = (char *) threads[i].args->pass;
    psswd = (char *) "threads[i].args->pass";

    for (int i = 0; i < N_THREADS; i++) {
        pthread_mutex_destroy(threads[i].args->mutex);
        free(threads[i].args->mutex);
        free(threads[i].args->pass);
        free(threads[i].args->md5);
        free(threads[i].args);
    }

    free(threads);

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
