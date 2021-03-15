#include <sys/types.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define PASS_LEN 6
#define N_THREADS 8

struct data
{
    char *md5;
    int found;
    pthread_mutex_t *mutex;
};

struct break_md5
{
    int id;
    struct data *data;
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

void *break_pass(void *ptr) {
    struct break_md5 *args = ptr;
    unsigned char res[MD5_DIGEST_LENGTH];
    char hex_res[MD5_DIGEST_LENGTH * 2 + 1];
    unsigned char *pass = malloc((PASS_LEN + 1) * sizeof(char));
    long bound = ipow(26, PASS_LEN); // we have passwords of PASS_LEN
                                     // lowercase chars =>
                                    //     26 ^ PASS_LEN  different cases
    for(long i=args->id; i < bound; i += N_THREADS) {
        pthread_mutex_lock(args->data->mutex);
        if (!args->data->found) {
            pthread_mutex_unlock(args->data->mutex);
            long_to_pass(i, pass);

            MD5(pass, PASS_LEN, res);

            to_hex(res, hex_res);

            if(!strcmp(hex_res, args->data->md5)) {
                printf("%s: %s\n", args->data->md5, pass);
                
                pthread_mutex_lock(args->data->mutex);
                args->data->found = 1;
                pthread_mutex_unlock(args->data->mutex);

                break; // Found it!
            }
        } else {
            pthread_mutex_unlock(args->data->mutex);
            break;
        }

    }

    free(pass);

    return NULL;
}

void init_data(struct data *data, char *md5) {
    data->mutex = malloc(sizeof(pthread_mutex_t));

    if (data->mutex == NULL) {
        printf("Not enough memory\n");
        exit(1);
    }

    pthread_mutex_init(data->mutex, NULL);

    data->md5 = md5;
    data->found = 0;
}

struct thread_info *start_threads(struct data *data) {
    struct thread_info *threads;

    threads = malloc(sizeof(struct thread_info) * N_THREADS);

    if (threads == NULL) {
        printf("Not enough memory\n");
        exit(1);
    }

    for (long i = 0; i < N_THREADS; i++) {
        threads[i].args = malloc(sizeof(struct break_md5));

        threads[i].args->id = i;
        threads[i].args->data = data;

        if (0 != pthread_create(&threads[i].thread, NULL, break_pass, threads[i].args)) {
            printf("Could not create thread #%d out of %d", (int) i, N_THREADS);
            exit(1);
        }
    }

    return threads;
}

void wait(struct thread_info *threads, struct data *data) {
    for (int i = 0; i < N_THREADS; i++)
        pthread_join(threads[i].thread, NULL);

    for (int i = 0; i < N_THREADS; i++)
        free(threads[i].args);

    pthread_mutex_destroy(data->mutex);
    free(data->mutex);

    free(threads);
}

int main(int argc, char *argv[]) {
    struct thread_info *thrs;
    struct data data;

    if(argc < 2) {
        printf("Use: %s string\n", argv[0]);
        exit(0);
    }

    init_data(&data, argv[1]);

    thrs = start_threads(&data);

    wait(thrs, &data);

    return 0;
}
