#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>

#define CHUNK_DISTRICT 20
typedef struct report{
    int ID;
    char Nume_Inspector[50];
    float latitude;
    float longitude;
    char category[20];
    int severity;
    time_t timestamp;
    char description[100];
}report


char *districte[20];
int nr_districte;

void add(char *district){
    int exists=0;
    for(int i=0;i<nr_districte;i++){

    }
}


int main(int argc, char **argv){
    if (argc < 3){
        fprintf(stderr, "Argumente prea putine\n");
        return -1;
    }
    if(strcmp(argv[1],"--role")!=0){
        fprintf(stderr,"Folosire gresita!!\n");
        return -2
    }
    int manager=0;
    if(strcmp(argv[2],"manager")==0)
        manager=1;

    return 0;
}
