#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define MAX_STR 32
#define MAX_DESC 256
#define MAX_INSPECTORS 100

// Aceeași structură pe care am folosit-o în city_manager
typedef struct {
    int id;
    char inspector[MAX_STR];
    double lat;
    double lon;
    char category[MAX_STR];
    int severity;
    long timestamp;
    char description[MAX_DESC];
} Report;

typedef struct {
    char name[MAX_STR];
    int workload;
} InspectorScore;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Eroare Scorer: District nespecificat.\n");
        return 1;
    }

    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/reports.dat", argv[1]);

    int fd = open(filepath, O_RDONLY);
    if (fd == -1) {
        printf("Districtul '%s' nu are rapoarte (sau nu exista).\n", argv[1]);
        return 0;
    }

    InspectorScore scores[MAX_INSPECTORS];
    int num_inspectors = 0;
    Report r;

    while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
        int found = 0;
        // Căutăm dacă am mai calculat ceva pentru acest inspector
        for (int i = 0; i < num_inspectors; i++) {
            if (strcmp(scores[i].name, r.inspector) == 0) {
                scores[i].workload += r.severity;
                found = 1;
                break;
            }
        }
        // Inspector nou
        if (!found && num_inspectors < MAX_INSPECTORS) {
            strcpy(scores[num_inspectors].name, r.inspector);
            scores[num_inspectors].workload = r.severity;
            num_inspectors++;
        }
    }
    close(fd);

    // Afișăm rezultatele (acestea se vor duce în pipe-ul din city_hub)
    printf("--- Rezultate District: %s ---\n", argv[1]);
    for (int i = 0; i < num_inspectors; i++) {
        printf("Inspector: %s | Scor Severitate: %d\n", scores[i].name, scores[i].workload);
    }

    return 0;
}