#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

#define MAX_INSPECTORI 100

typedef struct {
    char name[32];
    int total_workload;
} GlobalScore;

void calculate_scores(char *args) {
    char *district = strtok(args, " \n");
    
    GlobalScore global_scores[MAX_INSPECTORI];
    int num_global = 0;

    while (district != NULL) {
        int fd[2];
        if (pipe(fd) == -1) {
            perror("Eroare pipe");
            break;
        }

        pid_t pid = fork();
        if (pid == 0) {
            //copil
            close(fd[0]); 
            dup2(fd[1], STDOUT_FILENO);
            close(fd[1]);

            execlp("./scorer", "scorer", district, NULL);
            perror("Eroare exec scorer");
            exit(1);
        } else {
            //parinte
            close(fd[1]); 
            
            FILE *stream = fdopen(fd[0], "r");//transform din file descriptor in FILE * ca sa pot apela sscanf
            char line[256];
            
            while (fgets(line, sizeof(line), stream) != NULL) {
                char current_name[32];
                int current_score;
                
                if (sscanf(line, "%s %d", current_name, &current_score) == 2) {
                    int found = 0;
                    for (int i = 0; i < num_global; i++) {
                        if (strcmp(global_scores[i].name, current_name) == 0) {
                            global_scores[i].total_workload += current_score; 
                            found = 1;//gasit inspector in lista deja existenta de inspectori
                            break;
                        }
                    }
                    
                    if (!found && num_global < MAX_INSPECTORI) { //
                        strcpy(global_scores[num_global].name, current_name);
                        global_scores[num_global].total_workload = current_score;
                        num_global++;
                    }
                }
            }
            
            fclose(stream); //fclose apeleaza si functia close pe file descriptor
            waitpid(pid, NULL, 0);
        }
        
        district = strtok(NULL, " \n"); //parsam pe districte
    }

    printf("\n--- Combined Workload Report ---\n");
    if (num_global == 0) {
        printf("Nu s-au gasit date pentru districtele specificate.\n");
    } else {
        for (int i = 0; i < num_global; i++) {
            printf("Inspector: %s | Scor Total Cumulat: %d\n", global_scores[i].name, global_scores[i].total_workload);
        }
    }
    printf("------------------------------------------------\n");
}

void start_monitor() {
    pid_t hub_mon_pid = fork();

    if (hub_mon_pid == 0) {
        //procesul hub_mon
        int fd[2]; 
        if (pipe(fd) == -1) {
            perror("Eroare la crearea pipe-ului");
            exit(1);
        }

        pid_t monitor_pid = fork(); 
        
        if (monitor_pid == 0) {
            //monitor_reports
            close(fd[0]); 
            
            // redirect stdout-ul monitorului direct în pipe
            dup2(fd[1], STDOUT_FILENO);
            close(fd[1]);//nu mai am nevoie de capatul de scriere
            
            execlp("./monitor_reports", "monitor_reports", NULL);
            perror("Eroare exec monitor_reports");
            exit(1);
        } else {
            //hub_mon
            close(fd[1]); 

            char buffer[256];
            ssize_t bytes_read;
            while ((bytes_read = read(fd[0], buffer, sizeof(buffer) - 1)) > 0) {
                buffer[bytes_read] = '\0';
                printf("\n[NOTIFICARE MONITOR] %s", buffer);
                fflush(stdout); 
            }
            printf("\n[HUB_MON] Procesul monitor s-a incheiat definitiv.\ncity_hub> ");
            fflush(stdout);//fortam scrierea la stdout fara a folosii bufferul
            close(fd[0]);
            exit(0);
        }
    } else if (hub_mon_pid > 0) {
        printf("Procesul hub_mon a fost pornit in fundal (PID %d).\n", hub_mon_pid);
    }
}


int main() {
    char command_line[256];

    printf("--- City Hub Interface ---\n");
    printf("Comenzi disponibile:\n");
    printf("  start_monitor\n");
    printf("  calculate_scores <district1> <district2> ...\n");
    printf("  exit\n\n");

    while (1) {
        printf("city_hub> ");
        if (fgets(command_line, sizeof(command_line), stdin) == NULL) {
            break;
        }
        if (strncmp(command_line, "exit", 4) == 0) {
            break;
        } else if (strncmp(command_line, "start_monitor", 13) == 0) {
            start_monitor();
        } else if (strncmp(command_line, "calculate_scores", 16) == 0) {
            // Trimitem tot ce e după comanda propriu-zisă
            calculate_scores(command_line + 17);
        } else if (command_line[0] != '\n') {
            printf("Comanda necunoscuta.\n");
        }
    }
    return 0;
}