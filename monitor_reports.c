#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>

volatile sig_atomic_t keep_running = 1;

//Handler pentru SIGINT (Când utilizatorul apasă Ctrl+C)
void handle_sigint(int sig) {
    keep_running = 0;
    const char *msg = "\n[Monitor] S-a primit SIGINT. Se inchide programul...\n";
    write(STDOUT_FILENO, msg, strlen(msg));
}

// Handler pentru SIGUSR1 (Notificare de la city_manager că s-a adăugat un raport)
 
void handle_sigusr1(int sig) {
    const char *msg = "[Monitor] ALERTA: Un nou raport a fost adaugat intr-un district!\n";
    write(STDOUT_FILENO, msg, strlen(msg));
}

int main() {
    struct sigaction sa_int, sa_usr;

    sa_int.sa_handler = handle_sigint;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    sigaction(SIGINT, &sa_int, NULL);

    sa_usr.sa_handler = handle_sigusr1;
    sigemptyset(&sa_usr.sa_mask);
    sa_usr.sa_flags = SA_RESTART; // Asigură că alte apeluri de sistem nu sunt întrerupte brusc
    sigaction(SIGUSR1, &sa_usr, NULL);

    pid_t pid = getpid();
    int fd = open(".monitor_pid", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd != -1) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%d\n", pid);
        write(fd, buf, strlen(buf));
        close(fd);
    } else {
        perror("Eroare la crearea fisierului .monitor_pid");
        return 1;
    }

    printf("[Monitor] A pornit cu PID-ul %d. Astept semnale...\n", pid);

    while (keep_running) {
        pause(); 
    }

    if (unlink(".monitor_pid") == -1) {
        perror("Eroare la stergerea .monitor_pid");
    } else {
        printf("[Monitor] Fisierul .monitor_pid a fost sters. Iesire cu succes.\n");
    }

    return 0;
}