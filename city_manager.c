#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <dirent.h>


#define MAX_STR 32
#define MAX_DESC 256

typedef struct {
    int id;
    char inspector[MAX_STR];
    double lat;
    double lon;
    char category[MAX_STR];
    int severity;
    time_t timestamp;
    char description[MAX_DESC];
} Report;


void check_and_cleanup_symlinks() {
    // Deschidem directorul curent (".")
    DIR *dir = opendir(".");
    if (!dir) return;

    struct dirent *entry;
    
    // Citim fiecare element din folder unul câte unul
    while ((entry = readdir(dir)) != NULL) {
        
        // Căutăm doar fișierele care încep cu "active_reports-"
        if (strncmp(entry->d_name, "active_reports-", 15) == 0) {
            struct stat lst, st;
            
            if (lstat(entry->d_name, &lst) == 0 && S_ISLNK(lst.st_mode)) {
                
                // 2. Folosim stat() pentru a verifica dacă DESTINAȚIA există
                if (stat(entry->d_name, &st) == -1) {
                    printf("Avertisment: S-a detectat un symlink orfan '%s'. Se curata...\n", entry->d_name);
                    
                    if (unlink(entry->d_name) == -1) {
                        perror("Eroare fatala la stergerea symlink-ului (unlink a esuat)");
                    } else {
                        printf("Symlink-ul '%s' a fost sters cu succes.\n", entry->d_name);
                    }
                }
            }
        }
    }
    closedir(dir);
}

//creearea(daca e nevoie) si initializarea fisierelor corespunzatoare directoryului corespunzator (district.cfg si simlinkurile)
void setup_district(const char *district_ID){
    char filepath[256];
    if(mkdir(district_ID,0750) == -1){
        //Directory deja existent
    }
    snprintf(filepath, sizeof(filepath), "%s/district.cfg", district_ID);

    int fd_cfg=open(filepath, O_CREAT | O_EXCL | O_WRONLY, 0640); //file descriptorul pentru fisierul cfg
    if(fd_cfg != -1){
        //acuma creem fisierul
        chmod(filepath,0640); //repetam punerea de permisiuni pe rw- r-- --- in caz ca aceasta a fost neconforma din cauza umask ului
        char *default_config="threshold=2\n";
        write(fd_cfg,default_config,strlen(default_config));
        close(fd_cfg);
    }

    char symlink_name[256];
    char target_name[256];
    snprintf(symlink_name, sizeof(symlink_name), "active_reports-%s",district_ID); //ne formam numele linkului simbolic
    snprintf(target_name, sizeof(target_name), "%s/reports.dat",district_ID);//formam pathul catre fisierul la care trebuie sa fie linkuit symlinkul
    struct stat st;
    if(lstat(symlink_name,&st)==-1){
        //nu exista link
        symlink(target_name,symlink_name); //il creem
    }
}

void mode_to_string(mode_t mode, char *str){
    strcpy(str,"---------");
    //User
    if(mode & S_IRUSR) str[0] = 'r';
    if(mode & S_IWUSR) str[1] = 'w';
    if(mode & S_IXUSR) str[2] = 'x';
    //Group
    if(mode & S_IRGRP) str[3] = 'r';
    if(mode & S_IWGRP) str[4] = 'w';
    if(mode & S_IXGRP) str[5] = 'x';
    //Other
    if(mode & S_IROTH) str[6] = 'r';
    if(mode & S_IWOTH) str[7] = 'w';
    if(mode & S_IXOTH) str[8] = 'x';
}

int verify_permision(const char *filepath, const char *role, char tip_acces){
    struct stat st;
    if(lstat(filepath,&st)==-1){
        fprintf(stderr,"Fisier inexistent\n");
        return 0;
    }

    if(strcmp(role,"manager")==0){
        //Verificam primii 3 biti pentru manager deoarece acesta este considerat Owner
        if(tip_acces=='r' && (st.st_mode & S_IRUSR)) return 1;
        if(tip_acces=='w' && (st.st_mode & S_IWUSR)) return 1;
        if(tip_acces=='x' && (st.st_mode & S_IXUSR)) return 1;
    }
    if(strcmp(role,"inspector")==0){
        //Inspectorul este considerat la GROUP acces asa ca verificam cei 3 biti din mijloc
        if(tip_acces=='r' && (st.st_mode & S_IRGRP)) return 1;
        if(tip_acces=='w' && (st.st_mode & S_IWGRP)) return 1;
        if(tip_acces=='x' && (st.st_mode & S_IXGRP)) return 1;
    }
    //nu avem nici un rol cunoscut care sa apartina cazului de OTHER
    return 0;
}

void log_action(const char *district, const char *role, const char *user, const char *action){
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/logged_district", district);
    int fd=open(filepath, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd==-1) return;//verificam doar daca exista ca sa putem apela functia stat pe el
    close(fd);
    chmod(filepath,0644); //fortam cu chmod permisiunile fisierului care s-ar putea sa fi fost tocmai acuma creat
    if(!verify_permision(filepath,role,'w')){
        printf("Acces interzis: Rolul '%s' nu are permisiunea de WRITE ('w') pe %s.\n", role, filepath);
        return;
    }
    fd=open(filepath,O_WRONLY | O_APPEND);
    char log_entry[512];
    time_t now=time(NULL);
    char *time_str=strtok(ctime(&now),"\n"); //salvam timpul curent intr-un string
    snprintf(log_entry,sizeof(log_entry),"[%s]User %s | Role %s | Action %s", time_str, user, role, action);
    write(fd, log_entry,strlen(log_entry));
    close(fd);
}

int add_report(const char *district, const char *role, const char *inspector_name, double lat, double lon, const char *category, int severity, const char *description){
    char filepath[256];
    snprintf(filepath,sizeof(filepath),"%s/reports.dat",district);
    int fd=open(filepath, O_RDWR | O_CREAT | O_APPEND, 0664);
    if(fd==-1){
        perror("Eroare la deschiderea/crearea reports.dat");
        return 0;
    }
    if(verify_permision(filepath,role, 'w')==0){
        printf("Rolul %s nu are permisiunea de a scrie in fisierul %s!\n",role,filepath);
        return 0;
    }
    chmod(filepath,0664);//fortam permisiunile pe 644(rw-rw-r--)
    Report new_report;
    //initializam toata structura cu 0 ca sa nu avem probleme cu octetii de padding care incearca sa fie scrisi in fisierul binar
    memset(&new_report,0,sizeof(Report));

    struct stat st;
    if(fstat(fd,&st) == 0 && st.st_size >=sizeof(Report)){ //verificam daca avem minim un report in fisier ca sa putem calcula urmatorul ID in functie de ID ul lui
        Report last_report;
        //citim ultimul report
        lseek(fd, -sizeof(Report),SEEK_END);//mutam cursorul la finalul fisierului - sizeof(Report)
        if(read(fd,&last_report,sizeof(Report))==sizeof(Report)){
            new_report.id=last_report.id+1;
        }else {
            new_report.id=1; //in caz de eroare
        }
    } else {
        //daca ii mai mic ca sizeof(Report) inseamna ca tocmai a fost creat fisierul sau este pur si simplu gol
        new_report.id=1;
    }
    //introducem toate valorile in structura
    strncpy(new_report.inspector,inspector_name,MAX_STR-1);
    new_report.lat=lat;
    new_report.lon=lon;
    strncpy(new_report.category, category, MAX_STR-1);
    new_report.severity=severity;
    new_report.timestamp=time(NULL); //timpul curent
    strncpy(new_report.description,description,MAX_DESC-1);

    ssize_t bytes_written=write(fd, &new_report,sizeof(Report)); //scriem totul in fisier
    if(bytes_written!=sizeof(Report)){//daca nu s-a scris totul in fisier scriem o eroare
        perror("Eroare la scrierea binara!!");
        close(fd);
        return 0;
    }
    printf("Raportul #%d a fost adaugat cu succes in %s\n",new_report.id,district);
    close(fd);
    return 1;
}

void list_reports(const char *district, const char *role){
    char filepath[256];
    snprintf(filepath,sizeof(filepath), "%s/reports.dat",district);
    if(verify_permision(filepath,role, 'r')==0){
        printf("Rolul %s nu are permisiunea de a citi din fisierul %s",role,filepath);
        return;
    }
    struct stat st;
    if(lstat(filepath,&st)==-1){
        printf("Nu exista rapoarte pentru districtul '%s' sau fisierul nu a putut fi accesat.\n", district);
        return;
    }

    char permisions[10];
    mode_to_string(st.st_mode, permisions); //apelam functia de transforma din mode in string

    char *mtime_str=strtok(ctime(&st.st_mtime),"\n"); //timpul ultimei modificari

    printf("\n--- Informatii fisier: %s ---\n", filepath);
    printf("Permisiuni: %s\n", permisions);
    printf("Dimensiune: %lld bytes\n", st.st_size);
    printf("Ultima modificare: %s\n", mtime_str);
    printf("---------------------------------------\n\n");

    int fd=open(filepath,O_RDONLY); //deschidem fisierul doar pentru citire
    if(fd==-1) return;

    Report r;
    int count=0;

    while(read(fd,&r,sizeof(Report))==sizeof(Report)){
        printf("[ID: %d] %s - Severitate: %d | Categorie: %s | Inspector: %s\n",
            r.id,strtok(ctime(&r.timestamp),"\n"),r.severity,r.category,r.inspector);
            count++;
    }
    if(count==0){
        printf("Nu exista rapoarte inregistrate in acest district.\n");
    }
    close(fd);
}

void view_report(const char *district, const char *role, int target_id){
    char filepath[256];
    snprintf(filepath,sizeof(filepath),"%s/reports.dat",district);
    if(verify_permision(filepath, role, 'r')==0){
        printf("Rolul %s nu are acces sa citeasca din fisierul %s!\n",role,filepath);
        return;
    }
    int fd=open(filepath,O_RDONLY);
    if(fd==-1){
        printf("Nu s-a putut deschide fisierul de reports!\n");
        return;
    }

    Report r;
    int found=0; //flag pentru a semnala ca am gasit reportul cu ID ul cautat

    while(read(fd,&r,sizeof(Report))==sizeof(Report)){
        if(r.id==target_id){
            printf("\n=== DETALII RAPORT #%d ===\n", r.id);
            printf("Data: %s", ctime(&r.timestamp)); // ctime pune automat \n la final
            printf("Inspector: %s\n", r.inspector);
            printf("Categorie: %s\n", r.category);
            printf("Severitate: %d\n", r.severity);
            printf("Coordonate GPS: %.6f, %.6f\n", r.lat, r.lon);
            printf("Descriere: %s\n", r.description);
            printf("==========================\n\n");
            found=1;
            break;
        }
    }
    if(found==0){
        printf("Nu am gasit reportul cu ID-ul %d in districtul %s",target_id,district);
    }
    close(fd);
}

int update_threshold(const char *district, const char *role, int new_threshold){
    char filepath[256];
    snprintf(filepath,sizeof(filepath), "%s/district.cfg" ,district);
    if(verify_permision(filepath, role, 'w')==0){
        printf("Rolul %s nu are permisiune de a scrie in fisierul %s",role,filepath);
        return 0;
    }
    struct stat st;
    if(lstat(filepath,&st)==-1){
        printf("Nu exista fisierul %s",filepath);
        return 0;
    }
    if((st.st_mode & 0777)!=0640){
        printf("Eroare de securitate!! Permisiunile fisierului au fost alterate (trebuie 640)");
        return 0;
    }
    int fd=open(filepath,O_WRONLY | O_TRUNC);
    if(fd==-1){
        printf("Eroare deschidere fisier %s",filepath);
        return 0;
    }
    char buffer[64];
    snprintf(buffer,sizeof(buffer),"Threshold = %d",new_threshold);
    write(fd,buffer,strlen(buffer));
    close(fd);

    printf("Pragul de severitate a fost schimbat pentru districtul %s\n",district);
    return 1;
}

int remove_report(const char *district, const char *role, int target_id){
    char filepath[256];
    snprintf(filepath,sizeof(filepath),"%s/reports.dat",district);
    if(verify_permision(district,role, 'w')==0){
        printf("Rolul %s nu are voie sa modifice strutura directorului %s",role,district);
        return 0;
    }
    int fd=open(filepath,O_RDWR);
    if(fd==-1){
        printf("Eroare deschidere fisier!\n");
        return 0;
    }
    Report r;
    off_t target_offset=-1;
    off_t current_offset=0;

    while(read(fd,&r,sizeof(Report))==sizeof(Report)){
        if(r.id==target_id){
            target_offset=current_offset;
            break;
        }
        current_offset+=sizeof(Report);
    }
    if(target_offset==-1){
        printf("Nu a fost gasit raportul cu ID-ul %d",target_id);
        close(fd);
        return 0;
    }

    off_t read_pos=target_offset +sizeof(Report);
    off_t write_pos = target_offset;

    while(1){
        lseek(fd,read_pos,SEEK_SET);
        ssize_t bytes_read = read(fd,&r,sizeof(Report));
        if(bytes_read<=0){
            break;
        }
        lseek(fd,write_pos,SEEK_SET);
        write(fd,&r,sizeof(Report)); //suprascriem peste reportul pe care vrem sa il stergem
        read_pos+=sizeof(Report);
        write_pos+=sizeof(Report);
    }
    if(ftruncate(fd, write_pos)==-1){
        printf("Eroare la trunchierea fisierului!\n");
        return 0;
    }else {
        printf("Raportul %d a fost sters cu succes!\n",target_id);
    }
    close(fd);
    return 1;
}

int parse_condition(const char *input, char *field, char *op, char *value) {
    // Verificăm pointerii pentru a preveni crash-uri
    if (!input || !field || !op || !value) {
        return 0;
    }

    // 1. Găsim primul ':'
    const char *first_colon = strchr(input, ':');
    if (!first_colon) {
        return 0; // Format invalid
    }

    // 2. Găsim al doilea ':'
    const char *second_colon = strchr(first_colon + 1, ':');
    if (!second_colon) {
        return 0; // Format invalid
    }

    // 3. Extragem 'field'
    size_t field_len = first_colon - input;
    strncpy(field, input, field_len);
    field[field_len] = '\0';

    // 4. Extragem 'operator'
    size_t op_len = second_colon - (first_colon + 1);
    strncpy(op, first_colon + 1, op_len);
    op[op_len] = '\0';

    // 5. Extragem 'value' (tot restul string-ului de după al doilea ':')
    strcpy(value, second_colon + 1);

    // 6. Validăm 'field' (suportate: severity, category, inspector, timestamp)
    int valid_field = (strcmp(field, "severity") == 0 ||
                       strcmp(field, "category") == 0 ||
                       strcmp(field, "inspector") == 0 ||
                       strcmp(field, "timestamp") == 0);

    // 7. Validăm 'operator' (suportate: ==, !=, <, <=, >, >=)
    int valid_op = (strcmp(op, "==") == 0 ||
                    strcmp(op, "!=") == 0 ||
                    strcmp(op, "<") == 0 ||
                    strcmp(op, "<=") == 0 ||
                    strcmp(op, ">") == 0 ||
                    strcmp(op, ">=") == 0);

    // Dacă vreuna din componente nu este validă, respingem condiția
    if (!valid_field || !valid_op) {
        return 0; 
    }

    return 1; // Succes
}

int match_condition(Report *r, const char *field, const char *op, const char *value) {
    // Verificăm pointerii pentru siguranță
    if (!r) {
        return 0;
    }

    // --- 1. Evaluare pentru câmpul 'severity' (Tip: int) ---
    if (strcmp(field, "severity") == 0) {
        int v = atoi(value); // Convertim string-ul în int
        
        if (strcmp(op, "==") == 0) return r->severity == v;
        if (strcmp(op, "!=") == 0) return r->severity != v;
        if (strcmp(op, "<") == 0)  return r->severity < v;
        if (strcmp(op, "<=") == 0) return r->severity <= v;
        if (strcmp(op, ">") == 0)  return r->severity > v;
        if (strcmp(op, ">=") == 0) return r->severity >= v;
    }
    
    // --- 2. Evaluare pentru câmpul 'timestamp' (Tip: time_t) ---
    else if (strcmp(field, "timestamp") == 0) {
        // time_t este de obicei un long integer (secunde de la Epoch)
        time_t v = (time_t)strtoll(value, NULL, 10);
        
        if (strcmp(op, "==") == 0) return r->timestamp == v;
        if (strcmp(op, "!=") == 0) return r->timestamp != v;
        if (strcmp(op, "<") == 0)  return r->timestamp < v;
        if (strcmp(op, "<=") == 0) return r->timestamp <= v;
        if (strcmp(op, ">") == 0)  return r->timestamp > v;
        if (strcmp(op, ">=") == 0) return r->timestamp >= v;
    }
    
    // --- 3. Evaluare pentru 'category' sau 'inspector' (Tip: string) ---
    else if (strcmp(field, "category") == 0 || strcmp(field, "inspector") == 0) {
        // Alegem ce câmp din structură verificăm
        const char *r_val = (strcmp(field, "category") == 0) ? r->category : r->inspector;
        
        // Comparam string-urile (returnează 0 pentru egal, <0 sau >0 altfel)
        int cmp = strcmp(r_val, value);
        
        if (strcmp(op, "==") == 0) return cmp == 0;
        if (strcmp(op, "!=") == 0) return cmp != 0;
        if (strcmp(op, "<") == 0)  return cmp < 0;
        if (strcmp(op, "<=") == 0) return cmp <= 0;
        if (strcmp(op, ">") == 0)  return cmp > 0;
        if (strcmp(op, ">=") == 0) return cmp >= 0;
    }
    // Dacă ajungem aici, câmpul sau operatorul nu este recunoscut
    return 0;
}


void filter_reports(const char *district_id, int condition_count, char *conditions[]) {
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/reports.dat", district_id);

    int fd = open(filepath, O_RDONLY);
    if (fd == -1) {
        printf("Nu s-a putut deschide fisierul de rapoarte pentru filtrare.\n");
        return;
    }

    Report r;
    int found_any = 0;

    printf("\n--- Rezultatele filtrarii pentru '%s' ---\n", district_id);

    // Citim binar structură cu structură
    while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
        int matches_all = 1; // Presupunem inițial că raportul trece testul

        // Trecem raportul prin toate condițiile date în terminal
        for (int i = 0; i < condition_count; i++) {
            char field[32], op[4], value[64];
            
            if (parse_condition(conditions[i], field, op, value)) {
                // Dacă PICĂ măcar o condiție, setăm flag-ul pe 0 și oprim bucla FOR
                if (!match_condition(&r, field, op, value)) {
                    matches_all = 0;
                    break; 
                }
            } else {
                printf("Avertisment: Conditia '%s' este scrisa gresit si a fost ignorata.\n", conditions[i]);
            }
        }

        // Dacă a trecut cu brio de TOATE condițiile, îl afișăm
        if (matches_all) {
            char *time_str = strtok(ctime(&r.timestamp), "\n");
            printf("[ID: %d] %s - Severitate: %d | Categ: %s | Insp: %s\n", 
                   r.id, time_str, r.severity, r.category, r.inspector);
            found_any = 1;
        }
    }

    if (!found_any) {
        printf("Niciun raport nu respecta criteriile selectate.\n");
    }

    close(fd);
}

int main(int argc, char *argv[]){
    char *role=NULL;
    char *user=NULL;
    char *district=NULL;
    char *operation=NULL;
    char *extra_arg=NULL;
    char *filter_conditions[10]; 
    int filter_count = 0;

    for(int i=1;i<argc;i++){

        //Parsarea lui argv pentru a separa fiecare input si pentru a alege tipul de operatie
        if(strcmp(argv[i],"--role")==0 && i+1<argc){role=argv[++i];}
        else if(strcmp(argv[i],"--user")==0 && i+1<argc){user=argv[++i];}
        else if(strcmp(argv[i],"--add")==0 && i+1<argc){operation="add"; district=argv[++i];}
        else if(strcmp(argv[i],"--list")==0 && i+1<argc){operation="list"; district=argv[++i];}
        else if(strcmp(argv[i],"--view")==0 && i+2<argc){operation="view"; district=argv[++i]; extra_arg=argv[++i];}
        else if(strcmp(argv[i],"--remove_report")==0 && i+2<argc){operation="remove"; district=argv[++i]; extra_arg=argv[++i];}
        else if(strcmp(argv[i],"--update_threshold")==0 && i+2<argc){operation="update"; district=argv[++i]; extra_arg=argv[++i];}
        else if(strcmp(argv[i], "--filter") == 0 && i + 1 < argc) {
            operation = "filter"; 
            district = argv[++i]; 
            
            // Cât timp mai avem argumente și ele NU încep cu "--" (adică nu sunt altă comandă)
            while (i + 1 < argc && strncmp(argv[i + 1], "--", 2) != 0) {
                filter_conditions[filter_count++] = argv[++i];
            }
        }

    }
    //conditia de a fi utilizat corect programul
    if(!role || !user || !district || !operation){
        fprintf(stderr,"Utilizare incorecta!(Exemplu: ./city_manager --role inpector --user adelin --add downtown)");
        return -1;
    }

    check_and_cleanup_symlinks();

    setup_district(district);
    if(strcmp(operation,"add")==0){
        double lat,lon;
        char category[MAX_STR];
        char desc[MAX_DESC];
        int severity;
        int c,i=0;
        printf("Introduceti informatiile despre report:\n");
        printf("===========================");
        printf("\nLatitudine: ");
        scanf("%lf",&lat);
        printf("Longitudine: ");
        scanf("%lf",&lon);
        printf("Categoria reportului: ");
        scanf("%s",category);
        printf("Severitate: ");
        scanf("%d",&severity);
        printf("Descriere succinta a reportului:");
        getchar();
        while((c=getchar())!='\n' && i<256) desc[i++]=c;
        add_report(district, role, user, lat, lon, category,severity, desc);
        log_action(district, role, user, "Added report\n");
    }
    else if (strcmp(operation,"list")==0) {
        list_reports(district,role);
        log_action(district,role,user,"Listed all reports\n");
    }
    else if (strcmp(operation,"view")==0){
        if(!extra_arg){
            printf("Operatia --view necesita un ID de raport.\n");
            return -1;
        }
        view_report(district,role, atoi(extra_arg));
        log_action(district, role, user,"Viewed report\n");
    }
    else if (strcmp(operation,"update")==0){
        if(!extra_arg){
            printf("Operatia --update_threshold are nevoie de un nou threshold.\n");
            return -1;
        }
        update_threshold(district,role, atoi(extra_arg));
        log_action(district,role,user,"Updated the threshold.\n");
    }
    else if (strcmp(operation, "remove")==0){
        if(!extra_arg){
            printf("Operatioa --remove_report are nevoie de un ID de report!\n");
            return -1;
        }
        if(remove_report(district,role, atoi(extra_arg))){
            log_action(district, role,user,"Removed a report.\n");
        }
    }
    else if (strcmp(operation, "filter") == 0) {
        if (filter_count == 0) {
            printf("Eroare: Comanda --filter necesita cel putin o conditie.\n");
            return -1;
        }
        filter_reports(district, filter_count, filter_conditions);
        log_action(district, role, user, "Filtered reports");
    }
    return 0;
}