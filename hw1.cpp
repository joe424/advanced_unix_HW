#include <iostream>
#include <vector>
#include <sstream>

#include <pwd.h>
#include <fcntl.h>
#include <errno.h>
#include <regex.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BUF_SIZE 512

using namespace std;

class INFO{
    public:
        string pid;
        string comm;
        string username;
        string fd;
        string type;
        string inode;
        string name;
};

void err_sys(string str) { 
    cerr << str << endl;
    exit(1);
} 

bool is_number(string str){
    string::const_iterator it = str.begin();
    while(it != str.end() && isdigit(*it)) ++it;
    return !str.empty() && it == str.end();
}

void print_field(){
    //cout << "COMMAND\tPID\tUSER\tFD\tTYPE\tNODE\tNAME\n";
    cout.width(38);
    cout << left << "COMMAND";
    cout.width(8);
    cout << left << "PID";
    cout.width(19);
    cout << left << "USER";
    cout.width(7);
    cout << left << "FD";
    cout.width(8);
    cout << left << "TYPE";
    cout.width(9);
    cout << left << "NODE";
    cout << left << "NAME";
    cout << endl;
}

void print_result(vector<INFO> info, string argC, string argT, string argF){
    regex_t regC, regF;
    regmatch_t pmatch[1];
    const size_t nmatch = 1;
    if(argC != "")
        regcomp(&regC, argC.c_str(), REG_EXTENDED);
    if(argF != "")
        regcomp(&regF, argF.c_str(), REG_EXTENDED);
    for(int i=0; i<info.size(); i++){
        if(argC != "" && regexec(&regC, (info[i].comm).c_str(), nmatch, pmatch, 0) == REG_NOMATCH)
            continue;
        if(argT != "" && argT != info[i].type)
            continue;
        if(argF != "" && regexec(&regF, (info[i].name).c_str(), nmatch, pmatch, 0) == REG_NOMATCH)
            continue;
        cout.width(38);
        cout << left << info[i].comm;
        cout.width(8);
        cout << left << info[i].pid;
        cout.width(19);
        cout << left << info[i].username;
        cout.width(7);
        cout << left << info[i].fd;
        cout.width(8);
        cout << left << info[i].type;
        cout.width(9);
        cout << left << info[i].inode;
        cout << left << info[i].name;
        cout << endl;
    }
    if(argC != "")
        regfree(&regC);
    if(argF != "")
        regfree(&regF);
}

string mode_determine(unsigned st_mod){
    if((st_mod & S_IRUSR) && (st_mod & S_IWUSR))
        return "u";
    else if(st_mod & S_IRUSR)
        return "r";
    else
        return "w";  
}

string type_determine(unsigned st_type){
    switch(st_type){
        case S_IFDIR:
            return "DIR";
        case S_IFREG:
            return "REG";
        case S_IFCHR:
            return "CHR";
        case S_IFIFO:
            return "FIFO";
        case S_IFSOCK:
            return "SOCK";
        default:
            return "unknown";
    }
}

int main(int argc, char *argv[]){

    if(argc % 2 != 1) /* must be odd */
        err_sys("argument no value");
    string argC = "", argT = "", argF = "";
    for(int i=1; i<argc; i++){
        if(i % 2 == 1){
            if((string)argv[i] == "-c")
                argC = argv[i + 1];
            else if((string)argv[i] == "-t")
                argT = argv[i + 1];
            else if((string)argv[i] == "-f")
                argF = argv[i + 1];
            else
                err_sys("invalid arguments");
        }
    }
    regex_t reg;
    if(argC != ""){
        if(regcomp(&reg, argC.c_str(), REG_EXTENDED) != 0){
            regfree(&reg);
            err_sys("-c's argument compile failed");
        }
        regfree(&reg);
    }
    if(argF != ""){
        if(regcomp(&reg, argF.c_str(), REG_EXTENDED) != 0){
            regfree(&reg);
            err_sys("-f's argument compile failed");
        }
        regfree(&reg);
    }

    vector<INFO> info;
    DIR *dp;
    struct dirent d, *p;
    
    print_field();
    
    if((dp = opendir("/proc")) == NULL)
        err_sys("cannot open directory \"proc\"");

    while(readdir_r(dp, &d, &p) == 0 && p != NULL){
        if(is_number(p->d_name)){
            INFO in;
            int fd;
            struct stat st;
            char buf[BUF_SIZE];
            memset(buf, NULL, BUF_SIZE);

            /* get pid */
            in.pid = p->d_name;

            /* get command name and user name */
            if((fd = open(("/proc/" + in.pid + "/comm").c_str(), O_RDONLY)) == -1)
                err_sys("cannot open file /proc/" + in.pid + "/comm");
            if((read(fd, buf, BUF_SIZE)) == -1)
                err_sys("cannot read file /proc/" + in.pid + "/comm");
            in.comm = ((string)buf).substr(0, ((string)buf).find("\n"));
            if((fstat(fd, &st)))
                err_sys("failed fstat file /proc/" + in.pid + "/comm");
            struct passwd *pws;
            pws = getpwuid(st.st_uid);
            in.username = pws->pw_name;
            close(fd);
            
            /* get cwd, root, exe's type, node, name */
            string fds[3] = {"cwd", "root", "exe"};
            for(int i=0; i<sizeof(fds)/sizeof(fds[0]); i++){
                memset(buf, NULL, BUF_SIZE);
                if((readlink(("/proc/" + in.pid + "/"  + fds[i]).c_str(), buf, BUF_SIZE)) == -1){
                    if(errno == 13 /* Permission denied */){
                        in.fd = fds[i];
                        in.type = "unknown";
                        in.inode = "";
                        in.name = "/proc/" + in.pid + "/"  + fds[i] + " (readlink: Permission denied)";
                    }else if(errno == 2 /* No such file or directory */){
                        continue;
                    }else{
                        cout << errno << endl;
                        cout << strerror(errno) << endl;
                        err_sys("readlink failed at /proc/" + in.pid + "/"  + fds[i]);
                    }
                }else{
                    in.fd = fds[i];
                    in.name = ((string)buf).substr(0, ((string)buf).find("\n"));
                    stat(("/proc/" + in.pid + "/"  + fds[i]).c_str(), &st);
                    in.type = type_determine(st.st_mode & S_IFMT);
                    in.inode = to_string(st.st_ino);
                }
                info.push_back(in);
            }

            /* mem */
            if((fd = open(("/proc/" + in.pid + "/maps").c_str(), O_RDONLY)) == -1){
                if(errno != 13 /* NOT Permission denied */){
                    cout << errno << ": " << strerror(errno) << endl;
                    err_sys("cannot open file /proc/" + in.pid + "/maps");
                }
            }else{
                string str = "";
                memset(buf, NULL, BUF_SIZE);
                while((read(fd, buf, BUF_SIZE)) > 0){
                    for(int i=0; i<BUF_SIZE; i++)
                        str += buf[i];
                    memset(buf, NULL, BUF_SIZE);
                }
                close(fd);
                str = str.substr(0, str.rfind("\n"));
                stringstream ss(str);
                string tmp = "";
                vector<string> paths;
                size_t found;
                while(getline(ss, tmp, '\n')){
                    found = tmp.find(":");
                    tmp = tmp.substr(found + 4, tmp.size() - found);
                    found = tmp.find("/");
                    if(found != string::npos){
                        if(paths.size() == 0 || paths[paths.size()-1] != tmp)
                            paths.push_back(tmp);
                    }
                }
                for(int i=0; i<paths.size(); i++){
                    tmp = paths[i];
                    found = tmp.find("/");
                    in.inode = to_string(stoi(tmp.substr(0, found)));
                    tmp = tmp.substr(found, tmp.size() - found);
                    found = tmp.find("(deleted)");
                    if(found != string::npos){
                        in.fd = "del";
                        in.name = tmp.substr(0, found - 1);
                        in.type = "unknown";
                    }else{
                        in.fd = "mem";
                        in.name = tmp;
                        stat(tmp.c_str(), &st);
                        in.type = type_determine(st.st_mode & S_IFMT);
                    }
                    info.push_back(in);
                }
                paths.clear();
                ss.str("");
                ss.clear();
            }

            /* /proc/[pid]/fd */
            DIR *fd_dir;
            if((fd_dir = opendir(("/proc/" + in.pid + "/fd").c_str())) == NULL){
                if(errno == 13 /* Permission denied */){
                    in.fd = "NOFD";
                    in.type = "";
                    in.inode = "";
                    in.name = "/proc/" + in.pid + "/fd (opendir: Permission denied)";
                    info.push_back(in);
                }else{
                    cout << errno << ": " << strerror(errno) << endl;
                    err_sys("cannot open directory /proc/" + in.pid + "/fd");
                }
            }else{
                struct dirent _d, *_p;
                while(readdir_r(fd_dir, &_d, &_p) == 0 && _p != NULL){
                    if(strcmp(_p->d_name, ".") != 0 && strcmp(_p->d_name, "..") != 0){
                        memset(buf, NULL, BUF_SIZE);
                        if((readlink(("/proc/" + in.pid + "/fd/" + _p->d_name).c_str(), buf, BUF_SIZE)) == -1){
                            cout << errno << ": " << strerror(errno) << endl;
                            err_sys("readlink failed at /proc/" + in.pid + "/fd/" + _p->d_name);
                        }else{
                            in.name = ((string)buf).substr(0, ((string)buf).find("\n"));
                            lstat(("/proc/" + in.pid + "/fd/" + _p->d_name).c_str(), &st);
                            in.fd = _p->d_name + mode_determine(st.st_mode);
                            in.type = type_determine(st.st_mode & S_IFMT);
                            in.inode = to_string(st.st_ino);
                        }
                        info.push_back(in);
                    }
                }
            }
            closedir(fd_dir);

        }
    }

    print_result(info, argC, argT, argF);
    closedir(dp);
}