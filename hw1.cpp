#include <iostream>
#include <vector>

#include <pwd.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BUF_SIZE 100

using namespace std;

class INFO{
    public:
        string pid;
        string comm;
        string username;
        string fd;
        string type;
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

int main(int argc, char *argv[]){
    
    vector<INFO> info;
    DIR *dp;
    struct dirent d, *p;
    
    //cout << "COMMAND\tPID\tUSER\tFD\tTYPE\tNODE\tNAME\n";
    cout.width(20);
    cout << left << "COMMAND";
    cout.width(7);
    cout << left << "PID";
    cout.width(10);
    cout << left << "USER";
    cout << endl;
    
    if((dp = opendir("/proc")) == NULL)
        err_sys("cannot open directory \"proc\"");

    while(readdir_r(dp, &d, &p) == 0 && p != NULL){
        if(is_number(p->d_name)){
            INFO in;
            int fd;
            struct stat st;
            struct passwd *pws;
            string str = "";            
            char buf[BUF_SIZE];
            memset(buf, NULL, BUF_SIZE);

            in.pid = p->d_name;

            if((fd = open(("/proc/" + in.pid + "/comm").c_str(), O_RDONLY)) == -1)
                err_sys("cannot open file /proc/" + in.pid + "/comm");

            if((read(fd, buf, BUF_SIZE)) == -1)
                err_sys("cannot read file /proc/" + in.pid + "/comm");

            for(int i=0; i<BUF_SIZE; i++){
                if(buf[i] == '\n')
                    break;
                str += buf[i];
            }
            in.comm = str;

            if((fstat(fd, &st)))
                err_sys("failed fstat file /proc/" + in.pid + "/comm");
            pws = getpwuid(st.st_uid);
            in.username = pws->pw_name;

            close(fd);
            info.push_back(in);
        }
    }

    for(int i=0; i<info.size(); i++){
        cout.width(20);
        cout << left << info[i].comm;
        cout.width(7);
        cout << left << info[i].pid;
        cout.width(10);
        cout << left << info[i].username;
        cout << endl;
    }


    closedir(dp);
}