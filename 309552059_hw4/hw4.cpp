#include <stdio.h>
#include <iostream>
#include <sstream>
#include <stdlib.h>
#include <vector>
#include <elf.h>
#include <fstream>
#include <cstring>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <inttypes.h>
#include <signal.h>
#include <capstone/capstone.h>

#define OPEN_SUCC 0
#define OPEN_FAIL 1
#define NOT_ELF 2
#define ELF32 1
#define ELF64 2
#define BUFFERSIZE 32
#define NOT_LOADED 0
#define LOADED 1
#define RUNNING 2

#define SWITCH_REG(name) \
	if(strcmp(regName, #name)==0){\
		printf("%s = %lld (0x%llx)\n", #name, pinfo->regs->name, pinfo->regs->name);\
		return;}
#define SET_REG(name)\
	if(strcmp(regName, #name)==0){\
		regs->name = regVal;\
		if(ptrace(PTRACE_SETREGS, pid, 0, regs)==0) return;\
		else return;}

using namespace std;

struct pInfo_t{
	pid_t pid;
	char name[64];
	char argv[16][16];
	int terminiated;
	int state;

	struct breakpointList_t *bplist;
	struct dump_t *dumpinfo;
	struct elf_t *elf;
	struct disasm_t *disasm;
	struct user_regs_struct *regs;
};
struct dump_t{
	unsigned long long dumpAddr;
	char dumpChar[16];
};
struct breakpointList_t{
	unsigned long long address;
	long code;
	struct breakpointList_t *next;
};
struct elf32_t{
	FILE *file;
	Elf32_Ehdr header;
	Elf32_Shdr strHeader;
	Elf32_Shdr textHeader;
	char strtab[65535];
	long text_flag;
	char *text_section;
};
struct elf64_t{
	FILE *file;
	Elf64_Ehdr header;
	Elf64_Shdr strHeader;
	Elf64_Shdr textHeader;
	char strtab[65535];	
	long text_flag;
	char *text_section;
	
};
struct elf_t{
	char *name;
	unsigned long entry;
	unsigned long text_addr;
	unsigned long text_offset;
	unsigned long text_size;
	long text_flag;
	char *text_section;
	int isDynamic;
	FILE* file;
};

struct pInfo_t* pinfo;
vector<string> commands;
vector<unsigned long long> bpRmByCont;

void read_script(string script){
    ifstream f(script);
    if(!f.good()){
		printf("script file not exist.\n");
        exit(0);
    }
    string str;
    while(getline(f, str))
        commands.push_back(str);
}

void elf64_init(struct elf64_t *elf, char* name){
	FILE *file = fopen(name, "rb");
	elf->file = file;
	//header
	fread(&(elf->header), 1, sizeof(Elf64_Ehdr), file);


	//str section header
	int strSectionHeaderOffset = elf->header.e_shoff + (elf->header.e_shstrndx)*sizeof(Elf64_Shdr);
	fseek(file, strSectionHeaderOffset, SEEK_SET);
	fread(&(elf->strHeader), 1, sizeof(Elf64_Shdr), file);

	// LOGD("size:%lx\n", elf->strHeader.sh_size);
	// LOGD("offset: %lx\n", elf->strHeader.sh_offset);
	//read str table in str section
	fseek(file, elf->strHeader.sh_offset, SEEK_SET);
	fread(elf->strtab, elf->strHeader.sh_size, sizeof(char), file);
}
void elf64_findtextHeader(struct elf64_t *elf){
	Elf64_Shdr tempHeader;
	//find .text header
	fseek(elf->file, elf->header.e_shoff, SEEK_SET);
	for(int i=0;i<elf->header.e_shnum;i++){
		fread(&tempHeader, 1, sizeof(Elf64_Shdr), elf->file);	
		if(strcmp((elf->strtab + tempHeader.sh_name), ".text") == 0){
			elf->textHeader = tempHeader;
			break;
		}
	}

	Elf64_Phdr pHeader;
	//find .text in thich segment
	fseek(elf->file, elf->header.e_phoff, SEEK_SET);
	for(int i=0;i<elf->header.e_phnum;i++){
		fread(&pHeader, 1, sizeof(Elf64_Phdr), elf->file);
		if(pHeader.p_vaddr <= elf->textHeader.sh_addr && 
				pHeader.p_vaddr+pHeader.p_memsz > elf->textHeader.sh_addr){
			elf->text_flag = pHeader.p_flags;
		}
	}
}
void elf64_gettextSection(struct elf64_t *elf){
	fseek(elf->file, elf->textHeader.sh_offset, SEEK_SET);
	elf->text_section = (char*)malloc(sizeof(char) * elf->textHeader.sh_size);
	fread(elf->text_section, elf->textHeader.sh_size, sizeof(char), elf->file);
}
void elf64_assign(struct elf_t *self, struct elf64_t *elf){
	self->entry = elf->header.e_entry;
	self->text_addr = elf->textHeader.sh_addr;
	self->text_offset = elf->textHeader.sh_offset;
	self->text_size = elf->textHeader.sh_size;
	self->text_flag = elf->text_flag;
	self->text_section = elf->text_section;
	self->isDynamic = elf->header.e_type==ET_DYN?1:0;
	self->file = elf->file;
}
void elf32_init(struct elf32_t *elf, string name){
	FILE *file = fopen(name.c_str(), "rb");
	elf->file = file;
	//header
	fread(&(elf->header), 1, sizeof(Elf32_Ehdr), file);


	//str section header
	int strSectionHeaderOffset = elf->header.e_shoff + (elf->header.e_shstrndx)*sizeof(Elf32_Shdr);
	fseek(file, strSectionHeaderOffset, SEEK_SET);
	fread(&(elf->strHeader), 1, sizeof(Elf64_Shdr), file);

	// LOGD("size:%x\n", elf->strHeader.sh_size);
	// LOGD("offset: %x\n", elf->strHeader.sh_offset);
	//read str table in str section
	fseek(file, elf->strHeader.sh_offset, SEEK_SET);
	fread(elf->strtab, elf->strHeader.sh_size, sizeof(char), file);
}
void elf32_findtextHeader(struct elf32_t *elf){
	Elf32_Shdr tempHeader;
	
	//find .text header
	fseek(elf->file, elf->header.e_shoff, SEEK_SET);
	for(int i=0;i<elf->header.e_shnum;i++){
		fread(&tempHeader, 1, sizeof(Elf32_Shdr), elf->file);	
		if(strcmp((elf->strtab + tempHeader.sh_name), ".text") == 0){
			elf->textHeader = tempHeader;
			break;
		}
	}	

	Elf32_Phdr pHeader;
	//find .text in thich segment
	fseek(elf->file, elf->header.e_phoff, SEEK_SET);
	for(int i=0;i<elf->header.e_phnum;i++){
		fread(&pHeader, 1, sizeof(Elf32_Phdr), elf->file);
		if(pHeader.p_vaddr <= elf->textHeader.sh_addr && 
				pHeader.p_vaddr+pHeader.p_memsz > elf->textHeader.sh_addr){
			elf->text_flag = pHeader.p_flags;
		}
	}
}
void elf32_gettextSection(struct elf32_t *elf){
	fseek(elf->file, elf->textHeader.sh_offset, SEEK_SET);
	elf->text_section = (char*)malloc(sizeof(char) * elf->textHeader.sh_size);
	fread(elf->text_section, elf->textHeader.sh_size, sizeof(char), elf->file);
}
void elf32_assign(struct elf_t *self, struct elf32_t *elf){
	self->entry = elf->header.e_entry;
	self->text_addr = elf->textHeader.sh_addr;
	self->text_offset = elf->textHeader.sh_offset;
	self->text_size = elf->textHeader.sh_size;
	self->text_flag = elf->text_flag;
	self->text_section = elf->text_section;
	self->isDynamic = elf->header.e_type==ET_DYN?1:0;
	self->file = elf->file;
}
int elf_check(char* name, int *type){
	char magic[5];

	FILE *file = fopen(name, "rb");
	if(file){
		fread(&magic, 5, sizeof(char), file);
		fclose(file);
		if(magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F' ){
			if(magic[4] == 0x02)
                *type = ELF64;
			else
                *type = ELF32;
			return OPEN_SUCC;
		}else
            return NOT_ELF;
	}else
        return OPEN_FAIL;	
}
void elf_init(struct elf_t **self, char* name, int type){
	(*self) = (struct elf_t*)malloc(sizeof(struct elf_t));
	(*self)->name = (char*)malloc(sizeof(char) * strlen(name));
	strcpy((*self)->name, name);

	if(type == ELF64){
		struct elf64_t elf64;
		elf64_init(&elf64, name);
		elf64_findtextHeader(&elf64);
		elf64_gettextSection(&elf64);
		elf64_assign((*self), &elf64);
	}else{
		struct elf32_t elf32;
		elf32_init(&elf32, name);
		elf32_findtextHeader(&elf32);
		elf32_gettextSection(&elf32);
		elf32_assign((*self), &elf32);	
	}
}

long get_startAddr(pid_t pid){
	size_t size = 128;
	char *line = (char*)malloc(sizeof(char) * size);
	char vmmapPath[128] = {'\0'};
	sprintf(vmmapPath, "/proc/%d/maps", pid);
	// LOGD("[INFO] vmmap path: %s\n", vmmapPath);

	FILE *fp = fopen(vmmapPath, "rb");
	getline(&line, &size, fp);	
	// LOGD("[INFO] vmmap line: %s", line);
	char startAddr[64] = {'\0'};
	sscanf(line, "%[^-]", startAddr);
	// LOGD("[INFO] start addr: %s\n", startAddr);
	long startAddrNum = strtol(startAddr, NULL, 16);
	// LOGD("[INFO] addrNum: %lx (%ld)\n", startAddrNum, startAddrNum);
	free(line);
	return startAddrNum;
}
long set_INT3(long relativeAddrPos, struct pInfo_t *pinfo){
	long addrPos = relativeAddrPos;
	if(pinfo->elf->isDynamic){
		long startAddr = get_startAddr(pinfo->pid);
		addrPos = startAddr + (relativeAddrPos);
	}
	long code = ptrace(PTRACE_PEEKTEXT, pinfo->pid, addrPos, 0);
	// LOGD("[INFO] INT3: addr:%lx, code: %lx pid:%d\n", addrPos, code, pinfo->pid);
	if(ptrace(PTRACE_POKETEXT, pinfo->pid, addrPos, (code & 0xffffffffffffff00) | 0xcc) != 0){
		// LOGD("[ERROR] set breakpoint fail\n");
	}
	// LOGD("[INFO] change byte code 0xcc succ\n");

	return code;
}
void init_regs(struct user_regs_struct **regs){
	(*regs) = (struct user_regs_struct*)malloc(sizeof(struct user_regs_struct));
}
void init_breakpoint_to_start(struct pInfo_t *pinfo){
	struct breakpointList_t *cur = pinfo->bplist;

	while(cur){
		// LOGD("[INFO] init bp to start: %llx\n", cur->address);
		long code = set_INT3(cur->address, pinfo);
		cur->code = code;
		cur = cur->next;
	}
}
int disasm_word(unsigned char* code, long addrNum, char **buffer){
	csh handle;

	if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return -1;
		
	cs_insn *insn;
	size_t count;

	count = cs_disasm(handle, code, sizeof(long), addrNum, 1, &insn);
	sprintf(*buffer, "0x%06lx: ",insn[0].address);
	char bytecode[64] = {'\0'};
	int spaceSize=20;
	for(int i=0;i<insn[0].size;i++){
		sprintf(*buffer, "%s%02x ", *buffer, insn[0].bytes[i]);
		spaceSize -= 3;
	}
	for(int i=0;i<spaceSize;i++) sprintf(*buffer, "%s ", *buffer);
	sprintf(*buffer, "%s\t%s\t%s", *buffer, insn[0].mnemonic, insn[0].op_str);

	return insn[0].size;	
}
int read_regs(struct user_regs_struct *regs, pid_t pid){
	// LOGD("[INFO] pid: %d\n", pid);
	// if(pid <= 0){
	// 	printf("** program not start up \n");
	// 	return 0;
	// }
	
	if(ptrace(PTRACE_GETREGS, pid, 0, regs)<0){
		// LOGD("[ERROR] get register fail\n");
		return 0;
	}
	
	return 1;
} 
void set_reg(struct user_regs_struct *regs, char *regName, long regVal, pid_t pid){
	// LOGD("[INFO] regName:%s regVal:%lu\n", regName, regVal);
	SET_REG(rax); SET_REG(rbx); SET_REG(rcx); SET_REG(rdx);
	SET_REG(r8);  SET_REG(r9);  SET_REG(r10); SET_REG(r11);
	SET_REG(r12); SET_REG(r13); SET_REG(r14); SET_REG(r15);
	SET_REG(rdi); SET_REG(rsi); SET_REG(rbp); SET_REG(rsp);
	SET_REG(rip);
	if(strcmp(regName, "flags")==0){
		regs->eflags = regVal;
		if(ptrace(PTRACE_SETREGS, pid, 0, regs)==0) return;
		else return;
		// else LOGD("[ERROR] set register fail\n"); return;
	}
	printf("** %s is not allowed\n", regName);
}
long get_breakpoint_code(struct breakpointList_t **self, unsigned long long stopaddr){
	struct breakpointList_t *cur = *self;
	
	while(cur){
		if(cur->address == stopaddr){
			return cur->code;
		}
		cur = cur->next;
	}

	return -1;
	
}
void recover_breakpoint(struct breakpointList_t **self, int id, pid_t pid){
	if(*self == NULL){
		printf("** no breakpoint\n");	
		return ;
	}

	struct breakpointList_t *cur = *self;
	struct breakpointList_t *prev = cur;
	int order = 0;
	while(cur){
		if(order == id){
			if(*self == cur && !(cur->next)) *self = NULL;
			if(*self == cur && cur->next) *self = cur->next;
			if(*self != cur) prev->next = cur->next;
			break;
		}
		prev = cur;
		cur = cur->next;
		order++;
	}
	if(order != id) {
		printf("** breakpoint id not allowed\n");
		return;
	}
	if(id < 0) return;
	if(ptrace(PTRACE_POKETEXT, pid, cur->address, cur->code)!=0) 
		// LOGD("[ERROR] restore bp fail\n");
		free(cur);
	printf("** breakpoint %d deleted\n", id);
}
long disasm_runtime(long addrNum, pid_t pid){
	long ret, code;
	unsigned char *byteCode = (unsigned char *)&ret;

	char *buffer = (char*)malloc(sizeof(char) * 128);
	int offset = 0;

	for(int i=0;i<10;i++){
		addrNum += offset;
		ret = ptrace(PTRACE_PEEKTEXT, pid, addrNum, 0);

		memset(buffer, '\0', 128);
		if((code = get_breakpoint_code(&pinfo->bplist, addrNum)) != -1)
			offset = disasm_word((unsigned char*)&code, addrNum, &buffer);
		else
			offset = disasm_word(byteCode, addrNum, &buffer);
		if(offset == 0) break;
		printf("\t%s\n", buffer);
	}
	free(buffer);

	return addrNum;
}
void dump_init(struct dump_t **self, char *addr){
	(*self) = (struct dump_t*)malloc(sizeof(struct dump_t));
	unsigned long long addrNum = strtol(addr, NULL, 0);
	(*self)->dumpAddr = addrNum;
} 
void dump_show(struct dump_t *self, pid_t pid){
	long ret;
	unsigned char *byteCode = (unsigned char *)&ret;
	int addrSize = sizeof(unsigned long long);
	unsigned char twoWordCode[16];

	for(int j=0;j<5;j++){
		printf("%05llx:  ", self->dumpAddr);
		ret = ptrace(PTRACE_PEEKTEXT, pid, self->dumpAddr, 0);
		for(int i=0;i<addrSize;i++) twoWordCode[i] = byteCode[i];
		self->dumpAddr += 8;
		ret = ptrace(PTRACE_PEEKTEXT, pid, self->dumpAddr, 0);
		for(int i=0;i<addrSize;i++) twoWordCode[i+8] = byteCode[i];
		self->dumpAddr += 8;

		//print byte code
		for(int i=0;i<addrSize*2;i++) printf("%02x ", twoWordCode[i]);
		printf(" ");

		//print byte code in char
		printf("|");
		for(int i=0;i<addrSize*2;i++){
			unsigned int thisNum = (unsigned int)twoWordCode[i];
			if(thisNum>=32 && thisNum<127) printf("%c", twoWordCode[i]);
			else printf(".");
		}
		printf("|");
		printf("\n");
	}
}

void load(char* program, stringstream& ss){
    memset(pinfo, 0, sizeof(struct pInfo_t));
    strcpy(pinfo->name, program);

	string str;
	int index = 0;
	strcpy((pinfo->argv)[index++], program);
	while(ss >> str){
		strcpy((pinfo->argv)[index], str.c_str());
		index++;
	}
	memset((pinfo->argv)[index], '\0', sizeof((pinfo->argv)[index]));
	for(int i = 0; i < sizeof((pinfo->argv)[index]); i++){
		(pinfo->argv)[index][i] = '\0';		
	}

    int type, status;
	if((status = elf_check(pinfo->name, &type)) == 0){
		elf_init(&(pinfo->elf), pinfo->name, type);
		pinfo->state = LOADED;
		printf("** program '%s' loaded. entry point 0x%06lx\n", pinfo->elf->name, pinfo->elf->entry);
		// printf("** program '%s' loaded. entry point 0x%08lx, vaddr 0x%08lx, offset 0x%02lx, size 0x%02lx\n",
		// 	pinfo->elf->name, pinfo->elf->entry, pinfo->elf->text_addr, pinfo->elf->text_offset, pinfo->elf->text_size);
	}else
		printf("** program '%s' not exist.\n", program);
}
void help(){
	printf("- break {instruction-address}: add a break point\n");
	printf("- cont: continue execution\n");
	printf("- delete {break-point-id}: remove a break point\n");
	printf("- disasm addr: disassemble instructions in a file or a memory region\n");
	printf("- dump addr [length]: dump memory content\n");
	printf("- exit: terminate the debugger\n");
	printf("- get reg: get a single value from a register\n");
	printf("- getregs: show registers\n");
	printf("- help: show this message\n");
	printf("- list: list break points\n");
	printf("- load {path/to/a/program}: load a program\n");
	printf("- run: run the program\n");
	printf("- vmmap: show memory layout\n");
	printf("- set reg val: get a single value to a register\n");
	printf("- si: step into instruction\n");
	printf("- start: start the program and stop at the first instruction\n");
}
void start(){
	if((pinfo->pid = fork()) < 0){
		printf("** fork failed\n");
		return;
	}else if(pinfo->pid == 0){
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
			exit(0);
		char** arg = new char*[17];
		for(int i=0, j=0; i<16; i++){
			if((pinfo->argv)[i][0] != '\0')
				arg[j++] = strdup((pinfo->argv)[i]);
			else{
				arg[j] == NULL;
				break;
			}
		}
		if(execvp(pinfo->name, arg) == -1){
			printf("** '%s' load fail, %s, try './%s'\n", pinfo->name, strerror(errno), pinfo->name);
			string tmp = "./" + (string)pinfo->name;
			arg[0] = strdup(tmp.c_str());
			if(execvp(arg[0], arg) == -1)
				printf("** './%s' load fail, '%s'.\n", pinfo->name, strerror(errno));
		}
	}else{
		int status;
		if(waitpid(pinfo->pid, &status, 0)<0){
			printf("child error\n");
			return ;
		}
		// if(WIFSTOPPED(status)) LOGD("[INFO]child stop\n");
		if(WIFSTOPPED(status));
		ptrace(PTRACE_SETOPTIONS, pinfo->pid, 0, PTRACE_O_EXITKILL|PTRACE_O_TRACESYSGOOD);
		printf("** pid %d\n", pinfo->pid);

		pinfo->state = RUNNING;
		pinfo->terminiated = 0;
		init_regs(&pinfo->regs);
		init_breakpoint_to_start(pinfo);
	}
}
void store_breakpoint(struct breakpointList_t **self, unsigned long long address, long code){
	struct breakpointList_t *temp;
	temp = (struct breakpointList_t *)malloc(sizeof(struct breakpointList_t));

	temp->address = address;
	temp->code = code;
	temp->next = NULL;

	if(*self == NULL){
		(*self) = temp;
		// LOGD("[INFO] fist breakpoint (%p)\n", (*self));
		return;
	}
	struct breakpointList_t *cur = *self;
	while(cur->next){
		cur = cur->next;
	}
	cur->next = temp;

}
void setBreakpoint(const char* addr){
	long addrPos = strtol(addr, NULL, 0);

	// if(!isRuntime(pinfo)){
	// 	store_breakpoint(&pinfo->bplist, addrPos, -1);
	// 	return;
	// }
	long code = set_INT3(addrPos, pinfo);
	store_breakpoint(&pinfo->bplist, addrPos, code);
}
void cont(){
	int status;

	if(bpRmByCont.size()){
		ptrace(PTRACE_SINGLESTEP, pinfo->pid, 0, 0);
		waitpid(pinfo->pid, &status, 0);
		struct breakpointList_t *cur = pinfo->bplist;
		while(bpRmByCont.size()){
			cur = pinfo->bplist;
			while(cur){
				if(cur->address == bpRmByCont[0]){
					set_INT3(cur->address, pinfo);
					break;
				}
				cur->next;
			}
			bpRmByCont.erase(bpRmByCont.begin());
		}
	}

	ptrace(PTRACE_CONT, pinfo->pid, 0, 0);
	waitpid(pinfo->pid, &status, 0);
	if(WIFSTOPPED(status) && !(WSTOPSIG(status)&0x80)){
		// LOGD("[INFO] process stop\n");
		if(read_regs(pinfo->regs, pinfo->pid)){
			unsigned long long stopaddr = pinfo->regs->rip - 1;
			long code;

			// LOGD("[INFO] stop addr: %llx\n", stopaddr);
			code = get_breakpoint_code(&pinfo->bplist, stopaddr);
			if(pinfo->elf->isDynamic){
				unsigned long long startaddr = get_startAddr(pinfo->pid);
				// LOGD("[INFO] (loding dynamic) stop addr in bp: %llx\n", stopaddr - startaddr);
				code = get_breakpoint_code(&pinfo->bplist,stopaddr-startaddr);
			}	
			// LOGD("[INFO] get bp: %ld\n", code);
			if(code != -1){
				// LOGD("[INFO] is break point\n");
				
				//restore rip (pc)
				string rip = "rip";
				set_reg(pinfo->regs, &rip[0], pinfo->regs->rip-1, pinfo->pid);
				// LOGD("[INFO] reset rip %llx\n", pinfo->regs->rip);
				
				//restore code
				if(ptrace(PTRACE_POKETEXT, pinfo->pid, stopaddr, code)!=0);
				bpRmByCont.push_back(stopaddr);
					// LOGD("[ERROR] restore bp fail\n");


				//disasm program bytecode
				char *buffer = (char*)malloc(sizeof(char) * 128);
				disasm_word((unsigned char*)&code, stopaddr, &buffer);
				string str = buffer;
				str.erase(str.begin()); str.erase(str.begin());
				printf("** breakpoint @ \t%s\n", str.c_str());
				free(buffer);
			}
		}	
	}
	if(WIFEXITED(status)){ 
		pinfo->terminiated = 1;
		printf("** child process %d terminiated normally (code %d)\n", pinfo->pid, status);
	}
}
void list(){
	struct breakpointList_t *cur = pinfo->bplist;
	int order = 0;

	while(cur){
		printf("  %d:   %06llx\n", order, cur->address);
		// LOGD("code: %lx\n", cur->code);
		cur = cur->next;
		order++;
	}
}
void getregs(){
	if(read_regs(pinfo->regs, pinfo->pid)){
		printf("RAX %-18llxRBX %-18llxRCX %-18llx RDX %-18llx\n", 
				pinfo->regs->rax, pinfo->regs->rbx, pinfo->regs->rcx, pinfo->regs->rdx);
		printf("R8  %-18llxR9  %-18llxR10 %-18llx R11 %-18llx\n", 
				pinfo->regs->r8, pinfo->regs->r9, pinfo->regs->r10, pinfo->regs->r11);
		printf("R12 %-18llxR13 %-18llxR14 %-18llx R15 %-18llx\n", 
				pinfo->regs->r12, pinfo->regs->r13, pinfo->regs->r14, pinfo->regs->r15);
		printf("RDI %-18llxRSI %-18llxRBP %-18llx RSP %-18llx\n", 
				pinfo->regs->rdi, pinfo->regs->rsi, pinfo->regs->rbp, pinfo->regs->rsp);
		printf("RIP %-18llxFLAGS %016llx\n", 
				pinfo->regs->rip, pinfo->regs->eflags);
	}
}
void quit(){
	if(pinfo->state == LOADED){
		fclose(pinfo->elf->file);
		free(pinfo->elf->text_section);
		free(pinfo->elf->name);
		free(pinfo->elf);
	}
	if(pinfo->state == RUNNING){
		kill(pinfo->pid, SIGTERM);
		free(pinfo->regs);
	}
	free(pinfo);
	exit(0);
}
void get(const char* regName){
	if(read_regs(pinfo->regs, pinfo->pid)){
		SWITCH_REG(rax); SWITCH_REG(rbx); SWITCH_REG(rcx); SWITCH_REG(rdx);
		SWITCH_REG(r8);  SWITCH_REG(r9);  SWITCH_REG(r10); SWITCH_REG(r11);
		SWITCH_REG(r12); SWITCH_REG(r13); SWITCH_REG(r14); SWITCH_REG(r15);
		SWITCH_REG(rdi); SWITCH_REG(rsi); SWITCH_REG(rbp); SWITCH_REG(rsp);
		SWITCH_REG(rip);
		if(strcmp(regName, "flags") == 0){
			printf("%s = %lld (0x%llx)\n", "flags", pinfo->regs->eflags, pinfo->regs->eflags);
			return;
		}
		printf("** %s is not allowed\n", regName);	
	}
}
void delete_breakpoint(const char* id){
	int idNum = (int)*id - (int)'0';
	recover_breakpoint(&pinfo->bplist, idNum, pinfo->pid);
}
void disasm(void* addr){
	/*if(!isRuntime(pinfo)){
		if(addr == NULL){
			if(disasm_hasLeft(pinfo->disasm)) disasm_show(pinfo->disasm);
			else printf("** no addr is given.\n");
				return;
		}

		if(disasm_textInit(pinfo, addr)) disasm_show(pinfo->disasm);	
	}else{*/
		static long addrNum = -1;
		if(addr == NULL){
			if(addrNum == -1){
				printf("** no addr is given.\n");
				return;
			}
		}
		else {
			addrNum = strtol((char*)addr, NULL, 0);
			if(pinfo->elf->isDynamic){
				long startAddr = get_startAddr(pinfo->pid);
				addrNum = startAddr + (addrNum-pinfo->elf->entry);
			}
		}
		addrNum = disasm_runtime(addrNum, pinfo->pid);
	/*}*/

}
void run(){
	if(pinfo->terminiated)
		cont();
	else{
		start();
		cont();
	}
}
void dump(char* addr){
	dump_init(&(pinfo->dumpinfo), addr);
	dump_show(pinfo->dumpinfo, pinfo->pid);	
}
void vmmap(){
	char map[32];
	sprintf(map, "/proc/%d/maps", pinfo->pid);
	ifstream f((string)map);
    if(!f.good())
		printf("** can't found '%s'\n", map);
    string str, str2;
	bool first = true;
    while(f >> str){
		/* 0000000000400000-0000000000401000  */
		istringstream ss(str);
		while(getline(ss, str2, '-')){
			for(int i=0; i<16-str2.size(); i++)
				printf("0");
			if(first){
				first = false;
				printf("%s-", str2.c_str());
			}
			else
				printf("%s ", str2.c_str());
		}
		first = true;
		
		/* r-x */
		f >> str;
		printf("%c%c%c ", str[0], str[1], str[2]);
		
		/* 0 */
		f >> str; f >> str; f >> str;
		printf("%-9s", str.c_str());

		/* /home/chuang/unix_prog/hw4_sdb/sample/hello64 */	
		f >> str;
		printf("%s\n", str.c_str());	
	}
}
void set(char* regName, char* value){
	if(read_regs(pinfo->regs, pinfo->pid)){
		long regVal = strtol(value, NULL, 0);
		set_reg(pinfo->regs, regName, regVal, pinfo->pid);
	}
}
void si(){
	if(ptrace(PTRACE_SINGLESTEP, pinfo->pid, 0, 0) == -1){
		// LOGD("[ERROR] sigle step fail\n");
	}
	// LOGD("[INFO] single step success");
}

void parse_command(string line){
	stringstream ss;
	string str;
	ss.str(line);
	if(ss >> str){
		if(str == "break" || str == "b"){
			if(!(ss >> str))
				printf("** no {instruction-address} is given.\n");
			else if(pinfo->state != RUNNING)
				printf("** program is not running.\n");
			else
				setBreakpoint(str.c_str());
		}
		else if(str == "cont" || str == "c"){
			if(pinfo->state != RUNNING)
				printf("** program is not running\n");
			else
				cont();
		}
		else if(str == "delete"){
			if(!(ss >> str))
				printf("** no {break-point-id} is given.\n");
			else if(pinfo->state != RUNNING)
				printf("** program is not running\n");
			else
				delete_breakpoint(str.c_str());
		}
		else if(str == "disasm" || str == "d"){
			if(pinfo->state != RUNNING)
				printf("** program is not running\n");
			else{
				if(ss >> str)
					disasm(&str[0]);
				else
					disasm(NULL);
			}
		}
		else if(str == "dump" || str == "x"){
			if(!(ss >> str))
				printf("** no addr is given.\n");
			else if(pinfo->state != RUNNING)
				printf("** program is not running\n");
			else
				dump(&str[0]);
		}
		else if(str == "exit" || str == "q"){
			quit();
		}
		else if(str == "get" || str == "g"){
			if(!(ss >> str))
				printf("** no reg is given.\n");
			else if(pinfo->state != RUNNING)
				printf("** program is not running\n");
			else
				get(str.c_str());
		}
		else if(str == "getregs"){
			if(pinfo->state != RUNNING)
				printf("** program is not running\n");
			else
				getregs();
		}
		else if(str == "help" || str == "h"){
			help();
		}
		else if(str == "list" || str == "l"){
			list();
		}
		else if(str == "load"){
			if(!(ss >> str))
				printf("** no {path/to/a/program} is given.\n");
			else if(pinfo->state != NOT_LOADED)
				printf("** the program is already loaded.\n");
			else
				load(&str[0], ss);
		}
		else if(str == "run" || str == "r"){
			if(pinfo->state == RUNNING){
				printf("** program %s is already running.\n", pinfo->name);
				cont();
			}
			else if(pinfo->state == NOT_LOADED)
				printf("** no program is loaded.\n");
			else
				run();
		}
		else if(str == "vmmap" || str == "m"){
			if(pinfo->state != RUNNING)
				printf("** program is not running\n");
			else
				vmmap();
		}
		else if(str == "set" || str == "s"){
			if(pinfo->state != RUNNING)
				printf("** program is not running\n");
			else{
				string str2;
				ss >> str;
				ss >> str2;
				set(&str[0], &str2[0]);
			}
		}
		else if(str == "si"){
			if(pinfo->state != RUNNING)
				printf("** program is not running\n");
			else
				si();
		}
		else if(str == "start"){
			if(pinfo->state == NOT_LOADED)
				printf("** no program is loaded.\n");
			else
				start();
		}
		else
			printf("** Undefined command: \"%s\".\n", str.c_str());
	}
	ss.str(""); ss.clear();
}

void sdb(){
	string line;
	if(commands.size() != 0){
		while(commands.size()){
			parse_command(commands[0]);
			commands.erase(commands.begin());
		}
		printf("Bye.\n");
	}else{
		printf("sdb> ");
		while(getline(cin, line, '\n')){
			parse_command(line);
			printf("sdb> ");
		}
	}
}

int main(int argc, char *argv[]){
	setvbuf(stdout, NULL, _IONBF, 0);
    pinfo = (struct pInfo_t*)malloc(sizeof(struct pInfo_t));
	pinfo->state = NOT_LOADED;
	// char *line = (char*)malloc(sizeof(char) * BUFFERSIZE);
	size_t buffersize = BUFFERSIZE;

    /* pass no arguments */
    if(argc == 1)
		sdb();
    /* pass only script */
    else if(argc == 3 && (string)argv[1] == "-s"){
        read_script((string)argv[2]);
        sdb();
    }
    /* pass script and program */
    else if((string)argv[1] == "-s"){
        read_script((string)argv[2]);
		stringstream ss;
		for(int i=4; i<argc; i++){
			ss << (string)argv[i];
			ss << " ";
		}
        load(argv[3], ss);
		sdb();
    }
	/* pass only program */
    else{
		stringstream ss;
		for(int i=2; i<argc; i++){
			ss << (string)argv[i];
			ss << " ";
		}
		load(argv[1], ss);
		sdb();
    }
}