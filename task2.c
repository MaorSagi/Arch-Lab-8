#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "elf.h"

char* filename;
int current_fd;
void* map_start;
struct stat fd_stat;
Elf64_Ehdr *header;
int debug_mode;
int unit_size;
char* data_pointer;
char* getType(int num);

void set_file_name_handler(){
    char tmp[100];
    printf("Please enter filename:\n");
    fgets(tmp,100,stdin);
    while(tmp[0]=='\t'||tmp[0]==' '){
            strncpy(tmp,tmp+1,strlen(tmp));
    }
    if(filename==NULL)
        filename=malloc(sizeof(char)*strlen(tmp));
    else{
        free(filename);
        filename=malloc(sizeof(char)*strlen(tmp));
    }
    strncpy(filename,tmp,strlen(tmp)-1);
}

int open_and_mmap(){
   int fd;
    if( (fd = open(filename, O_RDWR)) < 0 ) {
      perror("Error: open file\n");
      exit(-1);
   }

   if( fstat(fd, &fd_stat) != 0 ) {
      perror("stat failed\n");
      exit(-1);
   }

   if ( (map_start = mmap(0, fd_stat.st_size, PROT_READ , MAP_SHARED, fd, 0)) == MAP_FAILED ) {
      perror("mmap failed\n");
      exit(-4);
   }
    header = (Elf64_Ehdr *) map_start;
    return fd;
    
    
}
void toggle_debug_mode_handler(){
    char input[10];
    printf("Set debug mode:\n");
    fgets(input,10,stdin);
    sscanf(input,"%d",&debug_mode);
    if(debug_mode!='1' || debug_mode!='0'){
        perror("Invalid input\n");
        return;
    }
}
void examine_elf_file_handler(){
    set_file_name_handler();
    if(current_fd!=-1){
        close(current_fd);
    }
    int fd = open_and_mmap();
    int rc;
   if((header->e_ident[0]!=0x7f)||(header->e_ident[1]!=0x45)||(header->e_ident[2]!=0x4c)||(header->e_ident[3]!=0x46)){
       perror("Error: not elf\n");
       if((rc = munmap(map_start, fd_stat.st_size))!=0){
        perror("Error: unmap file\n");
        exit(-1);
        }
       close(fd);
       current_fd=-1;
}
   else{
        current_fd=fd;
        printf("\n");
        printf("ELF Header:\n  Magic:   %x %x %x\n",header->e_ident[EI_MAG1],header->e_ident[EI_MAG2],header->e_ident[EI_MAG3]);
        printf("  Data:                              ");
        switch(header->e_ident[EI_DATA]){
            case ELFDATANONE:
                printf("Invalid data encoding");
                break;
            case ELFDATA2LSB:
                printf("2's complement, little endian");
                break;
            case ELFDATA2MSB:
                printf("2's complement, big endian");
                break;
            
        }
        printf("\n");
        printf("  Entry point address:               0x%x\n",header->e_entry);
        printf("  Start of section headers:          %lu (bytes into file)\n",header->e_shoff);
        printf("  Number of section headers:         %d\n",header->e_shnum);
        printf("  Size of section headers:           %d (bytes)\n",header->e_shentsize);
        printf("  Start of program headers:          %lu (bytes into file)\n",header->e_phoff);
        printf("  Number of program headers:         %d\n",header->e_phnum);
        printf("  Size of program headers:           %d (bytes)\n",header->e_phentsize);
        printf("\n");
}
   

}
  char* get_section_name(unsigned int i){
 Elf64_Shdr* shdr = map_start+(header->e_shoff)+(sizeof(Elf64_Shdr)*header->e_shstrndx);//+map_start=string tbl
 return (map_start+shdr->sh_offset)+i; 
 
}



void print_section_names_handler(){
    if(current_fd==-1){
        printf("Error: No open file\n");
        return;
    }
    unsigned long offset;
    Elf64_Shdr* shdr = map_start+header->e_shoff;
    printf("\n");
    printf("Section Headers:\n");
    printf("  [Nr]\tName\t\t\tType\t\t\t\tAddress\t\t\t\t\tOffset\t\t\t\tEntSize\n");
    offset= 0;
    for(int i = 0; i<header->e_shnum;i++){
        char* name = get_section_name(shdr->sh_name);
        if(shdr->sh_type<20)
        printf("  [ %d]\t%s\t\t\t%s\t\t\t\t%016x\t\t\t%08x\t\t\t%016x\n",i,name,getType((int)shdr->sh_type),shdr->sh_addr,shdr->sh_offset,shdr->sh_size);
        else
        printf("  [ %d]\t%s\t\t\t%s\t\t\t%016x\t\t\t%08x\t\t\t%016x\n",i,name,getType((int)shdr->sh_type),shdr->sh_addr,shdr->sh_offset,shdr->sh_size);
        offset= offset+sizeof(Elf64_Shdr);
        shdr=map_start+header->e_shoff+offset;
        
        //TO DO debug_mode: print also important indices and offsets (as shstrndx and section name offsets)
    }
    
}
void print_symbols_handler(){
     if(current_fd==-1){
        printf("Error: No open file\n");
        return;
    }
    printf("\n");
    printf("Symbol table:\n");
    printf("  [Nr]\t\tValue\t\t\tSection Idx\t\tSection Name\t\tSymbol Name\n");
    unsigned long offset;
    Elf64_Shdr* shdr = map_start+header->e_shoff;
    offset=0;
     
    for(int i = 0; i<header->e_shnum;i++){
        
    
        if(shdr->sh_type==SHT_SYMTAB||shdr->sh_type==SHT_DYNSYM){
    Elf64_Sym* symdr = map_start+shdr->sh_offset;
    unsigned long sym_offset;
    sym_offset=0;
    for(int j=0; j<(shdr->sh_size/sizeof(Elf64_Sym));j++){
        char* name;
        Elf64_Shdr* tmp = map_start+header->e_shoff;
        if(symdr->st_shndx==0||symdr->st_shndx==65521)name="";
        else name = get_section_name(tmp[symdr->st_shndx].sh_name);
        printf("  [ %d]\t\t%016x\t\t%d\t\t%s\t\t\t%s\n",j,symdr->st_value,symdr->st_shndx,name,map_start+tmp[shdr->sh_link].sh_offset+symdr->st_name); //shdr->sh_link <=> idx of string table section
        //TO DO debug_mode: print size of symbol table,num of symbols
        sym_offset=sym_offset+sizeof(Elf64_Sym);
        symdr= map_start+shdr->sh_offset+sym_offset;
    }
     }
    offset= offset+sizeof(Elf64_Shdr);
    shdr=map_start+header->e_shoff+offset;
    }
}



void quit_handler(){
    //unmapped close map and open files (throw errors)
    int rc;
    if((rc = munmap(map_start, fd_stat.st_size))!=0){
        perror("Error: unmap file");
        exit(-1);
    }
    exit(0);
}


char* getType(int num){

    switch(num){
        case 0: return "NULL";
        case 1: return "PROGBITS";
        case 2: return "SYMTAB";
        case 3: return "STRTAB";
        case 4: return "RELA";
        case 5: return "HASH";
        case 6: return "DYNAMIC";
        case 7: return "NOTE";
        case 8: return "NOBITS";
        case 9: return "REL";
        case 10: return "SHLIB";
        case 11: return "SYNSYM";
        case 14: return "INIT_ARRAY";
        case 15: return "FINI_ARRAY";
        case 16: return "PREINIT_ARRAY";
        case 17: return "GROUP";
        case 18: return "SYMTAB_SHNDX";
        case 19: return "NUM";
        case 0x60000000: return "LOOS";
        case 0x6ffffff7: return "GNU_LIBLIST";
        case 0x6ffffff8: return "CHECKSUM";
        case 0x6ffffffa: return "LOSUNW";
        case 0x6ffffffb: return "GNU_COMDAT";
        case 0x6ffffffc: return "GNU_syminfo";
        case 0x6ffffffd: return "GNU_verdef";
        case 0x6ffffffe: return "GNU_verneed";
        case 0x6fffffff: return "HIOS";
        case 0x70000000: return "LOPROC";
        case 0x7fffffff: return "HIPROC";
        case 0x80000000: return "LOUSER";
        case 0x8fffffff: return "HIUSER";
    }
    return"";
}


int main(int argc, char **argv) {
    debug_mode=0;
    map_start=NULL;
    current_fd=-1;
    filename=NULL;
     void (*func_ptr_arr[])()={toggle_debug_mode_handler,examine_elf_file_handler,print_section_names_handler,print_symbols_handler,quit_handler};
    char input[2048];
    printf("------------\nChoose action:\n0-Toggle Debug Mode\n1-Examine ELF File\n2-Print Section Names\n3-Print Symbols\n4-Quit\n------------\n");
    fgets(input,2048,stdin);
    while(1){
        if(input[0]=='\n')
            printf("Invalid input\n");
        if(input[0]=='\t'||input[0]==' '){
            strncpy(input,input+1,strlen(input));
            continue;
        }
        if(input[0]!='0'&&input[0]!='1'&&input[0]!='2'&&input[0]!='3'&&input[0]!='4')
            printf("Invalid input\n");
        else{
         
        (*func_ptr_arr[atoi(input)])();  
        }
        printf("------------\nChoose action:\n0-Toggle Debug Mode\n1-Examine ELF File\n2-Print Section Names\n3-Print Symbols\n4-Quit\n------------\n");
        fgets(input,2048,stdin);
    }
    
    return 0;
}