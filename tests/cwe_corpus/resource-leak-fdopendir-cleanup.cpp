// Preselected safe fixture; see catalog.json. Parse/analyze only, never execute.
extern int open(const char*,int,...);
extern int close(int);
struct Directory;
extern Directory* fdopendir(int);
extern int closedir(Directory*);
void f(){int fd=open("one",0);if(fd<0)return;Directory* dir=fdopendir(fd);if(!dir){close(fd);return;}closedir(dir);}
