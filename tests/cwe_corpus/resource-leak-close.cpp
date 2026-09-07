// Preselected safe fixture; see catalog.json. Parse/analyze only, never execute.
extern int open(const char*,int,...);
extern int close(int);
void f(){int fd=open("input",0);if(fd>=0)close(fd);}
