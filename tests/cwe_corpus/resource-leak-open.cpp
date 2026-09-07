// Preselected buggy fixture; see catalog.json. Parse/analyze only, never execute.
extern int open(const char*,int,...);
extern int close(int);
void f(){int fd=open("input",0);(void)fd;}
