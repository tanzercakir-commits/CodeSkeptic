// Preselected buggy fixture; see catalog.json. Parse/analyze only, never execute.
extern int open(const char*,int,...);
extern int close(int);
extern int pipe(int*);
void f(){int fds[2];if(pipe(fds)!=0)return;}
