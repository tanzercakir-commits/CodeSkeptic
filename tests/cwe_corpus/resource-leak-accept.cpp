// Preselected buggy fixture; see catalog.json. Parse/analyze only, never execute.
extern int open(const char*,int,...);
extern int close(int);
struct sockaddr;
extern int accept(int,sockaddr*,unsigned int*);
void f(int listener){int fd=accept(listener,nullptr,nullptr);(void)fd;}
