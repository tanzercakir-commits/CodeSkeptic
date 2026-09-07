// Preselected safe fixture; see catalog.json. Parse/analyze only, never execute.
extern int open(const char*,int,...);
extern int close(int);
struct Owner{int fd;explicit Owner(int v):fd(v){}~Owner(){if(fd>=0)::close(fd);}Owner(const Owner&)=delete;Owner& operator=(const Owner&)=delete;};
void f(){Owner owner(open("one",0));}
