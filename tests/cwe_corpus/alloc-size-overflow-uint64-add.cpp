// Preselected buggy fixture; see catalog.json. Parse/analyze only, never execute.
typedef __SIZE_TYPE__ size_t;
extern void* malloc(size_t);
extern size_t read_size();
void* f(){size_t n=read_size();return malloc(n+16);}
