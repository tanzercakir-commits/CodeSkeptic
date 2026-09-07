// Preselected buggy fixture; see catalog.json. Parse/analyze only, never execute.
typedef __SIZE_TYPE__ size_t;
extern void* malloc(size_t);
extern size_t read_size();
void* f(){size_t n=read_size(),bytes;bool overflow=__builtin_add_overflow(n,16,&bytes);overflow=false;if(overflow)return 0;return malloc(bytes);}
