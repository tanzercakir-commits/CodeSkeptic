// Preselected buggy fixture; see catalog.json. Parse/analyze only, never execute.
extern void* memcpy(void*,const void*,__SIZE_TYPE__);
void f(){char dst[4]={},src[2]={};memcpy(dst,src,3);}
