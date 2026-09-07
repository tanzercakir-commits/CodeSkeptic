// Preselected safe fixture; see catalog.json. Parse/analyze only, never execute.
int f(){int* p=new int(7);int result=*p;delete p;return result;}
