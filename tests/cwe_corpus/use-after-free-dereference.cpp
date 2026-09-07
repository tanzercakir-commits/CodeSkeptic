// Preselected buggy fixture; see catalog.json. Parse/analyze only, never execute.
int f(){int* p=new int(7);delete p;return *p;}
