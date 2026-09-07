// Preselected unknown fixture; see catalog.json. Parse/analyze only, never execute.
extern void write_value(int*);
int f(){int value;write_value(&value);return value;}
