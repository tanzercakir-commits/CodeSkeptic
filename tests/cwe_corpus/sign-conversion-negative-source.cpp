// Preselected buggy fixture; see catalog.json. Parse/analyze only, never execute.
extern int read_value();
unsigned long f(){int value=read_value();return (unsigned long)value;}
