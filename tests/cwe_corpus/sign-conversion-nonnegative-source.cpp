// Preselected safe fixture; see catalog.json. Parse/analyze only, never execute.
extern int read_value();
unsigned long f(){int value=read_value();if(value<0)return 0;return (unsigned long)value;}
