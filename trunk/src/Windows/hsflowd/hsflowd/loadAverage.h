#include <math.h>

HANDLE initLoadAverageThread(void);
DWORD WINAPI LoadAverageProc( LPVOID lpParam );
double getCpuLoad(void);
