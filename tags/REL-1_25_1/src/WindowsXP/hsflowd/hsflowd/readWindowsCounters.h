#define COUNTER_MAX 4294967296

//define counters used here
#define CPU_PERCENT_USER_TIME 1852
#define CPU_PERCENT_PRIVILEGED_TIME 1854


uint64_t readSingleCounter(char* path);
uint32_t readMultiCounter(char* path, PPDH_RAW_COUNTER_ITEM *ppBuffer);
uint64_t readFormattedCounter(char* path);