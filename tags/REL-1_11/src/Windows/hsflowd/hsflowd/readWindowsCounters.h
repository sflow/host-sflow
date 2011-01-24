#define COUNTER_MAX 4294967296
uint64_t readSingleCounter(char* path);
uint32_t readMultiCounter(char* path, PPDH_RAW_COUNTER_ITEM *ppBuffer);
uint64_t readFormattedCounter(char* path);