#define COUNTER_MAX 4294967296
uint32_t readSingleCounter(char* path);
uint32_t readMultiCounter(char* path, PPDH_RAW_COUNTER_ITEM *ppBuffer);