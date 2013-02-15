#define COUNTER_INSTANCE_TOTAL L"_Total"
#define COUNTER_INSTANCE_ALL L"*"

#define NIO_COUNTER_OBJECT L"Network Interface"
#define NIO_COUNTER_BYTES_IN L"Bytes Received/sec"
#define NIO_COUNTER_BYTES_OUT L"Bytes Sent/sec"
#define NIO_COUNTER_PACKETS_IN L"Packets Received/sec"
#define NIO_COUNTER_PACKETS_OUT L"Packets Sent/sec"
#define NIO_COUNTER_ERRORS_IN L"Packets Received Errors"
#define NIO_COUNTER_ERRORS_OUT L"Packets Outbound Errors"
#define NIO_COUNTER_DISCARDS_IN L"Packets Received Discarded"
#define NIO_COUNTER_DISCARDS_OUT L"Packets Outbound Discarded"

#define DISK_COUNTER_OBJECT L"PhysicalDisk"
#define DISK_COUNTER_READS L"Disk Reads/sec"
//time in 100ns units (counterType=542573824, PERF_PRECISION_100NS_TIMER)
#define DISK_COUNTER_READ_TIME L"% Disk Read Time"
#define DISK_COUNTER_READ_BYTES L"Disk Read Bytes/sec"
#define DISK_COUNTER_WRITES L"Disk Writes/sec"
//time in 100ns units (counterType=542573824, PERF_PRECISION_100NS_TIMER)
#define	DISK_COUNTER_WRITE_TIME L"% Disk Write Time"
#define DISK_COUNTER_WRITE_BYTES L"Disk Write Bytes/sec"

#define SYS_COUNTER_OBJECT L"System"
#define SYS_COUNTER_PROC_QLEN L"Processor Queue Length"
#define SYS_COUNTER_CONTEXTS L"Context Switches/sec"
#define SYS_COUNTER_UPTIME L"System Up Time"
#define SYS_COUNTER_PROCESSES L"Processes"

#define CPU_COUNTER_OBJECT L"Processor"
//time in 100ns units (counterType=542180608, PERF_100NSEC_TIMER)
#define CPU_COUNTER_TIME L"% Processor Time"
#define CPU_COUNTER_USER L"% User Time"
#define CPU_COUNTER_SYSTEM L"% Privileged Time"
#define CPU_COUNTER_IDLE L"% Idle Time"
#define CPU_COUNTER_INTR L"% Interrupt Time"
#define CPU_COUNTER_INTERRUPTS L"Interrupts/sec"

#define THR_COUNTER_OBJECT L"Thread"
#define THR_COUNTER_STATE L"Thread State"

#define MEM_COUNTER_OBJECT L"Memory"
#define MEM_COUNTER_CACHE L"Cache Bytes"
#define MEM_COUNTER_PAGE_IN L"Pages Input/sec"
#define MEM_COUNTER_PAGE_OUT L"Pages Output/sec"

#define IF_COUNTER_OBJECT L"Hyper-V Virtual Switch Port"
#define IF_COUNTER_BYTES_IN L"Bytes Received/sec"
#define IF_COUNTER_BYTES_OUT L"Bytes Sent/sec"
#define IF_COUNTER_PACKETS_IN L"Directed Packets Received/sec"
#define IF_COUNTER_PACKETS_OUT L"Directed Packets Sent/sec"
#define IF_COUNTER_MULTICASTS_IN L"Multicast Packets Received/sec"
#define IF_COUNTER_MULTICASTS_OUT L"Multicast Packets Sent/sec"
#define IF_COUNTER_BROADCASTS_IN L"Broadcast Packets Received/sec"
#define IF_COUNTER_BROADCASTS_OUT L"Broadcast Packets Sent/sec"
#define IF_COUNTER_DISCARDS_IN L"Dropped Packets Incoming/sec"
#define IF_COUNTER_DISCARDS_OUT L"Dropped Packets Outgoing/sec"

#define VNIO_COUNTER_OBJECT L"Hyper-V Virtual Network Adapter"
#define VNIO_COUNTER_BYTES_IN L"Bytes Received/sec"
#define VNIO_COUNTER_BYTES_OUT L"Bytes Sent/sec"
#define VNIO_COUNTER_PACKETS_IN L"Directed Packets Received/sec"
#define VNIO_COUNTER_PACKETS_OUT L"Directed Packets Sent/sec"
#define VNIO_COUNTER_DISCARDS_IN L"Dropped Packets Incoming/sec"
#define VNIO_COUNTER_DISCARDS_OUT L"Dropped Packets Outgoing/sec"

#define VDISK_COUNTER_OBJECT L"Hyper-V Virtual Storage Device"
#define VDISK_COUNTER_READ_BYTES L"Read Bytes/sec"
#define VDISK_COUNTER_WRITE_BYTES L"Write Bytes/sec"
#define VDISK_COUNTER_READS L"Read Count"
#define VDISK_COUNTER_WRITES L"Write Count"
#define VDISK_COUNTER_ERRORS L"Error Count"

#define VMEM_COUNTER_OBJECT L"Hyper-V Dynamic Memory VM"
#define VMEM_COUNTER_MAX L"Guest Visible Physical Memory"
#define VMEM_COUNTER_PHYS L"Physical Memory" 
#define VMEM_COUNTER_PRESSURE L"Current Pressure"

#define VCPU_COUNTER_OBJECT L"Hyper-V Hypervisor Virtual Processor"
//time in 100ns units (counterType=542573824, PERF_PRECISION_100NS_TIMER)
#define VCPU_COUNTER_CPU_TIME L"% Guest Run Time"

#define tick_to_ms 10000 //divide by this to convert 100ns tick to ms

PDH_STATUS makeSingleCounterQuery(wchar_t *object, wchar_t *instance, wchar_t *counterName,
								  PDH_HQUERY *query, PDH_HCOUNTER *counter);
PDH_STATUS addCounterToQuery(wchar_t *object, wchar_t *instance, wchar_t *counterName,
							 PDH_HQUERY *query, PDH_HCOUNTER *counter);
LONGLONG getRawCounterValue(PDH_HCOUNTER *counter);
uint32_t getRawCounterValues(PDH_HCOUNTER *counter, PPDH_RAW_COUNTER_ITEM_W *values);
LONGLONG getCookedCounterValue(PDH_HCOUNTER *counter);