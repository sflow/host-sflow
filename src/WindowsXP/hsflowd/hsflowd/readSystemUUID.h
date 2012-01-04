#if defined(__cplusplus)
extern "C" {
#endif

//http://cs.mipt.ru/docs/comp/eng/hardware/spec/sys_man_spec/main.pdf 

#define SMBIOS_TABLE_SYSTEM_INFORMATION 1
#define COBJMACROS

//3.1.2
typedef struct smbiosHeader
{
	uint8_t type;
	uint8_t length;
	uint16_t handle;
}smbiosHeader;


//3.3.2
typedef struct smbiosSystemInformation
{
	uint8_t type;
	uint8_t length;
	uint16_t handle;
	uint8_t manufacturer;
	uint8_t product_name;
	uint8_t version;
	uint8_t serial_number;
	uint8_t uuid[16];
	uint8_t wake_up_type;
}smbiosSystemInformation;

//http://msdn.microsoft.com/en-us/library/ms724379(VS.85).aspx
//typedef struct RawSMBIOSData
//{
//    BYTE	Used20CallingMethod;
//    BYTE	SMBIOSMajorVersion;
//    BYTE	SMBIOSMinorVersion;
//    BYTE	DmiRevision;
//    DWORD	Length;
//	BYTE	SMBIOSTableData[1];
//}RawSMBIOSData;
#if defined(__cplusplus)
} /* extern "C" */
#endif
