/**
 * File: installHelper.cpp
 * Author: Stuart Johnston
 * Version: $Id$
 * 
 * Functions to provide custom actions to the MSI installer.
 *
 * Copyright (C) InMon Corporation 2011 ALL RIGHTS RESERVED
 */

#include <windows.h>
#include <wchar.h>
#include <msi.h>
#include <msiquery.h>
#include <stdio.h>

#define MAX_LENGTH 64

#define POLLING_VALUE_PROPERTY L"POLLING_VALUE"
#define POLLING_VALIDATE_PROPERTY L"POLLING_VALIDATED"
#define POLLING_VALUE_DEFAULT 20
#define POLLING_VALUE_MIN 1
#define POLLING_VALUE_MAX 60
#define SAMPLING_VALUE_PROPERTY L"SAMPLING_VALUE"
#define SAMPLING_VALIDATE_PROPERTY L"SAMPLING_VALIDATED"
#define SAMPLING_VALUE_DEFAULT 256
#define SAMPLING_VALUE_MIN 1
#define SAMPLING_VALUE_MAX 65536
#define HYPERV_SERVICE L"vmms"
#define HYPERV_PRESENT_PROPERTY L"HYPERV_PRESENT"

/**
 * Cleans a string in property to make it an integer. If the value
 * of property starts with a '#', this is first removed. Then, if
 * the remaining value is a valid integer, which is within the bounds
 * provided, it is stored back into the property, as a string. If
 * the value is not an integer, or is outside the bounds, then defaultVal
 * is stored in the property.
 * @param handle the installer handle.
 * @param property the installer property to clean.
 * @param minValue the minimum value for property.
 * @param maxVal the maximum value for property.
 * @param defaultVal the default value for property.
 */
static VOID cleanStringToInt(MSIHANDLE handle, wchar_t *property,
                             int minVal, int maxVal, int defaultVal)
{
    wchar_t value[MAX_LENGTH];
    long result;
    DWORD length = MAX_LENGTH;
    UINT error = MsiGetProperty(handle, property, value, &length);
    if (error == ERROR_SUCCESS && length > 0) {
        wchar_t *start = value;
        if (value[0] == L'#') {
            start++;
            length--;
        }
        wchar_t *stop;
        result = wcstol(start, &stop, 10);
        if (result < minVal || result > maxVal) {
            result = defaultVal;
        }
    } else {
        result = defaultVal;
    }
    error = _ltow_s(result, value, MAX_LENGTH, 10);
    if (error == 0) {
        MsiSetProperty(handle, property, value);
    }
}

/**
 * Cleans the installer polling interval property.
 * @param handle the installer handle.
 * @return the success value of this function.
 */
extern "C" __declspec(dllexport) UINT cleanPollingInterval(MSIHANDLE handle)
{
    cleanStringToInt(handle, POLLING_VALUE_PROPERTY,
                     POLLING_VALUE_MIN, POLLING_VALUE_MAX, POLLING_VALUE_DEFAULT);
    return ERROR_SUCCESS;
}

/**
 * Cleans the installer sampling rate property.
 * @param handle the installer handle.
 * @return the success value of this function.
 */
extern "C" __declspec(dllexport) UINT cleanSamplingRate(MSIHANDLE handle)
{
    cleanStringToInt(handle, SAMPLING_VALUE_PROPERTY,
                     SAMPLING_VALUE_MIN, SAMPLING_VALUE_MAX, SAMPLING_VALUE_DEFAULT);
    return ERROR_SUCCESS;
}

/**
 * Removes leading and trailing white space from str, and returns
 * a pointer to the start of the trimmed string.
 * @param str the string to trim.
 * @return a pointer to the trimmed string.
 */
static wchar_t *trimWhitespace(wchar_t *str)
{
    wchar_t *end;
    // Trim leading space
    while(iswspace(*str)) {
        str++;
    }
    // Trim trailing space
    end = str+wcslen(str)-1;
    while(end > str && iswspace(*end)) {
        end--;
    }
    // Write new null terminator
    *(end+1) = 0;
    return str;
 }

/**
 * Validates the installer property, as an integer between minVal and maxVal.
 * validateProperty will be set to "1" if the value of property is valid, otherwise "0".
 * @param handle the installer handle.
 * @param property the property to validate.
 * @param validateProperty the property to set with the result of validation.
 * @param minVal the minimum allowed value of property.
 * @param maxVal the maximum allowed value of property.
 * @return TRUE if the property was validated, FALSE otherwise.
 */
static BOOL validateProperty(MSIHANDLE handle, wchar_t *property, wchar_t *validateProperty,
                             int minVal, int maxVal)
{
    wchar_t value[MAX_LENGTH];
    long result;
    BOOL valid = FALSE;
    DWORD length = MAX_LENGTH;
    UINT error = MsiGetProperty(handle, property, value, &length);
    if (error == ERROR_SUCCESS && length > 0) {
        wchar_t *stop;
        result = wcstol(trimWhitespace(value), &stop, 10);
        valid = stop != NULL && *stop == 0 && result >= minVal && result <= maxVal;
    }
    MsiSetProperty(handle, validateProperty, valid ? L"1" : L"0");
    return valid;
}

/**
 * Validates the UI edit fields.
 * @param handle the installer handle.
 * @return the success value of this function.
 */
extern "C" __declspec(dllexport) UINT validateUI(MSIHANDLE handle)
{
    if (validateProperty(handle, POLLING_VALUE_PROPERTY, POLLING_VALIDATE_PROPERTY,
                         POLLING_VALUE_MIN, POLLING_VALUE_MAX)) {
        cleanStringToInt(handle, POLLING_VALUE_PROPERTY,  // Remove characters such as + and -
                         POLLING_VALUE_MIN, POLLING_VALUE_MAX, POLLING_VALUE_DEFAULT);
    }
    if (validateProperty(handle, SAMPLING_VALUE_PROPERTY, SAMPLING_VALIDATE_PROPERTY,
                         SAMPLING_VALUE_MIN, SAMPLING_VALUE_MAX)) {
        cleanStringToInt(handle, SAMPLING_VALUE_PROPERTY,  // Remove characters such as + and -
                         SAMPLING_VALUE_MIN, SAMPLING_VALUE_MAX, SAMPLING_VALUE_DEFAULT);
    }
    return ERROR_SUCCESS;
}

/**
 * Tests whether Hyper-V is running or not, and sets HYPERV_PRESENT_PROPERTY appropriately.
 * @param handle the installer handle.
 * @return the success value of this function.
 */
extern "C" __declspec(dllexport) UINT testForHyperV(MSIHANDLE handle)
{
    SERVICE_STATUS_PROCESS serviceStatus; 
    DWORD bytesNeeded;
    SC_HANDLE serviceMgr = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, GENERIC_READ);
    BOOLEAN hyperVPresent = FALSE;
    if (serviceMgr != NULL) {
        SC_HANDLE service = OpenService(serviceMgr, HYPERV_SERVICE, GENERIC_READ);
        if (service != NULL) {
            if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                     (LPBYTE)&serviceStatus, sizeof(SERVICE_STATUS_PROCESS),
                                     &bytesNeeded)) {
                hyperVPresent = serviceStatus.dwCurrentState != SERVICE_STOPPED &&
                    serviceStatus.dwCurrentState != SERVICE_STOP_PENDING;
            }
            CloseServiceHandle(service); 
        }
        CloseServiceHandle(serviceMgr);
    }
    MsiSetProperty(handle, HYPERV_PRESENT_PROPERTY, hyperVPresent ? L"1" : L"0");
    return ERROR_SUCCESS;
}