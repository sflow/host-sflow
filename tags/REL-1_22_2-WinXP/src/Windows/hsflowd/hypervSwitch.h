/*
 * Copyright (c) 2011 InMon Corp. ALL RIGHTS RESERVED
 * This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#ifndef HYPERVSWITCH_H
#define HYPERVSWITCH_H

#if defined(__cplusplus)
extern "C" {
#endif

void openFilter(HSP *sp);
ULONG_PTR setFilterSamplingParams(HSP *sp);
DWORD queueRead(HANDLE dev, PUCHAR buffer, DWORD bufferLen, LPOVERLAPPED overlap);
ULONG_PTR readFilterSwitchPorts(HSP *sp);
void readPackets(HSP *sp, PUCHAR buffer);

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif HYPERVSWITCH_H