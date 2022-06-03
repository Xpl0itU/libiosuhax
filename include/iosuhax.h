/***************************************************************************
 * Copyright (C) 2016
 * by Dimok
 *
 * This software is provided 'as-is', without any express or implied
 * warranty. In no event will the authors be held liable for any
 * damages arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any
 * purpose, including commercial applications, and to alter it and
 * redistribute it freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you
 * must not claim that you wrote the original software. If you use
 * this software in a product, an acknowledgment in the product
 * documentation would be appreciated but is not required.
 *
 * 2. Altered source versions must be plainly marked as such, and
 * must not be misrepresented as being the original software.
 *
 * 3. This notice may not be removed or altered from any source
 * distribution.
 ***************************************************************************/
#pragma once

#include <coreinit/filesystem.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Deprecated: Use FS_STAT_DIRECTORY
#ifndef DIR_ENTRY_IS_DIRECTORY
#define DIR_ENTRY_IS_DIRECTORY FS_STAT_FILE
#endif

#define FSA_MOUNTFLAGS_BINDMOUNT (1 << 0)
#define FSA_MOUNTFLAGS_GLOBAL    (1 << 1)

int IOSUHAX_UnlockFSClient(FSClient *client);

int IOSUHAX_FSAMount(FSClient *client, const char *source, const char *target);
int IOSUHAX_FSAMountEx(int clientHandle, const char *source, const char *target);

int IOSUHAX_FSAUnmount(FSClient *client, const char *mountedTarget);
int IOSUHAX_FSAUnmountEx(int clientHandle, const char *mountedTarget);

int IOSUHAX_FSARawOpen(FSClient *client, char *device_path, int32_t *outHandle);
int IOSUHAX_FSARawOpenEx(int clientHandle, char *device_path, int32_t *outHandle);

int IOSUHAX_FSARawRead(FSClient *client, void *data, uint32_t size_bytes, uint32_t cnt, uint64_t blocks_offset, int device_handle);
int IOSUHAX_FSARawReadEx(int clientHandle, void *data, uint32_t size_bytes, uint32_t cnt, uint64_t blocks_offset, int device_handle);

int IOSUHAX_FSARawWrite(FSClient *client, const void *data, uint32_t size_bytes, uint32_t cnt, uint64_t blocks_offset, int device_handle);
int IOSUHAX_FSARawWriteEx(int clientHandle, const void *data, uint32_t size_bytes, uint32_t cnt, uint64_t blocks_offset, int device_handle);

int IOSUHAX_FSARawClose(FSClient *client, int32_t device_handle);
int IOSUHAX_FSARawCloseEx(int clientHandle, int32_t device_handle);

int IOSUHAX_Open(const char *dev); // if dev == NULL the default path /dev/iosuhax will be used
int IOSUHAX_Close(void);

int IOSUHAX_memwrite(uint32_t address, const uint8_t *buffer, uint32_t size); // IOSU external input
int IOSUHAX_memread(uint32_t address, uint8_t *out_buffer, uint32_t size);    // IOSU external output
int IOSUHAX_memcpy(uint32_t dst, uint32_t src, uint32_t size);                // IOSU internal memcpy only

int IOSUHAX_kern_write32(uint32_t address, uint32_t value);

int IOSUHAX_kern_read32(uint32_t address, uint32_t *out_buffer, uint32_t count);

int IOSUHAX_read_otp(uint8_t *out_buffer, uint32_t size);

int IOSUHAX_read_seeprom(uint8_t *out_buffer, uint32_t offset, uint32_t size);

int IOSUHAX_ODM_GetDiscKey(uint8_t *discKey);

int IOSUHAX_SVC(uint32_t svc_id, uint32_t *args, uint32_t arg_cnt);

#ifdef __cplusplus
}
#endif