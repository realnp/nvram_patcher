/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Pupyshev Nikita
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
/*
 * This file includes code from ios-kern-utils project licensed under the MIT License by Samuel Groß.
 * Copyright (c) 2014 Samuel Groß
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <mach/mach_init.h>
#include <mach/mach_error.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>
#include <mach/host_priv.h>
#include <mach/vm_map.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#define OFVARS_SEG_NAME "__DATA"
#define OFVARS_SECT_NAME "__data"
#define CSTRING_SEG_NAME "__TEXT"

#define MAX_CHUNK_SIZE 0x500

#if __LP64__
#define ADDR "%16lx"
#define IMAGE_OFFSET 0x2000
#define IMAGE_HEADER_SIZE sizeof(struct mach_header_64)
#define IMAGE_MAGIC MH_MAGIC_64
#define IMAGE_LC_SEGMENT LC_SEGMENT_64
#define IMAGE_DATA_ALIGNMENT 8
#else
#define ADDR "%8x"
#define IMAGE_OFFSET 0x1000
#define IMAGE_HEADER_SIZE sizeof(struct mach_header)
#define IMAGE_MAGIC MH_MAGIC
#define IMAGE_LC_SEGMENT LC_SEGMENT
#define IMAGE_DATA_ALIGNMENT 4
#endif

struct __attribute__((aligned(IMAGE_DATA_ALIGNMENT))) OFVariable {
	char   *variableName;
	uint32_t variableType;
	uint32_t variablePerm;
	int32_t variableOffset;
};
typedef struct OFVariable OFVariable;

bool validateOFVariables(struct OFVariable *ptr, unsigned int maxCount, vm_address_t cstringStart, vm_size_t cstringSize) {
	uint32_t currType = 1;
	int32_t currOfft = -1;
	
	uintptr_t variableName;
	uint32_t variableType;
	uint32_t variablePerm;
	int32_t variableOffset;
	for (unsigned int i = 0; i < maxCount; i++) {
		variableName = (uintptr_t)ptr->variableName;
		variableType = ptr->variableType;
		variablePerm = ptr->variablePerm;
		variableOffset = ptr->variableOffset;
		
		if (!variableName) {
			return i != 0;
		}
		if (variableName < cstringStart) {
			return false;
		}
		if (variableName >= (cstringStart + cstringSize)) {
			return false;
		}
		if (variableType > 4) {
			return false; //1-4
		}
		if (variablePerm > 3) {
			return false; //0-3
		}
		if (variableOffset <= currOfft) {
			if (variableOffset != -1) {
				return false;
			}
		} else {
			currOfft = variableOffset;
		}
		currType = variableType;
		ptr++;
	}
	return false;
}

vm_size_t read_kernel(task_t kernel_task, vm_address_t addr, unsigned char* buf, vm_size_t size) {
	kern_return_t ret;
	vm_size_t remainder = size;
	vm_size_t bytes_read = 0;
	
	vm_address_t end = addr + size;
	
	while (addr < end) {
		size = remainder > MAX_CHUNK_SIZE ? MAX_CHUNK_SIZE : remainder;
		
		ret = vm_read_overwrite(kernel_task, addr, size, (vm_address_t)(buf + bytes_read), &size);
		if (ret != KERN_SUCCESS || size == 0)
			break;
		
		bytes_read += size;
		addr += size;
		remainder -= size;
	}
	
	return bytes_read;
}

vm_size_t write_kernel(task_t kernel_task, vm_address_t addr, unsigned char* data, vm_size_t size) {
	kern_return_t ret;
	vm_size_t remainder = size;
	vm_size_t bytes_written = 0;
	
	vm_address_t end = addr + size;
	
	while (addr < end) {
		size = remainder > MAX_CHUNK_SIZE ? MAX_CHUNK_SIZE : remainder;
		
		ret = vm_write(kernel_task, addr, (vm_offset_t)(data + bytes_written), size);
		if (ret != KERN_SUCCESS)
			break;
		
		bytes_written += size;
		addr += size;
		remainder -= size;
	}
	
	return bytes_written;
}

vm_address_t get_kernel_base(task_t kernel_task) {
	kern_return_t ret;
	vm_region_submap_info_data_64_t info;
	vm_size_t size;
	mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
	unsigned int depth = 0;
	vm_address_t addr = 0; //todo: fix
	
	while (1) {
		ret = vm_region_recurse_64(kernel_task, &addr, &size, &depth, (vm_region_info_t)&info, &info_count);
		
		if (ret != KERN_SUCCESS) {
			printf("[-] error %i\n", ret);
			break;
		}
		
		if (size > 0x40000000)
			return addr + IMAGE_OFFSET;
		
		addr += size;
	}
	
	return 0;
}

int main(int argc, char *argv[]) {
	kern_return_t ret;
	task_t kernel_task = 0;
	
	ret = task_for_pid(mach_task_self(), 0, &kernel_task);
	if (ret != KERN_SUCCESS) {
		ret = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &kernel_task);
		if ((ret != KERN_SUCCESS) || !kernel_task) {
			printf("[-] Failed to access the kernel task (error %u).\n", ret);
			return -1;
		}
	}
	
	vm_address_t kernBase = get_kernel_base(kernel_task);
	if (kernBase == 0) {
		puts("[!] Failed to get kernel base.");
		return 0;
	}
	
	printf("[*] Kernel base is at %p.\n", (void *)kernBase);
	
	unsigned char buf[IMAGE_HEADER_SIZE];
	if (read_kernel(kernel_task, kernBase, buf, IMAGE_HEADER_SIZE) != IMAGE_HEADER_SIZE) {
		puts("[-] Kernel I/O failed.");
		return 0;
	}
	
#ifdef __LP64__
	struct mach_header_64 *header = (struct mach_header_64 *)&buf[0];
#else
	struct mach_header *header = (struct mach_header *)&buf[0];
#endif
	
	uint32_t magic = *(uint32_t *)&buf[0];
	if (magic != IMAGE_MAGIC) {
		puts("[-] Kernel Mach-O magic is invalid.");
		return 0;
	}
	
	uint32_t sizeofcmds = header->sizeofcmds;
	uint32_t ncmds = header->ncmds;
	
	void *lcBuf = malloc(sizeofcmds);
	if (!lcBuf) {
		puts("[-] Memory allocation error.");
		return 0;
	}
	if (read_kernel(kernel_task, kernBase + IMAGE_HEADER_SIZE, lcBuf, sizeofcmds) != sizeofcmds) {
		puts("[-] Kernel I/O failed.");
		return 0;
	}
	
	vm_address_t ofvarsSectionAddress = 0;
	vm_size_t ofvarsSectionSize = 0;
	vm_address_t cstringSectionAddress = 0;
	vm_size_t cstringSectionSize = 0;
	
	struct load_command *lcPtr = lcBuf;
	struct load_command *lcEndPtr = lcBuf + sizeofcmds;
	for (uint32_t i = 0; i < ncmds; i++) {
		if (lcPtr >= lcEndPtr) {
			puts("[-] Invalid size of load commands.");
			free(lcBuf);
			return 0;
		}
		
		if (lcPtr->cmd == IMAGE_LC_SEGMENT) {
#ifdef __LP64__
			struct segment_command_64 *cmd = (struct segment_command_64 *)lcPtr;
#else
			struct segment_command *cmd = (struct segment_command *)lcPtr;
#endif
			if (!strcmp(cmd->segname, OFVARS_SEG_NAME)) {
				uint32_t nsects = cmd->nsects;
#ifdef __LP64__
				struct section_64 *sect = (struct section_64 *)((uintptr_t)cmd + sizeof(*cmd));
#else
				struct section *sect = (struct section *)((uintptr_t)cmd + sizeof(*cmd));
#endif
				for (uint32_t j = 0; j < nsects; j++) {
					if (!strcmp(sect->sectname, OFVARS_SECT_NAME)) {
						ofvarsSectionAddress = sect->addr;
						ofvarsSectionSize = sect->size;
						printf("[+] Found "OFVARS_SEG_NAME"."OFVARS_SECT_NAME" section at address %p.\n", (void *)ofvarsSectionAddress);
						break;
					}
					sect++;
				}
			} else if (!strcmp(cmd->segname, CSTRING_SEG_NAME)) {
				uint32_t nsects = cmd->nsects;
#ifdef __LP64__
				struct section_64 *sect = (struct section_64 *)((uintptr_t)cmd + sizeof(*cmd));
#else
				struct section *sect = (struct section *)((uintptr_t)cmd + sizeof(*cmd));
#endif
				for (uint32_t j = 0; j < nsects; j++) {
					if (!strcmp(sect->sectname, "__cstring")) {
						cstringSectionAddress = sect->addr;
						cstringSectionSize = sect->size;
						printf("[+] Found "CSTRING_SEG_NAME".__cstring section at address %p.\n", (void *)cstringSectionAddress);
						break;
					}
					sect++;
				}
			}
		}
		
		lcPtr = (struct load_command *)((uintptr_t)lcPtr + lcPtr->cmdsize);
	}
	free(lcBuf);
	
	if (!ofvarsSectionAddress) {
		puts("[-] "OFVARS_SEG_NAME"."OFVARS_SECT_NAME" segment not found.");
		return 0;
	} else if (!cstringSectionAddress) {
		puts("[-] "CSTRING_SEG_NAME".__cstring section not found.");
		return 0;
	}
	
	puts("[*] Dumping "OFVARS_SEG_NAME"."OFVARS_SECT_NAME" section...");
	void *ofvarsSectionBuf = malloc(ofvarsSectionSize);
	if (!ofvarsSectionBuf) {
		puts("[-] Memory allocation error.");
		return 0;
	}
	
	puts("[*] Dumping "CSTRING_SEG_NAME".__cstring section...");
	void *cstringSectionBuf = malloc(cstringSectionSize);
	if (!cstringSectionBuf) {
		puts("[-] Memory allocation error.");
		free(ofvarsSectionBuf);
		return 0;
	}
	
	if (read_kernel(kernel_task, ofvarsSectionAddress, ofvarsSectionBuf, ofvarsSectionSize) != ofvarsSectionSize) {
		puts("[-] Kernel I/O failed.");
		free(ofvarsSectionBuf);
		free(cstringSectionBuf);
		return 0;
	}
	
	if (read_kernel(kernel_task, cstringSectionAddress, cstringSectionBuf, cstringSectionSize) != cstringSectionSize) {
		puts("[-] Kernel I/O failed.");
		free(ofvarsSectionBuf);
		free(cstringSectionBuf);
		return 0;
	}
	
	void *aLittleEndian = memmem(cstringSectionBuf, cstringSectionSize, "little-endian?", 15);
	if (!aLittleEndian) {
		puts("[-] \"little-endian?\" string not found.");
		free(ofvarsSectionBuf);
		free(cstringSectionBuf);
		return 0;
	}
	vm_address_t aLittleEndianAddress = aLittleEndian - cstringSectionBuf + cstringSectionAddress;
	
	void *ofvarsStart = memmem(ofvarsSectionBuf, ofvarsSectionSize, &aLittleEndianAddress, sizeof(aLittleEndianAddress));
	if (!ofvarsStart) {
		puts("[-] Unable to find \"little-endian?\" string xref.");
		free(ofvarsSectionBuf);
		free(cstringSectionBuf);
		return 0;
	}
	vm_offset_t ofvarsAddress = ofvarsSectionAddress + (ofvarsStart - ofvarsSectionBuf);
	vm_size_t ofvarsMaxSize = ofvarsSectionAddress + ofvarsSectionSize - ofvarsAddress;
	
	if (!validateOFVariables(ofvarsStart,ofvarsMaxSize/sizeof(struct OFVariable), cstringSectionAddress, cstringSectionSize)) {
		puts("[-] gOFVariables is corrupt.");
		free(ofvarsSectionBuf);
		free(cstringSectionBuf);
		return 0;
	}
	
	printf("[+] Found valid gOFVariables at %p.\n", (void *)ofvarsAddress);
	
	struct OFVariable *var = (struct OFVariable *)ofvarsStart;
	const char *name;
	while (var->variableName != NULL) {
		if (var->variablePerm == 3) {
			name = cstringSectionBuf + ((uintptr_t)var->variableName - cstringSectionAddress);
			var->variablePerm = 0;
			printf("[*] Edited permissions for %s.\n", name);
		}
		var++;
	}
	vm_size_t ofvarsSize = (void *)++var - ofvarsStart;
	
	puts("[*] Applying kernel patch...");
	if (write_kernel(kernel_task, ofvarsAddress, ofvarsStart, ofvarsSize) != ofvarsSize) {
		puts("[-] Kernel I/O failed.");
		free(ofvarsSectionBuf);
		free(cstringSectionBuf);
		return 0;
	}
	
	puts("[+] Done.");
	
	free(ofvarsSectionBuf);
	free(cstringSectionBuf);
	
	return 0;
}
