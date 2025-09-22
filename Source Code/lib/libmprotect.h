#pragma once

#include "ps5/kernel.h"
#include <ps5/klog.h>

static const unsigned long KERNEL_OFFSET_PROC_P_VMSPACE = 0x200;
static unsigned long KERNEL_OFFSET_VMSPACE_P_ROOT = 0x1c8;

//
// This function is from the latest SDK, etaHEN break it's execution with it. So while we don't fix it, let's place this useful function here
//
static int kernel_mprotect(int pid, unsigned long addr, unsigned long len, int prot) 
{ 
  unsigned long vm_map_entry_addr;
  unsigned long vmspace_addr;
  unsigned long proc_addr;
  unsigned char vm_prot;
  unsigned long start;
  unsigned long end;

  switch(kernel_get_fw_version() & 0xffff0000) {
    case 0x1000000:
    case 0x1010000:
    case 0x1020000:
      KERNEL_OFFSET_VMSPACE_P_ROOT  = 0x1c0;
      break;
  
    case 0x1050000:
    case 0x1100000:
    case 0x1110000:
    case 0x1120000:
    case 0x1130000:
    case 0x1140000:
      KERNEL_OFFSET_VMSPACE_P_ROOT  = 0x1c0;
      break;
  
    case 0x2000000:
      KERNEL_OFFSET_VMSPACE_P_ROOT  = 0x1c8;
      break;
  
    case 0x2200000:
    case 0x2250000:
    case 0x2260000:
    case 0x2300000:
    case 0x2500000:
    case 0x2700000:
      KERNEL_OFFSET_VMSPACE_P_ROOT  = 0x1c8;
      break;
  
    case 0x3000000:
    case 0x3100000:
    case 0x3200000:
    case 0x3210000:
      KERNEL_OFFSET_VMSPACE_P_ROOT  = 0x1c8;
      break;
  
    case 0x4020000:
      KERNEL_OFFSET_VMSPACE_P_ROOT  = 0x1c8;
      break;
  
    case 0x4000000:
    case 0x4030000:
    case 0x4500000:
    case 0x4510000:
      KERNEL_OFFSET_VMSPACE_P_ROOT  = 0x1c8;
      break;
  
    case 0x5000000:
    case 0x5020000:
    case 0x5100000:
    case 0x5500000:
      KERNEL_OFFSET_VMSPACE_P_ROOT  = 0x1c8;
      break;
  
    case 0x6000000:
    case 0x6020000:
    case 0x6500000:
      KERNEL_OFFSET_VMSPACE_P_ROOT  = 0x1d0;
      break;
  
    case 0x7000000:
    case 0x7010000:
    case 0x7200000:
    case 0x7400000:
    case 0x7600000:
    case 0x7610000:
    case 0x8000000:
    case 0x8200000:
    case 0x8400000:
    case 0x8600000:
    case 0x9000000:
    case 0x9200000:
    case 0x9400000:
    case 0x9600000:
      KERNEL_OFFSET_VMSPACE_P_ROOT  = 0x1d0;
      break;

    default:
      klog_printf("Unknown firmware: 0x%08x\n", kernel_get_fw_version());
      return -1;
  }

  if(!(proc_addr=kernel_get_proc(pid))) {
    return -1;
  }

  if(kernel_copyout(proc_addr + KERNEL_OFFSET_PROC_P_VMSPACE,
                    &vmspace_addr, sizeof(vmspace_addr))) {
    return -1;
  }

  if(kernel_copyout(vmspace_addr + KERNEL_OFFSET_VMSPACE_P_ROOT, &vm_map_entry_addr, sizeof(vm_map_entry_addr))) {
    return -1;
  }

  while(vm_map_entry_addr) {
    if(kernel_copyout(vm_map_entry_addr + 0x20, &start, sizeof(start))) {
      return -1;
    }
    if(kernel_copyout(vm_map_entry_addr + 0x28, &end, sizeof(end))) {
      return -1;
    } 

    if(addr < start) {
      // left
      if(kernel_copyout(vm_map_entry_addr + 0x10, &vm_map_entry_addr,
                        sizeof(vm_map_entry_addr))) {
        return -1;
      }
    } else if(addr >= end) {
      // right
      if(kernel_copyout(vm_map_entry_addr + 0x18, &vm_map_entry_addr,
                        sizeof(vm_map_entry_addr))) {
        return -1;
      }
    } else {
      // protection
      if(kernel_copyout(vm_map_entry_addr + 0x64, &vm_prot, sizeof(vm_prot))) {
        return -1;
      }
      vm_prot |= prot;
      if(kernel_copyin(&vm_prot, vm_map_entry_addr + 0x64, sizeof(vm_prot))) {
        return -1;
      }

      // max_protection
      if(kernel_copyout(vm_map_entry_addr + 0x65, &vm_prot, sizeof(vm_prot))) {
        return -1;
      }
      vm_prot |= prot;
      if(kernel_copyin(&vm_prot, vm_map_entry_addr + 0x65, sizeof(vm_prot))) {
        return -1;
      }

      return 0;
    }
  }

  return -1;
}
