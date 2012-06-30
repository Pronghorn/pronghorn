/* libpronghorn Subcontractor template
 * Copyright (C) 2012 Department of Defence Australia
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * \file subcontractor_partitiontable.c
 * \brief This subcontractor is responsible for identifying and parsing partition tables.
 * Given an input block, the subcontractor will determine whether the current block (boot record)
 * contains a valid partition table. It does this by checking the following:
 *  - Confirming boot record block tags (0x55 0xaa)
 *  - Checking the start chs < end chs
 *  - We have a valid boot status (0x80 or 0x00)
 *  - We don't have overlapping regions
 *  - We have a valid partition type
 */
#include <stdio.h>
#include <string.h>
#include <math.h>

#include <logger.h>
#include <config.h>
#include <blocks.h>

#include "subcontractor_helper.h"

/** Partition table offset into the Boot Record */
#define BR_OFFSET 446
/** Boot Record block size */
#define BLOCK_SIZE 512
/** Starting value for Extended Partitions */
#define START_EXT_PART_NUM 5
/** Integer representation for a Master Boot Record */
#define TYPE_MBR 10
/** Integer representation for an Extended Boot Record */
#define TYPE_EBR 11
/** Integer representation for the "Top" level in the partition structure */
#define LVL_TOP 12
/** Integer representation for other levels (ie. Not the top layer )in the partition structure */
#define LVL_LOW 13

/** Supported file types */
unsigned int supported_file_types[] = { MAGIC_TYPE_PART, 0 };

/**
 * CHS Structure.Ccontains the head/sector/cylinder information for a given CHS address.
 *
 */
struct chs_info
{
  unsigned char head;
  unsigned char sector;
  short cylinder;
};

/**
 * Partition structure. Contains relevant information about a given partition.
 */
struct partition_info
{
  unsigned char bootable_flag;  /* 0x80 - Bootable. 0x00 - Not bootable. Anything else is invalid */
  unsigned int partition_number;        /* Partition number in the partition structure */
  unsigned char type;           /* Integer value representing the partition type */
  struct chs_info chs_start;    /* Starting CHS address Struct */
  struct chs_info chs_end;      /* Starting CHS address Struct */
  unsigned long long lba_first_sect;    /* first LBA sector */
  unsigned int num_sectors;     /* Number of sectors in partitions */

  /* Re-added these for now.... */
  unsigned char active_partition;
  struct partition_info *extended_partition;
};

/**
 * Used to return a "meaningful" partition identifier based on the partition ID.
 * \param part_type_id The numerical type (ID) of the current partition.
 * \returns String representing the partition type.
 */
static const char *get_part_type(unsigned char part_type_id)
{
  switch (part_type_id)
  {
  case 0x00:
    return "Empty";
  case 0x01:
    return "FAT12(32MB)";
  case 0x02:
    return "XENIX Root";
  case 0x03:
    return "XENIX User";
  case 0x04:
    return "FAT16(32MB)";
  case 0x05:
    return "Extended(CHS)";
  case 0x06:
    return "FAT16B";
  case 0x07:
    return "IFS/HPFS/NTFS/exFAT/qnx";
  case 0x08:
    return "FAT12(Log)/FAT16(Log)/AIX/qny/OS2";
  case 0x09:
    return "AIX(boot)/qnz/Coherent(FS)";
  case 0x0A:
    return "OS2(boot)/Coherent(swap)/Unisys(OPUS)";
  case 0x0B:
    return "FAT32(CHS)";
  case 0x0C:
    return "FAT32X(LBA)";
  case 0x0E:
    return "FAT16X(LBA)";
  case 0x0F:
    return "Extended(LBA)";
  case 0x11:
    return "FAT12(Log)/FAT16(Log)/FAT12(Hidden)";
  case 0x12:
    return "Configuration/Hibernation/Diagnostics/Service/Rescue Partitions";
  case 0x14:
    return "FAT12(Log)/FAT16(Log)/FAT16(Hidden)";
  case 0x15:
    return "Extended(Hidden & CHS)";
  case 0x16:
    return "FAT16B(Hidden)";
  case 0x17:
    return "IFS(Hidden)/HPFS(Hidden)/NTFS(Hidden)/exFAT(Hidden)";
  case 0x18:
    return "AST Zero Volt Suspend/SmartSleep";
  case 0x19:
    return "Willowtech Photon coS";
  case 0x1B:
    return "FAT32(Hidden)";
  case 0x1C:
    return "FAT32X(Hidden & LBA)";
  case 0x1E:
    return "FAT16X(Hidden & LBA)";
  case 0x1F:
    return "Extended(Hidden & LBA)";
  case 0x20:
    return "WinMobile Update XIP/Willowsoft Overture FS";
  case 0x21:
    return "HP Volume Expansion(SpeedStor)/FSo2(Oxygen File System)";
  case 0x22:
    return "Oxygen Extended";
  case 0x23:
    return "WinMobile Boot XIP/Reserved(Microsoft/IBM)";
  case 0x24:
    return "FAT12(Log)/FAT16(Log)";
  case 0x25:
    return "WinMobile IMGFS";
  case 0x26:
    return "Reserved(Microsoft/IBM)";
  case 0x27:
    return "Windows Recovery/FAT32(Rescue)/NTFS(Rescue)/MirOS/RooterBOOT Kernel(ELF Linux)";
  case 0x2A:
    return "AtheOS File System";
  case 0x2B:
    return "SyllableSecure(SylStor)";
  case 0x31:
    return "Reserved(Microsoft/IBM)";
  case 0x32:
    return "Unknown";
  case 0x33:
    return "Reserved(Microsoft/IBM)";
  case 0x34:
    return "Reserved(Microsoft/IBM)";
  case 0x35:
    return "JFS";
  case 0x36:
    return "Reserved(Microsoft/IBM)";
  case 0x38:
    return "THEOS(2GB Partition)";
  case 0x39:
    return "Plan 9(Ed 3)/THEOS(v4,spanned)";
  case 0x3A:
    return "THEOS(v4,4GB)";
  case 0x3B:
    return "THEOS(v4,extended)";
  case 0x3C:
    return "PqRP";
  case 0x3D:
    return "NetWare(Hidden)";
  case 0x40:
    return "PICK R83/Venix 80286";
  case 0x41:
    return "Personal RISC(boot)/Old Linux/PPC PReP(boot)";
  case 0x42:
    return "Secure Filesystem(SFS)/Old Linux Swap/Dynamic Extended Partition Marker";
  case 0x43:
    return "Old Linux Native";
  case 0x44:
    return "GoBack(Norton/WildFile/Adaptec/Roxio)";
  case 0x45:
    return "Priam/Boot-US(boot manager)/EUMEL/ELAN";
  case 0x46:
    return "EUMEL/ELAN";
  case 0x47:
    return "EUMEL/ELAN";
  case 0x48:
    return "EUMEL/ELAN";
  case 0x4A:
    return "ALFS/THIN Advanced Lightweight FS";
  case 0x4C:
    return "Aos Filesystem";
  case 0x4D:
    return "Primary QNX";
  case 0x4E:
    return "Secondary QNX";
  case 0x4F:
    return "Tertiary QNX";
  case 0x50:
    return "Alternative NAT FS/Read-Only Partition/Lynx RTOS";
  case 0x51:
    return "Read-Write Partition(Aux1)";
  case 0x52:
    return "CP/M";
  case 0x53:
    return "Aux3";
  case 0x54:
    return "Dynamic Drive Overlay(DDO)";
  case 0x55:
    return "EZ-Drive";
  case 0x56:
    return "FAT12(Log)/FAT16(Log)/EZ-Drive Disk Manager/VFeature Partition Volume";
  case 0x57:
    return "DrivePro/VNDI Partition";
  case 0x5C:
    return "Priam EDisk";
  case 0x64:
    return "NetWare Filesystem 286";
  case 0x65:
    return "Netware Filesystem 386";
  case 0x78:
    return "XOSL Bootloader FS";
  case 0x80:
    return "Old Minix FS";
  case 0x81:
    return "MINIX Filesystem";
  case 0x82:
    return "Linux Swap";
  case 0x83:
    return "Linux(Native)";
  case 0x84:
    return "Hibernation(S2D)";
  case 0x85:
    return "Linux(extended)";
  case 0x86:
    return "FAT16(Legacy)";
  case 0x87:
    return "NTFS(Legacy)";
  case 0x88:
    return "Linux(plaintext)";
  case 0x8B:
    return "FAT32(Legacy)";
  case 0x8C:
    return "FAT32(Legacy & LBA)";
  case 0x8D:
    return "FAT12(Hidden)";
  case 0x8E:
    return "Linux(LVM)";
  case 0x90:
    return "FAT16(Hidden)";
  case 0x91:
    return "Extended(Hidden & CHS)";
  case 0x92:
    return "FAT16B(Hidden)";
  case 0x97:
    return "FAT32(Hidden)";
  case 0x98:
    return "FAT32X(Hidden)/Service Partition(bootable FAT)";
  case 0x9A:
    return "FAT16X(Hidden)";
  case 0x9B:
    return "Extended(Hidden & LBA)";
  case 0xA0:
    return "Diagnostic(HP)";
  case 0xA1:
    return "HP Volume Expansion(SpeedStor)";
  case 0xA3:
    return "HP Volume Expansion(SpeedStor)";
  case 0xA4:
    return "HP Volume Expansion(SpeedStor)";
  case 0xA5:
    return "BSD Slice";
  case 0xA6:
    return "HP Volume Expansion(SpeedSotr)/OpenBSD Slice";
  case 0xA7:
    return "NeXTSTEP";
  case 0xA8:
    return "Apple Mac OS X";
  case 0xA9:
    return "NetBSD Slice";
  case 0xAB:
    return "Apple Mac OS X Boot";
  case 0xAF:
    return "Apple Mac OS X HFS/HFS+";
  case 0xB1:
    return "HP Volume Expansion(SpeedStor)/QNX Neutrino Power-Safe FS";
  case 0xB2:
    return "QNX Neutrino Power-Safe FS";
  case 0xB3:
    return "HP Volume Expansion(SpeedStor)/QNX Neutrino Power-Safe FS";
  case 0xB4:
    return "HP Volume Expansion(SpeedStor)";
  case 0xB6:
    return "HP Volume Expansion(SpeedStor)";
  case 0xC0:
    return "FAT(Secured & <32MB)";
  case 0xC1:
    return "FAT12(Secured)";
  case 0xC4:
    return "FAT16(Secured)";
  case 0xC5:
    return "Extended(Secured & CHS)";
  case 0xC6:
    return "FAT16B(Secuerd)";
  case 0xCB:
    return "FAT32(Secured)";
  case 0xCC:
    return "FAT32X(Secured)";
  case 0xCE:
    return "FAT16X(Secured)";
  case 0xCF:
    return "Extended(Secured & LBA)";
  case 0xD0:
    return "FAT(Secured & >32MB)";
  case 0xD1:
    return "FAT12(Secured)";
  case 0xD4:
    return "FAT16(Secured)";
  case 0xD5:
    return "Extended(Secured & CHS)";
  case 0xD6:
    return "FAT16B(Secured)";
  case 0xDB:
    return "CP/M-86 Concurrent DOS";
  case 0xDE:
    return "Diagnostic(Dell)";
  case 0xE5:
    return "FAT12(Log)/FAT16(Log)";
  case 0xEB:
    return "BFS";
  case 0xED:
    return "EDC";
  case 0xEE:
    return "EFI Protective MBR";
  case 0xEF:
    return "EFI System Partition";
  case 0xF2:
    return "FAT12(Log)/FAT16(Log)";
  case 0xFB:
    return "VMWare VMFS";
  case 0xFC:
    return "VMWare VMKCORE";
  case 0xFD:
    return "Linux(RAID)";
  case 0xFE:
    return "IBM IML Partition";
  case 0xFF:
    return "XENIX Bad Block Table";
  default:
    return "UNKNOWN";
  }
}

/**
 * Used to return the result to the contractor.
 * \param ccr The contract completion report to fill out.
 * \param description The return string description.
 * \param confidence_value The confidence in our result.
 *
 */
static void contractor_return_result(contract_completion_report_t ccr, const char *description, int confidence_value, int is_contiguous, long long abs_off)
{
  result_t contract_result = result_init(NULL, 0);

  /* Close our blocks object */
  unsigned int size;
  block_range_t *ranges = block_end(&size);

  if (ranges != NULL)
  {
    if ((abs_off > -1) && (is_contiguous == 1))
    {
      result_set_block_ranges(contract_result, ranges, size);
    }
    for (int i = 0; i < size; i++)
    {
      block_range_close(ranges[i]);
    }
    g_free(ranges);
    ranges = NULL;
  }

  result_set_confidence(contract_result, confidence_value);
  result_set_data_description(contract_result, description);
  result_set_brief_data_description(contract_result, "MBR");
  contract_completion_report_add_result(ccr, contract_result);
  result_close(contract_result);        /* Close result */
}

/**
 * A recursive function used to generate a "description" of an extended boot record chain.
 * \param desc A string that we want to append to.
 * \param partition The current partition.
 * \param part_num The partition number for the current partition.
 * \returns A string representing the current extended partition(s).
 */
char *get_ext_partition_desc(char **desc, struct partition_info *partition, int *part_num)
{
  char *new_desc;
  const char *bootable_name;

  /* Our boot status */
  if (partition->bootable_flag == 0x80)
  {
    bootable_name = "Bootable";
  } else
  {
    bootable_name = "Non-bootable";
  }
  /* Partition Description */
  char *part_1_desc = g_strdup_printf("\tPartition %d, ID=%x(%s), Status=%s, Start Head=%d, Start LBA=%lld, Num Sectors=%d; ", *part_num, partition->type,
                                      get_part_type(partition->type), bootable_name, partition->chs_start.head, partition->lba_first_sect, partition->num_sectors);

  (*part_num)++;                /* Increment our ext partition number */
  new_desc = g_strdup_printf("%s %s", *desc, part_1_desc);
  /* Free our strigs */
  g_free(part_1_desc);
  part_1_desc = NULL;
  g_free(*desc);
  *desc = NULL;
  /* If we have another extended partition in the chain, recurse */
  if ((partition[1].extended_partition != NULL) && (partition[1].type == 0x05 || partition[1].type == 0x0F))
  {
    new_desc = get_ext_partition_desc(&new_desc, partition[1].extended_partition, part_num);
  }
  return new_desc;
}

/**
 *  Used to extract the information about the current (top level) partition. If the partition is an extended
 *  partition, the recursive function get_ext_partition_desc() is called.
 *  \param partition The current (top level) partition.
 *  \returns A string representing the current (top level) partition.
 */
char *get_partition_desc(struct partition_info *partition)
{
  char *ret_str;
  const char *bootable_name;
  int ext_part_num = START_EXT_PART_NUM;

  /* Boot status */
  if (partition->bootable_flag == 0x80)
  {
    bootable_name = "Bootable";
  } else
  {
    bootable_name = "Non-bootable";
  }
  /* Partition description */
  char *part_desc = g_strdup_printf("Partition %d, ID=%x(%s), Status=%s, Start Head=%d, Start LBA=%lld, Num Sectors=%d; ", partition->partition_number, partition->type,
                                    get_part_type(partition->type), bootable_name, partition->chs_start.head, partition->lba_first_sect, partition->num_sectors);

  /* If we have an extended partition, we need to call the respective function to handle it */
  if ((partition->extended_partition != NULL) && (partition->type == 0x05 || partition->type == 0x0F))
  {
    ret_str = get_ext_partition_desc(&part_desc, &partition->extended_partition[0], &ext_part_num);
  } else
  {
    return part_desc;
  }
  return ret_str;
}


/**
 * Boot record parser. Extracts partition data from Boot Record and stores
 * in a partition_info struct.
 * \param buff Character buffer representing the boot record we have to parse.
 * \param partitions Pointer to the partition info_struct we have to fill out.
 * \param br_type The type of boot record being parsed (ie. MBR or EBR)
 * \returns An integer representing the success of the function (0 = Success; -1 = Failure)
 */
static int parse_br(unsigned char *buff, struct partition_info *partitions, int br_type)
{
  /* Number of times to loop based on the BR type */
  int num_loops = 0;

  if (br_type == TYPE_MBR)
    num_loops = 4;
  else
    num_loops = 2;

  /* Check 0x55 0xaa signature */
  if ((buff[510] != 0x55) || (buff[511] != 0xAA))
  {
    debug_log("Invalid partition table signature!!");
    return -1;
  }

  /* loop through all partitions in table */
  for (int i = 0; i < num_loops; i++)
  {
    /* Handle boot status of partition */
    partitions[i].bootable_flag = buff[BR_OFFSET + i * 16];

    /* Handle CHS Start Address
     * Offset = 1 byte (INTO PARTITION); Each Partition is 16 bytes (i is our current partition)
     */
    partitions[i].chs_start.head = buff[BR_OFFSET + i * 16 + 1];        /* CHS start header - 1 byte */
    partitions[i].chs_start.sector = buff[BR_OFFSET + i * 16 + 2] & 0x3F;       /* CHS Start Sector - 6 bits (need to grab the entire byte) - Offset = 2 */
    /* We only want the lower 6 bits */
    partitions[i].chs_start.cylinder = buff[BR_OFFSET + i * 16 + 2] & 0xC0;     /* Grab the upper 2 bits of the CHS Start Sector (byte) - these become the 2 MSB of the 10bit Cylinder value */
    partitions[i].chs_start.cylinder = ((partitions[i].chs_start.cylinder) << 2) | buff[BR_OFFSET + i * 16 + 3];        /* Shift our 2 MSB (from above) to the left, and bitwise OR lower 8 bits of cylinder - This gives us our 10 bit cylinder number - Offset = 3 */

    /* Handle Partition type
     * Offset = 4
     */
    partitions[i].type = buff[BR_OFFSET + i * 16 + 4];  /* The 'integer' representing the partition type */

    /* Handle CHS End Address */
    partitions[i].chs_end.head = buff[BR_OFFSET + i * 16 + 5];  /* CHS start header, 1 byte - Offset = 5 */
    partitions[i].chs_end.sector = buff[BR_OFFSET + i * 16 + 6] & 0x3F; /* Our Sector is the lower 6 bits of this byte - Offset = 6 *//* We only want the lower 6 bits */
    partitions[i].chs_end.cylinder = buff[BR_OFFSET + i * 16 + 6] & 0xC0;       /* Grab the upper 2 bits of the CHS Start Sector (byte) - these become the 2 MSB of the 10bit Cylinder value */
    partitions[i].chs_end.cylinder = ((partitions[i].chs_end.cylinder) << 2) | buff[BR_OFFSET + i * 16 + 7];    /* Shift our 2 MSB (from above) to the left, and bitwise OR lower 8 bits of cylinder - This gives us our 10 bit cylinder number - Offset = 3 */

    partitions[i].lba_first_sect = 0;
    /* Shift lba bytes into an int */
    for (int j = 4; j > 0; j--)
    {
      partitions[i].lba_first_sect = (partitions[i].lba_first_sect << 8) | buff[BR_OFFSET + i * 16 + j + 7];
    }

    partitions[i].num_sectors = 0;
    /* Shift num sectors into an int */
    for (int j = 4; j > 0; j--)
    {
      partitions[i].num_sectors = (partitions[i].num_sectors << 8) | buff[BR_OFFSET + i * 16 + j + 11];
    }
    /*debug_log("P%d, Start Cylinder: %d, Start Head %d, Start Sector %d End Cylinder: %d, End Head %d, End Sector %d", 
       partitions[i].partition_number, partitions[i].chs_start.cylinder, partitions[i].chs_start.head, partitions[i].chs_start.sector,
       partitions[i].chs_end.cylinder, partitions[i].chs_end.head, partitions[i].chs_end.sector); */

    /* for now... */
    partitions[i].active_partition = 0;
    partitions[i].extended_partition = NULL;    /* Set this in has_more_partitions */

  }
  return 0;
}

/**
 * Used to determine if a partition is "empty".
 * \param partition the partition to test.
 * \returns An integer representing the success of the function (0 = Success; -1 = Failure)
 */
static int is_empty_partition(struct partition_info *partition)
{
  if (partition->type != 0x00)
  {
    return 0;
  }

  /* Empty partitions should contain no data (ie. It is all zero/null) */
  if ((partition->chs_start.sector != 0) || (partition->chs_start.cylinder != 0) || (partition->chs_start.head != 0) || (partition->chs_end.sector != 0) || (partition->chs_end.cylinder != 0)
      || (partition->chs_end.head != 0) || (partition->lba_first_sect != 0) || (partition->num_sectors != 0))
  {
    return 0;
  }

  return 1;
}

/**
 * Used to validate that the information parsed in parse_br() is valid. Checks a number of factors, including:
 *   - Valid boot status
 *   - Valid partition type
 *   - Overlapping partitions
 *   - CHS End > CHS Start
 * Optimally, the "MBR" is passed in to begin with, and if any extended partitions are identified, the function will
 * recurse through them until all partitions are verified.
 *  \param partitions The partition table (containing the partition data) to validate.
 *  \param part_type The type of partition table/boot record being passed in (MBR/EBR)
 *  \returns An integer representing the success of the function (0 = Success; -1 = Failure)
 */
static int validate_partitions(struct partition_info *partitions, int part_type)
{
  int num_loops = 0;

  if (part_type == TYPE_MBR)
    num_loops = 4;
  else
    num_loops = 2;
  for (int i = 0; i < num_loops; i++)
  {
    if ((partitions[i].bootable_flag != 0x00) && (partitions[i].bootable_flag != 0x80)) /* Note: 0x00 is still valid (along with 0x80) */
    {
      error_log("Partition has an invalid Boot flag.");
      return -1;
    }

    /* Sanity check - Our end CHS must be > start chs */
    if ((partitions[i].chs_end.cylinder < partitions[i].chs_start.cylinder) ||
        (partitions[i].chs_start.cylinder == partitions[i].chs_end.cylinder && (partitions[i].chs_end.head < partitions[i].chs_start.head)) ||
        (partitions[i].chs_start.head == partitions[i].chs_end.head && (partitions[i].chs_start.cylinder == partitions[i].chs_end.cylinder)
         && (partitions[i].chs_end.sector < partitions[i].chs_start.sector)))
    {
      error_log("Partition %d has a CHS Start value that is higher than it's CHS End value.", partitions[i].partition_number);
      return -1;
    }
    // Check for overlapped regions */
    /*
       if (i != 0 && is_empty_partition(&partitions[i]) == 0) // We don't want to do this for the first (0th) partition, or it will cause an error
       {
       if ((partitions[i].chs_start.cylinder < partitions[i-1].chs_end.cylinder) ||
       (partitions[i].chs_start.cylinder == partitions[i-1].chs_end.cylinder && (partitions[i].chs_start.head < partitions[i-1].chs_end.head)) || (partitions[i].chs_start.head == partitions[i-1].chs_end.head && (partitions[i].chs_start.cylinder == partitions[i-1].chs_end.cylinder) && (partitions[i].chs_start.sector < partitions[i-1].chs_end.sector)))
       {
       error_log("Partitions %d and %d are Overlapping", i-1, i);
       return -1;
       }
       } */

    if (partitions[i].type == 0x05 || partitions[i].type == 0x0F)       /* Extended Partition */
    {
      if (validate_partitions(partitions[i].extended_partition, TYPE_EBR) < 0)
      {
        error_log("Failed to validate Partitions");
        return -1;

      }
    }
  }

  return 0;
}



/**
 * Used to read the current extended partition. If further extended partitions are found, this function is recursively called to manipulate
 * the file pointer and read the partitions as necessary.
 * \param file_pointer The current file pointer.
 * \param partition The partition structure that we want to store the extended partition information in.
 * \param level The "level" (or layer) of the extended partition. The level will specify where the file_pointer needs to seek from.
 * (LVL_TOP seeks from the beginning of the file, whereas LVL_LOW will seek from the beginning of the primary EBR).
 */
static int has_more_partitions(FILE * file_pointer, unsigned char *char_buffer, struct partition_info *partition, int level)
{
  fpos_t file_pos;
  long long int curr_pos;

  if (level == LVL_TOP)
  {
    if (fseeko(file_pointer, (partition->lba_first_sect) * BLOCK_SIZE, SEEK_SET) != 0)  /* Seek to the start of our main EBR, from START of file */
    {
      error_log("Failed to read to position of extended boot record");
      return -1;
    }
    curr_pos = ftello(file_pointer);
    block_add_byte_range(curr_pos, curr_pos + 512);
    if (fgetpos(file_pointer, &file_pos) != 0)  /* Get our current file pos; the Start of the MAIN EBR */
    {
      error_log("Unable to get current file position");
      return -1;
    }
  } else
  {
    if (fgetpos(file_pointer, &file_pos) != 0)  /* This should be called when level != LVL_TOP (ie. recursive call for EBR). Get our current file pos; Should be the Start of the MAIN EBR */
    {
      error_log("Unable to get current file position");
      return -1;
    }

    if (fseeko(file_pointer, (partition->lba_first_sect) * BLOCK_SIZE, SEEK_CUR) != 0)  /* Seek to our required file offset, based on CURRENT file position (start of main EBR) */
    {
      error_log("Failed to read to position of extended boot record");
      return -1;
    }
    curr_pos = ftello(file_pointer);
    block_add_byte_range(curr_pos, curr_pos + 512);
  }


  if (fread(char_buffer, 1, 512, file_pointer) != 512)
  {
    error_log("Unable to read block for extended boot record");
    return -1;
  }

  if (parse_br(char_buffer, partition->extended_partition, TYPE_EBR) != 0)
  {
    error_log("Unable to parse Extended boot record");
    return -1;
  }

  /* Do we have more partitions? */
  if ((is_empty_partition(&partition->extended_partition[1]) == 0) && (partition->extended_partition[1].type == 0x05 || partition->extended_partition[1].type == 0x0F)) /* Our 2nd EBR entry is not empty/NULL, hence we have another EBR */
  {
    partition->extended_partition[1].extended_partition = (struct partition_info *) g_malloc(sizeof(struct partition_info) * 2);
    memset(partition->extended_partition[1].extended_partition, 0, sizeof(struct partition_info) * 2);
    /* Reset our file pointer */
    if (fsetpos(file_pointer, &file_pos) != 0)
    {
      error_log("Unable to set current file position");
      return -1;
    }
    /* Recursive call of has_more_partitions to handle extended partitions */
    if ((has_more_partitions(file_pointer, char_buffer, &partition->extended_partition[1], LVL_LOW)) < 0)
    {
      error_log("Unable to parse Extended boot record");
      return -1;
    }
  } else if (is_empty_partition(&partition->extended_partition[1]) == 0)        /* We have a non-empty partition in the EBR slot, with no extended type defined - Shouldn't happen */
  {
    error_log("Non-empty partition defined in slot 2 of EBR, with no extended partition type defined");
    return -1;
  }
  return 1;
}

void free_partitions(struct partition_info *partitions, int part_type)
{
  int i = 0;
  int loops = 0;

  if (part_type == TYPE_MBR)
    loops = 4;
  else
    loops = 2;

  for (; i < loops; i++)
  {
    if (NULL != partitions[i].extended_partition)
    {
      free_partitions(partitions[i].extended_partition, TYPE_EBR);
      g_free(partitions[i].extended_partition);
      partitions[i].extended_partition = NULL;
    }
  }
}

/**
 * Subcontractor initialisation. 
 *
 */
int subcontractor_init(void)
{
  return 0;
}

/**
 * Core contract analyse function.
 * \param ccr The contract completion report we are to complete.
 * \param to_analyse The contract we need to analyse.
 *
 */
int analyse_contract(contract_t to_analyse, contract_completion_report_t ccr)
{
  /*  For a partition table, we expect that it should exist at an offset
   *  of 446 bytes from the start of the block (specifically, the MBR usually).
   *  From here, we have a 64 byte section of data, which consists of
   *  four 16-byte partitions. The structure of these partitions is
   *  defined within the header file.
   */
  int completed_parse = 0;

  /* Confidence value */
  int confidence_value = 100;
  int contiguous = contract_is_contiguous(to_analyse);
  long long abs_off = contract_get_absolute_offset(to_analyse);

  /* Read our path in */
  const char *path = contract_get_path(to_analyse);

  /* Open file in readonly mode */
  FILE *file_pointer = fopen(path, "r");

  /* Our file open was unsuccessful */
  if (!file_pointer)
  {
    const char *errormsg = "Could not read";

    error_log("Error: Unable to open file");
    confidence_value = 0;
    contractor_return_result(ccr, errormsg, confidence_value, contiguous, abs_off);
    return 0;
  }

  /* 512 byte buffer to read MBR/EBR.
   * If blocksize >512, we dont read past 512 bytes (for now)
   */
  unsigned char char_buffer[512];

  /* Our block start */
  long long int file_offset = ftello(file_pointer);

  block_start(file_offset);
  block_add_byte_range(file_offset, file_offset + BLOCK_SIZE);

  /* Check we can read 512 bytes */
  if (fread(char_buffer, 1, 512, file_pointer) != 512)
  {
    const char *errormsg = "Invalid. Too small";

    warning_log("Error: Less than 512 bytes read.");
    confidence_value = 0;
    contractor_return_result(ccr, errormsg, confidence_value, contiguous, abs_off);
    fclose(file_pointer);
    return 0;
  }
  // Confidence values
  // 100 - Everything looks sane, at least one partition exists
  // 75 - Things look sane, an EBR was specified but wasn't found
  // 50 - Magic found, partitions exist but things don't look sane
  // 0 - No magic found

  GString *description = g_string_new(NULL);;
  struct partition_info partitions[4];

  memset(partitions, 0, sizeof(partitions));

  if (parse_br(char_buffer, partitions, TYPE_MBR) != 0)
  {
    const char *failedparse = "Failed to parse MBR";
    const char *toosmallmsg = "Invalid. Too small";

    debug_log("%s", failedparse);
    confidence_value = 0;
    contractor_return_result(ccr, toosmallmsg, confidence_value, contiguous, abs_off);
    fclose(file_pointer);
    file_pointer = NULL;
    return 0;
  }

  /* Need to determine number of non-empty partitions */
  int ret = -1;

  for (int i = 0; i < 4; i++)
  {
    if (is_empty_partition(&partitions[i]) == 1)
    {
      partitions[i].active_partition = 0;       /* Empty partition */
    } /* if empty partition */
    else
    {
      partitions[i].active_partition = 1;
      if ((partitions[i].type == 0x05) || (partitions[i].type == 0x0F)) /* Extended Partition */
      {
        partitions[i].extended_partition = (struct partition_info *) g_malloc(sizeof(struct partition_info) * 2);
        memset(partitions[i].extended_partition, 0, sizeof(struct partition_info) * 2);
        if ((ret = has_more_partitions(file_pointer, char_buffer, &partitions[i], LVL_TOP)) < 0)
        {
          confidence_value = (confidence_value < 50) ? confidence_value : 50;   /* We have some valid partitions but we failed to parse our ebr */
          error_log("Failed to parse Extended Partition (Partition %d in MBR)", i + 1);
          break;
        }
        /* If extended partition has more partitions */
      }
      /* If extended partition */
      partitions[i].partition_number = i + 1;
      g_string_append_printf(description, " %s", get_partition_desc(&partitions[i]));
    }                           /* Non empty partition */
    if (i == 3)
      completed_parse = 1;
  }                             /* for loop */

  /* Validate the partitions are sane */
  if (completed_parse == 1 && (validate_partitions(partitions, TYPE_MBR) == 0))
  {
    confidence_value = (confidence_value < 100) ? confidence_value : 100;
    contractor_return_result(ccr, description->len == 0 ? "Partition table" : description->str+1, confidence_value, contiguous, abs_off);      /* Return result */
  } else if (completed_parse == 0)
  {
    contractor_return_result(ccr, "Failed to parse a defined Extended Partition", confidence_value, contiguous, abs_off);
  } else
  {
    confidence_value = (confidence_value < 50) ? confidence_value : 50;
    contractor_return_result(ccr, "Failed to validate Partitions", confidence_value, contiguous, abs_off);
  }


  /* Complete */
  free_partitions(&partitions[0], TYPE_MBR);    /* Clean up allocated memory */
  g_string_free(description, TRUE);
  description = NULL;
  fclose(file_pointer);         /* Close our file pointer */
  return 0;
}

/**
 * Subcontractor close.
 */
int subcontractor_close(void)
{
  return 0;
}
