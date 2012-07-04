/* libpronghorn Sleuthkit loopback mount
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
 * \file subcontractor_sleuth.c
 * \brief This is the sleuthkit loopback FUSE mount for Pronghorn.
 *
 * This loopback mount will attempt to mount the supplied filesystem
 * and provide a view to the allocated inodes rather than the filenames
 * themselves.
 *
 * Filesystem users can create directories as long as they follow the
 * following structure:
 *
 * \<inode\>:mnt\<suffix\>
 *
 * The suffix is an arbitrary string provided to allow the identification
 * of the subcontractor module that caused the mount to occur.
 *
 * Inodes with a ':filename' suffix contain the filename belonging
 * to that inode. The filename is fully qualified relative to the
 * mountpoint.
 *
 * Writes should appear to work, but are actually ignored. This is to
 * support libraries that expect to write to the filesystem and would 
 * otherwise error out when failing to open the file with write-access.
 */

// Looks like it's leak free - apart from any TSK leaks
// It might appear to leak when in 'background' mode, but this is because
// fuse_main never returns in background mode so it's not possible to cleanup.
// However this is not a problem as the program is forced to exit.
//
// There is a pretty significant "feature" with libfuse. When fuse_main is called
// and is NOT unstructed to go to the foreground (ie, fuse_main calls fork()
// and exec()) then the cwd changes and relative paths may be broken.
// Therefore all potential file references must be opened before calling
// fuse_main to guarantee they will be opened correctly.
// Unfortunately calling getcwd() and realpath() are not suitable alternatives
// due to the documented bugs (see respective manpages)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <getopt.h>
#include <unistd.h>
#include <libgen.h>
#include <glib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <tsk3/libtsk.h>

#include <logger.h>
#include <transport.h>
#include <contract.h>
#include <result.h>
#include <report.h>
#include <lightmagic.h>
#include <base_fuse.h>
#include <blocks.h>

#include "subcontractor_helper.h"

unsigned int supported_file_types[] = { MAGIC_TYPE_FAT12, MAGIC_TYPE_FAT16, MAGIC_TYPE_FAT32, MAGIC_TYPE_NTFS, MAGIC_TYPE_EXT, 0 };

/** The option 'name' to define the input file */
#define INPUT_FILE_OPTION_NAME "file"
/** The option 'name' to define the logfile */
#define LOG_FILE_OPTION_NAME "logfile"
/** The option 'name' to define when to suppress directory enumeration */
#define FAST_OPTION_NAME "fast"
/** The option 'name' to define the filesystem type */
#define FSTYPE_OPTION_NAME "fstype"

/** This is the file to be mounted */
static char *input_filename = NULL;

/** The mountpoint where the filesystem will be mounted */
static char *mountpoint = NULL;

/** A lookup table to test the existence of an inode */
static GTree *inode_lookup = NULL;

/** Indicates whether the current contract is in a contiguous mappable area */
static int is_contiguous = 0;

/** Holds the absolute offset for the current contract if it's known */
static long long int absolute_offset = -1;

/**
 * This structure is used when reading the content of a file.
 */
struct read_struct
{
        /** The buffer to hold the data */
  unsigned char *buf;
        /** The desired offset into the file */
  off_t offset;
        /** The size remaining to be read */
  size_t size;
        /** The amount of data currently read */
  size_t read;
};

/** The TSK_IMG_INFO structure */
static TSK_IMG_INFO *img_info = NULL;

/** The TSK_FS_INFO structure */
static TSK_FS_INFO *fs_info = NULL;

/**
 * A TSK callback used when reading file content.
 *
 * \param a_fs_file The file being walked.
 * \param a_off The bytes offset in file that this data is for.
 * \param a_addr The address of the data in the buffer relative to the file start.
 * \param a_buf A buffer containing file content
 * \param a_len The length of the buffer in bytes.
 * \param a_flags Flags about the file content
 * \param a_ptr The result reference
 * \returns TSK_WALK_CONT to tell TSK to continue parsing if there's more data to be read.
 */
static TSK_WALK_RET_ENUM read_file_content_callback(TSK_FS_FILE * a_fs_file, TSK_OFF_T a_off, TSK_DADDR_T a_addr, char *a_buf, size_t a_len, TSK_FS_BLOCK_FLAG_ENUM a_flags, void *a_ptr)
{
  struct read_struct *r = (struct read_struct *) a_ptr;
  char *ptr = a_buf;
  int ptr_len = a_len;

  if (r->offset != 0)
  {
    if (r->offset >= ptr_len)
    {
      r->offset -= ptr_len;

      return TSK_WALK_CONT;
    }

    ptr += r->offset;
    ptr_len -= r->offset;
    r->offset = 0;
  }

  if (r->size <= ptr_len)
  {
    memcpy(r->buf, ptr, r->size);
    r->buf += r->size;
    r->read += r->size;
    r->size = 0;

    return TSK_WALK_STOP;
  }
  memcpy(r->buf, ptr, ptr_len);
  r->buf += ptr_len;
  r->read += ptr_len;
  r->size -= ptr_len;
  return TSK_WALK_CONT;
}

/**
 * Compares two ints. Used for g_tree sorting.
 *
 * \param a The first int
 * \param b The second in
 * \param user_data Not used
 * \returns 0 if identical, a negative number if b>a, a positive number if a>b
 */
gint unsigned_long_long_compare(unsigned long long *a, unsigned long long *b, gpointer user_data)
{
  if (a == NULL)
  {
    if (b == NULL)
    {
      return 0;
    }
    return -1;
  }

  if (b == NULL)
  {
    return 1;
  }

  if (*a < *b)
  {
    return -1;
  }

  if (*a == *b)
  {
    return 0;
  }

  return 1;
}

/**
 * Walks the file structure to obtain the list of blocks the file occupies (and it's absolute offset).
 *
 * This is a TSK callback.
 *
 * \param a_fs_file The file being walked.
 * \param a_off The bytes offset in file that this data is for.
 * \param a_addr The address of the data in the buffer relative to the file start.
 * \param a_buf A buffer containing file content
 * \param a_len The length of the buffer in bytes.
 * \param a_flags Flags about the file content
 * \param c The contract structure to populate with the files absolute address
 * \returns TSK_WALK_CONT to tell TSK to continue parsing.
 */
static TSK_WALK_RET_ENUM walk_file(TSK_FS_FILE * a_fs_file, TSK_OFF_T a_off, TSK_DADDR_T a_addr, char *a_buf, size_t a_len, TSK_FS_BLOCK_FLAG_ENUM a_flags, contract_t c)
{
  if ((a_flags & TSK_FS_BLOCK_FLAG_RAW) == 0)
  {
    return TSK_WALK_CONT;
  }
  // It seems that (at least for FAT12) the a_addr is a block offset, so it must be multiplied
  // by the filesystem block size. Is this a bug, or expected behaviour?
  a_addr = a_addr * a_fs_file->fs_info->block_size;

  if (contract_get_absolute_offset(c) == -1)
  {
    contract_set_absolute_offset(c, a_addr + absolute_offset);
  }

  block_add_byte_range(a_addr, a_addr + a_len);

  return TSK_WALK_CONT;
}

/**
 * Populates the result reference with the supplied file and its details.
 *
 * \param r The result reference to populate.
 * \param fs_file The file to populate into the result structure
 * \param a_path The path containing the file.
 */
static void populate_sleuth_result(result_t r, TSK_FS_FILE * fs_file, const char *a_path)
{
  if ((fs_file->meta == NULL) || (fs_file->meta->size == 0))
  {
    return;
  }

  if (fs_file->name->flags == TSK_FS_NAME_FLAG_UNALLOC)
  {
    debug_log("Not allocated: %" PRIdINUM " -> %s", fs_file->name->meta_addr, fs_file->name->name);
    return;
  }
  // Removing '.' and '..' entries
  if (fs_file->name->name[0] == '.')
  {
    if (fs_file->name->name[1] == '\0')
    {
      return;
    } else if (fs_file->name->name[1] == '.')
    {
      if (fs_file->name->name[2] == '\0')
      {
        return;
      }
    }
  }

  if (inode_lookup == NULL)
  {
    inode_lookup = g_tree_new_full((GCompareDataFunc) unsigned_long_long_compare, NULL, g_free, NULL);
  }

  if (g_tree_lookup(inode_lookup, &(fs_file->name->meta_addr)) != NULL)
  {
    // This can happen if we have a directory and a child of that directory called '..'
    // Or we have a hard link on the filesystem
    debug_log("Duplicate inode detected: %" PRIdINUM " -> %s", fs_file->name->meta_addr, fs_file->name->name);
    return;
  }
  unsigned long long *l = (unsigned long long *) g_malloc(sizeof(unsigned long long));

  *l = fs_file->name->meta_addr;
  g_tree_insert(inode_lookup, l, NULL);

  // No point walking the filesystem if it's not needed
  if (r != NULL)
  {
    contract_t c = contract_init(NULL, 0);

    char *inode_string = g_strdup_printf("%s/%" PRIdINUM, mountpoint, fs_file->name->meta_addr);

    contract_set_path(c, inode_string);
    g_free(inode_string);

    // We can't guarantee the file is contiguous
    contract_set_contiguous(c, 0);

    // Only do this if the original_contract is on contiguous space
    if ((is_contiguous == 1) && (absolute_offset >= 0))
    {
      // Getting the block list
      tsk_fs_file_walk(fs_file, TSK_FS_FILE_WALK_FLAG_SLACK, (TSK_FS_FILE_WALK_CB) walk_file, c);
    }

    if (fs_file->meta->type == TSK_FS_META_TYPE_REG)
    {
      // Only add it if it's actually a file
      result_add_new_contract(r, c);
    }
    contract_close(c);
  }

  // Add it to the virtual filesystem
  char* full_file_path = g_strdup_printf("%s%s", a_path, fs_file->name->name);
  add_file(fs_file->name->meta_addr, full_file_path, fs_file->meta->size);
  g_free(full_file_path);
}

/**
 * A TSK callback to examine the supplied directory entry.
 *
 * \param fs_file The TSK file entry.
 * \param a_path The path containing this file.
 * \param ptr Nothing.
 * \returns TSK_WALK_CONT to tell TSK to continue parsing.
 */
static TSK_WALK_RET_ENUM examine_dirent(TSK_FS_FILE * fs_file, const char *a_path, void *ptr)
{
  result_t r = (result_t) ptr;

  // We don't care about files that don't have any meta data
  // These don't have any data
  if (fs_file->meta == NULL)
  {
    return TSK_WALK_CONT;
  }

  // ADS support is disabled for now - the current architecture doesn't support it.
/*
  // Print out all the NTFS ADS
  if (TSK_FS_TYPE_ISNTFS(fs_file->fs_info->ftype))
  {
    // cycle through the attributes
    int cnt = tsk_fs_file_attr_getsize(fs_file);
    int i;

    for (i = 0; i < cnt; i++)
    {
      const TSK_FS_ATTR *fs_attr = tsk_fs_file_attr_get_idx(fs_file, i);

      if (fs_attr == NULL)
      {
        continue;
      }

      switch (fs_attr->type)
      {
      case TSK_FS_ATTR_TYPE_NTFS_DATA:
      case TSK_FS_ATTR_TYPE_NTFS_IDXROOT:
        populate_sleuth_result(r, fs_file, a_path);
      default:
        break;
      }
    }
    return TSK_WALK_CONT;
  }
*/

  populate_sleuth_result(r, fs_file, a_path);

  return TSK_WALK_CONT;
}

/**
 * Parses the file and populates the structures used by this FUSE driver.
 *
 * \param filename The filename to parse
 * \param r The result structure to populate (or NULL if not needed)
 * \returns 0 if successful, -1 if not.
 */
static int process_file(const char *filename, result_t new_result)
{
  img_info = tsk_img_open_sing(filename, TSK_IMG_TYPE_DETECT, 0);
  if (img_info == NULL)
  {
    info_log("Failed to open image: %s", filename);
    return -1;
  }

  fs_info = tsk_fs_open_img(img_info, 0, TSK_FS_TYPE_DETECT);
  if (fs_info == NULL)
  {
    info_log("Failed to open filesystem: %s", filename);
    return -1;
  }

  const char *fsname = tsk_fs_type_toname(fs_info->ftype);

  result_set_brief_data_description(new_result, fsname);
  mountpoint = g_strdup_printf("%s:mnt-%s", filename, fsname);

  char *description = g_strdup_printf("%" PRIdDADDR " bytes (%" PRIdDADDR " %ss of %u size)", fs_info->block_count * fs_info->block_size, fs_info->block_count, fs_info->duname, fs_info->block_size);

  result_set_data_description(new_result, description);
  g_free(description);

  result_set_confidence(new_result, 100);
  block_start(absolute_offset);

  TSK_FS_DIR_WALK_FLAG_ENUM name_flags = (TSK_FS_DIR_WALK_FLAG_ENUM) (TSK_FS_DIR_WALK_FLAG_ALLOC | TSK_FS_DIR_WALK_FLAG_UNALLOC | TSK_FS_DIR_WALK_FLAG_RECURSE);

  if (tsk_fs_dir_walk(fs_info, fs_info->root_inum, name_flags, examine_dirent, new_result) != 0)
  {
    // Why does this occur? Is it because it's an invalid filesystem structure, or the
    // structure is damaged? I'm going to assume the structure is damaged, but partially available.
    warning_log("Warning, unable to fully walk fs! Probably truncated or not a real FS header.");
  }

  unsigned int size;
  block_range_t *ranges = block_end(&size);

  if (ranges != NULL)
  {
    result_set_block_ranges(new_result, ranges, size);
    for (int i = 0; i < size; i++)
    {
      block_range_close(ranges[i]);
    }
    g_free(ranges);
  }

  if (inode_lookup != NULL)
  {
    g_tree_destroy(inode_lookup);
    inode_lookup = NULL;
  }

  unsigned int num_contracts;
  result_get_new_contracts(new_result, &num_contracts);
  if (num_contracts > 0)
  {
    // Ready to mount!
    int ret = do_mount(mountpoint);

    if (ret != 0)
    {
      error_log("Failed to mount filesystem!");
    }
  }

  remove_all_files();

  return 0;
}

/**
 * Analyse whatever contract is provided and respond
 *
 * Do not free to_analyse
 * The return value is also freed elsewhere.
 *
 * \param to_analyse The contract to analyse.
 * \param ccr The contract completion report to populate
 * \returns 0 on success, -1 on error
 */
int analyse_contract(contract_t to_analyse, contract_completion_report_t ccr)
{
  is_contiguous = contract_is_contiguous(to_analyse);
  absolute_offset = contract_get_absolute_offset(to_analyse);

  const char *path = contract_get_path(to_analyse);

  result_t new_result = result_init(NULL, 0);

  result_set_confidence(new_result, 0);
  result_set_subcontractor_name(new_result, PROCESS_NAME);
  result_set_brief_data_description(new_result, "Garbage");
  result_set_data_description(new_result, "Not properly detected");

  int ret = process_file(path, new_result);

  contract_completion_report_add_result(ccr, new_result);

  if (ret != 0)
  {
    debug_log("analyse_contract produced no result");
  }
  result_close(new_result);

  return 0;
}

const unsigned int BUFFER_AMOUNT = 1024 * 1024 * 1024;
const unsigned int FILE_SIZE_THRESHOLD = 100 * 1024 * 1024;
const unsigned int FILE_OFFSET_THRESHOLD = 10 * 1024 * 1024;
long long inode_buffered = -1;
unsigned char *inode_buffer = NULL;
unsigned int inode_buffer_size = 0;
unsigned long long inode_buffer_pos = 0;

/**
 * Populates the buffer with the contents of the specified filename.
 *
 * \param id_number The id number of the file (in our case the inode)
 * \param filename The real filename for this file.
 * \param buf The buffer to write data into
 * \param size The size of the buffer
 * \param offset The offset into the file the data should be taken from.
 * \returns The amount of bytes read, or -1 on error.
 */
int do_read(unsigned int id_number, const char *filename, char *buf, size_t size, off_t offset)
{
//FILE* outfile = fopen("/tmp/sleuth.txt", "a");
//fprintf(outfile, "do_read(%u, %s, %p, %zu, %zu);\n", id_number, filename, buf, size, offset);
//fflush(outfile);
//fprintf(outfile, "inode_buffer=%p, inode_buffered=%lld, inode_buf_pos=%llu, end=%llu\n", inode_buffer, inode_buffered, inode_buffer_pos, inode_buffer_pos + inode_buffer_size);
//fflush(outfile);
  // If the data is already cached in our buffer then read from that instead
  if ((inode_buffer != NULL) && (id_number == inode_buffered) && (offset >= inode_buffer_pos) && (offset < inode_buffer_pos + inode_buffer_size))
  {
    if ((offset + size) <= (inode_buffer_pos + inode_buffer_size))
    {
      offset = offset % BUFFER_AMOUNT;
      memcpy(buf, inode_buffer + offset, size);
//fprintf(outfile, "Fully cached!\n");
//fclose(outfile);
      return size;
    }
    // If we're here then we've cached part of the data needed, but not all of it
    // (ie, the data requested spans a block boundary)
    offset = offset % BUFFER_AMOUNT;
    memcpy(buf, inode_buffer + offset, inode_buffer_size - offset);
    int ret_size = inode_buffer_size - offset;

    ret_size += do_read(id_number, filename, buf + ret_size, size - ret_size, inode_buffer_pos + inode_buffer_size);
//fprintf(outfile, "Partially cached: Size = %d\n", ret_size);
//fclose(outfile);
    return ret_size;
  }

  TSK_FS_FILE *fs_file = tsk_fs_file_open_meta(fs_info, NULL, id_number);

  if (fs_file == NULL)
  {
//fprintf(outfile, "FS file not found?\n");
//fclose(outfile);
    return -1;
  }
  // If the file is larger than FILE_SIZE_THRESHOLD, and the offset is larger 
  // than FILE_OFFSET_THRESHOLD, buffer up BUFFER_AMOUNT and return from that

  if (fs_file->meta != NULL)
  {
//fprintf(outfile, "File size is %" PRIdDADDR" bytes\n", fs_file->meta->size);
//fflush(outfile);
    if (offset >= fs_file->meta->size)
    {
//fprintf(outfile, "Reading beyond end of file\n");
//fclose(outfile);
      return 0;
    }
    if ((fs_file->meta->size >= FILE_SIZE_THRESHOLD) && (offset >= FILE_OFFSET_THRESHOLD))
    {
      if (inode_buffer == NULL)
      {
        inode_buffer = (unsigned char *) g_malloc(BUFFER_AMOUNT);
      }
      inode_buffered = id_number;
      inode_buffer_pos = (offset / BUFFER_AMOUNT) * BUFFER_AMOUNT;

      struct read_struct r;

      r.buf = inode_buffer;
      r.offset = inode_buffer_pos;
      r.size = BUFFER_AMOUNT;
      r.read = 0;

//fprintf(outfile, "Caching data...offset = %zu, size =%zu\n", r.offset, r.size);
//fflush(outfile);
      tsk_fs_file_walk(fs_file, TSK_FS_FILE_WALK_FLAG_NONE, read_file_content_callback, &r);

      inode_buffer_size = r.read;
//fprintf(outfile, "Recursing to read data\n");
//fclose(outfile);
      return do_read(id_number, filename, buf, size, offset);
    }
  }

  struct read_struct r;

  r.buf = (unsigned char *) buf;
  r.offset = offset;
  r.size = size;
  r.read = 0;

  tsk_fs_file_walk(fs_file, TSK_FS_FILE_WALK_FLAG_NONE, read_file_content_callback, &r);
  tsk_fs_file_close(fs_file);

//fprintf(outfile, "Simple read %zu\n", r.read);
//fclose(outfile);
  return r.read;
}

/**
 * Called when the filesystem is unmounted, and allows the destruction
 * of structures and freeing allocated memory.
 */
void cleanup(void)
{
  if (input_filename != NULL)
  {
    g_free(input_filename);
    input_filename = NULL;
  }

  if (fs_info != NULL)
  {
    tsk_fs_close(fs_info);
  }
  fs_info = NULL;

  if (img_info != NULL)
  {
    tsk_img_close(img_info);
  }
  img_info = NULL;

  if (mountpoint != NULL)
  {
    g_free(mountpoint);
  }
  mountpoint = NULL;

  if (inode_buffer != NULL)
  {
    g_free(inode_buffer);
  }
}

/**
 * Inits global stuctures
 *
 * returns 0 for success
 */
int subcontractor_init(void)
{
  return 0;
}

/**
 * Destroys global stuctures
 *
 * returns 0 for success
 */
int subcontractor_close(void)
{
  return 0;
}
