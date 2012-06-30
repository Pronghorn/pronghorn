/* libpronghorn Raw loopback mount
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
 * \file rawmount.c
 * \brief This is the raw loopback FUSE mount for Pronghorn.
 *
 * This loopback mount will take an input file and provide an interface
 * to read data from this file at arbitrary offsets.
 *
 * For example, opening the file 1024 and reading is equivalent to
 * opening the input file, seeking to position 1024 and reading.
 *
 * This is useful for libraries that are unable to seek to arbitrary
 * offsets before processing the file.
 */

// Valgrind issues
// - Leak free (yay)
// - Seems to give a warning about uninitialised bytes when truncating and
//   overwriting files. Doesn't seem to be caused by anything I do, and may
//   be an artefact of me pretending to truncate/write... however I don't 
//   think this is the case. It happens between when getattr() returns 
//   (after the truncate()) and write() starts. Does not happen when
//   appending to files (ie, when truncate isn't called)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <glib.h>

/**
 * We need to specify the version we're compiling against
 * in case it changes in the future.
 */
#define FUSE_USE_VERSION 26
#include <fuse.h>

//#define HIDE_COMPLETED
//#define HIDE_UNTESTED

/** The command line option to specify an input file */
#define INPUT_FILE_OPTION_NAME "file"
/** The command line option to specify a logfile */
#define LOG_FILE_OPTION_NAME "logfile"

/** The suffix to contain the file's actual name */
#define FILENAME_SUFFIX ":filename"
/** The suffix to contain mountpoints */
#define CONTENT_SUFFIX ":mnt"
/** The name of the usage file */
#define USAGE_FILE "usage.txt"
/** The content inside the usage file */
#define USAGE_FILE_CONTENT "\
RawMount                                                             \n\
=========                                                            \n\
                                                                     \n\
Although it might appear there are no files here, they're actually   \n\
hidden away until you try to access them.                            \n\
                                                                     \n\
When mounted, the file supplied with the -o file= argument is the    \n\
data source. When you request a file you're actually requesting an   \n\
offset and a length into this data source.                           \n\
                                                                     \n\
The file format is as follows:                                       \n\
<offset>                (for example '512'), or                      \n\
<offset>-<length>       (for example '512-2048')                     \n\
                                                                     \n\
The content of such a file is identical to the data source at the    \n\
specified offset for the specified length. If no length is provided  \n\
then all data until the end of the data source is returned.          \n\
                                                                     \n\
All file extensions (if any are provided) are valid. So the data     \n\
returned for 512-2048 and 512-2048.zip is identical.                 \n\
                                                                     \n\
This is a read-only filesystem. The only exception is that you can   \n\
create directories and soft-symlinks in the root directory only.     \n\
Both directories and symlinks must be suffixed with '" CONTENT_SUFFIX "' \n\
plus an optional identifiation string to be valid. These are provided\n\
to allow for additions to the filesystem via mounting or symlinks.   \n\
                                                                     \n\
To know how large the data source is simply see how large the file   \n\
'0' is.                                                              \n\
"

/** The UID for each file */
static int FILE_UID = 0;

/** The GID for each file */
static int FILE_GID = 0;

/** The file being mapped */
static FILE *mappedFile = NULL;

/** The size of the mapped file */
static size_t mappedFile_size = 0;

/** The link linked-list head */
static GSList *link_list = NULL;

/** The directory linked-list head */
static GSList *dir_list = NULL;

/** The relates a link's path to it's destination */
struct link_pair
{
        /** The path */
  char *path;
        /** The destination */
  char *dest;
};

/** Used in g_slist as a custom comparator */
static int linkpathcmp(struct link_pair *a, char *b)
{
  return g_strcmp0(a->path, b);
}

/** Used in g_slist as a destructor */
static void linkfree(struct link_pair *a)
{
  g_free(a->path);
  a->path = NULL;
  g_free(a->dest);
  a->dest = NULL;
  g_free(a);
}

/**
 * Logging function for debugging purposes
 *
 * Activiated by adding a -ologfile=[name] option
 */
FILE *flog = NULL;

/** A simple logging function */
static void tolog(const char *s)
{
  if ((flog == NULL) || (s == NULL))
  {
    return;
  }

  fprintf(flog, "%s", s);
  fflush(flog);
}

/**
 * Checks whether the supplied filename (not path!) looks like a valid
 * offset range.
 *
 * Valid offset definitions look like:
 * - \d+, or
 * - \d+-\d+
 *
 * Returns 1 if win, else 0
 */
static int isValidOffsetRange(const char *name)
{
  if ((name == NULL) || (strlen(name) == 0))
  {
    return 0;
  }
  // Ensure a dash (-) only appears once at most, and not at the start or the end
  char *dash = strchr(name, '-');

  if (dash != NULL)
  {
    if (strchr(dash + 1, '-') != NULL)
    {
      // More than one dash.
      return 0;
    }

    if ((name[0] == '-') || (name[strlen(name)] == '-'))
    {
      // Dash at start or end.
      return 0;
    }
  }
  // Ensure the string is only comprised of the following characters
  // 0123456789-
  if (strspn(name, "0123456789-") == strlen(name))
  {
    return 1;
  }

  return 0;
}

/**
 * Checks that the directory name structure is valid.
 *
 * Valid directory structures are valid offset ranges (as defined above)
 * appended with a CONTENT_SUFFIX and optional description name
 *
 * Returns 1 if win, else 0
 */
static int isValidDirectoryStructure(const char *name)
{
  if ((name == NULL) || (strlen(name) <= strlen(CONTENT_SUFFIX)))
  {
    return 0;
  }
  // First check that it contains the correct CONTENT_SUFFIX
  char *ptr = strstr(name, CONTENT_SUFFIX);

  if (ptr == NULL)
  {
    return 0;
  }
  // Now check that the rest of the filename is a valid offset file
  char *copy = g_strndup(name, ptr - name);
  int valid = isValidOffsetRange(copy);

  g_free(copy);
  return valid;
}

/**
 * Checks if the supplied path is a known directory.
 *
 * The path argument is fully qualified, so it should start with a '/'.
 *
 * Returns 1 if the path is a directory, or 0 if not.
 */
static int isDirectory(const char *path)
{
  if ((path == NULL) || (path[0] != '/'))
  {
    return 0;
  }
  // Eliminate the starting '/'
  path++;

  // Checking for the '/' directory
  if (path[0] == '\0')
  {
    return 1;
  }
  // Need to check if it's a known directory
  if (g_slist_find_custom(dir_list, path, (GCompareFunc) strcmp) != NULL)
  {
    return 1;
  }

  return 0;
}

/**
 * Checks if the supplied path is a known symlink.
 *
 * The path argument is fully qualified, so it should start with a '/'.
 *
 * Returns 1 if the path is a symlink, or 0 if not.
 */
static int isSymlink(const char *path)
{
  if ((path == NULL) || (path[0] != '/'))
  {
    return 0;
  }
  // Eliminate the starting '/'
  path++;

  // Need to check if it's a known symlink
  if (g_slist_find_custom(link_list, path, (GCompareFunc) linkpathcmp) != NULL)
  {
    return 1;
  }

  return 0;
}

/**
 * Checks if the supplied path is a valid 'offset' file.
 *
 * The path argument is fully qualified, so it should start with a '/'.
 *
 * Returns 1 if the path is a valid offset file, or 0 if not.
 */
static int isOffset(const char *path)
{
  // Valid offset definitions
  // \d+.*
  // \d+-\d+.*
  // ... that's it.

  if ((path == NULL) || (path[0] != '/'))
  {
    return 0;
  }
  // Eliminate the starting '/'
  path++;

  // Find the period (if one exists), and limit all searches
  // to this point.
  char *ptr = strchr(path, '.');

  // Starts with a '.'
  if (ptr == path)
  {
    return 0;
  }

  char *name;

  if (ptr == NULL)
  {
    name = g_strdup(path);
  } else
  {
    name = g_strndup(path, ptr - path);
  }

  int valid = isValidOffsetRange(name);

  g_free(name);
  return valid;
}

/**
 * Checks that the provided name structure is a valid for defining
 * meta filenames.
 *
 * This will modify name.
 */
static int isValidMetaFilename(char *name)
{
  if ((name == NULL) || (strlen(name) <= strlen(FILENAME_SUFFIX)))
  {
    return 0;
  }
  // First check that it ends with the correct FILENAME_SUFFIX
  if (g_str_has_suffix(name, FILENAME_SUFFIX) == FALSE)
  {
    // Nope.
    return 0;
  }
  // Now check that the rest of the filename is a valid offset file
  name[strlen(name) - strlen(FILENAME_SUFFIX)] = '\0';
  return isValidOffsetRange(name);
}

/**
 * Determines if the math describes a file's filename.
 *
 * \param path The path to check
 * \returns 1 if true, 0 if false
 */
static int isMetaFilename(const char *path)
{
  if ((path == NULL) || (path[0] != '/'))
  {
    return 0;
  }
  // Eliminate the starting '/'
  path++;

  // Find the period (if one exists), and limit all searches
  // to this point.
  char *ptr = strchr(path, '.');

  // Starts with a '.'
  if (ptr == path)
  {
    return 0;
  }

  char *name;

  if (ptr == NULL)
  {
    name = g_strdup(path);
  } else
  {
    name = g_strndup(path, ptr - path);
  }

  int valid = isValidMetaFilename(name);

  g_free(name);
  return valid;
}

/** Get file attributes.
 *
 * Similar to stat(). The 'st_dev' and 'st_blksize' fields are
 * ignored.  The 'st_ino' field is ignored except if the 'use_ino'
 * mount option is given.
 *
 * struct stat {
 *   dev_t     st_dev;     // ID of device containing file
 *   ino_t     st_ino;     // inode number
 *   mode_t    st_mode;    // protection
 *   nlink_t   st_nlink;   // number of hard links
 *   uid_t     st_uid;     // user ID of owner
 *   gid_t     st_gid;     // group ID of owner
 *   dev_t     st_rdev;    // device ID (if special file)
 *   off_t     st_size;    // total size, in bytes
 *   blksize_t st_blksize; // blocksize for file system I/O
 *   blkcnt_t  st_blocks;  // number of 512B blocks allocated
 *   time_t    st_atime;   // time of last access
 *   time_t    st_mtime;   // time of last modification
 *   time_t    st_ctime;   // time of last status change
 * };
 */
static int fuse_getattr(const char *path, struct stat *buf)
{
#ifndef HIDE_COMPLETED
  tolog(path);
  tolog(" - getattr\n");
#endif

  struct timeval tv;

  if (gettimeofday(&tv, NULL) == 0)
  {
    buf->st_atime = tv.tv_sec;
    buf->st_mtime = tv.tv_sec;
    buf->st_ctime = tv.tv_sec;
  }

  buf->st_uid = FILE_UID;
  buf->st_gid = FILE_GID;

  if (isDirectory(path))
  {
    buf->st_mode = S_IFDIR | S_IRWXU;
    buf->st_nlink = 2;
    return 0;
  }

  if (isSymlink(path))
  {
    buf->st_mode = S_IFLNK | S_IRWXU;
    buf->st_nlink = 1;
    return 0;
  }

  if (isOffset(path))
  {
    // Even though it's read-only, the write flag is there in case
    // a library we use requires write access. It won't be able to write to
    // the file of course, but it will think it can.
    buf->st_mode = S_IFREG | S_IRUSR | S_IWUSR;
    buf->st_nlink = 1;

    off_t offset = -1;
    off_t length = -1;

    sscanf(path + 1, "%llu-%llu", (unsigned long long *) &offset, (unsigned long long *) &length);
    if ((length == -1) || (length > (mappedFile_size - offset)))
    {
      if (mappedFile_size < offset)
      {
        length = 0;
      } else
      {
        length = mappedFile_size - offset;
      }
    }
    buf->st_size = length;
    buf->st_blocks = (buf->st_size + 511) / 512;
    return 0;
  }

  if (isMetaFilename(path))
  {
    // While we are aware of such a beast, these are all zero sized.
    buf->st_mode = S_IFREG | S_IRUSR | S_IWUSR;
    buf->st_nlink = 1;
    buf->st_size = 0;
    buf->st_blocks = 0;
    return 0;
  }
  // They might be enquiring about the usage file.
  if (g_strcmp0(path, "/" USAGE_FILE) == 0)
  {
    buf->st_mode = S_IFREG | S_IRUSR | S_IWUSR;
    buf->st_nlink = 1;
    buf->st_size = strlen(USAGE_FILE_CONTENT);
    buf->st_blocks = (buf->st_size + 511) / 512;
    return 0;
  }

  return -ENOENT;
}

/** Read the target of a symbolic link
 *
 * The buffer should be filled with a null terminated string.  The
 * buffer size argument includes the space for the terminating
 * null character. If the linkname is too long to fit in the
 * buffer, it should be truncated. The return value should be 0
 * for success.
 */
static int fuse_readlink(const char *path, char *buf, size_t len)
{
#ifndef HIDE_COMPLETED
  tolog(path);
  tolog(" - readlink\n");
#endif

  path++;
  GSList *l = g_slist_find_custom(link_list, path, (GCompareFunc) linkpathcmp);

  if (l != NULL)
  {
    struct link_pair *a = (struct link_pair *) (l->data);

    strncpy(buf, a->dest, len);
    return 0;
  }

  return -ENOENT;
}

/** Create a file node
 *
 * This is called for creation of all non-directory, non-symlink
 * nodes.  If the filesystem defines a create() method, then for
 * regular files that will be called instead.
 */
static int fuse_mknod(const char *path, mode_t mode, dev_t rdev)
{
#ifndef HIDE_UNTESTED
  tolog(" - mknod\n");
#endif

  return -ENOSYS;
}

/** Create a directory 
 *
 * Note that the mode argument may not have the type specification
 * bits set, i.e. S_ISDIR(mode) can be false.  To obtain the
 * correct directory type bits use  mode|S_IFDIR
 * */
static int fuse_mkdir(const char *path, mode_t dir)
{
#ifndef HIDE_COMPLETED
  tolog(path);
  tolog(" - mkdir\n");
#endif

  // Get rid of the / at the front
  path++;

  if ((g_slist_find_custom(dir_list, path, (GCompareFunc) strcmp) != NULL) || (g_slist_find_custom(link_list, path, (GCompareFunc) linkpathcmp) != NULL))
  {
    return -EEXIST;
  }
  // Only allow directories on the first level
  if (strchr(path, '/') != NULL)
  {
    return -EINVAL;
  }

  if (isValidDirectoryStructure(path) != 1)
  {
    return -EINVAL;
  }

  char *p = g_strdup(path);

  dir_list = g_slist_prepend(dir_list, p);

  return 0;
}

/** Remove a file */
static int fuse_unlink(const char *path)
{
#ifndef HIDE_COMPLETED
  tolog(path);
  tolog(" - unlink\n");
#endif

  path++;
  GSList *item = g_slist_find_custom(link_list, path, (GCompareFunc) linkpathcmp);

  if (item == NULL)
  {
    return -ENOENT;
  }

  struct link_pair *l = (struct link_pair *) item->data;

  g_free(l->path);
  g_free(l->dest);
  g_free(item->data);
  link_list = g_slist_delete_link(link_list, item);

  return 0;;
}

/** Remove a directory */
static int fuse_rmdir(const char *path)
{
#ifndef HIDE_COMPLETED
  tolog(path);
  tolog(" - rmdir\n");
#endif

  path++;
  GSList *item = g_slist_find_custom(dir_list, path, (GCompareFunc) strcmp);

  if (item == NULL)
  {
    return -ENOENT;
  }

  g_free(item->data);
  dir_list = g_slist_delete_link(dir_list, item);

  return 0;
}

/** Create a symbolic link */
static int fuse_symlink(const char *linkname, const char *path)
{
#ifndef HIDE_COMPLETED
  tolog(path);
  tolog(" - symlink to ");
  tolog(linkname);
  tolog("\n");
#endif

  // Get rid of the / at the front
  path++;

  if ((g_slist_find_custom(dir_list, path, (GCompareFunc) strcmp) != NULL) || (g_slist_find_custom(link_list, path, (GCompareFunc) linkpathcmp) != NULL))
  {
    return -EEXIST;
  }
  // Only allow symlinks on the first level
  if (strchr(path, '/') != NULL)
  {
    return -EINVAL;
  }

  if (isValidDirectoryStructure(path) != 1)
  {
    return -EINVAL;
  }

  struct link_pair *l = g_malloc(sizeof(struct link_pair));

  l->path = g_strdup(path);
  l->dest = g_strdup(linkname);

  link_list = g_slist_prepend(link_list, l);

  return 0;
}

/** Rename a file */
static int fuse_rename(const char *oldpath, const char *newpath)
{
#ifndef HIDE_UNTESTED
  tolog(oldpath);
  tolog(" - rename to ");
  tolog(newpath);
  tolog("\n");
#endif

  return -ENOSYS;
}

/** Create a hard link to a file */
static int fuse_link(const char *oldpath, const char *newpath)
{
#ifndef HIDE_UNTESTED
  tolog(oldpath);
  tolog(" - hardlink to ");
  tolog(newpath);
  tolog("\n");
#endif

  return -ENOSYS;
}

/** Change the permission bits of a file */
static int fuse_chmod(const char *path, mode_t mode)
{
#ifndef HIDE_UNTESTED
  tolog(path);
  tolog(" - chmod\n");
#endif

  return -ENOSYS;
}

/** Change the owner and group of a file */
static int fuse_chown(const char *path, uid_t uid, gid_t gid)
{
#ifndef HIDE_UNTESTED
  tolog(path);
  tolog(" - chown\n");
#endif

  return -ENOSYS;
}

/** Change the size of a file */
static int fuse_truncate(const char *path, off_t size)
{
#ifndef HIDE_COMPLETE
  tolog(path);
  tolog(" - truncate ");
  {
    char buf[80];

    sprintf(buf, "%d\n", (int) size);
    tolog(buf);
  }
#endif

  // Fool programs into thinking they can overwite files
  if (g_strcmp0(path, "/" USAGE_FILE) == 0)
  {
    return 0;
  }

  if (isOffset(path) || isMetaFilename(path))
  {
    return 0;
  }

  return -ENOENT;
}

/** File open operation
 *
 * No creation(O_CREAT, O_EXCL) and by default also no
 * truncation(O_TRUNC) flags will be passed to open(). If an
 * application specifies O_TRUNC, fuse first calls truncate()
 * and then open(). Only if 'atomic_o_trunc' has been
 * specified and kernel version is 2.6.24 or later, O_TRUNC is
 * passed on to open.
 *
 * Unless the 'default_permissions' mount option is given,
 * open should check if the operation is permitted for the
 * given flags. Optionally open may also return an arbitrary
 * filehandle in the fuse_file_info structure, which will be
 * passed to all file operations.
 *
 * Changed in version 2.2
 *
 * struct fuse_file_info {
 *   int flags; // Open flags. Available in open() and release()
 *   unsigned long fh_old; // Old file handle, don't use
 *   int writepage; // In case of a write operation indicates if
 *                  // this was caused by a writepage
 *   unsigned int direct_io : 1; // Can be filled in by open, to
 *                               // use direct I/O on this file.
 *                               // Introduced in version 2.4
 *   unsigned int keep_cache : 1; // Can be filled in by open, to
 *                                // indicate, that cached file data
 *                                // need not be invalidated.
 *                                // Introduced in version 2.4
 *   unsigned int flush : 1; // Indicates a flush operation.  Set
 *                           // in flush operation, also maybe set
 *                           // in highlevel lock operation and
 *                           // lowlevel release operation. 
 *                           // Introduced in version 2.6
 *   unsigned int nonseekable : 1; // Can be filled in by open, to
 *                                 // indicate that the file is not
 *                                 // seekable.
 *                                 // Introduced in version 2.8
 *   unsigned int padding : 28; // Padding.  Do not use
 *   uint64_t fh; // File handle.  
 *                // May be filled in by filesystem in open().
 *                // Available in all other file operations
 *   uint64_t lock_owner; // Lock owner id.  Available in locking
 *                        // operations and flush
 * };
 */
static int fuse_open(const char *path, struct fuse_file_info *info)
{
#ifndef HIDE_COMPLETED
  tolog(path);
  tolog(" - open\n");
#endif

  if (g_strcmp0(path, "/" USAGE_FILE) == 0)
  {
    return 0;
  }

  if (isOffset(path) || isMetaFilename(path))
  {
    return 0;
  }

  return -ENOENT;
}

/** Read data from an open file
 *
 * Read should return exactly the number of bytes requested except
 * on EOF or error, otherwise the rest of the data will be
 * substituted with zeroes.  An exception to this is when the
 * 'direct_io' mount option is specified, in which case the return
 * value of the read system call will reflect the return value of
 * this operation.
 *
 * Changed in version 2.2
 */
static int fuse_read(const char *path, char *buf, size_t buf_size, off_t offset, struct fuse_file_info *info)
{
#ifndef HIDE_COMPLETED
  tolog(path);
  tolog(" - read\n");
#endif

  if (g_strcmp0(path, "/" USAGE_FILE) == 0)
  {
    size_t size = buf_size;

    if (size > (strlen(USAGE_FILE_CONTENT) - offset))
    {
      size = strlen(USAGE_FILE_CONTENT) - offset;
    }

    if (size > 0)
    {
      memcpy(buf, USAGE_FILE_CONTENT + offset, size);
    }
    return size;
  }

  if (isOffset(path))
  {
    off_t file_offset = -1;
    off_t file_length = -1;

    sscanf(path + 1, "%llu-%llu", (unsigned long long *) &file_offset, (unsigned long long *) &file_length);
    fseeko(mappedFile, offset + file_offset, SEEK_SET);
    if ((file_length == -1) || (file_length > buf_size))
    {
      file_length = buf_size;
    }

    int ret = fread(buf, 1, file_length, mappedFile);

    return ret;
  }

  if (isMetaFilename(path))
  {
    return 0;
  }

  return -ENOENT;
}

/** Write data to an open file
 *
 * Write should return exactly the number of bytes requested
 * except on error.  An exception to this is when the 'direct_io'
 * mount option is specified(see read operation).
 *
 * Changed in version 2.2
 */
static int fuse_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *info)
{
#ifndef HIDE_COMPLETE
  tolog(path);
  tolog(" - write\n");
#endif

  // Fool programs into thinking they can write
  if (g_strcmp0(path, "/" USAGE_FILE) == 0)
  {
    return size;
  }

  if (isOffset(path) || isMetaFilename(path))
  {
    return size;
  }

  return -ENOENT;
}

/** Get file system statistics
 *
 * The 'f_frsize', 'f_favail', 'f_fsid' and 'f_flag' fields are ignored
 *
 * Replaced 'struct statfs' parameter with 'struct statvfs' in
 * version 2.5
 *
 * struct statvfs {
 *  unsigned long  f_bsize;    // file system block size
 *  unsigned long  f_frsize;   // fragment size
 *  fsblkcnt_t     f_blocks;   // size of fs in f_frsize units
 *  fsblkcnt_t     f_bfree;    // # free blocks
 *  fsblkcnt_t     f_bavail;   // # free blocks for unprivileged users
 *  fsfilcnt_t     f_files;    // # inodes
 *  fsfilcnt_t     f_ffree;    // # free inodes
 *  fsfilcnt_t     f_favail;   // # free inodes for unprivileged users
 *  unsigned long  f_fsid;     // file system ID
 *  unsigned long  f_flag;     // mount flags
 *  unsigned long  f_namemax;  // maximum filename length
 * };
 */
static int fuse_statfs(const char *path, struct statvfs *buf)
{
#ifndef HIDE_COMPLETED
  tolog(path);
  tolog(" - statfs\n");
#endif
  buf->f_bsize = 512;
  buf->f_blocks = (mappedFile_size + (buf->f_bsize - 1)) / buf->f_bsize;
  buf->f_bfree = 0;
  buf->f_files = mappedFile_size;
  buf->f_ffree = 0;
  buf->f_favail = 0;
  buf->f_namemax = 1024 * 1024;

  return 0;
}

/** Possibly flush cached data
 *
 * BIG NOTE: This is not equivalent to fsync().  It's not a
 * request to sync dirty data.
 *
 * Flush is called on each close() of a file descriptor.  So if a
 * filesystem wants to return write errors in close() and the file
 * has cached dirty data, this is a good place to write back data
 * and return any errors.  Since many applications ignore close()
 * errors this is not always useful.
 *
 * NOTE: The flush() method may be called more than once for each
 * open(). This happens if more than one file descriptor refers
 * to an opened file due to dup(), dup2() or fork() calls. It is
 * not possible to determine if a flush is final, so each flush
 * should be treated equally.  Multiple write-flush sequences are
 * relatively rare, so this shouldn't be a problem.
 *
 * Filesystems shouldn't assume that flush will always be called
 * after some writes, or that if will be called at all.
 *
 * Changed in version 2.2
 */
static int fuse_flush(const char *path, struct fuse_file_info *info)
{
#ifndef HIDE_COMPLETED
  tolog(path);
  tolog(" - flush\n");
#endif

  return 0;
}

/** Release an open file
 *
 * Release is called when there are no more references to an open
 * file: all file descriptors are closed and all memory mappings
 * are unmapped.
 *
 * For every open() call there will be exactly one release() call
 * with the same flags and file descriptor.  It is possible to
 * have a file opened more than once, in which case only the last
 * release will mean, that no more reads/writes will happen on the
 * file.  The return value of release is ignored.
 *
 * Changed in version 2.2
 */
static int fuse_release(const char *path, struct fuse_file_info *info)
{
#ifndef HIDE_COMPLETED
  tolog(path);
  tolog(" - release\n");
#endif

  return 0;
}

/** Synchronize file contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data.
 *
 * Changed in version 2.2
 */
static int fuse_fsync(const char *path, int datasync, struct fuse_file_info *info)
{
#ifndef HIDE_UNTESTED
  tolog(path);
  tolog(" - fsync\n");
#endif

  return -ENOSYS;
}

/** Set extended attributes */
static int fuse_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
#ifndef HIDE_UNTESTED
  tolog(path);
  tolog(" - setxattr set: ");
  tolog(name);
  tolog(" = ");
  tolog(value);
  tolog("\n");
#endif

  return 0;
}

/** Get extended attributes */
static int fuse_getxattr(const char *path, const char *name, char *value, size_t size)
{
#ifndef HIDE_COMPLETED
  tolog(path);
  tolog(" - getxattr requested: ");
  tolog(name);
  tolog("\n");
#endif

  return -ENOSYS;
}

/** List extended attributes */
static int fuse_listxattr(const char *path, char *list, size_t size)
{
#ifndef HIDE_UNTESTED
  tolog(path);
  tolog(" - listxattr\n");
#endif

  return -ENOSYS;
}

/** Remove extended attributes */
static int fuse_removexattr(const char *path, const char *name)
{
#ifndef HIDE_UNTESTED
  tolog(path);
  tolog(" - removexattr\n");
#endif

  return -ENOSYS;
}

/** Open directory
 *
 * Unless the 'default_permissions' mount option is given,
 * this method should check if opendir is permitted for this
 * directory. Optionally opendir may also return an arbitrary
 * filehandle in the fuse_file_info structure, which will be
 * passed to readdir, closedir and fsyncdir.
 *
 * Introduced in version 2.3
 */
static int fuse_opendir(const char *path, struct fuse_file_info *info)
{
#ifndef HIDE_COMPLETED
  tolog(path);
  tolog(" - opendir\n");
#endif

  if (isDirectory(path))
  {
    return 0;
  }

  return -ENOENT;
}

/** Read directory
 *
 * This supersedes the old getdir() interface.  New applications
 * should use this.
 *
 * The filesystem may choose between two modes of operation:
 *
 * 1) The readdir implementation ignores the offset parameter, and
 * passes zero to the filler function's offset.  The filler
 * function will not return '1'(unless an error happens), so the
 * whole directory is read in a single readdir operation.  This
 * works just like the old getdir() method.
 *
 * 2) The readdir implementation keeps track of the offsets of the
 * directory entries.  It uses the offset parameter and always
 * passes non-zero offset to the filler function.  When the buffer
 * is full(or an error happens) the filler function will return
 * '1'.
 *
 * Introduced in version 2.3
 */
static int fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *info)
{
#ifndef HIDE_COMPLETED
  tolog(path);
  tolog(" - readdir\n");
#endif

  if (path[0] != '/')
  {
    return -ENOENT;
  }
  path++;

  filler(buf, ".", NULL, 0);
  filler(buf, "..", NULL, 0);

  if (g_slist_find_custom(dir_list, path, (GCompareFunc) strcmp) != NULL)
  {
    return 0;
  }

  filler(buf, USAGE_FILE, NULL, 0);

  GSList *l = dir_list;

  while (l != NULL)
  {
    filler(buf, l->data, NULL, 0);
    l = g_slist_next(l);
  }

  l = link_list;
  while (l != NULL)
  {
    struct link_pair *p = (struct link_pair *) l->data;

    filler(buf, p->path, NULL, 0);
    l = l->next;
  }

  return 0;
}

/** Release directory
 *
 * Introduced in version 2.3
 */
static int fuse_releasedir(const char *path, struct fuse_file_info *info)
{
#ifndef HIDE_COMPLETED
  tolog(path);
  tolog(" - releasedir\n");
#endif

  return 0;
}

/** Synchronize directory contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data
 *
 * Introduced in version 2.3
 */
static int fuse_fsyncdir(const char *path, int datasync, struct fuse_file_info *info)
{
#ifndef HIDE_UNTESTED
  tolog(path);
  tolog(" - fsyncdir\n");
#endif

  return -ENOSYS;
}

/**
 * Initialize filesystem
 *
 * The return value will passed in the private_data field of
 * fuse_context to all file operations and as a parameter to the
 * destroy() method.
 *
 * Introduced in version 2.3
 * Changed in version 2.6
 */
void *f_init(struct fuse_conn_info *conn)
{
#ifndef HIDE_COMPLETED
  tolog("init called\n");
#endif

  // Conn has the following structure
  // proto_major (read-only)
  // proto_minor (read-only)
  conn->async_read = 0;
  // max_write (maximum size of write buffer)
  // max_readahead
  // capable (capability flags that the kernel supports)
  // want (capability flags that the filesystem wants to enable)

  return NULL;
}

/**
 * Clean up filesystem
 *
 * Called on filesystem exit.
 *
 * Introduced in version 2.3
 */
void f_destroy(void *data)
{
#ifndef HIDE_COMPLETED
  tolog("destroy called\n");
#endif

  g_slist_free_full(link_list, (GDestroyNotify) linkfree);
  link_list = NULL;

  g_slist_free_full(dir_list, free);
  dir_list = NULL;

  fclose(mappedFile);
  mappedFile = NULL;

  if (flog != NULL)
  {
    struct timeval tv;

    gettimeofday(&tv, NULL);
    fprintf(flog, "===== Log finished at %ld.%06ld =====\n", tv.tv_sec, tv.tv_usec);
    fclose(flog);
    flog = NULL;
  }
}

/**
 * Check file access permissions
 *
 * This will be called for the access() system call.  If the
 * 'default_permissions' mount option is given, this method is not
 * called.
 *
 * This method is not called under Linux kernel versions 2.4.x
 *
 * Introduced in version 2.5
 */
static int fuse_access(const char *path, int mask)
{
#ifndef HIDE_COMPLETED
  tolog(path);
  tolog(" - access\n");
#endif

  return 0;
}

/**
 * Create and open a file
 *
 * If the file does not exist, first create it with the specified
 * mode, and then open it.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the mknod() and open() methods
 * will be called instead.
 *
 * Introduced in version 2.5
 */
static int fuse_create(const char *path, mode_t mode, struct fuse_file_info *info)
{
#ifndef HIDE_UNTESTED
  tolog(path);
  tolog(" - create\n");
#endif

  return -ENOSYS;
}

/**
 * Change the size of an open file
 *
 * This method is called instead of the truncate() method if the
 * truncation was invoked from an ftruncate() system call.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the truncate() method will be
 * called instead.
 *
 * Introduced in version 2.5
 */
static int fuse_ftruncate(const char *path, off_t size, struct fuse_file_info *info)
{
#ifndef HIDE_UNTESTED
  tolog(path);
  tolog(" - ftruncate\n");
#endif

  return -ENOSYS;
}

/**
 * Get attributes from an open file
 *
 * This method is called instead of the getattr() method if the
 * file information is available.
 *
 * Currently this is only called after the create() method if that
 * is implemented(see above).  Later it may be called for
 * invocations of fstat() too.
 *
 * Introduced in version 2.5
 */
static int fuse_fgetattr(const char *path, struct stat *buf, struct fuse_file_info *info)
{
#ifndef HIDE_COMPLETED
  tolog(path);
  tolog(" - fgetattr\n");
#endif

  return fuse_getattr(path, buf);
}

/**
 * Perform POSIX file locking operation
 *
 * The cmd argument will be either F_GETLK, F_SETLK or F_SETLKW.
 *
 * For the meaning of fields in 'struct flock' see the man page
 * for fcntl(2).  The l_whence field will always be set to
 * SEEK_SET.
 *
 * For checking lock ownership, the 'fuse_file_info->owner'
 * argument must be used.
 *
 * For F_GETLK operation, the library will first check currently
 * held locks, and if a conflicting lock is found it will return
 * information without calling this method.  This ensures, that
 * for local locks the l_pid field is correctly filled in. The
 * results may not be accurate in case of race conditions and in
 * the presence of hard links, but it's unlikly that an
 * application would rely on accurate GETLK results in these
 * cases.  If a conflicting lock is not found, this method will be
 * called, and the filesystem may fill out l_pid by a meaningful
 * value, or it may leave this field zero.
 *
 * For F_SETLK and F_SETLKW the l_pid field will be set to the pid
 * of the process performing the locking operation.
 *
 * Note: if this method is not implemented, the kernel will still
 * allow file locking to work locally.  Hence it is only
 * interesting for network filesystems and similar.
 *
 * Introduced in version 2.6
 */
static int fuse_lock(const char *path, struct fuse_file_info *info, int cmd, struct flock *lock)
{
#ifndef HIDE_COMPLETED
  tolog(path);
  tolog(" - lock\n");
#endif

  return -ENOSYS;
}

/**
 * Change the access and modification times of a file with
 * nanosecond resolution
 *
 * Introduced in version 2.6
 */
static int fuse_utimens(const char *path, const struct timespec tv[2])
{
#ifndef HIDE_UNTESTED
  tolog(path);
  tolog(" - utimens\n");
#endif

  return -ENOSYS;
}

/**
 * Map block index within file to block index within device
 *
 * Note: This makes sense only for block device backed filesystems
 * mounted with the 'blkdev' option
 *
 * Introduced in version 2.6
 */
static int fuse_bmap(const char *path, size_t blocksize, uint64_t * idx)
{
#ifndef HIDE_UNTESTED
  tolog(path);
  tolog(" - bmap\n");
#endif

  return -ENOSYS;
}

/**
 * Ioctl
 *
 * flags will have FUSE_IOCTL_COMPAT set for 32bit ioctls in
 * 64bit environment.  The size and direction of data is
 * determined by _IOC_*() decoding of cmd.  For _IOC_NONE,
 * data will be NULL, for _IOC_WRITE data is out area, for
 * _IOC_READ in area and if both are set in/out area.  In all
 * non-NULL cases, the area is of _IOC_SIZE(cmd) bytes.
 *
 * Introduced in version 2.8
 */
static int fuse_ioctl(const char *path, int cmd, void *arg, struct fuse_file_info *info, unsigned int flags, void *data)
{
#ifndef HIDE_UNTESTED
  tolog(path);
  tolog(" - ioctl\n");
#endif

  return -ENOSYS;
}

/**
 * Poll for IO readiness events
 *
 * Note: If ph is non-NULL, the client should notify
 * when IO readiness events occur by calling
 * fuse_notify_poll() with the specified ph.
 *
 * Regardless of the number of times poll with a non-NULL ph
 * is received, single notification is enough to clear all.
 * Notifying more times incurs overhead but doesn't harm
 * correctness.
 *
 * The callee is responsible for destroying ph with
 * fuse_pollhandle_destroy() when no longer in use.
 *
 * Introduced in version 2.8
 */
static int fuse_poll(const char *path, struct fuse_file_info *info, struct fuse_pollhandle *ph, unsigned *reventsp)
{
#ifndef HIDE_UNTESTED
  tolog(path);
  tolog("poll not implemented\n");
#endif

  return -ENOSYS;
}

static struct fuse_operations fop = {
  .getattr = fuse_getattr,
  .readlink = fuse_readlink,
  .mknod = fuse_mknod,
  .mkdir = fuse_mkdir,
  .unlink = fuse_unlink,
  .rmdir = fuse_rmdir,
  .symlink = fuse_symlink,
  .rename = fuse_rename,
  .link = fuse_link,
  .chmod = fuse_chmod,
  .chown = fuse_chown,
  .truncate = fuse_truncate,
  .open = fuse_open,
  .read = fuse_read,
  .write = fuse_write,
  .statfs = fuse_statfs,
  .flush = fuse_flush,
  .release = fuse_release,
  .fsync = fuse_fsync,
  .setxattr = fuse_setxattr,
  .getxattr = fuse_getxattr,
  .listxattr = fuse_listxattr,
  .removexattr = fuse_removexattr,
  .opendir = fuse_opendir,
  .readdir = fuse_readdir,
  .releasedir = fuse_releasedir,
  .fsyncdir = fuse_fsyncdir,
  .init = f_init,
  .destroy = f_destroy,
  .access = fuse_access,
  .create = fuse_create,
  .ftruncate = fuse_ftruncate,
  .fgetattr = fuse_fgetattr,
  .lock = fuse_lock,
  .utimens = fuse_utimens,
  .bmap = fuse_bmap,
  .ioctl = fuse_ioctl,
  .poll = fuse_poll,
};

/**
 * Adds an argument to the argv array, and increments argc appropriately.
 *
 * \param argc The number of args
 * \param argv The arg array
 * \param opt The option to add to the argv array
 */
static void addopt(int *argc, char ***argv, const char *opt)
{
  (*argc)++;
  *argv = (char **) realloc(*argv, sizeof(char *) * (*argc));
  (*argv)[(*argc - 1)] = g_strdup(opt);
}

/**
 * Prints the usage to screen.
 *
 * \param prog The program name
 */
static void printUsage(const char *prog)
{
  printf("\nUsage: %s -o file=<input file> [-df -ologfile=<log>] <mount point>\n", prog);
  printf("\nOther options:\n");
  printf("\t-d \t- debug mode\n");
  printf("\t-f \t- foreground mode\n");
  printf("\t-o logfile=<log>\t- logfile for debugging\n");
  // Forced on
//      printf("\t-o allow_other \t- Allow other users to look into mountpoint\n");
}

/**
 * Starts the program
 *
 * \param argc The number of args
 * \param argv The arg array
 * \returns 0 for success, -1 on error
 */
int main(int argc, char *argv[])
{
  FILE_UID = getuid();
  FILE_GID = getgid();

  int newargc = 0;
  char **newargv = NULL;

  addopt(&newargc, &newargv, argv[0]);
  // Always add -s (single threaded)
  addopt(&newargc, &newargv, "-s");
  addopt(&newargc, &newargv, "-oallow_other");

  int opt;
  char *ptr = NULL;

  while ((opt = getopt(argc, argv, "o:df")) != -1)
  {
    switch (opt)
    {
    case 'o':
      ptr = strtok(optarg, ",");
      while (ptr != NULL)
      {
        if (strncasecmp(ptr, INPUT_FILE_OPTION_NAME "=", strlen(INPUT_FILE_OPTION_NAME "=")) == 0)
        {
          if (mappedFile != NULL)
          {
            printf("Can't specify more than one '%s=' option\n", INPUT_FILE_OPTION_NAME);
            printUsage(argv[0]);
            return -1;
          }
          ptr += strlen(INPUT_FILE_OPTION_NAME "=");

          mappedFile = fopen(ptr, "rb");
          if (mappedFile == NULL)
          {
            perror(ptr);
            return -1;
          }
          fseeko(mappedFile, 0, SEEK_END);
          mappedFile_size = ftello(mappedFile);
        } else if (strncasecmp(ptr, LOG_FILE_OPTION_NAME "=", strlen(LOG_FILE_OPTION_NAME "=")) == 0)
        {
          if (flog != NULL)
          {
            printf("Can't specify more than one '%s=' option\n", LOG_FILE_OPTION_NAME);
            printUsage(argv[0]);
            return -1;
          }
          ptr += strlen(LOG_FILE_OPTION_NAME "=");
          flog = fopen(ptr, "ab");
          if (flog == NULL)
          {
            perror(ptr);
            return -1;
          }
          struct timeval tv;

          gettimeofday(&tv, NULL);
          fprintf(flog, "===== Log started at %ld.%06ld =====\n", tv.tv_sec, tv.tv_usec);
        } else
        {
          addopt(&newargc, &newargv, "-o");
          addopt(&newargc, &newargv, ptr);
        }

        ptr = strtok(NULL, ",");
      }

      break;
    case 'd':
      addopt(&newargc, &newargv, "-d");
      addopt(&newargc, &newargv, "-o");
      addopt(&newargc, &newargv, "debug");
      break;
    case 'f':
      addopt(&newargc, &newargv, "-f");
      break;
    default:
      printUsage(argv[0]);
      return -1;
    }
  }
  if (optind >= argc)
  {
    printf("Missing mountpoint\n");
    printUsage(argv[0]);
    return -1;
  }

  if (mappedFile == NULL)
  {
    printf("Input file not provided\n");
    printUsage(argv[0]);
    return -1;
  }

  addopt(&newargc, &newargv, argv[optind]);

  // -s single threaded
  // -d -o debug (enable debug mode)
  // -f foreground
  int ret = fuse_main(newargc, newargv, &fop, NULL);

  int i;

  for (i = 0; i < newargc; i++)
  {
    g_free(newargv[i]);
  }
  g_free(newargv);

  return ret;
}
