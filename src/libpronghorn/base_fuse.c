/* libpronghorn Base FUSE driver
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
 * \file base_fuse.c
 * \brief This is a basic fuse setup which specific implementations can
 * extend to simply their design.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <glib.h>

#include <logger.h>
#include <config.h>
#include <defaults.h>
#include <base_fuse.h>

#ifdef DEBUG
        /** For debug. Comment out if not needed */
//      #define DEBUG_FUSE_GETATTR
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_READLINK
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_MKNOD
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_MKDIR
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_UNLINK
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_RMDIR
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_SYMLINK
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_RENAME
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_LINK
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_CHMOD
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_CHOWN
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_TRUCATE
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_OPEN
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_READ
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_WRITE
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_STATFS
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_FLUSH
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_RELEASE
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_FSYNC
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_SETXATTR
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_GETXATTR
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_LISTXATTR
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_REMOVEXATTR
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_OPENDIR
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_READDIR
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_RELEASEDIR
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_FSYNCDIR
        /** For debug. Comment out if not needed */
#define DEBUG_F_INIT
        /** For debug. Comment out if not needed */
#define DEBUG_F_DESTROY
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_ACCESS
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_CREATE
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_FTRUNCATE
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_FGETATTR
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_LOCK
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_UTIMENS
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_BMAP
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_IOCTL
        /** For debug. Comment out if not needed */
#define DEBUG_FUSE_POLL
#endif // DEBUG

/** Defines the suffix that specifies the filename */
#define FILENAME_SUFFIX ":filename"
/** Defines the suffix that specifies a directory */
#define MOUNTPOINT_SUFFIX ":mnt"

/** Identifies the type of an entry_struct */
enum type_t
{ ENTRY_LINK, ENTRY_DIR, ENTRY_FILE };

/**
 * This is the generic structure used to record entries in
 * the filesystem.
 *
 * Not all members will be documented! Only type (and filename)
 * are guaranteed to be populated. The rest will be populated 
 * depending on the type value.
 *
 * ENTRY_LINK
 *  - Has destname
 *
 * ENTRY_DIR
 *  (Nothing)
 *
 * ENTRY_FILE
 *  - Has (original) filename
 *  - Has size
 */
struct entry_struct
{
        /** The type of the entry struct */
  enum type_t type;
        /** The filename of the entry */
  char *filename;
        /** The size of the file */
  unsigned long long size_of_file;
        /** The destname of the link */
  char *destname;
};

/**
 * This structure is used when 'filling' directory entries 
 * while performing a directory listing. (Refer to fuse_readdir)
 */
struct filler_struct
{
        /** The filler function */
  fuse_fill_dir_t filler;
        /** The buffer to fill */
  void *buf;
};

/** The UID to give to the file */
static int FILE_UID = 0;

/** The GID to give to the file */
static int FILE_GID = 0;

/** A g_tree which holds all the entries for this fs */
static GTree *entry_tree = NULL;

/** Defines whether to allow directory listings or not (for efficiency)*/
static int no_directory_listing = 0;

/** The log file handle. We need to use a file as the logger doesn't work inside fuse */
static FILE *flog = NULL;

/**
 * Compares two filenames for sorting.
 *
 * Used by g_tree.
 *
 * \param a String a
 * \param b String b
 * \param user_data Nothing.
 * \returns 0 if equal, <0 if a<b, >0 if a>b
 */
static gint compare_filenames(gconstpointer a, gconstpointer b, gpointer user_data)
{
  return g_strcmp0((const char *) a, (const char *) b);
}

/**
 * A cleanup function to free the memory allocated to a g_tree entry.
 *
 * \param entry The entry to free.
 */
static void free_entry_struct(struct entry_struct *entry)
{
  if (entry != NULL)
  {
    if (entry->filename != NULL)
    {
      g_free(entry->filename);
    }
    if (entry->destname != NULL)
    {
      g_free(entry->destname);
    }
    g_free(entry);
  }
}

/**
 * Adds an entry into the entry struct.
 *
 * This function should not be called directly. Instead add_file, add_directory or add_link should be used instead.
 *
 * \param type The type of entry
 * \param key The key for this entry
 * \param filename The true filename for this key
 * \param size_of_file The size of the file
 * \param destname The destination pointer for the link type
 */
static void add_entry(enum type_t type, const char *key, const char *filename, unsigned long long size_of_file, const char *destname)
{
  char *key_dup = g_strdup(key);

  struct entry_struct *entry = (struct entry_struct *) g_malloc(sizeof(struct entry_struct));

  entry->type = type;

  if (filename != NULL)
  {
    entry->filename = g_strdup(filename);
  } else
  {
    entry->filename = NULL;
  }

  entry->size_of_file = size_of_file;

  if (destname != NULL)
  {
    entry->destname = g_strdup(destname);
  } else
  {
    entry->destname = NULL;
  }

  if (entry_tree == NULL)
  {
    entry_tree = g_tree_new_full(compare_filenames, NULL, (GDestroyNotify) free, (GDestroyNotify) free_entry_struct);
  }
  // This will replace any existing entry with the same name
  g_tree_insert(entry_tree, key_dup, entry);
}

int add_file(unsigned int id_number, const char *filename, unsigned long long size_of_file)
{
  if (filename == NULL)
  {
    return -1;
  }

  char *key = g_strdup_printf("%u", id_number);

  add_entry(ENTRY_FILE, key, filename, size_of_file, NULL);
  g_free(key);
  return 0;
}

void remove_all_files(void)
{
  if (entry_tree != NULL)
  {
    g_tree_destroy(entry_tree);
    entry_tree = NULL;
  }
}

/**
 * Adds a directory to the entry structure.
 *
 * \param directory_name The name of the directory
 * \returns 0 on success, -1 on error.
 */
static int add_directory(const char *directory_name)
{
  if (directory_name == NULL)
  {
    return -1;
  }

  add_entry(ENTRY_DIR, directory_name, NULL, 0, NULL);
  return 0;
}

/**
 * Adds a link to the entry structure
 *
 * \param link_name The name of the link on the filesystem
 * \param dest_name Where the link points.
 * \returns 0 on success, -1 on error
 */
static int add_link(const char *link_name, const char *dest_name)
{
  if ((link_name == NULL) || (dest_name == NULL))
  {
    return -1;
  }

  add_entry(ENTRY_LINK, link_name, NULL, 0, dest_name);
  return 0;
}

/**
 * Locates and returns an entry structure.
 *
 * Path is expected to start with a '/'
 *
 * \param path The path to lookup.
 * \returns The entry structure for that path, or NULL if not found.
 */
static struct entry_struct *get_entry(const char *path)
{
  if ((path == NULL) || (path[0] != '/'))
  {
    return NULL;
  }
  // Eliminate the starting '/'
  path++;

  return (struct entry_struct *) g_tree_lookup(entry_tree, path);
}

/**
 * A callback used by g_tree to iterate through the elements in the g_tree and populate the readdir structure.
 *
 * \param key The key for the entry
 * \param value The entry
 * \param data The filler structure
 * \returns FALSE, signifying the iteration should continue.
 */
static gboolean populate_file_entries(gpointer key, gpointer value, gpointer data)
{
  struct filler_struct *f = (struct filler_struct *) data;
  struct entry_struct *s = (struct entry_struct *) value;

  f->filler(f->buf, (const char *) key, NULL, 0);

  if (s->type == ENTRY_FILE)
  {
    // Populate the meta filenames
    char *meta = g_strdup_printf("%s%s", (char *) key, FILENAME_SUFFIX);

    f->filler(f->buf, meta, NULL, 0);
    g_free(meta);
  }

  return FALSE;
}

static struct entry_struct *is_valid_entry_with_extension(const char *name)
{
  const char *ptr = strchr(name, '.');

  if (ptr == NULL)
  {
    return NULL;
  }

  char *shortname = g_strndup(name, ptr - name);
  struct entry_struct *entry = get_entry(shortname);

  g_free(shortname);
  return entry;
}

/**
 * Checks that the supplied name has the specified suffix and the base
 * name for the entry exists.
 *
 * \param name The name to test
 * \param suffix The suffix the name must have
 * \returns The entry struct for the base entry name, or NULL if it is invalid.
 */
static struct entry_struct *is_valid_entry_with_suffix(const char *name, const char *suffix)
{
  if ((name == NULL) || (strlen(name) <= strlen(suffix)))
  {
    return NULL;
  }
  // First check that it ends with the correct suffix
  if (g_str_has_suffix(name, suffix) == FALSE)
  {
    // Nope.
    return NULL;
  }

  char *shortname = g_strdup(name);

  shortname[strlen(shortname) - strlen(suffix)] = '\0';

  struct entry_struct *entry = get_entry(shortname);

  g_free(shortname);

  return entry;
}

/**
 * Checks the supplied name conforms to the directory structure format.
 *
 * \param name The name to test
 * \returns The entry related to the basename of the supplied name, or NULL if it is not a valid name.
 */
static struct entry_struct *is_valid_directory_structure(const char *name)
{
  // This has changed since it was decided that we will allow a subcontractor defined
  // suffix to describe the mount point type. So the following examples are now considered
  // valid: 1000:mnt-pdf, 1000:mntdoc, 1000:mnttype5
//      return is_valid_entry_with_suffix(name, MOUNTPOINT_SUFFIX);
  const char *pos = strstr(name, MOUNTPOINT_SUFFIX);

  if (pos == NULL)
  {
    return NULL;
  }

  char *shortname = g_strdup(name);

  shortname[strlen(name) - strlen(pos)] = '\0';

  struct entry_struct *entry = get_entry(shortname);

  g_free(shortname);

  return entry;
}

/**
 * Checks the supplied name conforms to the filename structure format
 *
 * \param name The name to test
 * \returns The entry related to the basename of the supplied name, or NULL if it is not a valid name.
 */
static struct entry_struct *is_valid_filename_structure(const char *name)
{
  return is_valid_entry_with_suffix(name, FILENAME_SUFFIX);
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
 *
 * \param path The path to get
 * \param buf The stat buf
 * \return 0 on success, -errno error
 */
static int fuse_getattr(const char *path, struct stat *buf)
{
#ifdef DEBUG_FUSE_GETATTR
  if (flog != NULL)
  {
    fprintf(flog, "%s - getattr. Answer => ", path);
  }
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

  if (strcmp(path, "/") == 0)
  {
    buf->st_mode = S_IFDIR | S_IRWXU;
    buf->st_nlink = 2;
#ifdef DEBUG_FUSE_GETATTR
    if (flog != NULL)
    {
      fprintf(flog, "is root directory\n");
    }
#endif
    return 0;
  }

  struct entry_struct *entry = is_valid_filename_structure(path);

  if (entry != NULL)
  {
    buf->st_mode = S_IFREG | S_IRUSR | S_IWUSR;
    buf->st_nlink = 1;
    buf->st_size = strlen(entry->filename);
    buf->st_blocks = (buf->st_size + 511) / 512;
#ifdef DEBUG_FUSE_GETATTR
    if (flog != NULL)
    {
      fprintf(flog, "is meta filename\n");
    }
#endif
    return 0;
  }

  entry = is_valid_entry_with_extension(path);
  if (entry == NULL)
  {
    entry = get_entry(path);
  }

  if (entry != NULL)
  {
    switch (entry->type)
    {
    case ENTRY_LINK:
      buf->st_mode = S_IFLNK | S_IRWXU;
      buf->st_nlink = 1;
#ifdef DEBUG_FUSE_GETATTR
      if (flog != NULL)
      {
        fprintf(flog, "is link\n");
      }
#endif
      return 0;

    case ENTRY_DIR:
      buf->st_mode = S_IFDIR | S_IRWXU;
      buf->st_nlink = 2;
#ifdef DEBUG_FUSE_GETATTR
      if (flog != NULL)
      {
        fprintf(flog, "is directory\n");
      }
#endif
      return 0;

    case ENTRY_FILE:
      // Even though it's read-only, the write flag is there in case
      // a library we use requires write access. It won't be able to write to
      // the file of course, but it will think it can.
      buf->st_mode = S_IFREG | S_IRUSR | S_IWUSR;
      buf->st_nlink = 1;
      buf->st_size = entry->size_of_file;
      buf->st_blocks = (buf->st_size + 511) / 512;
#ifdef DEBUG_FUSE_GETATTR
      if (flog != NULL)
      {
        fprintf(flog, "is regular file (inode)\n");
      }
#endif
      return 0;
    }
  }
#ifdef DEBUG_FUSE_GETATTR
  if (flog != NULL)
  {
    fprintf(flog, "is invalid\n");
  }
#endif
  return -ENOENT;
}

/** Read the target of a symbolic link
 *
 * The buffer should be filled with a null terminated string.  The
 * buffer size argument includes the space for the terminating
 * null character. If the linkname is too long to fit in the
 * buffer, it should be truncated. The return value should be 0
 * for success.
 *
 * \param path The path to read
 * \param buf The buf to fill.
 * \param len The length of the buffer
 * \returns 0 on success, -errno on error
 */
static int fuse_readlink(const char *path, char *buf, size_t len)
{
#ifdef DEBUG_FUSE_READLINK
  if (flog != NULL)
  {
    fprintf(flog, "%s - readlink ", path);
  }
#endif

  struct entry_struct *entry = get_entry(path);

  if (entry != NULL)
  {
    strncpy(buf, entry->destname, len);
#ifdef DEBUG_FUSE_READLINK
    if (flog != NULL)
    {
      fprintf(flog, "(Success)\n");
    }
#endif
    return 0;
  }
#ifdef DEBUG_FUSE_READLINK
  if (flog != NULL)
  {
    fprintf(flog, "(Not found)\n");
  }
#endif
  return -ENOENT;
}

/** Create a file node
 *
 * This is called for creation of all non-directory, non-symlink
 * nodes.  If the filesystem defines a create() method, then for
 * regular files that will be called instead.
 *
 * \param path The path to test
 * \param mode The mode for the node
 * \param rdev The dev numbers
 * \returns 0 on success, -errno on error
 */
static int fuse_mknod(const char *path, mode_t mode, dev_t rdev)
{
#ifdef DEBUG_FUSE_MKNOD
  if (flog != NULL)
  {
    fprintf(flog, " - mknod (Not supported)\n");
  }
#endif

  return -ENOSYS;
}

/** Create a directory 
 *
 * Note that the mode argument may not have the type specification
 * bits set, i.e. S_ISDIR(mode) can be false.  To obtain the
 * correct directory type bits use  mode|S_IFDIR
 *
 * \param path The path to create
 * \param dir The mode
 * \returns - 0 on success, -errno on error
 */
static int fuse_mkdir(const char *path, mode_t dir)
{
#ifdef DEBUG_FUSE_MKDIR
  if (flog != NULL)
  {
    fprintf(flog, "%s - mkdir ", path);
  }
#endif

  if (is_valid_directory_structure(path) == NULL)
  {
#ifdef DEBUG_FUSE_MKDIR
    if (flog != NULL)
    {
      fprintf(flog, "(Invalid)\n");
    }
#endif
    return -EINVAL;
  }

  if (get_entry(path) != NULL)
  {
#ifdef DEBUG_FUSE_MKDIR
    if (flog != NULL)
    {
      fprintf(flog, "(Already exists)\n");
    }
#endif
    return -EEXIST;
  }

  add_directory(path + 1);

#ifdef DEBUG_FUSE_MKDIR
  if (flog != NULL)
  {
    fprintf(flog, "(Success)\n");
  }
#endif
  return 0;
}

/**
 * Remove a file
 *
 * \param path the file to remove
 * \returns 0 on success, -errno on error
 */
static int fuse_unlink(const char *path)
{
#ifdef DEBUG_FUSE_UNLINK
  if (flog != NULL)
  {
    fprintf(flog, "%s - unlink\n", path);
  }
#endif

  struct entry_struct *entry = get_entry(path);

  if (entry == NULL)
  {
    return -ENOENT;
  }

  if (entry->type != ENTRY_LINK)
  {
    // Can only remove links
    return -EINVAL;
  }

  g_tree_remove(entry_tree, path);
  return 0;
}

/**
 * Remove a directory
 *
 * \param path The path to remove
 * \returns 0 on success, -errno on error.
 */
static int fuse_rmdir(const char *path)
{
#ifdef DEBUG_FUSE_RMDIR
  if (flog != NULL)
  {
    fprintf(flog, "%s - rmdir\n", path);
  }
#endif

  struct entry_struct *entry = get_entry(path);

  if (entry == NULL)
  {
    return -ENOENT;
  }

  if (entry->type != ENTRY_DIR)
  {
    // Can only remove directories
    return -EINVAL;
  }

  g_tree_remove(entry_tree, path + 1);
  return 0;
}

/**
 * Create a symbolic link
 *
 * \param linkname What the link points to
 * \param path The link
 * \returns 0 on success, -errno on error
 */
static int fuse_symlink(const char *linkname, const char *path)
{
#ifdef DEBUG_FUSE_SYMLINK
  if (flog != NULL)
  {
    fprintf(flog, "%s - symlink to %s", path, linkname);
  }
#endif

  if (is_valid_directory_structure(path) == NULL)
  {
#ifdef DEBUG_FUSE_SYMLINK
    if (flog != NULL)
    {
      fprintf(flog, " (Invalid)\n");
    }
#endif
    return -EINVAL;
  }

  if (get_entry(path) != NULL)
  {
#ifdef DEBUG_FUSE_SYMLINK
    if (flog != NULL)
    {
      fprintf(flog, " (Already exists)\n");
    }
#endif
    return -EEXIST;
  }

  add_link(path + 1, linkname);

#ifdef DEBUG_FUSE_SYMLINK
  if (flog != NULL)
  {
    fprintf(flog, " (Success)\n");
  }
#endif
  return 0;
}

/**
 * Rename a file 
 *
 * \param oldpath The old path
 * \param newpath The new path
 * \returns 0 on success, -errno on error
 */
static int fuse_rename(const char *oldpath, const char *newpath)
{
#ifdef DEBUG_FUSE_RENAME
  if (flog != NULL)
  {
    fprintf(flog, "%s - rename to %s\n", oldpath, newpath);
  }
#endif

  return -ENOSYS;
}

/**
 * Create a hard link to a file
 *
 * \param oldpath The old path
 * \param newpath The new path
 * \returns 0 on success, -errno on error
 */
static int fuse_link(const char *oldpath, const char *newpath)
{
#ifdef DEBUG_FUSE_LINK
  if (flog != NULL)
  {
    fprintf(flog, "%s - hardlink to %s\n", oldpath, newpath);
  }
#endif

  return -ENOSYS;
}

/**
 * Change the permission bits of a file
 *
 * \param path The path
 * \param mode The mode
 * \returns 0 on success, -errno on error
 */
static int fuse_chmod(const char *path, mode_t mode)
{
#ifdef DEBUG_FUSE_CHMOD
  if (flog != NULL)
  {
    fprintf(flog, "%s - chmod\n", path);
  }
#endif

  return -ENOSYS;
}

/**
 * Change the owner and group of a file
 *
 * \param path The path to the file
 * \param uid The new UID
 * \param git The new GID
 * \returns 0 on success, -errno on error
 */
static int fuse_chown(const char *path, uid_t uid, gid_t gid)
{
#ifdef DEBUG_FUSE_CHOWN
  if (flog != NULL)
  {
    fprintf(flog, "%s - chown\n", path);
  }
#endif

  return -ENOSYS;
}

/**
 * Change the size of a file
 *
 * \param path The path to the file
 * \param size Its new size
 * \returns 0 on success, -errno on error
 */
static int fuse_truncate(const char *path, off_t size)
{
#ifdef DEBUG_FUSE_TRUNCATE
  if (flog != NULL)
  {
    fprintf(flog, "%s - truncate to %d\n", path, size);
  }
#endif

  // Fool programs into thinking they can overwite files
  if (is_valid_filename_structure(path) != NULL)
  {
    // Its the filename meta file
    return 0;
  }
  if (is_valid_entry_with_extension(path) != NULL)
  {
    // It's a regular file with an extension
    return 0;
  }
  if (get_entry(path) != NULL)
  {
    // It's a regular file
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
 *
 * \param path The path to open
 * \param info The info struct
 * \returns 0 on success, -errno on error
 */
static int fuse_open(const char *path, struct fuse_file_info *info)
{
#ifdef DEBUG_FUSE_OPEN
  if (flog != NULL)
  {
    fprintf(flog, "%s - open ", path);
  }
#endif

  if (is_valid_filename_structure(path) != NULL)
  {
#ifdef DEBUG_FUSE_OPEN
    if (flog != NULL)
    {
      fprintf(flog, "(success)\n");
    }
#endif
    return 0;
  }
  if ((is_valid_entry_with_extension(path) != NULL) || (get_entry(path) != NULL))
  {
#ifdef DEBUG_FUSE_OPEN
    if (flog != NULL)
    {
      fprintf(flog, "(success)\n");
    }
#endif
    return 0;
  }
#ifdef DEBUG_FUSE_OPEN
  if (flog != NULL)
  {
    fprintf(flog, "(failure)\n");
  }
#endif
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
 *
 * \param path The path to read
 * \param buf The buffer to read into
 * \param buf_size The amount to read
 * \param offset The offset into the file to read
 * \param info An info struct
 * \returns Number of bytes read, or -errno.
 */
static int fuse_read(const char *path, char *buf, size_t buf_size, off_t offset, struct fuse_file_info *info)
{
#ifdef DEBUG_FUSE_READ
  if (flog != NULL)
  {
    fprintf(flog, "%s - read\n", path);
  }
#endif

  struct entry_struct *entry = is_valid_filename_structure(path);

  if (entry != NULL)
  {
    int len = strlen(entry->filename) + 1;

    if (offset >= len)
    {
      return 0;
    }
    if (offset + buf_size > len)
    {
      buf_size = len - offset;
    }

    memcpy(buf, entry->filename + offset, buf_size);
    return buf_size;
  }

  entry = is_valid_entry_with_extension(path);
  if (entry == NULL)
  {
    entry = get_entry(path);
  }
  if ((entry != NULL) && (entry->type == ENTRY_FILE))
  {
    int ret = do_read(atoi(path + 1), entry->filename, buf, buf_size, offset);

    if (ret == -1)
    {
      return -ENOENT;
    }
    return ret;
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
 *
 * \param path The path to write to
 * \param buf The buffer with data to write
 * \param size The size of the buffer
 * \param offset The offset into the file to write
 * \returns Amount of bytes read, -errno on error
 */
static int fuse_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *info)
{
#ifdef DEBUG_FUSE_WRITE
  if (flog != NULL)
  {
    fprintf(flog, "%s - write\n", path);
  }
#endif

  // Fool programs into thinking they can write
  if (is_valid_filename_structure(path) != NULL)
  {
    return size;
  }
  if (is_valid_entry_with_extension(path) != NULL)
  {
    return size;
  }
  if (get_entry(path) != NULL)
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
 *
 * \param path The path to stat
 * \param buf The statvfs struct.
 * \returns 0 on success, -errno on error
 */
static int fuse_statfs(const char *path, struct statvfs *buf)
{
#ifdef DEBUG_FUSE_STATFS
  if (flog != NULL)
  {
    fprintf(flog, "%s - statfs\n", path);
  }
#endif
  buf->f_bsize = 512;

  buf->f_blocks = 1000;
  buf->f_bfree = 0;
  buf->f_files = 1000;
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
 *
 * \param path The path to flush
 * \param info File info
 * \returns 0 on success, -errno on error
 */
static int fuse_flush(const char *path, struct fuse_file_info *info)
{
#ifdef DEBUG_FUSE_FLUSH
  if (flog != NULL)
  {
    fprintf(flog, "%s - flush (success)\n", path);
  }
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
 *
 * \param path The path to release
 * \param info The info structure
 * \returns 0 on success, -errno on error
 */
static int fuse_release(const char *path, struct fuse_file_info *info)
{
#ifdef DEBUG_FUSE_RELEASE
  if (flog != NULL)
  {
    fprintf(flog, "%s - release (success)\n", path);
  }
#endif

  return 0;
}

/** Synchronize file contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data.
 *
 * Changed in version 2.2
 *
 * \param path The path to sync
 * \param datasync Flags
 * \param info Info struct
 * \returns 0 on success, -errno on error
 */
static int fuse_fsync(const char *path, int datasync, struct fuse_file_info *info)
{
#ifdef DEBUG_FUSE_FSYNC
  if (flog != NULL)
  {
    fprintf(flog, "%s - fsync\n", path);
  }
#endif

  return -ENOSYS;
}

/**
 * Set extended attributes
 *
 * \param path The path to set
 * \param name The xattr to set
 * \param value The value to set it to
 * \param size The size of the value
 * \param flags Flags
 * \returns 0 on success, -errno on error
 */
static int fuse_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
#ifdef DEBUG_FUSE_SETXATTR
  if (flog != NULL)
  {
    fprintf(flog, "%s - setxattr set: %s\n", path, name);
  }
#endif

  return 0;
}

/**
 * Get extended attributes
 *
 * \param path The path to get
 * \param name The xattr name to get
 * \param value The value returned
 * \param size The size of the value buffer
 * \returns The size of the attribute, or -errno on error
 */
static int fuse_getxattr(const char *path, const char *name, char *value, size_t size)
{
#ifdef DEBUG_FUSE_GETXATTR
  if (flog != NULL)
  {
    fprintf(flog, "%s - getxattr requested: %s\n", path, name);
  }
#endif

  return -ENOSYS;
}

/**
 * List extended attributes
 *
 * \param path The path to list
 * \param list The xattr list
 * \param size The size of list
 * \returns The number of attributes or -errno on error
 */
static int fuse_listxattr(const char *path, char *list, size_t size)
{
#ifdef DEBUG_FUSE_LISTXATTR
  if (flog != NULL)
  {
    fprintf(flog, "%s - listxattr\n", path);
  }
#endif

  return -ENOSYS;
}

/**
 * Remove extended attributes
 *
 * \param path The path to modify
 * \param name The xattr to remove
 * \returns 0 on success, -errno on error.
 */
static int fuse_removexattr(const char *path, const char *name)
{
#ifdef DEBUG_FUSE_REMOVEXATTR
  if (flog != NULL)
  {
    fprintf(flog, "%s - removexattr\n", path);
  }
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
 *
 * \param path The path to open
 * \param info The info struct
 * \returns 0 on success, -errno on error
 */
static int fuse_opendir(const char *path, struct fuse_file_info *info)
{
#ifdef DEBUG_FUSE_OPENDIR
  if (flog != NULL)
  {
    fprintf(flog, "%s - opendir ", path);
  }
#endif

  struct entry_struct *entry = get_entry(path);

  if ((entry != NULL) && (entry->type == ENTRY_DIR))
  {
#ifdef DEBUG_FUSE_OPENDIR
    if (flog != NULL)
    {
      fprintf(flog, "(Success)\n");
    }
#endif
    return 0;
  }

  if (strcmp(path, "/") == 0)
  {
#ifdef DEBUG_FUSE_OPENDIR
    if (flog != NULL)
    {
      fprintf(flog, "(Success)\n");
    }
#endif
    return 0;
  }
#ifdef DEBUG_FUSE_OPENDIR
  if (flog != NULL)
  {
    fprintf(flog, "(Not found)\n");
  }
#endif
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
 *
 * \param path The path to read
 * \param buf The buffer containing the enumerated directory entries.
 * \param filler The filler function to use to fill the buffer
 * \param offset The offset into the directory to read.
 * \returns 0 on success, -errno on error
 */
static int fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *info)
{
#ifdef DEBUG_FUSE_READDIR
  if (flog != NULL)
  {
    fprintf(flog, "%s - readdir offset=%d ", path, (int) offset);
  }
#endif

  struct entry_struct *entry = get_entry(path);

  if ((entry != NULL) && (entry->type == ENTRY_DIR))
  {
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
#ifdef DEBUG_FUSE_READDIR
    if (flog != NULL)
    {
      fprintf(flog, "(Success)\n");
    }
#endif
    return 0;
  }

  if (strcmp(path, "/") != 0)
  {
#ifdef DEBUG_FUSE_READDIR
    if (flog != NULL)
    {
      fprintf(flog, "(Not found)\n");
    }
#endif
    return -ENOENT;
  }

  filler(buf, ".", NULL, 0);
  filler(buf, "..", NULL, 0);

  if (no_directory_listing == 0)
  {
    struct filler_struct f;

    f.filler = filler;
    f.buf = buf;

    g_tree_foreach(entry_tree, populate_file_entries, &f);
  }
#ifdef DEBUG_FUSE_READDIR
  if (flog != NULL)
  {
    fprintf(flog, "(Success)\n");
  }
#endif
  return 0;
}

/** Release directory
 *
 * Introduced in version 2.3
 *
 * \param path The path to release
 * \param info The info structure
 * \returns 0 on success, -errno on error.
 */
static int fuse_releasedir(const char *path, struct fuse_file_info *info)
{
#ifdef DEBUG_FUSE_RELEASEDIR
  if (flog != NULL)
  {
    fprintf(flog, "%s - releasedir (Success)\n", path);
  }
#endif

  return 0;
}

/** Synchronize directory contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data
 *
 * Introduced in version 2.3
 *
 * \param path The path to sync
 * \param datasync Flags
 * \param info The info structure
 * \returns 0 on success, -errno on error
 */
static int fuse_fsyncdir(const char *path, int datasync, struct fuse_file_info *info)
{
#ifdef DEBUG_FUSE_FSYNCDIR
  if (flog != NULL)
  {
    fprintf(flog, "%s - fsyncdir\n", path);
  }
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
 *
 * \param conn Conn info
 * \returns An array to pass to f_destroy
 */
void *f_init(struct fuse_conn_info *conn)
{
#ifdef DEBUG_F_INIT
  if (flog != NULL)
  {
    fprintf(flog, "init called\n");
  }
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
 *
 * \param data The data returned from init.
 */
void f_destroy(void *data)
{
#ifdef DEBUG_F_DESTROY
  if (flog != NULL)
  {
    fprintf(flog, "destroy called\n");
  }
#endif

  if (entry_tree != NULL)
  {
    g_tree_destroy(entry_tree);
    entry_tree = NULL;
  }

  if (flog != NULL)
  {
    struct timeval tv;

    gettimeofday(&tv, NULL);
    fprintf(flog, "===== Log finished at %ld.%06ld =====\n", tv.tv_sec, tv.tv_usec);
    fclose(flog);
    flog = NULL;
  }

  cleanup();
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
 *
 * \param path The path to access
 * \param mask The mask to use
 * \returns 0 on success, -errno on error
 */
static int fuse_access(const char *path, int mask)
{
#ifdef DEBUG_FUSE_ACCESS
  if (flog != NULL)
  {
    fprintf(flog, "%s - access\n", path);
  }
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
 *
 * \param path The path to create
 * \param mode The mode to set
 * \param info Info struct
 * \returns 0 on success, -errno on error
 */
static int fuse_create(const char *path, mode_t mode, struct fuse_file_info *info)
{
#ifdef DEBUG_FUSE_CREATE
  if (flog != NULL)
  {
    fprintf(flog, "%s - create\n", path);
  }
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
 *
 * \param path The path to truncate
 * \param size The size to truncate it to
 * \param info Info struct
 * \returns 0 on success, -errno on error
 */
static int fuse_ftruncate(const char *path, off_t size, struct fuse_file_info *info)
{
#ifdef DEBUG_FUSE_FTRUNCATE
  if (flog != NULL)
  {
    fprintf(flog, "%s - ftruncate\n", path);
  }
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
 *
 * \param path The path to query
 * \param buf The buffer to populate
 * \param info Info struct
 * \returns 0 on success, -errno on errro
 */
static int fuse_fgetattr(const char *path, struct stat *buf, struct fuse_file_info *info)
{
#ifdef DEBUG_FUSE_FGETATTR
  if (flog != NULL)
  {
    fprintf(flog, "%s - fgetattr\n", path);
  }
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
 *
 * \param path The path to lock
 * \param info Info struct
 * \param cmd Command to perform
 * \param lock Lock struct
 * \returns 0 on success, -errno on error
 */
static int fuse_lock(const char *path, struct fuse_file_info *info, int cmd, struct flock *lock)
{
#ifdef DEBUG_FUSE_LOCK
  if (flog != NULL)
  {
    fprintf(flog, "%s - lock (not supported)\n", path);
  }
#endif

  return -ENOSYS;
}

/**
 * Change the access and modification times of a file with
 * nanosecond resolution
 *
 * Introduced in version 2.6
 *
 * \param path The path to change
 * \param tv The time values to set
 * \returns 0 on success, -errno on error
 */
static int fuse_utimens(const char *path, const struct timespec tv[2])
{
#ifdef DEBUG_FUSE_UTIMENS
  if (flog != NULL)
  {
    fprintf(flog, "%s - utimens\n", path);
  }
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
 *
 * \param path The path to set
 * \param blocksize The blocksize to use
 * \param idx The index to map
 * \returns 0 on success, -errno on error
 */
static int fuse_bmap(const char *path, size_t blocksize, uint64_t * idx)
{
#ifdef DEBUG_FUSE_BMAP
  if (flog != NULL)
  {
    fprintf(flog, "%s - bmap\n", path);
  }
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
 * 
 * \param path The path
 * \param cmd The command to perform
 * \param arg Args for the info
 * \param info Info struct
 * \param flags Flags to use
 * \param data Data to set
 * \returns 0 on success, -errno on error
 */
static int fuse_ioctl(const char *path, int cmd, void *arg, struct fuse_file_info *info, unsigned int flags, void *data)
{
#ifdef DEBUG_FUSE_IOCTL
  if (flog != NULL)
  {
    fprintf(flog, "%s - ioctl\n", path);
  }
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
 *
 * \param path The path to poll
 * \param info Info struct
 * \param ph The poll handle
 * \param reventsp ??
 * \returns 0 on success, -errno on error
 */
static int fuse_poll(const char *path, struct fuse_file_info *info, struct fuse_pollhandle *ph, unsigned *reventsp)
{
#ifdef DEBUG_FUSE_POLL
  if (flog != NULL)
  {
    fprintf(flog, "%s - poll not implemented\n", path);
  }
#endif

  return -ENOSYS;
}

int do_mount(char *mountpoint)
{
  FILE_UID = getuid();
  FILE_GID = getgid();

  struct fuse_operations fop = { 0 };
  fop.getattr = fuse_getattr;
  fop.readlink = fuse_readlink;
  fop.mknod = fuse_mknod;
  fop.mkdir = fuse_mkdir;
  fop.unlink = fuse_unlink;
  fop.rmdir = fuse_rmdir;
  fop.symlink = fuse_symlink;
  fop.rename = fuse_rename;
  fop.link = fuse_link;
  fop.chmod = fuse_chmod;
  fop.chown = fuse_chown;
  fop.truncate = fuse_truncate;
  fop.open = fuse_open;
  fop.read = fuse_read;
  fop.write = fuse_write;
  fop.statfs = fuse_statfs;
  fop.flush = fuse_flush;
  fop.release = fuse_release;
  fop.fsync = fuse_fsync;
  fop.setxattr = fuse_setxattr;
  fop.getxattr = fuse_getxattr;
  fop.listxattr = fuse_listxattr;
  fop.removexattr = fuse_removexattr;
  fop.opendir = fuse_opendir;
  fop.readdir = fuse_readdir;
  fop.releasedir = fuse_releasedir;
  fop.fsyncdir = fuse_fsyncdir;
  fop.init = f_init;
  fop.destroy = f_destroy;
  fop.access = fuse_access;
  fop.create = fuse_create;
  fop.ftruncate = fuse_ftruncate;
  fop.fgetattr = fuse_fgetattr;
  fop.lock = fuse_lock;
  fop.utimens = fuse_utimens;
  fop.bmap = fuse_bmap;
  fop.ioctl = fuse_ioctl;
  fop.poll = fuse_poll;

  if (config_get_int(NULL, CONFIG_FUSE_NO_DIRECTORY_LISTINGS, &no_directory_listing) != 0)
  {
    no_directory_listing = 0;
  }

  char *debug_file;

  if ((config_get(NULL, CONFIG_FUSE_OUTPUT_DEBUG_FILE, &debug_file) == 0) && (debug_file != NULL))
  {
    flog = fopen(debug_file, "w");
    if (flog == NULL)
    {
      debug_log("Failed to open fuse output debug file %s: %s", debug_file, strerror(errno));
    }
    g_free(debug_file);
  }
  // Create the mountpoint if it doesn't exist
  struct stat buf;

  if (stat(mountpoint, &buf) != 0)
  {
    if (mkdir(mountpoint, S_IRWXU) != 0)
    {
      error_log("base_fuse.c: Unable to create mountpoint %s", mountpoint);
      return -1;
    }
  }
  // Forking to allow the parent to continue
  int pid = fork();

  if (pid != 0)
  {
    // As fuse_main is not called with -f then the child process will
    // exit when it creates it's child

    int status;

    waitpid(pid, &status, 0);

    remove_all_files();

    if (status == 0)
    {
      debug_log("fuse_mount exited with status %d", status);
    } else
    {
      severe_log("fuse_mounted exited with status %d", status);
      severe_log("This could be caused by a) Mount point is occupied, b) Too many mounts (increase the value in /etc/fuse.conf), c) Insufficient permissions, d) Any of a number of other factors");
    }

    return 0;
  }
  // We're in the child here
  // WE CANNOT DO ANYTHING WITH A TRANSPORT LAYER
  // ZMQ makes things go boom

  // These are the args that fuse_main accepts
  // -s single threaded
  // -d -o debug (enable debug mode)
  // -f foreground
  char *process_name_copy = g_strdup(PROCESS_NAME);
  const char *args[] = { process_name_copy, "-s", "-oallow_other", mountpoint };

  int ret = fuse_main(sizeof(args) / sizeof(char *), (char **) args, &fop, NULL);

  g_free(process_name_copy);

  // Is this nice?
  _exit(ret);
}
