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
 * \file base_fuse.h
 * \brief This is a basic fuse setup which specific implementations can
 * extend to simply their design.
 */

#ifndef BASE_FUSE_H
#define BASE_FUSE_H

/**
 * We need to specify the version we're compiling against
 * in case it changes in the future.
 */
#define FUSE_USE_VERSION 26
#include <fuse.h>

/**
 * Mounts the FUSE filesystem onto the specified mountpoint
 *
 * \param mountpoint The location to mount the filesystem
 * \returns 0 on success, something else on error
 */
int do_mount(char *mountpoint);

/**
 * Adds a file to the file listing.
 *
 * \param id_number An ID number YOU assign to the file.
 * \param filename The name of the file it represents. (Relative path
 * to the file within the container where the file was found.)
 * \param size_of_file The size of the file in bytes.
 * \returns 0 on success, -1 on error.
 */
int add_file(unsigned int id_number, const char *filename, unsigned long long size_of_file);

/**
 * Removes all files added via the add_file mechanism.
 *
 * Should be called to free the internal structure. Should only be called by
 * base_fuse by the parent following the fork.
 */
void remove_all_files(void);

/**
 * Is called whenever a file is read.
 *
 * \warning YOU must implement this function.
 *
 * It is not implemented by base_fuse, it is called by base_fuse.
 *
 * \param id_number The ID number of the file to read
 * \param filename The true filename of the file to read
 * \param buf The buffer to populate.
 * \param size The amount of data to put into the buffer.
 * \param offset The offset INTO THE FILE where the data should be source from.
 * \returns Number of bytes read, or -1 if invalid.
 */
int do_read(unsigned int id_number, const char *filename, char *buf, size_t size, off_t offset) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Is called when the filesystem is unmounted.
 *
 * \warning YOU must implement this function.
 *
 * It allows you to cleanup your internal structures when the filesystem is unmounted.
 */
void cleanup(void);

#endif
