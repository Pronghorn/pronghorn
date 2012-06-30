/* Pronghorn lprocess header
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
 *
 */

/**
 * \file lprocess.h
 * \brief lprocess header file
 *
 * This is a helper library to assist with creating a process with limited resources.
 *
 * It allows the parent to easily set limits on the resources a child can use. This is useful when parents are unable to trust their children will behave appropriately.
 */

#ifndef LPROCESS_H
#define LPROCESS_H

#include <unistd.h>
#include <glib.h>

/**
 * Creates a new child process.
 *
 * \warning REMEMBER TO CALL wait/waitpid TO REAP THE CHILD ONCE IT DIES
 *
 * \warning You probably don't want this function - it should only be used by the pronghorn process.
 *
 * \param argv Just like argv in main(), however it must have a NULL string as its last element.
 * \param pid The PID of the child
 * \param mem_limit Defines the memory limit for the new process in megabytes, or -1 for no limit.
 * \param disk_limit Defines the amount of disk the new process can use in megabytes, or -1 for no limit.
 * \param proc_limit Defines the amount of CPU the new process can use in seconds, or -1 for no limit.
 * \param valgrind_opts Comma separated valgrind options
 * \returns 0 on success -1 on error. errno is set.
 */
int spawn_limited_process_with_valgrind(char *const *argv, pid_t * pid, int mem_limit, int disk_limit, int proc_limit, char *valgrind_opts);

/**
 * Creates a new child process.
 *
 * \warning REMEMBER TO CALL wait/waitpid TO REAP THE CHILD ONCE IT DIES
 *
 * \param argv Just like argv in main(), however it must have a NULL string as its last element.
 * \param pid The PID of the child
 * \param mem_limit Defines the memory limit for the new process in megabytes, or -1 for no limit.
 * \param disk_limit Defines the amount of disk the new process can use in megabytes, or -1 for no limit.
 * \param proc_limit Defines the amount of CPU the new process can use in seconds, or -1 for no limit.
 * \returns 0 on success -1 on error. errno is set.
 */
int spawn_limited_process(char *const *argv, pid_t * pid, int mem_limit, int disk_limit, int proc_limit);

/**
 * Creates a new child process.
 *
 * It will automatically look into a config object to determine process limits.
 *
 * \param argv Just like argv in main(), however it must have a NULL string as its last element.
 * \param pid The PID of the child
 * \returns 0 on success -1 on error. errno is set.
 */
int spawn_process(char *const *argv, pid_t * pid);

/**
 * Creates a new child process and waits for it to terminate before returning.
 *
 * \warning You probably don't want this function - it should only be used by the pronghorn process.
 *
 * \param argv Just like argv in main(), however it must have a NULL string as its last element.
 * \param mem_limit Defines the memory limit for the new process in megabytes, or -1 for no limit.
 * \param disk_limit Defines the amount of disk the new process can use in megabytes, or -1 for no limit.
 * \param proc_limit Defines the amount of CPU the new process can use in seconds, or -1 for no limit.
 * \param valgrind_opts Comma separated valgrind options
 * \returns The status of the dead child (or -1 on error). Read waitpid for macros to interpret the status int
 * \note Clears all current signal masks
 */
int spawn_limited_process_with_valgrind_and_wait(char *const *argv, int mem_limit, int disk_limit, int proc_limit, char *valgrind_opts) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Creates a new child process and waits for it to terminate before returning.
 *
 * \param argv Just like argv in main(), however it must have a NULL string as its last element.
 * \param mem_limit Defines the memory limit for the new process in megabytes, or -1 for no limit.
 * \param disk_limit Defines the amount of disk the new process can use in megabytes, or -1 for no limit.
 * \param proc_limit Defines the amount of CPU the new process can use in seconds, or -1 for no limit.
 * \returns The status of the dead child (or -1 on error). Read waitpid for macros to interpret the status int
 * \note Clears all current signal masks
 */
int spawn_limited_process_and_wait(char *const *argv, int mem_limit, int disk_limit, int proc_limit) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Creates a new child process and waits for it to terminate before returning.
 *
 * It will automatically look into a config object to determine process limits.
 *
 * \param argv Just like argv in main(), however it must have a NULL string as its last element.
 * \returns The status of the dead child (or -1 on error). Read waitpid for macros to interpret the status int
 */
int spawn_process_and_wait(char *const *argv) G_GNUC_WARN_UNUSED_RESULT;

#endif
