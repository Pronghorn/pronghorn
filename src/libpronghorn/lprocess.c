/* Pronghorn lprocess
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
 * \file lprocess.c
 * \brief lprocess file
 *
 * This is a helper library to assist with creating a process with limited resources.
 *
 * It allows the parent to easily set limits on the resources a child can use. This is useful when parents are unable to trust their children will behave appropriately.
 */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <signal.h>
#include <time.h>               // For nanosleep
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <glib.h>

#include <config.h>
#include <defaults.h>
#include <logger.h>
#include <basename_safe.h>

#include "lprocess.h"

#define CHILD_WAIT_COUNTER_MAX 1000
#define CHILD_WAIT_LOOP_SLEEP_MSEC 5
#define SIGNAL_TO_NOTIFY_CHILD SIGUSR1

volatile sig_atomic_t child_wait_counter = 0;

void signal_handler(int signal, siginfo_t * siginfo, void *context)
{
  child_wait_counter = CHILD_WAIT_COUNTER_MAX;
}

/**
 * Adds the valgrind options to the start of the argv array
 *
 * This function does not modify the original array.
 *
 * \warning You must free the returned array by iterating through it's non-NULL members calling g_free, then g_freeing the array itself!
 *
 * \param argv The original argv array
 * \param valgrind_options The comma separated values to add
 * \returns A new argv array
 */
static char **add_valgrind_options(char *const *argv, char *valgrind_options)
{
  int num_args = 0;
  char *ptr = valgrind_options;

  num_args++;
  while ((ptr = strchr(ptr, ',')) != NULL)
  {
    num_args++;
    ptr++;
  }

  num_args++;
  char *const *ptr2 = argv;

  while (*ptr2 != NULL)
  {
    num_args++;
    ptr2++;
  }

  // We need a new argv array with num_args elements
  char **valgrind_argv = (char **) g_malloc(sizeof(char *) * num_args);

  ptr = strtok(valgrind_options, ",");
  num_args = 0;
  while (ptr != NULL)
  {
    valgrind_argv[num_args++] = g_strdup(ptr);
    ptr = strtok(NULL, ",");
  }

  ptr2 = argv;
  while (*ptr2 != NULL)
  {
    valgrind_argv[num_args++] = g_strdup(*ptr2);
    ptr2++;
  }

  valgrind_argv[num_args] = NULL;

  return valgrind_argv;
}

static int spawn_limited_process_real(char *const *argv, pid_t * pid, int mem_limit, int disk_limit, int proc_limit)
{
  *pid = -1;

  if (argv == NULL || access(argv[0], R_OK | X_OK) != 0)
  {
    return -1;
  }
  // Setting up a signal handler for our child to handle
  struct sigaction oldsignal;

  memset(&oldsignal, 0, sizeof(struct sigaction));
  struct sigaction newsignal;

  memset(&newsignal, 0, sizeof(struct sigaction));
  newsignal.sa_sigaction = signal_handler;
  newsignal.sa_flags = SA_SIGINFO;

  child_wait_counter = 0;
  if (sigaction(SIGNAL_TO_NOTIFY_CHILD, &newsignal, &oldsignal) != 0)
  {
    error_log("Failed to setup signal handler!");
    return -1;
  }

  *pid = fork();
  if (*pid == 0)
  {
    // We're in the child

    // Wait for signal from the parent to continue running
    for (; child_wait_counter < CHILD_WAIT_COUNTER_MAX; child_wait_counter++)
    {
      struct timespec req;

      req.tv_sec = 0;
      req.tv_nsec = CHILD_WAIT_LOOP_SLEEP_MSEC * 1000 * 1000;
      nanosleep(&req, NULL);
    }

    // The state of signal masks is preserved when a child is spawned.
    // This is almost certainly not what we want in pronghorn, as such
    // we ensure that all signals are unblocked
    sigset_t x;

    sigfillset(&x);
    sigprocmask(SIG_UNBLOCK, &x, NULL);

    struct rlimit limit;

    if (mem_limit != -1)
    {
      limit.rlim_cur = mem_limit * 1024 * 1024L;
      limit.rlim_max = limit.rlim_cur;
      if (setrlimit(RLIMIT_AS, &limit) != 0)
      {
        perror("RLIMIT_AS");
      }
    }

    if (disk_limit != -1)
    {
      limit.rlim_cur = disk_limit * 1024 * 1024L;
      limit.rlim_max = limit.rlim_cur;
      if (setrlimit(RLIMIT_FSIZE, &limit) != 0)
      {
        perror("RLIMIT_FIZE");
      }
    }

    if (proc_limit != -1)
    {
      limit.rlim_cur = mem_limit;
      limit.rlim_max = limit.rlim_cur;
      if (setrlimit(RLIMIT_CPU, &limit) != 0)
      {
        perror("RLIMIT_CPU");
      }
    }

    execv(argv[0], argv);

    // DO NOT USE ANY ZMQ TRANSPORTS HERE
    // It makes things go boom
    //severe_log("Failed to spawn %s?", argv[0]);
    fprintf(stderr, "lprocess.c Failed to exec \"%s\" !\n", argv[0]);

    _exit(1);
  }
  // Restoring the old signal handler
  if (sigaction(SIGNAL_TO_NOTIFY_CHILD, &oldsignal, NULL) != 0)
  {
    error_log("Unable to restore old signal handler!");
  }
  // Ready to give the child a slap to welcome it into the world
  kill(*pid, SIGNAL_TO_NOTIFY_CHILD);

  debug_log("Spawned %s. Process ID = %d", argv[0], *pid);

  return 0;
}

int spawn_limited_process_with_valgrind(char *const *argv, pid_t * pid, int mem_limit, int disk_limit, int proc_limit, char *valgrind_opts)
{
  if (valgrind_opts == NULL)
  {
    return spawn_limited_process_real(argv, pid, mem_limit, disk_limit, proc_limit);
  }

  char **valgrind_argv = add_valgrind_options(argv, valgrind_opts);
  int ret = spawn_limited_process_real(valgrind_argv, pid, mem_limit, disk_limit, proc_limit);

  char **ptr = valgrind_argv;

  while (*ptr != NULL)
  {
    g_free(*ptr);
    ptr++;
  }
  g_free(valgrind_argv);

  return ret;
}

int spawn_limited_process(char *const *argv, pid_t * pid, int mem_limit, int disk_limit, int proc_limit)
{
  const char *exe_name = basename_safe(argv[0]);

  char *valgrind_options = NULL;

  if ((config_get(exe_name, CONFIG_VALGRIND_OPTION_NAME, &valgrind_options) == -1) || (valgrind_options == NULL) || (strlen(valgrind_options) == 0))
  {
    if ((config_get(CONFIG_GENERAL_GROUP_OPTION_NAME, CONFIG_VALGRIND_OPTION_NAME, &valgrind_options) == -1) || (valgrind_options == NULL) || (strlen(valgrind_options) == 0))
    {
      return spawn_limited_process_with_valgrind(argv, pid, mem_limit, disk_limit, proc_limit, NULL);
    }
  }

  int ret = spawn_limited_process_with_valgrind(argv, pid, mem_limit, disk_limit, proc_limit, valgrind_options);

  g_free(valgrind_options);

  return ret;
}

int spawn_process(char *const *argv, pid_t * pid)
{
  // Need to get config values for the process being spawned.
  const char *exe_name = basename_safe(argv[0]);

  int mem_limit;

  if ((config_get_int(exe_name, CONFIG_SPAWN_MEMORY_LIMIT, &mem_limit) == -1) || (mem_limit == 0))
  {
    mem_limit = -1;
  } else
  {
    debug_log("Limiting the memory for process %s to %dMb", exe_name, mem_limit);
  }

  int disk_limit;

  if ((config_get_int(exe_name, CONFIG_SPAWN_DISK_LIMIT, &disk_limit) == -1) || (disk_limit == 0))
  {
    disk_limit = -1;
  } else
  {
    debug_log("Limiting the disk usage for process %s to %dMb", exe_name, disk_limit);
  }

  int proc_limit;

  if ((config_get_int(exe_name, CONFIG_SPAWN_PROC_LIMIT, &proc_limit) == -1) || (proc_limit == 0))
  {
    proc_limit = -1;
  } else
  {
    debug_log("Limiting the process time for process %s to %d.. somethings?", exe_name, proc_limit);
  }

  return spawn_limited_process(argv, pid, mem_limit, disk_limit, proc_limit);
}

int spawn_limited_process_with_valgrind_and_wait(char *const *argv, int mem_limit, int disk_limit, int proc_limit, char *valgrind_opts)
{
  int pid = 0;

  if (spawn_limited_process_with_valgrind(argv, &pid, mem_limit, disk_limit, proc_limit, valgrind_opts) != 0)
  {
    return -1;
  }
  int status = 0;

  waitpid(pid, &status, 0);

  return status;
}

int spawn_limited_process_and_wait(char *const *argv, int mem_limit, int disk_limit, int proc_limit)
{
  return spawn_limited_process_with_valgrind_and_wait(argv, mem_limit, disk_limit, proc_limit, NULL);
}

int spawn_process_and_wait(char *const *argv)
{
  int pid = 0;

  if (spawn_process(argv, &pid) != 0)
  {
    return -1;
  }
  int status = 0;

  waitpid(pid, &status, 0);

  return status;
}
