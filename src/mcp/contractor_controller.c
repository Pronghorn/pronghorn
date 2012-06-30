/* Pronghorn Contractor Controller
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
 * \file contractor_controller.c
 * \brief This file helps the master control program out by taking
 * care of the management of contractors.
 *
 */
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <glib.h>

#include <lprocess.h>
#include <config.h>
#include <defaults.h>
#include <prong_assert.h>

#include "contractor_controller.h"

/** GLOBALS */

/** The current state of the MCP. This is provided by the MCP */
extern volatile sig_atomic_t mcp_state;

/** The target number of contractors we want */
int target_number_contractors = 0;

/** Our collection of contractors */
GSList *child_contractors = NULL;

/**
 * Is there a currently pending unhandled contractor death? If a contractor
 * crashes, it's catastrophic. 
 */
volatile sig_atomic_t contractor_exited = 0;

/** DEFINITIONS */


/**
 * \brief Return the contractor process with a given pid
 *
 * \param pid The pid of the contractor process we want
 * \return If a contractor is found with given pid, returns it. If a 
 * contractor process is not found with the given pid, returns NULL.
 */
struct contractor_process *get_contractor_by_pid(pid_t pid)
{

  if (child_contractors == NULL)
    return NULL;

  GSList *curr = child_contractors;

  while (curr != NULL)
  {
    struct contractor_process *curr_con = (struct contractor_process *) curr->data;

    prong_assert(curr_con != NULL);

    if (curr_con->pid == pid)
    {
      return curr_con;
    }

    curr = curr->next;
  }

  return NULL;
}


/**
 * \brief Spawns a new contractor
 *
 * \return 0 on success, -1 on failure
 *
 * Spawns a new contractor. There is nothing to pass, since all contractors 
 * are generic in their nature. 
 *
 */
int spawn_new_contractor(void)
{

  // Calculate the options we require.
  gchar *contractor_executable = NULL;
  gchar *config_endpoint = NULL;

  if ((config_get_with_default_macro(NULL, CONFIG_CONTRACTOR_EXECUTABLE_NAME, &contractor_executable) != 0) || (contractor_executable == NULL))
  {

    severe_log("Couldn't spawn a new contractor as there was an error " "determining the executable path");

    if (contractor_executable != NULL)
    {
      g_free(contractor_executable);
    }

    return -1;
  }

  if ((config_get_with_default_macro(NULL, CONFIG_CONFIG_CONNECT_ENDPOINT, &config_endpoint) != 0) || (config_endpoint == NULL))
  {

    severe_log("Couldn't spawn a new contractor as there was an error " "determining the config endpoint to connect to");

    if (config_endpoint != NULL)
    {
      g_free(config_endpoint);
    }

    return -1;
  }

  gchar *spawn_args[3];

  spawn_args[0] = contractor_executable;
  spawn_args[1] = config_endpoint;
  spawn_args[2] = NULL;

  // Wait until we have spawned everything before worrying about sigchlds  
  sigset_t x;

  sigemptyset(&x);
  sigaddset(&x, SIGCHLD);
  sigprocmask(SIG_BLOCK, &x, NULL);

  // Setup the structure that will hold the new record

  struct contractor_process *cp = (struct contractor_process *) g_malloc(sizeof(struct contractor_process));

  int ret = spawn_process(spawn_args, (sig_atomic_t *) & cp->pid);

  g_free(contractor_executable);
  g_free(config_endpoint);

  if (ret != 0)
  {
    severe_log("Couldn't spawn new contractor!");
    return -1;
  }
  // Sorting shouldn't be required - the number of contractors will be
  // relatively small.
  child_contractors = g_slist_insert(child_contractors, cp, 0);

  sigprocmask(SIG_UNBLOCK, &x, NULL);

  return 0;
}


/** 
 * \brief Contractor sigchild handler. Catches contractors dieing.
 *
 * \param sig Signal being handled
 * \param sig_info Extra info about the signal
 * \param ucontext Not used
 *
 * Handles the cleanup required when a child contractor dies. It sets the 
 * pid of the dead contractor to -1, and sets the global flag 
 * unhandled_contractor_death
 *
 */
void contractor_sigchld_handler(int sig, siginfo_t * sig_info, void *ucontext)
{

  // NB "When the handler for a particular signal is invoked,
  // that signal is automatically blocked until the handler returns
  // from:
  // http://www.gnu.org/software/libc/manual/html_node/Signals-in-Handler.html
  //
  // NB Two signals that happen at the same time may be merged into one
  // from:
  // http://www.cs.utah.edu/dept/old/texinfo/glibc-manual-0.02/library_toc.html#SEC356
  // Although I'm not sure this is stil the case for sigaction, since sig_info contains
  // a pid. At any rate, we err on the side of caution and assume that we might have
  // two merged signals.

  pid_t pid;
  int status;

  while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
  {
    // Have reaped the child, now need to handle it from a contractor point
    // of view!
    struct contractor_process *remove_me = NULL;

    remove_me = get_contractor_by_pid(pid);

    if (remove_me != NULL)
    {

      if (mcp_state == RUNNING)
      {
        contractor_exited = -1;
      }

      remove_me->pid = -1;
    }
  }

}


// Documented in header
int contractor_controller_init(int target_num_contractors)
{

  target_number_contractors = target_num_contractors;
  child_contractors = NULL;

  /* Setup the signal handler */

  struct sigaction action;

  memset(&action, 0, sizeof(action));
  action.sa_sigaction = contractor_sigchld_handler;
  action.sa_flags = SA_SIGINFO;

  if (sigaction(SIGCHLD, &action, NULL))
  {
    severe_log("Oroblem setting sigaction for contractor controller (%s)", strerror(errno));
    return -1;
  }

  /* Spawn contractors */

  int i = 0;

  for (i = 0; i < target_number_contractors; i++)
  {
    if (spawn_new_contractor() != 0)
    {
      return -1;
    }
  }

  return 0;
}



/**
 * \brief Determines if the passed pid is a contractor process
 *
 * \param pid The pid to determine whether or not is a contractor
 * \return 1 if the pid is a contractor, 0 if it's not
 */
int pid_is_contractor(pid_t pid)
{
  if (get_contractor_by_pid(pid) == NULL)
  {
    return 0;
  }

  return 1;
}


/** 
 * \brief Send all contractors the specified signal
 *
 * \param sig The signal to send
 * \warning You should ensure that signals are blocked before 
 * using this function. 
 *
 * Send all the contractors we know to be alive the specified signal
 * 
 */
void _send_all_contractors_signal(int sig)
{

  debug_log("Sending all contractors signal \"%s\"", strsignal(sig));

  GSList *curr = child_contractors;

  while (curr != NULL)
  {
    struct contractor_process *curr_con = (struct contractor_process *) curr->data;

    prong_assert(curr_con != NULL);

    volatile int local_pid = curr_con->pid;

    if (local_pid != -1)
    {
      kill(local_pid, sig);
    }

    curr = curr->next;

  }

  debug_log("Sent all contractors signal %s", strsignal(sig));

}


// Documented in header
unsigned int contractor_controller_number_contractors(void)
{

  guint alive_contractors = 0;

  GSList *curr = child_contractors;

  while (curr != NULL)
  {
    struct contractor_process *curr_con = (struct contractor_process *) curr->data;

    prong_assert(curr_con != NULL);

    if (curr_con->pid != -1)
    {
      alive_contractors++;
    }

    curr = curr->next;
  }

  return alive_contractors;
}


// Documented in header
int kill_all_contractors_using_signal(int signal)
{

  // While we kill off all the contractors, we need to block signals
  // so we don't get funny stuff happening while we're trying to kill
  // off contractors.
  sigset_t x;

  sigemptyset(&x);
  sigaddset(&x, SIGCHLD);

  sigprocmask(SIG_BLOCK, &x, NULL);

  _send_all_contractors_signal(signal);

  sigprocmask(SIG_UNBLOCK, &x, NULL);
  //

  // All of the processes have now been sent a <signal>, and hopefully
  // have had their signals handled. We now loop through with a small
  // delay, checking if they are dead. If they aren't we just start
  // killing them

  int all_dead = 0;

  struct timespec timeout;

  timeout.tv_sec = 0;
  timeout.tv_nsec = 100000000;

  struct timespec remainder;

  remainder.tv_sec = 1;
  remainder.tv_nsec = 1;

  while (all_dead == 0 && remainder.tv_sec > 0 && remainder.tv_nsec > 0)
  {
    // Remaining will not be zero if we get interrupted by a
    // signal during our sleep, so we wait for things to "settle down"
    nanosleep(&timeout, &remainder);

    // Now we disable masking, and check if everything is dead....
    sigprocmask(SIG_BLOCK, &x, NULL);

    if (contractor_controller_number_contractors() == 0)
    {
      all_dead = 1;
      debug_log("All child contractors are dead");
    }
    sigprocmask(SIG_UNBLOCK, &x, NULL);
    //
  }

  return contractor_controller_number_contractors();

}

/**
 * \brief Frees each element of a gslist of contractors
 *
 * \param to_free The element to free
 *
 */
void contractor_gslist_free(gpointer to_free)
{

  // This is only here a placeholder in case contractor_process becomes more complex.

  struct contractor_process *data = (struct contractor_process *) to_free;

  g_free(data);

}


// Documented in header
int contractor_controller_close(void)
{

  debug_log("contractor_controller_close called.");

  if (kill_all_contractors_using_signal(SIGTERM) != 0)
  {

    warning_log("Not all contractors died after being sent a SIGTERM, will SIGKILL");

    if (kill_all_contractors_using_signal(SIGKILL) != 0)
    {
      error_log("Not all contractors died after bing sent a SIGKILL!");
      return -1;
    }
  }

  if (child_contractors != NULL)
  {
    g_slist_free_full(child_contractors, contractor_gslist_free);
    child_contractors = NULL;
  }

  return 0;
}
