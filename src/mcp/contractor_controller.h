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
 * \file contractor_controller.h
 * \brief This file helps the master control program out by taking
 * care of the management of contractors.
 *
 */
#ifndef CONTRACTOR_CONTROLLER_H
#define CONTRACTOR_CONTROLLER_H

/** The status of the contractor controller is normal */
#define CC_STATUS_NORMAL 1
/** The contractor controller is in an error state */
#define CC_STATUS_ERROR 2
/** The contractor controller has not been setup yet */
#define CC_STATUS_NOT_SETUP 3

/** The MCP is running */
#define RUNNING 0
/** The MCP is shutting down as there are no more blocks to process */
#define SHUTTING_DOWN_NO_MORE_BLOCKS 2
/** The MCP is shutting down due to an error */
#define SHUTTING_DOWN_ERROR 3
/** The MCP is shutting down due to no more blocks and all contractors have been notified */
#define SHUTTING_DOWN_CONTRACTORS_NOTIFIED 4

#include <glib.h>
#include <signal.h>
#include <logger.h>

/** A struct containing all the info about a single contractor process */
struct contractor_process
{

  /** pid of the contractor */
  volatile sig_atomic_t pid;

};

/** 
 * \brief Sets up the contractor controller, and spawns a batch of contractors
 *
 * \param target_num_contractors Target number of contractors we want spawned
 * \return 0 on success, -1 on failure
 *
 */
int contractor_controller_init(int target_num_contractors) G_GNUC_WARN_UNUSED_RESULT;


/**
 * \brief Close down the contractor controller
 *
 * \return 0 on success, -1 on failure
 *
 * Closes down the contractor_controller (and in turn all the contractors).
 * It sends a SIGTERM to all the children is knows about, and waits. If they
 * don't all appear to die correctly, it sends a SIGKILL, and waits. It returns
 * 0 if everything reports as dead after this, or -1 if it's possible 
 * child processes were not cleaned up correctly.
 */
int contractor_controller_close(void) G_GNUC_WARN_UNUSED_RESULT;


/**
 * \brief Returns the number of alive child contractors
 *
 * \return The number of alive contractors
 */
unsigned int contractor_controller_number_contractors(void) G_GNUC_WARN_UNUSED_RESULT;


/**
 * \brief Kill all contractors using the specified signal
 *
 * \param signal The signal to use to try and kill the children (SIGTERM or SIGKILL 
 * are the sensible options)
 *
 * \return 0 if all contractors appear to have died, or a number greater 
 * than zero representing how many contractors still appear to be alive.
 *
 * Sends a signal, waits a while, and counts how many contractors
 * are still alive.
 */
int kill_all_contractors_using_signal(int signal);

#endif // CONTRACTOR_CONTROLLER_H


