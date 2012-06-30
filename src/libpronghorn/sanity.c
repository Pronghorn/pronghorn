/* libpronghorn Dependency check library
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
 * \file sanity.c
 * \brief Library functions to confirm that the dependencies are met
 *
 */

#include <stdio.h>
#include <zmq.h>

#include <sanity.h>

/**
 * Checks the ZMQ version is sane
 *
 * \returns 1 if ok, 0 if not ok
 */
static int check_zmq()
{
  const int MAJOR_MIN = 2;
  const int MINOR_MIN = 2;
  const int PATCH_MIN = 0;

  int major;
  int minor;
  int patch;

  zmq_version(&major, &minor, &patch);

  // Checking major number
  if (major < MAJOR_MIN)
  {
    goto ZMQ_FAIL;
  }
  // Assuming all future major versions are API compliant
  if (major > MAJOR_MIN)
  {
    return 1;
  }

  if (minor < MINOR_MIN)
  {
    goto ZMQ_FAIL;
  }

  if (minor > MINOR_MIN)
  {
    return 1;
  }

  if (patch < PATCH_MIN)
  {
    goto ZMQ_FAIL;
  }

  return 1;

ZMQ_FAIL:
  printf("ZMQ dependency not met. Need version %d.%d.%d, have %d.%d.%d\n", MAJOR_MIN, MINOR_MIN, PATCH_MIN, major, minor, patch);
  return 0;
}

/**
 * \brief Check the user is in the correct fuse group
 * \return 1 if fuse is configured OK, 0 if not.
 *
 * Check that the user_allow_other setting is set in /etc/fuse.conf
 */
static int check_fuse()
{
  /** \todo This function requires implementation */
  // TODO This function requires implementation
  return 1;
}

int are_all_dependencies_met()
{
  if (check_zmq() != 1)
  {
    return 0;
  }

  if (check_fuse() != 1)
  {
    return 0;
  }

  return 1;
}
