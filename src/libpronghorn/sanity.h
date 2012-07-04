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
 * \file sanity.h
 * \brief Library functions to confirm that the dependencies are met
 */

#ifndef SANITY_H
#define SANITY_H

#include <glib.h>

/**
 * Checks that all the dependencies are met.
 *
 * \returns 1 if all dependencies are met, 0 otherwise
 */
unsigned int are_all_dependencies_met(void) G_GNUC_WARN_UNUSED_RESULT;

#endif
