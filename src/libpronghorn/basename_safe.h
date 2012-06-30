/* libpronghorn Basename Safe Fn
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

#ifndef BASENAME_SAFE
#define BASENAME_SAFE

#include <glib.h>

/**
 * This is a safe version of basename as basename could use internal static buffers, and could modify the input path.
 *
 * \param path The path to extract the basename from
 * \returns The base name from the path
 */
const char *basename_safe(const char *path) G_GNUC_WARN_UNUSED_RESULT;

#endif
