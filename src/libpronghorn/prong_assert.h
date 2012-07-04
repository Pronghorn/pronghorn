/* Libpronghorn assert mechanism
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
 * \file prong_assert.h
 * \brief Defines the prong_assert macro
 */

#ifndef PRONG_ASSERT_T
#define PRONG_ASSERT_T

#include <glib.h>

void prong_stacktrace(const char *file, unsigned int line, const char *function, const char *expr);

#ifdef DEBUG
#define prong_assert(expr) do { if G_LIKELY (expr) ; else prong_stacktrace(__FILE__, __LINE__, G_STRFUNC, #expr); } while (0)
#else
#define prong_assert(expr) ((void)(expr))
#endif

#endif
