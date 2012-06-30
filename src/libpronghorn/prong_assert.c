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
 * \file prong_assert.c
 * \brief Defines the prong_assert macro
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <execinfo.h>
#include <sys/types.h>

#include <glib.h>

static const char *DUMP_FILE = "pronghorn.assert";
static FILE *dump_file = NULL;

#define dual_log(...) fprintf(stderr, __VA_ARGS__) ; if (dump_file != NULL) fprintf(dump_file, __VA_ARGS__)

void prong_stacktrace(const char *file, int line, const char *function, const char *expr)
{
  dump_file = fopen(DUMP_FILE, "a");
  dual_log("**********************************************************\n");
  dual_log("Assert failed! (%s)\n", expr);
  dual_log("PID: %d\n", getpid());
  dual_log("File: %s\n", file);
  dual_log("Line: %d\n", line);
  dual_log("Function: %s\n", function);
  time_t t = time(NULL);

  dual_log("Time: %s", ctime(&t));
  dual_log("**********************************************************\n");
  dual_log("Stack trace follows:\n");

  void *buf[1024];
  int nptrs = backtrace(buf, sizeof(buf));

  char **strings = backtrace_symbols(buf, nptrs);

  if (strings == NULL)
  {
    dual_log("Backtrace failed\n");
  }

  for (int i = 0; i < nptrs; i++)
  {
    dual_log("%s\n", strings[i]);
  }

  free(strings);
  dual_log("**********************************************************\n");

  if (dump_file != NULL)
  {
    fclose(dump_file);
  }

  abort();
}
