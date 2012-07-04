/* Libpronghorn log structure
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
 * \file struct_protobuf/log.c
 * \brief Libpronghorn log structure
 *
 * This defines the log structure used when passing logging messages.
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <glib.h>

#include <logger.h>
#include <prong_assert.h>

#include "structures.pb-c.h"
#include "log.h"

/**
 * A unique ID to identify a log reference.
 * 
 * It's just four bytes taken from /dev/urandom
 */
static const unsigned int LOG_MAGIC = 0x77E3CFE2;

log_t log_init(const char *initial_values, unsigned int initial_values_size)
{
  Log temp = LOG__INIT;
  Log *l = (Log *) g_malloc(sizeof(Log));

  memcpy(l, &temp, sizeof(Log));
  l->has_magic = 1;
  l->magic = LOG_MAGIC;

  if (initial_values != NULL)
  {
    // We need to free unpacked_log using log__free_unpacked
    // Unfortunately this means we need to copy all the internal variables to our own structure
    Log *unpacked_log = log__unpack(NULL, initial_values_size, (const unsigned char *) initial_values);

    if ((unpacked_log == NULL) || (unpacked_log->has_magic != 1) || (unpacked_log->magic != LOG_MAGIC))
    {
      log_close((log_t) l);
      errno = EINVAL;
      return NULL;
    }

    l->sender_id = g_strdup(unpacked_log->sender_id);
    l->has_severity = unpacked_log->has_severity;
    l->severity = unpacked_log->severity;
    l->has_timestamp_sec = unpacked_log->has_timestamp_sec;
    l->timestamp_sec = unpacked_log->timestamp_sec;
    l->has_timestamp_usec = unpacked_log->has_timestamp_usec;
    l->timestamp_usec = unpacked_log->timestamp_usec;
    l->message = g_strdup(unpacked_log->message);

    log__free_unpacked(unpacked_log, NULL);
  }

  return (log_t) l;
}

char *log_serialise(log_t _l, unsigned int *output_data_size)
{
  prong_assert(_l != NULL);
  Log *l = (Log *) _l;

  prong_assert(l->magic == LOG_MAGIC);

  *output_data_size = log__get_packed_size(l);
  char *buf = (char *) g_malloc(*output_data_size);

  log__pack(l, (unsigned char *) buf);

  return buf;
}

log_t log_clone(log_t _l)
{
  unsigned int size;
  char *l_serialised = log_serialise(_l, &size);

  if (l_serialised == NULL)
  {
    return NULL;
  }

  log_t newlog = log_init(l_serialised, size);

  g_free(l_serialised);

  return newlog;
}

const char *log_get_sender_id(log_t _l)
{
  prong_assert(_l != NULL);
  Log *l = (Log *) _l;

  prong_assert(l->magic == LOG_MAGIC);

  return l->sender_id;
}

int log_set_sender_id(log_t _l, const char *sender_id)
{
  prong_assert(_l != NULL);
  Log *l = (Log *) _l;

  prong_assert(l->magic == LOG_MAGIC);

  prong_assert(sender_id != NULL);

  if (l->sender_id != NULL)
  {
    g_free(l->sender_id);
  }

  l->sender_id = g_strdup(sender_id);

  return 0;
}

int log_get_severity(log_t _l)
{
  prong_assert(_l != NULL);
  Log *l = (Log *) _l;

  prong_assert(l->magic == LOG_MAGIC);

  if (l->has_severity == 0)
  {
    return LOG_SEVERITY_DEBUG;
  }

  return l->severity;
}

int log_set_severity(log_t _l, unsigned int severity)
{
  prong_assert(_l != NULL);
  Log *l = (Log *) _l;

  prong_assert(l->magic == LOG_MAGIC);

  prong_assert(severity >= LOG_SEVERITY_DEBUG);
  prong_assert(severity <= LOG_SEVERITY_SEVERE);

  l->has_severity = 1;
  l->severity = severity;

  return 0;
}

const char *log_get_message(log_t _l)
{
  prong_assert(_l != NULL);
  Log *l = (Log *) _l;

  prong_assert(l->magic == LOG_MAGIC);

  return l->message;
}

int log_set_message(log_t _l, const char *message)
{
  prong_assert(_l != NULL);
  Log *l = (Log *) _l;

  prong_assert(l->magic == LOG_MAGIC);

  prong_assert(message != NULL);

  if (l->message != NULL)
  {
    g_free(l->message);
  }

  l->message = g_strdup(message);

  return 0;
}

long log_get_timestamp_sec(log_t _l)
{
  prong_assert(_l != NULL);
  Log *l = (Log *) _l;

  prong_assert(l->magic == LOG_MAGIC);

  if (l->has_timestamp_sec == 0)
  {
    return 0;
  }

  return l->timestamp_sec;
}

long log_get_timestamp_usec(log_t _l)
{
  prong_assert(_l != NULL);
  Log *l = (Log *) _l;

  prong_assert(l->magic == LOG_MAGIC);

  if (l->has_timestamp_usec == 0)
  {
    return 0;
  }

  return l->timestamp_usec;
}

int log_set_timestamp(log_t _l, long sec, long usec)
{
  prong_assert(_l != NULL);
  Log *l = (Log *) _l;

  prong_assert(l->magic == LOG_MAGIC);

  prong_assert(sec > 0);
  prong_assert(usec >= 0);

  l->has_timestamp_sec = 1;
  l->timestamp_sec = sec;
  l->has_timestamp_usec = 1;
  l->timestamp_usec = usec;

  return 0;
}

int log_close(log_t _l)
{
  if (_l == NULL)
  {
    return -1;
  }

  Log *l = (Log *) _l;

  prong_assert(l->magic == LOG_MAGIC);

  g_free(l->sender_id);
  g_free(l->message);

  g_free(l);

  return 0;
}
