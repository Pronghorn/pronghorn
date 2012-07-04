/* libpronghorn contract library
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
 * \file struct_protobuf/contract.c
 * \brief Library functions for contract completion reports
 *
 * In pronghorn, jobs tend to be passed around as "contracts". A contract
 * is normally along the lines of "please classify this block". This file 
 * contains functions to work with these contract structs
 * reports.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <glib.h>

#include <prong_assert.h>

#include "structures.pb-c.h"
#include "contract.h"

/**
 * A unique ID to identify a contract reference.
 * 
 * It's just four bytes taken from /dev/urandom
 */
static const unsigned int CONTRACT_MAGIC = 0xC0F71A6E;

contract_t contract_init(const char *initial_values, unsigned int initial_values_size)
{
  Contract temp = CONTRACT__INIT;
  Contract *c = (Contract *) g_malloc(sizeof(Contract));

  memcpy(c, &temp, sizeof(Contract));
  c->has_magic = 1;
  c->magic = CONTRACT_MAGIC;

  if (initial_values != NULL)
  {
    // We need to free unpacked_contract using contract__free_unpacked
    // Unfortunately this means we need to copy all the internal variables to our own structure
    Contract *unpacked_contract = contract__unpack(NULL, initial_values_size, (const unsigned char *) initial_values);

    if ((unpacked_contract == NULL) || (unpacked_contract->has_magic != 1) || (unpacked_contract->magic != CONTRACT_MAGIC))
    {
      contract_close((contract_t) c);
      errno = EINVAL;
      return NULL;
    }

    c->path = g_strdup(unpacked_contract->path);
    if (unpacked_contract->n_types > 0)
    {
      c->n_types = unpacked_contract->n_types;
      c->types = (unsigned int *) g_malloc(unpacked_contract->n_types * sizeof(*(unpacked_contract->types)));
      memcpy(c->types, unpacked_contract->types, unpacked_contract->n_types * sizeof(*(unpacked_contract->types)));
    }
    c->has_is_contiguous = unpacked_contract->has_is_contiguous;
    c->is_contiguous = unpacked_contract->is_contiguous;
    c->has_absolute_offset = unpacked_contract->has_absolute_offset;
    c->absolute_offset = unpacked_contract->absolute_offset;
    c->has_sleep = unpacked_contract->has_sleep;
    c->sleep = unpacked_contract->sleep;

    contract__free_unpacked(unpacked_contract, NULL);
  }

  return (contract_t) c;
}

char *contract_serialise(contract_t _c, unsigned int *output_data_size)
{
  prong_assert(_c != NULL);
  Contract *c = (Contract *) _c;

  prong_assert(c->magic == CONTRACT_MAGIC);

  *output_data_size = contract__get_packed_size(c);
  char *buf = (char *) g_malloc(*output_data_size);

  contract__pack(c, (unsigned char *) buf);

  return buf;
}

contract_t contract_clone(contract_t _c)
{
  unsigned int size;
  char *c_serialised = contract_serialise(_c, &size);

  if (c_serialised == NULL)
  {
    return NULL;
  }

  contract_t newcontract = contract_init(c_serialised, size);

  g_free(c_serialised);

  return newcontract;
}

const char *contract_get_path(contract_t _c)
{
  prong_assert(_c != NULL);
  Contract *c = (Contract *) _c;

  prong_assert(c->magic == CONTRACT_MAGIC);

  return c->path;
}

int contract_set_path(contract_t _c, const char *path)
{
  prong_assert(_c != NULL);
  Contract *c = (Contract *) _c;

  prong_assert(c->magic == CONTRACT_MAGIC);

  prong_assert(path != NULL);

  if (c->path != NULL)
  {
    g_free(c->path);
  }

  c->path = g_strdup(path);

  return 0;
}

const unsigned int *contract_get_types(contract_t _c, unsigned int *num_types)
{
  prong_assert(_c != NULL);
  Contract *c = (Contract *) _c;

  prong_assert(c->magic == CONTRACT_MAGIC);

  *num_types = c->n_types;
  return c->types;
}

int contract_delete_types(contract_t _c)
{
  prong_assert(_c != NULL);
  Contract *c = (Contract *) _c;

  prong_assert(c->magic == CONTRACT_MAGIC);

  if (c->types != NULL)
  {
    c->n_types = 0;
    g_free(c->types);
    c->types = NULL;
  }

  return 0;
}

int contract_add_type(contract_t _c, unsigned int type)
{
  prong_assert(_c != NULL);
  Contract *c = (Contract *) _c;

  prong_assert(c->magic == CONTRACT_MAGIC);

  c->types = (unsigned int *) g_realloc(c->types, sizeof(int) * (c->n_types + 1));
  c->types[c->n_types] = type;
  c->n_types++;

  return 0;
}

int contract_is_contiguous(contract_t _c)
{
  prong_assert(_c != NULL);
  Contract *c = (Contract *) _c;

  prong_assert(c->magic == CONTRACT_MAGIC);

  if (c->has_is_contiguous == 0)
  {
    return 0;
  }

  return c->is_contiguous;
}

int contract_set_contiguous(contract_t _c, unsigned int is_contiguous)
{
  prong_assert(_c != NULL);
  Contract *c = (Contract *) _c;

  prong_assert(c->magic == CONTRACT_MAGIC);

  c->has_is_contiguous = 1;
  c->is_contiguous = is_contiguous;

  return 0;
}

int contract_set_sleep_time(contract_t _c, int sleep)
{
  prong_assert(_c != NULL);
  Contract *c = (Contract *) _c;

  prong_assert(c->magic == CONTRACT_MAGIC);

  c->sleep = sleep;
  c->has_sleep = 1;

  return 0;
}

int contract_get_sleep_time(contract_t _c)
{
  prong_assert(_c != NULL);
  Contract *c = (Contract *) _c;

  prong_assert(c->magic == CONTRACT_MAGIC);

  if (c->has_sleep)
  {
    return c->sleep;
  }

  return 0;
}


long long int contract_get_absolute_offset(contract_t _c)
{
  prong_assert(_c != NULL);
  Contract *c = (Contract *) _c;

  prong_assert(c->magic == CONTRACT_MAGIC);

  if (c->has_absolute_offset == 0)
  {
    return -1;
  }

  prong_assert(c->absolute_offset >= -1);
  return c->absolute_offset;
}

int contract_set_absolute_offset(contract_t _c, long long int offset)
{
  prong_assert(_c != NULL);
  prong_assert(offset >= -1);
  Contract *c = (Contract *) _c;

  prong_assert(c->magic == CONTRACT_MAGIC);

  c->has_absolute_offset = 1;
  c->absolute_offset = offset;

  return 0;
}

int contract_close(contract_t _c)
{
  if (_c == NULL)
  {
    return -1;
  }

  Contract *c = (Contract *) _c;

  prong_assert(c->magic == CONTRACT_MAGIC);

  g_free(c->path);
  g_free(c->types);

  g_free(c);

  return 0;
}
