/* libpronghorn Result Library
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
 * \file struct_protobuf/result.c
 * \brief Library functions for contract completion reports
 *
 * In pronghorn, jobs tend to be passed around as "contracts". A contract
 * is normally along the lines of "please classify this block". When the 
 * classification is done, a "contract completion report" is generated 
 * containing the results (and potentially new contracts we've found).
 * This file contains functions to work with these contract completion
 * reports.
 */
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <glib.h>

#include <logger.h>
#include <prong_assert.h>

#include "structures.pb-c.h"
#include "result.h"

/**
 * A unique ID to identify a result reference.
 * 
 * It's just four bytes taken from /dev/urandom
 */
static const unsigned int RESULT_MAGIC = 0x5067EAB7;

result_t result_init(const char *initial_values, unsigned int initial_values_size)
{
  // Some compatibility testing
  // If this assert fails then the protobuf structure is invalid against this
  // code and the code should be re-examined
  prong_assert(sizeof(unsigned long long) == sizeof(uint64_t));

  Result temp = RESULT__INIT;
  Result *r = (Result *) g_malloc(sizeof(Result));

  memcpy(r, &temp, sizeof(Result));
  r->has_magic = 1;
  r->magic = RESULT_MAGIC;

  if (initial_values != NULL)
  {
    // We need to free unpacked_result using result__free_unpacked
    // Unfortunately this means we need to copy all the internal variables to our own structure
    Result *unpacked_result = result__unpack(NULL, initial_values_size, (const unsigned char *) initial_values);

    if ((unpacked_result == NULL) || (unpacked_result->has_magic != 1) || (unpacked_result->magic != RESULT_MAGIC))
    {
      result_close((result_t) r);
      errno = EINVAL;
      return NULL;
    }

    if (unpacked_result->n_block_ranges > 0)
    {
      r->n_block_ranges = unpacked_result->n_block_ranges;
      r->block_ranges = (BlockRange **) g_malloc(sizeof(block_range_t) * unpacked_result->n_block_ranges);
      for (int i = 0; i < r->n_block_ranges; i++)
      {
        r->block_ranges[i] = (BlockRange *) block_range_clone((block_range_t) unpacked_result->block_ranges[i]);
      }
    }

    r->data_description = g_strdup(unpacked_result->data_description);
    r->brief_data_description = g_strdup(unpacked_result->brief_data_description);
    r->has_confidence = unpacked_result->has_confidence;
    r->confidence = unpacked_result->confidence;
    r->subcontractor_name = g_strdup(unpacked_result->subcontractor_name);

    if (unpacked_result->n_new_contracts > 0)
    {
      r->n_new_contracts = unpacked_result->n_new_contracts;
      r->new_contracts = (Contract **) g_malloc(sizeof(contract_t) * r->n_new_contracts);
      for (int i = 0; i < r->n_new_contracts; i++)
      {
        r->new_contracts[i] = (Contract *) contract_clone((contract_t) unpacked_result->new_contracts[i]);
      }
    }

    result__free_unpacked(unpacked_result, NULL);
  }

  return (result_t) r;
}

void remove_duplicate_contracts(Result* r)
{

  GHashTable* previous = g_hash_table_new(g_str_hash, g_str_equal);

  for (int i=0; i < r->n_new_contracts; i++)
  {
    if (g_hash_table_contains(previous, r->new_contracts[i]->path) == TRUE)
    {

      // Want to know about this in debug mode
      prong_assert(0);

      // We have a duplicate
      if (i == r->n_new_contracts -1) 
      {
        // We're at the end of the array
        g_free(r->new_contracts[i]);
        r->n_new_contracts--;
      } 
      else
      {
        // Need to replace this current one. 
        g_free(r->new_contracts[i]);
        r->new_contracts[i] = r->new_contracts[r->n_new_contracts - 1];
        r->n_new_contracts--;
      }
    }
    else
    {
      // This is not a duplicate
      g_hash_table_insert(previous, r->new_contracts[i]->path, NULL);
    }

  }

  g_hash_table_destroy(previous);

}

char *result_serialise(result_t _r, unsigned int *output_data_size)
{
  prong_assert(_r != NULL);
  Result *r = (Result *) _r;

  prong_assert(r->magic == RESULT_MAGIC);

	remove_duplicate_contracts(r);

  *output_data_size = result__get_packed_size(r);
  char *buf = (char *) g_malloc(*output_data_size);

  result__pack(r, (unsigned char *) buf);

  return buf;
}

result_t result_clone(result_t _r)
{
  unsigned int size;
  char *r_serialised = result_serialise(_r, &size);

  if (r_serialised == NULL)
  {
    return NULL;
  }

  result_t newresult = result_init(r_serialised, size);

  g_free(r_serialised);

  return newresult;
}

block_range_t *result_get_block_ranges(result_t _r, unsigned int *num_ranges)
{
  prong_assert(_r != NULL);
  Result *r = (Result *) _r;

  prong_assert(r->magic == RESULT_MAGIC);

  *num_ranges = r->n_block_ranges;
  return (block_range_t *) r->block_ranges;
}

int result_set_block_ranges(result_t _r, block_range_t * ranges, unsigned int num_ranges)
{
  prong_assert(_r != NULL);
  Result *r = (Result *) _r;

  prong_assert(r->magic == RESULT_MAGIC);

  if (r->n_block_ranges != 0)
  {
    for (int i = 0; i < r->n_block_ranges; i++)
    {
      block_range_close((block_range_t) r->block_ranges[i]);
    }
    g_free(r->block_ranges);
  }

  r->n_block_ranges = num_ranges;
  r->block_ranges = (BlockRange **) g_malloc(sizeof(block_range_t) * num_ranges);

  for (int i = 0; i < r->n_block_ranges; i++)
  {
    r->block_ranges[i] = (BlockRange *) block_range_clone(ranges[i]);
  }

  return 0;
}

const char *result_get_data_description(result_t _r)
{
  prong_assert(_r != NULL);
  Result *r = (Result *) _r;

  prong_assert(r->magic == RESULT_MAGIC);

  return r->data_description;
}

const char *result_get_brief_data_description(result_t _r)
{
  prong_assert(_r != NULL);
  Result *r = (Result *) _r;

  prong_assert(r->magic == RESULT_MAGIC);

  return r->brief_data_description;
}

int result_set_data_description(result_t _r, const char *data_description)
{
  prong_assert(_r != NULL);
  Result *r = (Result *) _r;

  prong_assert(r->magic == RESULT_MAGIC);

  prong_assert(data_description != NULL);

  if (r->data_description != NULL)
  {
    g_free(r->data_description);
  }

  r->data_description = g_strdup(data_description);

  return 0;
}

int result_set_brief_data_description(result_t _r, const char *brief_data_description)
{
  prong_assert(_r != NULL);
  Result *r = (Result *) _r;

  prong_assert(r->magic == RESULT_MAGIC);

  prong_assert(brief_data_description != NULL);

  if (r->brief_data_description != NULL)
  {
    g_free(r->brief_data_description);
  }

  r->brief_data_description = g_ascii_strup(brief_data_description, -1);

  return 0;
}

const int result_get_confidence(result_t _r)
{
  prong_assert(_r != NULL);
  Result *r = (Result *) _r;

  prong_assert(r->magic == RESULT_MAGIC);

  if (r->has_confidence == 0)
  {
    // Return -2 because -1 has special meaning for confidence
    return -2;
  }

  return r->confidence;
}

int result_set_confidence(result_t _r, const int confidence)
{
  prong_assert(_r != NULL);
  Result *r = (Result *) _r;

  prong_assert(r->magic == RESULT_MAGIC);

  prong_assert(confidence >= -1);
  prong_assert(confidence <= 100);

  r->has_confidence = 1;
  r->confidence = confidence;

  return 0;
}

const char *result_get_subcontractor_name(result_t _r)
{
  prong_assert(_r != NULL);
  Result *r = (Result *) _r;

  prong_assert(r->magic == RESULT_MAGIC);

  return r->subcontractor_name;
}

int result_set_subcontractor_name(result_t _r, const char *subcontractor_name)
{
  prong_assert(_r != NULL);
  Result *r = (Result *) _r;

  prong_assert(r->magic == RESULT_MAGIC);

  prong_assert(subcontractor_name != NULL);

  if (r->subcontractor_name != NULL)
  {
    g_free(r->subcontractor_name);
  }

  r->subcontractor_name = g_strdup(subcontractor_name);

  return 0;
}

const contract_t *result_get_new_contracts(result_t _r, unsigned int *new_contracts_count)
{
  prong_assert(_r != NULL);
  Result *r = (Result *) _r;

  prong_assert(r->magic == RESULT_MAGIC);

  *new_contracts_count = r->n_new_contracts;
  return (contract_t *) r->new_contracts;
}

int result_add_new_contract(result_t _r, contract_t new_contract)
{
  prong_assert(_r != NULL);
  Result *r = (Result *) _r;

  prong_assert(r->magic == RESULT_MAGIC);

  prong_assert(new_contract != NULL);

  // TODO This fn could be more efficient
  /** \todo This fn could be more efficient */
  r->new_contracts = (Contract **) g_realloc(r->new_contracts, sizeof(contract_t) * (r->n_new_contracts + 1));
  r->new_contracts[r->n_new_contracts] = (Contract *) contract_clone(new_contract);
  r->n_new_contracts++;

  return 0;
}

int result_close(result_t _r)
{
  if (_r == NULL)
  {
    return -1;
  }

  Result *r = (Result *) _r;

  prong_assert(r->magic == RESULT_MAGIC);

  if (r->n_block_ranges != 0)
  {
    for (int i = 0; i < r->n_block_ranges; i++)
    {
      block_range_close((block_range_t) r->block_ranges[i]);
    }
    g_free(r->block_ranges);
  }

  g_free(r->data_description);
  g_free(r->brief_data_description);
  g_free(r->subcontractor_name);

  for (int i = 0; i < r->n_new_contracts; i++)
  {
    contract_close((contract_t) r->new_contracts[i]);
  }
  g_free(r->new_contracts);

  g_free(r);

  return 0;
}
