/* libpronghorn report library
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
 * \file report.c
 * \brief Library functions for contract completion reports
 *
 * In pronghorn, jobs tend to be passed around as "contracts". A contract
 * is normally along the lines of "please classify this block". When the 
 * classification is done, a "contract completion report" is generated 
 * containing the results (and potentially new contracts we've found).
 * This file contains functions to work with these contract completion
 * reports.
 */

#include <string.h>
#include <errno.h>
#include <glib.h>

#include <logger.h>
#include <prong_assert.h>

#include "structures.pb-c.h"
#include "report.h"

/**
 * A unique ID to identify a contract_completion_report reference.
 * 
 * It's just four bytes taken from /dev/urandom
 */
static const unsigned int REPORT_MAGIC = 0x6473B7C7;

contract_completion_report_t contract_completion_report_init(const char *initial_values, unsigned int initial_values_size)
{
  Report temp = REPORT__INIT;
  Report *r = (Report *) g_malloc(sizeof(Report));

  memcpy(r, &temp, sizeof(Report));
  r->has_magic = 1;
  r->magic = REPORT_MAGIC;

  if (initial_values != NULL)
  {
    // We need to free unpacked_report using report__free_unpacked
    // Unfortunately this means we need to copy all the internal variables to our own structure
    Report *unpacked_report = report__unpack(NULL, initial_values_size, (const unsigned char *) initial_values);

    if ((unpacked_report == NULL) || (unpacked_report->has_magic != 1) || (unpacked_report->magic != REPORT_MAGIC))
    {
      contract_completion_report_close((contract_completion_report_t) r);
      errno = EINVAL;
      return NULL;
    }

    if (unpacked_report->original_contract != NULL)
    {
      r->original_contract = (Contract *) contract_clone((contract_t) (unpacked_report->original_contract));
    }

    if (unpacked_report->n_results > 0)
    {
      r->n_results = unpacked_report->n_results;
      r->results = (Result **) g_malloc(sizeof(result_t) * r->n_results);
      for (int i = 0; i < r->n_results; i++)
      {
        r->results[i] = (Result *) result_clone((result_t) (unpacked_report->results[i]));
      }
    }

    report__free_unpacked(unpacked_report, NULL);
  }

  return (contract_completion_report_t) r;
}

char *contract_completion_report_serialise(contract_completion_report_t _r, unsigned int *output_data_size)
{
  prong_assert(_r != NULL);
  Report *r = (Report *) _r;

  prong_assert(r->magic == REPORT_MAGIC);

  *output_data_size = report__get_packed_size(r);
  char *buf = (char *) g_malloc(*output_data_size);

  report__pack(r, (unsigned char *) buf);

  return buf;
}

contract_completion_report_t contract_completion_report_clone(contract_completion_report_t _r)
{
  unsigned int size;
  char *r_serialised = contract_completion_report_serialise(_r, &size);

  if (r_serialised == NULL)
  {
    return NULL;
  }

  contract_completion_report_t newreport = contract_completion_report_init(r_serialised, size);

  g_free(r_serialised);

  return newreport;
}

const result_t *contract_completion_report_get_results(contract_completion_report_t _r, unsigned int *num_results)
{
  prong_assert(_r != NULL);
  Report *r = (Report *) _r;

  prong_assert(r->magic == REPORT_MAGIC);

  *num_results = r->n_results;
  return (result_t *) r->results;
}

int contract_completion_report_add_result(contract_completion_report_t _r, result_t new_result)
{
  prong_assert(_r != NULL);
  prong_assert(new_result != NULL);

  result_set_subcontractor_name(new_result, PROCESS_NAME);
  // These are commonly missed by subcontractors - so they're explicitly checked
//  prong_assert(result_get_subcontractor_name(new_result) != NULL);
  prong_assert(result_get_brief_data_description(new_result) != NULL);
  prong_assert(result_get_data_description(new_result) != NULL);

  Report *r = (Report *) _r;

  prong_assert(r->magic == REPORT_MAGIC);

  // \todo This could be more efficient
  // TODO - This could be more efficient.
  r->results = (Result **) g_realloc(r->results, sizeof(result_t) * (r->n_results + 1));
  r->results[r->n_results] = (Result *) result_clone(new_result);
  r->n_results++;

  return 0;
}

const contract_t contract_completion_report_get_original_contract(contract_completion_report_t _r)
{
  prong_assert(_r != NULL);
  Report *r = (Report *) _r;

  prong_assert(r->magic == REPORT_MAGIC);

  return (contract_t) r->original_contract;
}

int contract_completion_report_set_original_contract(contract_completion_report_t _r, contract_t c)
{
  prong_assert(_r != NULL);
  prong_assert(c != NULL);

  Report *r = (Report *) _r;

  prong_assert(r->magic == REPORT_MAGIC);

  if (r->original_contract != NULL)
  {
    contract_close((contract_t) r->original_contract);
  }

  r->original_contract = (Contract *) contract_clone(c);
  return 0;
}

int contract_completion_report_close(contract_completion_report_t _r)
{
  if (_r == NULL)
  {
    return -1;
  }

  Report *r = (Report *) _r;

  prong_assert(r->magic == REPORT_MAGIC);

  contract_close((contract_t) (r->original_contract));

  for (int i = 0; i < r->n_results; i++)
  {
    result_close((result_t) (r->results[i]));
  }
  g_free(r->results);

  g_free(r);

  return 0;
}
