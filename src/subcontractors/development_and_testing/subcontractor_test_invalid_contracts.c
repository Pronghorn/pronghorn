/* libpronghorn Subcontractor Testing Module - Produce Invalid Contracts
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

/**
 * \file subcontractor_test_invalid_contracts.c
 *
 * DO NOT USE THIS FILE. TESTING ONLY.
 *
 */
#include <stdio.h>

#include <logger.h>
#include <config.h>
#include <blocks.h>

#include "subcontractor_helper.h"

unsigned int supported_file_types[] = { 0 };
//unsigned int supported_file_types[] = {MAGIC_TYPE_TEXT, 0};

int subcontractor_init(void)
{
  // Initialise any structures here
  debug_log("subcontractor_init called");
  return 0;
}

int analyse_contract(contract_t to_analyse, contract_completion_report_t ccr)
{

  contract_t new_contract = NULL;
  new_contract = contract_init(NULL, 0);
  contract_set_path(new_contract, "/There/is/no/chance/this/file/exists");
  result_t new_result = NULL;
  new_result = result_init(NULL, 0);
  result_set_confidence(new_result, 10);
  result_set_data_description(new_result, "This is a test");
  result_add_new_contract(new_result, new_contract);
  contract_completion_report_add_result(ccr, new_result);
  return 0;
}

int subcontractor_close(void)
{
  debug_log("subcontractor_close");
  return 0;
}
