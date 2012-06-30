/* libpronghorn Subcontractor template
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

// Subcontractor text is significantly broken under some scenarios
// It operates by reading the largest possible chunk of data which
// contains 'text' characters. It then proceeds to identify whether
// this chunk is HTML, XML, CSV, etc...
//
// This is broken as it does not handle the case where you have two
// adjacent blocks with different content.
//
// This is a very difficult problem to solve as it is difficult to
// categorise a block when you aren't guaranteed the block will conform
// to the data (ie, a 512byte chunk from a HTML file isn't guaranteed
// to have any HTML tags) Hence it may not be possible to detect when
// a chain of HTML blocks ends as the block following the starting
// HTML block may not actually hold any HTML itself.
//
// This problem is currently unsolved in any efficient/satisfactory
// manner. It is on our TODO list.
//

/**
 * \file subcontractor_text.c
 * \brief Tries to identify different types of tests and also decodes
 * base64, base85, hex.
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>
#include <gsl/gsl_statistics.h>
#include <gsl/gsl_sort.h>
//#include <base_fuse.h>

#include <logger.h>
#include <config.h>
#include <blocks.h>
#include <lightmagic.h>
#include <subcontractor_helper.h>
#include <base_fuse.h>
#include <prong_assert.h>

#include "text_helper.h"
#include "ascii85.h"

#define CONFIG_MIN_TEXT_LENGTH_OPTION_NAME "min_text_length"
#define CONFIG_MIN_TEXT_LENGTH_DEFAULT 32
#define CONFIG_MAX_TEXT_LENGTH_OPTION_NAME "max_text_length"
#define CONFIG_MAX_TEXT_LENGTH_DEFAULT 104857600
#define CONFIG_MAX_CSV_LINES_OPTION_NAME "max_csv_lines"
#define CONFIG_MAX_CSV_LINES_DEFAULT 50

#define CONFIG_WHITESPACE_THRESHOLD_OPTION_NAME "whitespace_threshold"
#define CONFIG_WHITESPACE_THRESHOLD_DEFAULT 50
#define CONFIG_HTML_THRESHOLD_OPTION_NAME "html_threshold"
#define CONFIG_HTML_THRESHOLD_DEFAULT 50
#define CONFIG_XML_THRESHOLD_OPTION_NAME "xml_threshold"
#define CONFIG_XML_THRESHOLD_DEFAULT 50
#define CONFIG_CSS_THRESHOLD_OPTION_NAME "css_threshold"
#define CONFIG_CSS_THRESHOLD_DEFAULT 50
#define CONFIG_JSON_THRESHOLD_OPTION_NAME "json_threshold"
#define CONFIG_JSON_THRESHOLD_DEFAULT 50
#define CONFIG_BASE64_THRESHOLD_OPTION_NAME "base64_threshold"
#define CONFIG_BASE64_THRESHOLD_DEFAULT 50
#define CONFIG_BASE85_THRESHOLD_OPTION_NAME "base85_threshold"
#define CONFIG_BASE85_THRESHOLD_DEFAULT 50
#define CONFIG_HEX_THRESHOLD_OPTION_NAME "hex_threshold"
#define CONFIG_HEX_THRESHOLD_DEFAULT 50
#define CONFIG_CSV_THRESHOLD_OPTION_NAME "csv_threshold"
#define CONFIG_CSV_THRESHOLD_DEFAULT 50
#define CONFIG_JS_THRESHOLD_OPTION_NAME "js_threshold"
#define CONFIG_JS_THRESHOLD_DEFAULT 50
#define CONFIG_LOG_THRESHOLD_OPTION_NAME "log_threshold"
#define CONFIG_LOG_THRESHOLD_DEFAULT 50
#define CONFIG_TXT_THRESHOLD_OPTION_NAME "txt_threshold"
#define CONFIG_TXT_THRESHOLD_DEFAULT 50

static int block_size = 0;
static int min_text_length = 0;
static int max_text_length = 0;
static int max_csv_lines = 0;
static int threshold_whitespace = 0;
static int threshold_html = 0;
static int threshold_xml = 0;
static int threshold_css = 0;
static int threshold_json = 0;
static int threshold_base64 = 0;
static int threshold_base85 = 0;
static int threshold_hex = 0;
static int threshold_csv = 0;
static int threshold_js = 0;
static int threshold_log = 0;
static int threshold_txt = 0;

char *result_type = NULL;
char *global_path = NULL;
result_t global_result = NULL;

unsigned int supported_file_types[] = { MAGIC_TYPE_TEXT, MAGIC_TYPE_HEX, MAGIC_TYPE_BASE64, MAGIC_TYPE_BASE85, 0 };

int decoded_size_base64(char *buff, int size);
int decoded_size_base85(char *buff, int size);
int decoded_size_hex(char *buff, int size);
gchar *hex_decode(char *buff, int buff_size, gsize * size);

// ####################### subroutines ##########################
int add_result_with_length(contract_completion_report_t ccr, const gchar * brief_description, const gchar * description, int confidence, long long int abs_offset, unsigned long long length,
                           int is_contiguous)
{
  prong_assert(global_result == NULL);
  global_result = result_init(NULL, 0);
  int ret = populate_result_with_length(global_result, brief_description, description, confidence, abs_offset, length, is_contiguous);

  result_type = g_strdup(brief_description);
  debug_log("Setting result type %s", result_type);
  return ret;
}

static int is_whitespace(char *buff, int buff_size, int threshold, contract_completion_report_t ccr, unsigned long long absolute_offset, int is_contiguous)
{
  debug_log("is_whitespace");
  if (regex_match_count(buff, buff_size, "^\\s*$", (GRegexCompileFlags) (G_REGEX_OPTIMIZE | G_REGEX_NO_AUTO_CAPTURE)) == 1)
  {
    debug_log("is_whitespace: confidence 100");
    add_result_with_length(ccr, "whitespace", "Content solely exists of whitespaces", 100, absolute_offset, buff_size, is_contiguous);
    return 1;
  } else
  {
    debug_log("is_whitespace: confidence 0");
    return 0;
  }
}

static int is_html(char *buff, int buff_size, int threshold, contract_completion_report_t ccr, unsigned long long absolute_offset, int is_contiguous)
{
  debug_log("is_html");

#define HTML_REGEX_COUNT 8
  const char *match_strings[HTML_REGEX_COUNT] = { "<html.*>", "<div.*>", "<p.*>", "<a.*>", "<span.*>", "<body.*>", "<head.*>", "<title.*>" };

  int confidence = (regexen_matched_count(buff, buff_size, match_strings, HTML_REGEX_COUNT, (GRegexCompileFlags) 0) * 100) / HTML_REGEX_COUNT;

  if (confidence >= threshold)
  {
    debug_log("is_html: confidence %d", confidence);
    add_result_with_length(ccr, "html", "a file with html like tags", confidence, absolute_offset, buff_size, is_contiguous);
    return 1;
  }

  debug_log("is_html: confidence %d", confidence);
  return 0;
}

static int check_log(char *buff, int buff_size, const char *regex)
{
#define SHORT_SIZE 1024
  const int prelim_size = buff_size < SHORT_SIZE ? buff_size : SHORT_SIZE;

  debug_log("check_log: %s", regex);
  if (regex_match_count(buff, prelim_size, regex, (GRegexCompileFlags) (G_REGEX_MULTILINE | G_REGEX_OPTIMIZE | G_REGEX_NO_AUTO_CAPTURE)) > 0)
  {
    int num_log_lines = regex_match_count(buff, buff_size, regex, (GRegexCompileFlags) (G_REGEX_MULTILINE | G_REGEX_OPTIMIZE | G_REGEX_NO_AUTO_CAPTURE));
    const int num_lines = regex_match_count(buff, buff_size, "\\R+", (GRegexCompileFlags) (G_REGEX_OPTIMIZE | G_REGEX_NO_AUTO_CAPTURE));

    debug_log("log lines: %d, total_lines %d", num_log_lines, num_lines);
    return num_log_lines * 100 / num_lines;
  }

  return 0;
}

static int is_log(char *buff, int buff_size, int threshold, contract_completion_report_t ccr, unsigned long long absolute_offset, int is_contiguous)
{

  debug_log("Checking if is log");

  //first test for dmesg style logs
  const char *log_regex = "^\\[\\s*\\d+\\.\\d+\\]\\s+.*$";
  int confidence = check_log(buff, buff_size, log_regex);

  //now check for syslog style logs
  const char *syslog_regex = "^\\w+\\s\\d{1,2}\\s\\d{2}:\\d{2}:\\d{2}\\s\\w+\\s.*$";
  int new_confidence = check_log(buff, buff_size, syslog_regex);

  confidence = new_confidence > confidence ? new_confidence : confidence;

  //check for files where the rows are timestamped
  const char *timestamp_log_regex = "\\d{4}-\\d{2}-\\d{2}\\s\\d{2}:\\d{2}:\\d{2}";

  new_confidence = check_log(buff, buff_size, timestamp_log_regex);
  confidence = new_confidence > confidence ? new_confidence : confidence;

  //TODO, java style log files with log levels
  /*
     const char * java_style_log = "debug|alert|info|warn|warning|.*$";
     log_lines = regex_match_count(buff, java_style_log, G_REGEX_MULTILINE|G_REGEX_CASELESS);
   */

  if (confidence >= threshold)
  {
    confidence = confidence > 100 ? 100 : confidence;
    debug_log("is_log: confidence %d", confidence);
    add_result_with_length(ccr, "log", "log file", confidence, absolute_offset, buff_size, is_contiguous);
    return 1;
  }

  debug_log("is_log: confidence %d", confidence);
  return 0;
}

//buff MUST be null terminated
static int check_csv(char **lines, char delim, double *delims_per_line, int max_lines)
{
  //find the number of the lines in the file
  //extract the number of delims on each line into an array
  //analise the comma array
  int line_len, delim_count, non_empty_lines;

  memset(delims_per_line, 0, sizeof(double) * max_csv_lines);
  non_empty_lines = 0;

  //for each line
  //ignore the last line since it might contain the whole rest of the buffer
  for (int i = 0; lines[i] != NULL && i < max_lines - 1; i++)
  {
    line_len = strlen(lines[i]);
    char *delim_pos = strchr(lines[i], delim);

    delim_count = 0;
    while (delim_pos != NULL)
    {
      delim_count++;
      delim_pos = strchr(delim_pos + 1, delim);
    }

    //after processing each line only report lines that were not empty or entirely whitespace
    if (line_len > 2)
    {
      delims_per_line[non_empty_lines] = delim_count;

      non_empty_lines++;
    }
  }

  debug_log("non empty lines: %d", non_empty_lines);

  double mean, sd, median, coef_of_variance;

  gsl_sort(delims_per_line, 1, non_empty_lines);

  mean = gsl_stats_mean(delims_per_line, 1, non_empty_lines);
  median = gsl_stats_median_from_sorted_data(delims_per_line, 1, non_empty_lines);
  sd = gsl_stats_sd(delims_per_line, 1, non_empty_lines);
  coef_of_variance = sd / mean;


  debug_log("mean is: %f", mean);
  debug_log("median is: %f", median);
  debug_log("standard deviation is: %f", sd);
  debug_log("coefecient of variance is: %f", coef_of_variance);

  double confidence = 0;

  if (!(coef_of_variance > 1 || median < 1))
  {
    confidence = (1 - coef_of_variance) * 100;
  }

  debug_log("confidence that file is CSV: %f", confidence);

  return confidence;
}

static int is_csv(char *buff, int buff_size, int threshold, contract_completion_report_t ccr, unsigned long long absolute_offset, int is_contiguous)
{
  // This can be done more efficiently in one pass
  debug_log("is_csv");

#define MAX_LINES 10
#define NUM_DELIMS 4
  char delims[NUM_DELIMS] = { ',', '|', '\t', ' ' };
  int confidence = 0;
  char result_description[] = "csv file 'x' delimited";


  //split the buffer into lines of text
  char **lines = g_strsplit(buff, "\n", MAX_LINES);
  double *delims_per_line = (double *) g_malloc(sizeof(double) * max_csv_lines);

  for (int i = 0; i < NUM_DELIMS; i++)
  {
    if (check_csv(lines, delims[i], delims_per_line, MAX_LINES) >= 10)
    {
      char **lines = g_strsplit(buff, "\n", max_csv_lines);

      if ((confidence = check_csv(lines, delims[i], delims_per_line, max_csv_lines)) >= threshold)
      {
        debug_log("is_csv: confidence %d", confidence);
        result_description[10] = delims[i];
        add_result_with_length(ccr, "csv", result_description, confidence, absolute_offset, buff_size, is_contiguous);
        g_strfreev(lines);
        g_free(delims_per_line);
        return 1;
      }
    }
  }

  g_strfreev(lines);
  g_free(delims_per_line);

  debug_log("is_csv: confidence %d", confidence);
  return 0;
}

static int is_xml(char *buff, int buff_size, int threshold_xml, int threshold_html, contract_completion_report_t ccr, unsigned long long absolute_offset, int is_contiguous)
{
  debug_log("is_xml");

  int start_match_count =
    regex_match_count(buff, buff_size, "<[:._\\-a-zA-Z0-9]+(\\s[:._\\-a-zA-Z0-9]+=((\"[^<&\"]*\")|(\'[^<&\']*\')))*\\s?>", (GRegexCompileFlags) (G_REGEX_OPTIMIZE | G_REGEX_NO_AUTO_CAPTURE));
  int end_match_count = regex_match_count(buff, buff_size, "</[:._\\-a-zA-Z0-9]+\\s?>", (GRegexCompileFlags) (G_REGEX_OPTIMIZE | G_REGEX_NO_AUTO_CAPTURE));
  int self_match_count =
    regex_match_count(buff, buff_size, "<[:._\\-a-zA-Z0-9]+(\\s[:._\\-a-zA-Z0-9]+=((\"[^<&\"]*\")|(\'[^<&\']*\')))*\\s?/>", (GRegexCompileFlags) (G_REGEX_OPTIMIZE | G_REGEX_NO_AUTO_CAPTURE));

  int confidence = start_match_count > 3 ? 40 : start_match_count * 10;

  confidence = confidence + (end_match_count + self_match_count) * 10;
  confidence = confidence > 100 ? 100 : confidence;

  debug_log("is_xml: start_count %d, end_count %d, self_count %d, confidence %d", start_match_count, end_match_count, self_match_count, confidence);

  if (confidence >= threshold_xml)
  {
    if (is_html(buff, buff_size, threshold_html, ccr, absolute_offset, is_contiguous) == 1)
    {
      return 1;
    }

    debug_log("is_xml: confidence %d", confidence);
    add_result_with_length(ccr, "xml", "a file with xml like tags", confidence, absolute_offset, buff_size, is_contiguous);
    return 1;
  }

  debug_log("is_xml: confidence %d", confidence);
  return 0;
}

static int is_css(char *buff, int buff_size, int threshold, contract_completion_report_t ccr, unsigned long long absolute_offset, int is_contiguous)
{
  debug_log("TODO: is_css");
  // TODO Determine if it's CSS, and if so, whether it's above the threshold
  // If so, add to ccr and return 1
  return 0;
}

static int is_json(char *buff, int buff_size, int threshold, contract_completion_report_t ccr, unsigned long long absolute_offset, int is_contiguous)
{
  debug_log("TODO: is_json");
  // TODO Determine if it's JSON, and if so, whether it's above the threshold
  // If so, add to ccr and return 1
  return 0;
}

static int is_js(char *buff, int buff_size, int threshold, contract_completion_report_t ccr, unsigned long long absolute_offset, int is_contiguous)
{
  debug_log("TODO: is_js");
  // TODO Determine if it's js, and if so, whether it's above the threshold
  // If so, add to ccr and return 1
  return 0;
}

static int is_base85(char *buff, int buff_size, int threshold, contract_completion_report_t ccr, unsigned long long absolute_offset, int is_contiguous)
{
  debug_log("is_base85");
  if (regex_match_count(buff, buff_size, "^(<~)?[!\"#$%&'()*+,\\-./0-9:;<=>?@A-Z\\[\\\\\\]^_`a-u\n\r ]*(~>)?$", (GRegexCompileFlags) (G_REGEX_OPTIMIZE | G_REGEX_NO_AUTO_CAPTURE)) == 1)
    //if (regex_match_count(buff, buff_size, "^(<~)?(?:[!\"#$%&'()*+,\\-./0-9:;<=>?@A-Z\\[\\\\\\]^_`a-u ])*(~>)?$", G_REGEX_OPTIMIZE | G_REGEX_NO_AUTO_CAPTURE) == 1)
    //if (regex_match_count(buff, buff_size, "^(<~)?(?:[!\"#$%&'()*+,\\-./0-9:;<=>?@A-Z\\[\\\\\\]^_`a-u\n\r])*(~>)?$", G_REGEX_OPTIMIZE | G_REGEX_NO_AUTO_CAPTURE) == 1)
    //if (regex_match_count(buff, buff_size, "^(<~)?(?:[()*+,\\-./0-9:;<=>?@A-Z\\[\\\\\\]^_`a-u\n\r ])*(~>)?$", G_REGEX_OPTIMIZE | G_REGEX_NO_AUTO_CAPTURE) == 1)
  {
    debug_log("is_base85: confidence 100");
    add_result_with_length(ccr, "base85", "A base85 encoded block", 100, absolute_offset, buff_size, is_contiguous);
    return 1;
  } else
  {
    debug_log("is_base85: confidence 0");
    return 0;
  }
}

static int is_base64(char *buff, int buff_size, int threshold, contract_completion_report_t ccr, unsigned long long absolute_offset, int is_contiguous)
{
  // run regex for base64 - to return %confidence
  //  - runs for complete, well formed file (100%)
  //  - run for non-base64 chars (0%)
  debug_log("is_base64");

  const gchar *any_b64 = "^[A-Za-z0-9+/=_\\-.:!\r\n]*$";
  const gchar *complete_b64 = "^(?:[A-Za-z0-9+/_\\-.:!]{4}|\\R?)*(?:[A-Za-z0-9+/_\\-.:!]{2}==|[A-Za-z0-9+/=_\\-.:!]{3}=)?$";

  if (regex_match_count(buff, buff_size, any_b64, (GRegexCompileFlags) (G_REGEX_OPTIMIZE | G_REGEX_NO_AUTO_CAPTURE)) == 1)
  {
    int confidence = 60;

    if (regex_match_count(buff, buff_size, complete_b64, (GRegexCompileFlags) (G_REGEX_OPTIMIZE | G_REGEX_NO_AUTO_CAPTURE)) == 1)
    {
      confidence = 100;
    }

    debug_log("is_base64: confidence %d", confidence);
    add_result_with_length(ccr, "base64", "A base64 encoded block", confidence, absolute_offset, buff_size, is_contiguous);
    return 1;
  }

  debug_log("is_base64: confidence 0");
  return 0;
}

static int is_hex(char *buff, int buff_size, int threshold, contract_completion_report_t ccr, unsigned long long absolute_offset, int is_contiguous)
{
  debug_log("is_hex");
  if (regex_match_count(buff, buff_size, "^[A-Fa-f0-9\n\r\t\f ]*$", G_REGEX_OPTIMIZE) == 1)
  {
    debug_log("is_hex: confidence 100");
    add_result_with_length(ccr, "hex", "A hex encoded block", 100, absolute_offset, buff_size, is_contiguous);
    return 1;
  }

  debug_log("is_hex: confidence 0");
  return 0;
}

// ################ pronghorn callback functions ################

int subcontractor_init(void)
{
  // Initialise any structures here
//      debug_log("Hello world!");

  //get the block size
  if (config_get_int_with_default_macro(NULL, CONFIG_BLOCK_SIZE, &block_size) != 0)
  {
    error_log("could not retreive block size from config service, aborting");
    return -1;
  }

  if (block_size <= 0)
  {
    error_log("Block size is invalid! block_size = %d", block_size);
    return -1;
  }

  if (config_get_int_with_default_macro(NULL, CONFIG_MIN_TEXT_LENGTH, &min_text_length) != 0)
  {
    error_log("Could not retreive min text length from config service, aborting");
    return -1;
  }

  if (config_get_int_with_default_macro(NULL, CONFIG_MAX_TEXT_LENGTH, &max_text_length) != 0)
  {
    error_log("Could not retreive max text length from config service, aborting");
    return -1;
  }

  if (config_get_int_with_default_macro(NULL, CONFIG_MAX_CSV_LINES, &max_csv_lines) != 0)
  {
    error_log("Could not retreive max csv lines from config service, aborting");
    return -1;
  }

  if (config_get_int_with_default_macro(NULL, CONFIG_WHITESPACE_THRESHOLD, &threshold_whitespace) != 0)
  {
    error_log("Could not retreive WHITESPACE threshold from config service, aborting");
    return -1;
  }

  if (config_get_int_with_default_macro(NULL, CONFIG_HTML_THRESHOLD, &threshold_html) != 0)
  {
    error_log("Could not retreive HTML threshold from config service, aborting");
    return -1;
  }

  if (config_get_int_with_default_macro(NULL, CONFIG_XML_THRESHOLD, &threshold_xml) != 0)
  {
    error_log("Could not retreive XML threshold from config service, aborting");
    return -1;
  }

  if (config_get_int_with_default_macro(NULL, CONFIG_CSS_THRESHOLD, &threshold_css) != 0)
  {
    error_log("Could not retreive CSS threshold from config service, aborting");
    return -1;
  }

  if (config_get_int_with_default_macro(NULL, CONFIG_JSON_THRESHOLD, &threshold_json) != 0)
  {
    error_log("Could not retreive JSON threshold from config service, aborting");
    return -1;
  }

  if (config_get_int_with_default_macro(NULL, CONFIG_BASE64_THRESHOLD, &threshold_base64) != 0)
  {
    error_log("Could not retreive BASE64 threshold from config service, aborting");
    return -1;
  }

  if (config_get_int_with_default_macro(NULL, CONFIG_BASE85_THRESHOLD, &threshold_base85) != 0)
  {
    error_log("Could not retreive BASE85 threshold from config service, aborting");
    return -1;
  }

  if (config_get_int_with_default_macro(NULL, CONFIG_HEX_THRESHOLD, &threshold_hex) != 0)
  {
    error_log("Could not retreive HEX threshold from config service, aborting");
    return -1;
  }

  if (config_get_int_with_default_macro(NULL, CONFIG_CSV_THRESHOLD, &threshold_csv) != 0)
  {
    error_log("Could not retreive CSV threshold from config service, aborting");
    return -1;
  }

  if (config_get_int_with_default_macro(NULL, CONFIG_JS_THRESHOLD, &threshold_js) != 0)
  {
    error_log("Could not retreive JS threshold from config service, aborting");
    return -1;
  }

  if (config_get_int_with_default_macro(NULL, CONFIG_LOG_THRESHOLD, &threshold_log) != 0)
  {
    error_log("Could not retreive LOG threshold from config service, aborting");
    return -1;
  }

  if (config_get_int_with_default_macro(NULL, CONFIG_TXT_THRESHOLD, &threshold_txt) != 0)
  {
    error_log("Could not retreive TXT threshold from config service, aborting");
    return -1;
  }

  return 0;
}

int analyse_contract(contract_t to_analyse, contract_completion_report_t ccr)
{
  // These should have been free'd properly on the last execution
  prong_assert(global_path == NULL);

  //process text file
  global_path = g_strdup(contract_get_path(to_analyse));
  FILE *file = fopen(global_path, "r");

  if (file == NULL)
  {
    error_log("could not open file at file path %s for reading, aborting", global_path);
    g_free(global_path);
    global_path = NULL;
    return -1;
  }

  char *file_buffer = NULL;
  int file_buffer_size = 0;

  //allocates memory and reads the file into file_buffer
  file_buffer_size = smart_read_text(&file_buffer, file, block_size, max_text_length);

  //if the file was not text, exit cleanly but with no results
  if (file_buffer_size < min_text_length)
  {
    g_free(file_buffer);
    fclose(file);

    g_free(global_path);
    global_path = NULL;

    return 0;
  }
  // We now need to examine it for the following
  // txt, csv, log, html, xml, css, js, json, base64, base85, hex
  // The order selected (from most complex to least complex) is
  // html - requires <>
  // xml - requires <>
  // css - requires {}
  // json - requires {}
  // base85 - limited subset
  // base64 - limited subset
  // hex - limited subset
  // csv
  // js 
  // log
  // txt - everything else
  unsigned long long absolute_offset = contract_get_absolute_offset(to_analyse);
  int is_contiguous = contract_is_contiguous(to_analyse);

  if ((is_whitespace(file_buffer, file_buffer_size, threshold_whitespace, ccr, absolute_offset, is_contiguous) == 0) &&
      (is_xml(file_buffer, file_buffer_size, threshold_xml, threshold_html, ccr, absolute_offset, is_contiguous) == 0) &&
      (is_css(file_buffer, file_buffer_size, threshold_css, ccr, absolute_offset, is_contiguous) == 0) &&
      (is_json(file_buffer, file_buffer_size, threshold_json, ccr, absolute_offset, is_contiguous) == 0) &&
      (is_hex(file_buffer, file_buffer_size, threshold_hex, ccr, absolute_offset, is_contiguous) == 0) &&
      (is_base64(file_buffer, file_buffer_size, threshold_base85, ccr, absolute_offset, is_contiguous) == 0) &&
      (is_base85(file_buffer, file_buffer_size, threshold_base64, ccr, absolute_offset, is_contiguous) == 0) &&
      (is_csv(file_buffer, file_buffer_size, threshold_csv, ccr, absolute_offset, is_contiguous) == 0) &&
      (is_js(file_buffer, file_buffer_size, threshold_js, ccr, absolute_offset, is_contiguous) == 0) &&
      (is_log(file_buffer, file_buffer_size, threshold_log, ccr, absolute_offset, is_contiguous) == 0))
  {
    // It's none of the above!
    // Setting threshold_txt to > 100 will prevent identification of txt
    if (threshold_txt <= 100)
    {
      gchar *result_msg = g_strdup_printf("text of length: %i bytes.", file_buffer_size);

      add_result_with_length(ccr, "Text", result_msg, 100, absolute_offset, file_buffer_size, is_contiguous);
      g_free(result_msg);
    }
  } else
  {
    if (g_strcmp0(result_type, "base64") == 0 || g_strcmp0(result_type, "base85") == 0 || g_strcmp0(result_type, "hex") == 0)
    {
      int decoded_size = 0;

      //Determine file size
      if (g_strcmp0(result_type, "base64") == 0)
      {
        decoded_size = decoded_size_base64(file_buffer, file_buffer_size);
      }

      if (g_strcmp0(result_type, "base85") == 0)
      {
        decoded_size = decoded_size_base85(file_buffer, file_buffer_size);
      }

      if (g_strcmp0(result_type, "hex") == 0)
      {
        decoded_size = decoded_size_hex(file_buffer, file_buffer_size);
      }

      char *mountpoint = g_strdup_printf("%s:mnt-text", global_path);

      //Create subcontract
      char *sub_path = g_strdup_printf("%s/%d", mountpoint, 0);
      contract_t sub_contract = contract_init(NULL, 0);

      contract_set_path(sub_contract, sub_path);
      contract_set_absolute_offset(sub_contract, -1);
      contract_set_contiguous(sub_contract, 0);
      result_add_new_contract(global_result, sub_contract);
      contract_close(sub_contract);

      //Add file to fuse mount
      debug_log("Adding file %s with size %d", sub_path, decoded_size);
      add_file(0, result_type, decoded_size);
      g_free(sub_path);

      do_mount(mountpoint);
      g_free(mountpoint);
    }
  }

  if (global_result != NULL)
  {
    contract_completion_report_add_result(ccr, global_result);
    result_close(global_result);
    global_result = NULL;
  }

  g_free(file_buffer);
  fclose(file);
  g_free(global_path);
  global_path = NULL;
  g_free(result_type);

  //finished processing file for each file type passed
  return 0;
}

int subcontractor_close(void)
{
  // Destroy structures initialised in subcontractor_init

  debug_log("Bye");

  return 0;
}

int do_read(unsigned int id_number, const char *filename, char *buf, size_t size, off_t offset)
{
  //FILE *log = fopen("/tmp/text.log", "a");
  //fprintf(log, "Reading from file %s\n", global_path);
  //fprintf(log, "Reading file id:%d name:%s size:%zd offset:%lld\n", id_number, filename, size, (long long) offset);
  //fflush(log);
  
  FILE *file = fopen(global_path, "r");

  if (file == NULL)
  {
    //fprintf(log, "could not open file at file path %s for reading, aborting", global_path);
    //fclose(log);
    return -1;
  }

  char *file_buffer = NULL;

  //allocates memory and reads the file into file_buffer
  int buff_size = smart_read_text(&file_buffer, file, block_size, max_text_length);

  if (offset > buff_size)
  {
    //fprintf(log, "Offset exceeds file size\n");
    //fclose(log);
    return 0;
  }

  gsize out_size = 0;
  gchar *content = NULL;

  if (g_strcmp0(result_type, "base64") == 0)
  {
    //fprintf(log, "Processing base64 file\n");
    //fflush(log);
    content = (gchar *) g_base64_decode(file_buffer, &out_size);
  } else if (g_strcmp0(result_type, "base85") == 0)
  {
    //fprintf(log, "Processing base85 file\n");
    //fflush(log);
    content = ascii85_decode(file_buffer, &out_size);
  } else if (g_strcmp0(result_type, "hex") == 0)
  {
    //fprintf(log, "Processing hex file with %d bytes\n", buff_size);
    //fflush(log);
    content = hex_decode(file_buffer, buff_size, &out_size);
  }

  //fprintf(log, "Decoded %zd bytes\n", out_size);
  //fflush(log);

  int read_size = 0;

  if (out_size > offset)
  {
    read_size = (size < out_size - offset) ? size : out_size - offset;
    memcpy(buf, content + offset, read_size);
  }

  //fprintf(log, "Finished reading %d\n", read_size);
  //fclose(log);
  fclose(file);
  g_free(file_buffer);
  g_free(content);

  return read_size;
}

int decoded_size_base64(char *buff, int size)
{
  int raw_size = size;

  // Subtract newlines
  for (int i = 0; i < size; i++)
  {
    if (isspace(buff[i]))
    {
      raw_size--;
    }
  }
  int decoded_size = raw_size / 4 * 3;

  debug_log("Raw size %d, padded decoded size %d", raw_size, decoded_size);

  // Subtract padding from decoded size
  int eq_count = 0;
  int i = size - 1;

  debug_log("Last char %x", buff[i]);
  while (buff[i] == '=' || isspace(buff[i]))
  {
    debug_log("Current char %x", buff[i]);
    if (buff[i] == '=')
    {
      eq_count++;
    }
    i--;
  }

  if (eq_count > 2)
  {
    error_log("Shouldn't have more than 2 '=' of padding");
  }

  debug_log("EQ count %d", eq_count);
  return decoded_size - eq_count;
}

int decoded_size_base85(char *buff, int size)
{
  int raw_size = size;

  // Subtract newlines
  for (int i = 0; i < size; i++)
  {
    if (isspace(buff[i]))
    {
      raw_size--;
    }
  }

  // Don't count delimeters
  if (buff[0] == '<' && buff[1] == '~')
  {
    raw_size -= 2;
  }

  int i = size - 1;

  while (isspace(buff[i]))
  {
    i--;
  }

  if (buff[i] == '>' && buff[i - 1] == '~')
  {
    raw_size -= 2;
  }

  int decoded_size = raw_size / 5.0 * 4;

  debug_log("Raw size %d, padded decoded size %d", raw_size, decoded_size);
  return decoded_size;
}

int decoded_size_hex(char *buff, int size)
{
  int raw_size = size;

  // Subtract newlines
  for (int i = 0; i < size; i++)
  {
    if (isspace(buff[i]))
    {
      raw_size--;
    }
  }

  int decoded_size = raw_size / 2;

  debug_log("Raw size %d, padded decoded size %d", raw_size, decoded_size);
  return decoded_size;
}

gchar *hex_decode(char *buff, int buff_size, gsize * size)
{
  gchar *result = (gchar *) g_malloc(buff_size / 2 + 1);
  int count = 0;

  int result_pos = 0;
  char c;

  for (int i = 0; i < buff_size && buff[i] != '\0'; i++)
  {
    c = toupper(buff[i]);

    if (!isxdigit(c))
    {
      continue;
    }

    if (isdigit(c))
    {
      c -= '0';
    } else
    {
      c = c - 'A' + 10;
    }

    if (count == 0)
    {
      result[result_pos] = c << 4;
      count++;
    } else
    {
      result[result_pos] |= c;
      count = 0;
      result_pos++;
    }
  }

  *size = result_pos;
  return result;
}

void cleanup(void)
{
  // The filesystem is unmounted
  // Destroy any filesystem related structures
  g_free(global_path);
  g_free(result_type);
}
