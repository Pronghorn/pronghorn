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

/**
 * \file subcontractor_video.c
 */
#include <stdio.h>
#include <string.h>

#include <logger.h>
#include <config.h>
#include <blocks.h>
#include <glib.h>

// This is required to have this code work on C++ compilers
#ifdef __cplusplus
extern "C"
{
#define __STDC_CONSTANT_MACROS
#endif

#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>

#ifdef __cplusplus
}
#endif

//#include <base_fuse.h>

#include "subcontractor_helper.h"

#define CONFIG_SUB_VIDEO_ATTEMPT_VID_DECODE_OPTION_NAME "attempt_to_decode_videos"
#define CONFIG_SUB_VIDEO_ATTEMPT_VID_DECODE_DEFAULT 0

#define TYPE_AUDIO 0
#define TYPE_VIDEO 1

unsigned int supported_file_types[] = { MAGIC_TYPE_MP3, MAGIC_TYPE_AAC, MAGIC_TYPE_MPEG, MAGIC_TYPE_H264, MAGIC_TYPE_AVI, MAGIC_TYPE_WMV, MAGIC_TYPE_FLV, 0 };

/** 
 * \brief Setup the subcontractor. At this stage just setup the FFMPEG libraries
 * 
 * \return 0 on success, -1 on failure.
 */
int subcontractor_init(void)
{
  av_register_all();            //registers all available file formats and codecs so that when a file is read that uses a library or codec, it is already loaded.
  return 0;
}

/**
 * \brief Print out a debug log with the libavformat error string 
 *
 * \param message The message to print with it
 * \param code the libavformat error code returned
 *
 */
void debug_log_av_error(const char *message, int code)
{

  int err_buff_size = 512;
  char *err_buff = (char *) g_malloc(err_buff_size);

  if (av_strerror(code, err_buff, err_buff_size) != 0)
  {
    debug_log("%s (and failed to lookup a valid error code).", message);
  } else
  {
    debug_log("%s (error was %s)", message, err_buff);
  }

  g_free(err_buff);
}

/**
 * \brief Free up memory when analysis is completed
 *
 * \param extended_info our info array
 * \param summary the file type string
 * \param av_context our opened av file context
 *
 */
int clean_up(int return_val, GArray * extended_info, gchar * summary, AVFormatContext * av_context)
{
  if (summary != NULL)
  {
    g_free(summary);
  }

  if (av_context != NULL)
  {
    avformat_close_input(&av_context);
  }

  for (int j = 0; j < extended_info->len; j++)
  {
    g_free(g_array_index(extended_info, char *, j));
  }

  g_free(g_array_free(extended_info, TRUE));

  return return_val;
}

/**
 * \brief opens up an AV file for processing
 *
 * \param path the path of the file being opened
 * \param av_context the context into which to load the file
 *
 */
int open_av_file(const char *path, AVFormatContext ** av_context)
{
  int ret_code = avformat_open_input(av_context, path, NULL, NULL);

  if (ret_code != 0)
  {
    debug_log_av_error("Couldn't open the AV file", ret_code);
    return -1;
  }

  return 0;
}
// find out what data streams are within the file.
/**
 * \brief Determine what streams are in the file
 *
 * \param av_context our loaded AV file
 * \param extended_info array to keep metadata
 * \param av_type flag for telling us if it is a video or audio file
 *
 */
int get_streams_info(AVFormatContext * av_context, GArray * extended_info, int *av_type)
{

  AVDictionaryEntry *tag = NULL;
  int ret_code = (avformat_find_stream_info(av_context, NULL) < 0);

  if (ret_code == -1)
  {
    debug_log_av_error("Couldn't get AV file information", ret_code);
    return -1;
  }

  debug_log("Getting meta data...");
  while ((tag = av_dict_get(av_context->metadata, "", tag, AV_DICT_IGNORE_SUFFIX)))
  {
    debug_log("Meta data found: %s=%s", tag->key, tag->value);

    if (g_strcmp0(tag->key, "title") == 0)
    {
      gchar *new_data = g_strdup_printf("Title: %s", tag->value);

      extended_info = g_array_prepend_val(extended_info, new_data);
    }

  }

  for (int i = 0; i < av_context->nb_streams; i++)
  {
    AVStream *current = av_context->streams[i];

    while ((tag = av_dict_get(current->metadata, "", tag, AV_DICT_IGNORE_SUFFIX)))
    {
      debug_log("Stream %i : Meta data found: %s=%s", i, tag->key, tag->value);
    }

    if (current->codec->codec_type == AVMEDIA_TYPE_VIDEO)
    {
      *av_type = TYPE_VIDEO;
    }
  }

  return 0;
}

/**
 * \brief populate a result set
 *
 * \param ccr the contract completion report to populate with the result
 * \param summary summary of our file
 * \param extended_info furth information about the file
 * \param score the confidence value
 * \param abs_off the absolute offset of our file
 * \param bytes_we_think_we_decoded the size of the file
 * \param is_contiguous flag of whether or the file is contiguous
 *
 */
int make_result(contract_completion_report_t ccr, const gchar * summary, GArray * extended_info, int score, long long int abs_off, unsigned long long bytes_we_think_we_decoded, int is_contiguous)
{

  gchar *extended_summary = NULL;


  for (int x = 0; x < extended_info->len; x++)
  {
    gchar *prev = extended_summary;

    if (extended_summary == NULL)
    {
      extended_summary = g_strdup_printf("%s", g_array_index(extended_info, char *, x));
    } else
    {
      extended_summary = g_strdup_printf("%s, %s", extended_summary, g_array_index(extended_info, char *, x));
    }
    g_free(prev);
  }

  if (extended_summary == NULL)
  {
    if (summary != NULL)
    {
      extended_summary = g_strdup(summary);
    } else
    {
      extended_summary = g_strdup("VIDEO");
    }
  }
  int ret_code = 0;

  if (summary == NULL)
  {
    result_t result = result_init(NULL, 0);

    if (abs_off != -1)
    {
      ret_code = (populate_result_with_length(result, "VIDEO", extended_summary, score, abs_off, bytes_we_think_we_decoded, is_contiguous) != 0);
    } else
    {
      ret_code = (populate_result(result, "VIDEO", extended_summary, score) != 0);
    }
    contract_completion_report_add_result(ccr, result);
    result_close(result);
  } else
  {
    result_t result = result_init(NULL, 0);

    if (abs_off != -1)
    {
      ret_code = (populate_result_with_length(result, summary, extended_summary, score, abs_off, bytes_we_think_we_decoded, is_contiguous) != 0);
    } else
    {
      ret_code = (populate_result(result, summary, extended_summary, score) != 0);
    }
    contract_completion_report_add_result(ccr, result);
    result_close(result);
  }


  if (ret_code == -1)
  {
    warning_log("Couldn't add my result!!!");
    if (extended_summary != NULL)
      g_free(extended_summary);
    return -1;
  }

  debug_log("Result added OK");
  if (extended_summary != NULL)
    g_free(extended_summary);

  return 0;
}

/**
 * \brief determine which stream is the main one
 *
 * \param av_context our loaded file
 * \param our_codec the codec of our stream
 * \param extended_info file metadata
 * \param av_type flags audio or video file type.
 *
 */
int guess_best_stream(AVFormatContext * av_context, AVCodec ** our_codec, GArray * extended_info, int av_type)
{

  int our_stream = -1;
  int ret_code = 0;

  if (av_type)
  {
    ret_code = av_find_best_stream(av_context, AVMEDIA_TYPE_VIDEO, -1, -1, our_codec, 0);
  } else
  {
    ret_code = av_find_best_stream(av_context, AVMEDIA_TYPE_AUDIO, -1, -1, our_codec, 0);
  }

  if (ret_code < 0)
  {
    debug_log_av_error("Error trying to get the best stream: ", ret_code);
    return -1;
  }

  our_stream = ret_code;

  gchar *new_sum = g_strdup_printf("Codec: %s (%s)", (*our_codec)->name, (*our_codec)->long_name);

  extended_info = g_array_prepend_val(extended_info, new_sum);

  debug_log("The best codec we could find is %s (%s)", (*our_codec)->name, (*our_codec)->long_name);

  return our_stream;
}

/**
 * \brief calculates the size of an mp3 stream based on framesize and count
 *
 * \param path the path of the file being scanned
 * \param av_context our loaded file
 * \param our_stream the stream within the file being examined
 * \returns the estimated file size, -1 if it couldn't get it
 *
 */
long long int get_mp3_size(const char *path, AVFormatContext * av_context, int our_stream, long long int *frame_total)
{
	int current_offset = 0;
	int first_frame_offset = 0;
	long long int num_of_frames = 0;
	long long int sample_rate = av_context->streams[our_stream]->codec->sample_rate;
	long long int bit_rate = av_context->streams[our_stream]->codec->bit_rate;
	long long int frame_size = 0;	

	int second_header_byte = 0;
	int error_count = 0;
	long long int estimated_file_size = -1;		
	
	// Frame size is calculated from the bit rate and sample rate
	if (sample_rate != 0 && bit_rate != 0)
	{
		frame_size = (144 * bit_rate / sample_rate);
	}
	else
	{
		debug_log("Sample rate or bit rate not available. Cannot calculate frame size");
		return -1;
	}

	debug_log("FRAME SIZE: %lli",frame_size);

	// open the file for reading
	FILE * fp = fopen(path,"rb");
			
	// Grab the first 10k bytes
	unsigned char * first_bytes = (unsigned char*)malloc(10240);
	int bytes_read = fread(first_bytes,1,10240,fp);	
	
	// scan through the bytes looking for the first valid mp3 frame header: 0xff 0xfx
	while (current_offset < bytes_read -1)
	{
		if (first_bytes[current_offset] == 0xff)
		{
			if (first_bytes[current_offset+1] > 240)
			{
				// if we've found the first frame, set this as our start and break.				
				debug_log("First Valid Frame Found: %d",current_offset);
				first_frame_offset = current_offset;
				second_header_byte = first_bytes[current_offset+1];
				break;
			}
		}
		// if we didn't find it, keep searching
		current_offset++;
	}

	// if we couldn't find a valid frame, return a size of -1
	if (!first_frame_offset)
	{
		estimated_file_size = -1;
	}

	// free the first bytes since we're done with them.			
	free(first_bytes);

	// if we found a valid frame header, scan through the file
	// looking for the header at each frame_size interval
	if (first_frame_offset)
	{	
		int subtractor = 2;
		unsigned char * current_frame = (unsigned char*)malloc(4);
		
		// go to the location of our first frame
		fseek(fp,first_frame_offset,SEEK_SET);

		// read in two bytes from this spot		
		while (fread(current_frame,1,2,fp) > 0)
		{
			// if the bytes match our frame header, increase the count
			if (current_frame[0] == 0xff && current_frame[1] == second_header_byte)
			{
				num_of_frames++;
	
				// reset our error count				
				error_count = 0;
			}
			// if we didn't find it there are a couple of options:
			// -bad frame, so increase the error.
			// -If we've had many failures in a row, break.
			// -if this is the second frame we've scanned, maybe the 
			// the framesize is off by 1 byte, so increase it and try again			
			else
			{
				// increase the error count				
				error_count++;
				
				// if this is the second frame, try changing the framesize 	
				if (num_of_frames < 2)
				{
					frame_size+=1;
					
					// because we've changed the framesize, we have to change the amount of our
					// next seek.
					subtractor = 1;
				}
				// if we've read a lot of bad frames in a row, stop searching
				// we've reached the end of the file
				if (error_count > 10000)
				{
					break;
				}
				else
				{
					// if we're going to continue, increase the frame count anyway					
					num_of_frames++;
				}
			}
			// go to the next frame
			fseek(fp,frame_size-subtractor,SEEK_CUR);
			subtractor=2;
		}
		
		// Once we're done, take the last block of bad frames off our frame count
		num_of_frames-=error_count;
				
		// if we found frames, calculate the file size
		if (num_of_frames > 1)			
		{
			estimated_file_size = first_frame_offset + (frame_size * num_of_frames);
		}
		else
		{
			estimated_file_size = -1;
		}

		// free our buffer
		free(current_frame);
	}
	// close the file
	fclose(fp);
	
	// pass back the number of frames found
	*frame_total = num_of_frames;

	// return the estimated file size.
	return estimated_file_size;
}
/**
 * \brief analyse the contract given to us
 *
 * \param to_analyse the contracted handed to us
 * \param ccr the completion report to populate
 *
 */
int analyse_contract(contract_t to_analyse, contract_completion_report_t ccr)
{

  const char *path = contract_get_path(to_analyse);
  long long int abs_off = contract_get_absolute_offset(to_analyse);
  int contiguous = contract_is_contiguous(to_analyse);

  gchar *summary = NULL;

  AVFormatContext *av_context = NULL;
  AVCodec *our_codec = NULL;

  int av_type = 0;

  int our_stream = -1;          // The stream we are working on

  GArray *extended_info = g_array_new(TRUE, TRUE, sizeof(char *));

  // Try and just open the file

  if (open_av_file(path, &av_context) != 0)
  {
    return clean_up(0, extended_info, summary, av_context);
  }
  // Try and find stream info

  if (get_streams_info(av_context, extended_info, &av_type) != 0)
  {
    // At this stage, we could open the file, but couldn't get any stream info out of it.
    make_result(ccr, summary, extended_info, 35, -1, 0, contiguous);
    debug_log("Error getting streams info");
    return clean_up(0, extended_info, summary, av_context);
  }

  if (av_context->nb_streams >= 1)
  {
    gchar *stream_inf = g_strdup_printf("%i Data Stream(s)", av_context->nb_streams);

    debug_log("%s", stream_inf);
    extended_info = g_array_prepend_val(extended_info, stream_inf);
  } else
  {
    debug_log("Got no streams!!");
  }

  debug_log("Got streams info OK");

  // Get the library to take its best shot at it...

  our_stream = guess_best_stream(av_context, &our_codec, extended_info, av_type);
  if (our_stream < 0)
  {

    // At this stage, we could open the file, find streams, but couldn't get a stream we have a codec for.
    make_result(ccr, summary, extended_info, 55, -1, 0, contiguous);
    return clean_up(0, extended_info, summary, av_context);

  }
  // The summary will depend on the av type
  if (av_type)
  {
    summary = g_strdup_printf("VIDEO (%s)", our_codec->name);
  } else
  {
    summary = g_strdup_printf("AUDIO (%s)", our_codec->name);
  }

  long long int estimated_file_size = -1;

/*ALL THE ATTEMPT DECODE STUFF IS DEPRECATED. THE CONFIG FILE IS NO LONGER USED. IT MIGHT BE ADDED BACK LATER!!
  // Now, should we try and decode it?
  int attempt_decode = 0;

  if (config_get_int_with_default_macro(NULL, CONFIG_SUB_VIDEO_ATTEMPT_VID_DECODE, &attempt_decode) != 0)
  {
    warning_log("I couldn't determine if you wanted me to attempt to decode video files or not. Will assume my default.");
    attempt_decode = CONFIG_SUB_VIDEO_ATTEMPT_VID_DECODE_DEFAULT;
  }

	if (attempt_decode == 1)
	{
		// We are done.
		//debug_log("Finished processing");
		//make_result(ccr, summary, extended_info, 75, -1, 0, contiguous);
		//return clean_up(0, extended_info, summary, av_context);
	}
*/

  // Is it actually worth us processing the data if we aren't going to claim it?
  if (contiguous && abs_off != -1)
  {
    // If it is an mp3, find its size!
    if (strstr(our_codec->name, "mp3"))
    {
      long long int num_of_frames = 0;

      estimated_file_size = get_mp3_size(path, av_context, our_stream, &num_of_frames);

      if (num_of_frames < 2)
      {
        // if we couldn't get more than one frame, proably wasn't an mp3, so give it low confidence
        debug_log("Couldn't determine file size. We are done.");
        make_result(ccr, summary, extended_info, 25, -1, 0, contiguous);
        return clean_up(0, extended_info, summary, av_context);
      }

    }
  } else
  {
    estimated_file_size = -1;
  }

  if (estimated_file_size == -1)
  {
    debug_log("Couldn't determine file size. We are done.");
    make_result(ccr, summary, extended_info, 80, -1, 0, contiguous);
    return clean_up(0, extended_info, summary, av_context);
  }
  // We have bytes...
  if (contiguous && abs_off != -1)
  {
    make_result(ccr, summary, extended_info, 100, abs_off, estimated_file_size, contiguous);
  } else
  {
    // We have bytes but we can't claim...
    make_result(ccr, summary, extended_info, 100, -1, 0, contiguous);
  }

  return clean_up(0, extended_info, summary, av_context);
}

int subcontractor_close(void)
{
  // Destroy structures initialised in subcontractor_init
  debug_log("Bye");

  return 0;
}
