/* libpronghorn Image Subcontractor
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
 * \file subcontractor_image.c
 *
 * \brief Subcontractor for processing image files using Pronghorn
 *
 * Confidence Levels:
 * 100 - ImageMagick can open the file and process the image
 * 0 - ImageMagick was unable to detect an image
 */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <glib.h>
#include <arpa/inet.h>
#include <math.h>

#include <logger.h>
#include <config.h>
#include <blocks.h>
#include "subcontractor_helper.h"
#include <lightmagic.h>
#include <prong_assert.h>

/* Define NAMESPACE_PREFIX to force ImageMagick to define defaults */
#define MAGICKCORE_NAMESPACE_PREFIX

/* Import ImageMagick and Exif libraries required by this plugin */
#include <wand/MagickWand.h>
#include <libexif/exif-data.h>

#include <base_fuse.h>

/* Handle API changes in different versions on ImageMagick */
#if defined(MagickOptionToMnemonic)
#define ImgOptionToMnemonic MagickOptionToMnemonic
#define ImgMagickSizeFormat MagickSizeFormat    //%10lu
#elif defined(CommandOptionToMnemonic)
#define ImgOptionToMnemonic CommandOptionToMnemonic
#define ImgMagickSizeFormat "%"MagickSizeFormat //lu
#endif

/* Declate functions for processing a generic image */
char *read_image_data();

/* Declare functions for processing exif data in JPGs */
char *read_exif_data(const char *path);
void get_tag(ExifEntry * entry, void *user_data);
void collate_entries(ExifContent * cont, void *user_data);

/* Declare functions for determining file sizes */
long get_bytes_jpg(const char *path);
long get_bytes_png(const char *path);
long get_bytes_gif(const char *path);

/* Global wand for ImageMagick */
MagickWand *mw = NULL;

unsigned int supported_file_types[] = { MAGIC_TYPE_JPG, MAGIC_TYPE_PNG, MAGIC_TYPE_GIF, MAGIC_TYPE_FAX, 0 };

int get_magic_const(char *type)
{
  if (strcasecmp(type, "JPEG") == 0)
  {
    return MAGIC_TYPE_JPG;
  } else if (strcasecmp(type, "PNG") == 0)
  {
    return MAGIC_TYPE_PNG;
  } else if (strcasecmp(type, "GIF") == 0)
  {
    return MAGIC_TYPE_GIF;
  } else if (strcasecmp(type, "FAX") == 0)
  {
    return MAGIC_TYPE_FAX;
  } else
  {
    return -1;
  }
}

#define CONFIG_SUB_IMAGE_DETERMINE_SIZE_OPTION_NAME "attempt_to_determine_size"
#define CONFIG_SUB_IMAGE_DETERMINE_SIZE_DEFAULT 1

/** 
 * Struct referencing JPG image data which
 * is used to provide access to embedded files for
 * the fuse do_read method. We can do this because we call
 * the base_fuse do_mount method which forks this process
 * freezing its state.
 */
typedef struct
{

  /** Array of properties */
  char **properties;
  /** Thumbnail */
  char *thumbnail;
  /** Thumb size */
  int thumb_size;
  /** Max size */
  int max_size;
  /** Actual size */
  int act_size;
  /** User data */
  void *user_data;

} jpg_t;

jpg_t *jpg_data = NULL;

// PNG constants 
/* PNG Header Size */
#define PNG_HEADER_SIZE 8
/* PNG Chunk Size */
#define PNG_CHUNK_SIZE 4
/* PNG Header Size */
#define GIF_HEADER_SIZE 6

/**
 * Initialises ImageMagick environment
 * 
 * \returns 0 on success
 */
int subcontractor_init(void)
{
  // Initialise any structures here
  debug_log("init");

  MagickWandGenesis();
  mw = NewMagickWand();

  return 0;
}

/**
 * Analyse contract and respond
 *
 * Attempts to parse the supplied file as an image
 *
 * \param to_analyse The contract to analyse
 * \param ccr The contract completeion report to populate
 * \return 0 on success, -1 on error
 */
int analyse_contract(contract_t to_analyse, contract_completion_report_t ccr)
{
  prong_assert(jpg_data == NULL);

  const char *path = contract_get_path(to_analyse);
  {       /* Try and open the file */
    MagickBooleanType status = MagickReadImage(mw, path);

    /* MagickWand failed to read image */
    if (status == MagickFalse)
    {
      error_log("Could not analyse file");
      ClearMagickWand(mw);

      return 0;
    }
  }

   /* Process image and extract generic image data */
  char *type = MagickGetImageFormat(mw);

  if (!memchr(supported_file_types, get_magic_const(type), sizeof(supported_file_types)))
  {
    debug_log("Not claiming unsupported filetype: %s", type);
    free(type);
    ClearMagickWand(mw);

    return 0;
  }

  gchar *data_str = read_image_data();

  {                             /* Perform type specific operations */
    gchar *extra = NULL;

    if (strcasecmp(type, "JPEG") == 0)
    {                           /* JPG: Exif and Thumbnail extraction */
      extra = read_exif_data(path);
    } else if (strcasecmp(type, "GIF") == 0)
    {                           /* GIF: Animation and number of frames */
      extra = g_strdup_printf("frame 1/%zu", MagickGetNumberImages(mw));
    }

    if (extra != NULL)
    {
      gchar *tmp = g_strdup_printf("%s, %s", data_str, extra);

      g_free(data_str);
      data_str = tmp;
      g_free(extra);
    }
  }

  {                             /* Fill in report and result data, identifying blocks if possible */
    long long int offset = contract_get_absolute_offset(to_analyse);
    int contig = contract_is_contiguous(to_analyse);

    /* If the offset is know and data is contiguous we can identify blocks */
    int determine_size = 0;

    if (config_get_int_with_default_macro(NULL, CONFIG_SUB_IMAGE_DETERMINE_SIZE, &determine_size) != 0)
    {
      severe_log("Significant Error");
      free(type);
      g_free(data_str);
      ClearMagickWand(mw);
      if (jpg_data != NULL)
      {
        for (int i = 0; i < jpg_data->act_size; i++)
        {
          g_free(jpg_data->properties[i]);
        }
        g_free(jpg_data->properties);
        g_free(jpg_data->thumbnail);
        
        g_free(jpg_data);
        jpg_data = NULL;
      }

      return -1;
    }

    long bytes = 0;

    if (determine_size == 1 && (offset != -1 && contig == 1))
    {
      if (strcasecmp(type, "JPEG") == 0)
      {
        bytes = get_bytes_jpg(path);
      } else if (strcasecmp(type, "PNG") == 0)
      {
        bytes = get_bytes_png(path);
      } else if (strcasecmp(type, "GIF") == 0)
      {
        bytes = get_bytes_gif(path);
      }

      if (bytes > 0)
      {
        char *tmp = g_strdup_printf("%ldB, %s", bytes, data_str);

        g_free(data_str);
        data_str = tmp;
      }
    }

    result_t result = result_init(NULL, 0);

    if (jpg_data != NULL)
    {
      gchar *mnt_path = g_strdup_printf("%s:mnt-image/", path);

      if (jpg_data->thumbnail != NULL)
      {
        gchar *sub_path = g_strdup_printf("%s%d", mnt_path, 0);
        contract_t contract = contract_init(NULL, 0);

        contract_set_path(contract, sub_path);
        contract_set_absolute_offset(contract, -1);
        contract_set_contiguous(contract, 1);

        result_add_new_contract(result, contract);
        contract_close(contract);
        g_free(sub_path);
      }

      for (int i = 1; i < jpg_data->act_size; i++)
      {
        gchar *sub_path = g_strdup_printf("%s%d", mnt_path, i);
        contract_t contract = contract_init(NULL, 0);

        contract_set_path(contract, sub_path);
        contract_set_absolute_offset(contract, -1);
        contract_set_contiguous(contract, 1);

        result_add_new_contract(result, contract);
        contract_close(contract);
        g_free(sub_path);
      }
      g_free(mnt_path);

    }

    populate_result_with_length(result, type, data_str, 100, offset, bytes, contig);
    contract_completion_report_add_result(ccr, result);
    result_close(result);
  }
  
  free(type);
  g_free(data_str);
  ClearMagickWand(mw);

  if (jpg_data != NULL)
  {
    for (int i = 0; i < jpg_data->act_size; i++)
    {
      g_free(jpg_data->properties[i]);
    }
    g_free(jpg_data->properties);
    g_free(jpg_data->thumbnail);

    g_free(jpg_data);
    jpg_data = NULL;
  }

  return 0;
}

/**
 * Invoked when the subcontractor is closing
 * Clears ImageMagick environment
 */
int subcontractor_close(void)
{
  debug_log("close");

  mw = DestroyMagickWand(mw);
  MagickWandTerminus();

  return 0;
}

/**
 * Populates the buffer with the contents of the specified filename.
 *
 * \param id_number The id number of the file
 * \param filename The real filename of this file
 * \param buf The buffer to write data into
 * \param size The size of the buffer
 * \param offset The offsetinto the file the data should be taken from
 * \retuns The amount of bytes read, or -1 on error
 */
int do_read(unsigned int id_number, const char *filename, char *buf, size_t size, off_t offset)
{
//    FILE *log;
//    log = fopen("/tmp/image.log", "a");
//    fprintf(log, "Reading file id: %d, name: %s, size: %zd, offset: %zd\n", id_number, filename, size, (size_t) offset);

  size_t read_size;

  if (id_number == 0)           /* ID 0 is reserved for thumbnail, return thumbnail data */
  {
//        fprintf(log, "Reading thumbnail\n");
    read_size = (size < jpg_data->thumb_size - offset) ? size : jpg_data->thumb_size - offset;
    memcpy(buf, jpg_data->thumbnail + offset, read_size);
//        fprintf(log, "Returning data from %zd to %zd. Read a total of %zd\n", (size_t)offset, (size_t)offset + size, read_size);
  } else
  {
//        fprintf(log, "Reading exif value\n");
    int id = id_number - 1;

//        fprintf(log, "id: %d, myid: %d\n", id_number, id);
    read_size = (size < strlen(jpg_data->properties[id]) - offset) ? size : strlen(jpg_data->properties[id]) - offset;

    memcpy(buf, jpg_data->properties[id], read_size);
//        fprintf(log, "Returning data from %zd to %zd. Read a total of %zd\n", (size_t)offset, (size_t)offset + size, read_size);
  }

//    fclose(log);

  return read_size;
}

/**
 * Called when the filesystem is unmounted, and allows the destruction
 * of structures and freeing allocated memory.
 */
void cleanup(void)
{
  // The filesystem is unmounted
  // Destroy any filesystem related structures
  if (jpg_data != NULL)
  {
    for (int i = 0; i < jpg_data->act_size; i++)
      g_free(jpg_data->properties[i]);
    g_free(jpg_data->properties);
    g_free(jpg_data->thumbnail);

    g_free(jpg_data);
    jpg_data = NULL;
  }
}

/**
 * Reads the image and gets several properties.
 * Properties include: Type, Height, Width, Number of Colours, Compression Type, Bit Depth and Resolution
 *
 * \param type The image type will be stored in this array
 * \returns String containing the formatted image properties
 */
char *read_image_data()
{
  // Obtain and format generic image properties
  gchar *wxh = g_strdup_printf("%zdx%zd", MagickGetImageWidth(mw), MagickGetImageHeight(mw));
  gchar *compress = g_strdup_printf("%s compressed", ImgOptionToMnemonic(MagickCompressOptions, MagickGetImageCompression(mw)));
  gchar *depth = g_strdup_printf("%zd-Bit", MagickGetImageDepth(mw));

  double irx, iry;

  MagickGetResolution(mw, &irx, &iry);

  gchar *res = NULL;
  int unit = MagickGetImageUnits(mw);

  switch (unit)
  {
  case PixelsPerInchResolution:
    res = g_strdup_printf("%.0fx%.0f ppi", irx, iry);
    break;
  case PixelsPerCentimeterResolution:
    res = g_strdup_printf("%.0fx%.0f ppi", irx, iry);
    break;
  case UndefinedResolution:
    res = g_strdup_printf("%.0fx%.0f pp?", irx, iry);
  }

  /* Example return value: 1366x768, 72x72 ppi, 8-Bit, LZW compression */
  gchar *data_str = g_strdup_printf("%s, %s, %s, %s", wxh, res, depth, compress);

  g_free(wxh);
  g_free(compress);
  g_free(depth);
  g_free(res);

  return data_str;
}

/**
 * Parses a JPG image looking for Exif data.
 * If Exif is found it will extract the fields and values for mounting.
 *
 * \param path The path to the file
 * \returns String specifing whether the file contains Exif data for use in descriptive field.
 */
char *read_exif_data(const char *path)
{
  /* Initialise jpg_t struct */
  jpg_data = (jpg_t *) g_malloc(sizeof(jpg_t));
  jpg_data->properties = (char **) g_malloc(sizeof(char *));
  jpg_data->max_size = 1;
  jpg_data->act_size = 0;
  jpg_data->thumbnail = NULL;
  jpg_data->thumb_size = 0;

  //if ((ExifData *exif = exif_data_new_from_file(path)) != NULL)
  ExifData *exif = exif_data_new_from_file(path);

  if (exif != NULL)
  {
    gchar *mnt_path = g_strdup_printf("%s:mnt-image", path);

    /* Extraction of thumbnail */
    if (exif->data && exif->size)
    {
      debug_log("Grabbing thumbnail of size %d", exif->size);
      jpg_data->thumb_size = exif->size;

      jpg_data->thumbnail = (char *) g_malloc(jpg_data->thumb_size);
      memcpy(jpg_data->thumbnail, exif->data, jpg_data->thumb_size);

      /* ID 0 is always reserved for the thumbnail */
      add_file(0, "thumbnail", jpg_data->thumb_size);
    }

    exif_data_foreach_content(exif, collate_entries, jpg_data);

    /* If Exif is found mount the image */
    do_mount(mnt_path);
    g_free(mnt_path);

    return g_strdup_printf("Contains Exif");
  }
  else
  {
    return g_strdup_printf("No Exif");
  }
}

/**
 * ExifDataForeachContentFunc - Executes on each IFD in turn.
 *
 * Executes get_tag on each EXIF tag in this IFD in turn.
 * The tags will no necessarily be visited in numerical order.
 *
 * \param cont IFD over which to iterate
 * \param user_data Data passed into each call of collate_entries
 */
void collate_entries(ExifContent * cont, void *user_data)
{
  ExifIfd ifd = exif_content_get_ifd(cont);

  exif_content_foreach_entry(cont, get_tag, &ifd);
}

/**
 * ExifContentForeachEntryFucnt - Executes on each tag in turn.
 *
 * Each tag represents an EXIF property name.
 */
void get_tag(ExifEntry * entry, void *user_data)
{
  const char *tag_name = exif_tag_get_name_in_ifd(entry->tag, *((ExifIfd *) user_data));

  /* As the number of properties per image can change, jpg_data->properties needs to be realloced when full */
  if (jpg_data->max_size <= jpg_data->act_size)
  {
    jpg_data->max_size *= 2;
    jpg_data->properties = (char **) g_realloc(jpg_data->properties, (jpg_data->max_size) * (sizeof(char *)));
  }

  char *curr_p;

  {                             /* Tag value is of an undeterminable size, keep allocating more until max is reached or whole value is obtained */
    int alloc_size = 128;

    curr_p = (char *) g_malloc(alloc_size);
    exif_entry_get_value(entry, curr_p, alloc_size);

    while (strlen(curr_p) == alloc_size && alloc_size <= 2048)
    {
      alloc_size *= 2;
      curr_p = (char *) g_realloc(curr_p, alloc_size * (sizeof(char *)));
      exif_entry_get_value(entry, curr_p, alloc_size);
    }
  }

  jpg_data->properties[jpg_data->act_size] = curr_p;    /* Add starting at property[0] */
  jpg_data->act_size++;
  add_file(jpg_data->act_size, tag_name, strlen(curr_p));       /* Add file starting with ID 1 as ID 0 is reserved for thumbnail */
}

/**
 * Processes a JPG skipping known fields looking for an EOF.
 * Required to manually look for EOF as ImageMagick incorrectly
 * reports the filesize for continuous or suffixed streams.
 *
 * \param path The path of the JPG image
 * \returns The size in bytes of the image
 */
long get_bytes_jpg(const char *path)
{
  unsigned char seg_start = 0xFF;
  unsigned char jpeg_eof = 0xD9;
  unsigned char seg_names[11] = { 0x00, 0x01, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8 };
  unsigned char buf[2], a_byte, b_byte;

  FILE *file = fopen(path, "r");

  if (file == NULL)
  {
    warning_log("get_bytes_jpg: Could not open file");
    return 0;
  }

  /* Continue till something breaks out */
  //TODO: maybe put a limit on this?
  while (1)
  {
    a_byte = fgetc(file);

    if (a_byte == seg_start)    /* Match against JPG segment start */
    {
      b_byte = fgetc(file);

      /* Check for padding */
      while (b_byte == seg_start)
        b_byte = fgetc(file);

      if (b_byte == jpeg_eof)   /* EOF match */
      {
        long size = ftell(file);

        fclose(file);

        return size;
      } else if (!memchr(seg_names, b_byte, 11))
      {
        /* If the byte after a segment match is not in the array,
           then it is followed by a 2 byte length field */
        if (fread(buf, 2, 1, file) != 1)
        {
          warning_log("get_bytes_jpg: Error comparing bytes\n");
          fclose(file);
          return -1;
        }

        /* JPEG is Big Endian, Machine is Little Endian, Network is Big Endian */
        int off = ntohs((int16_t)(*buf));
        fseek(file, off - 2, SEEK_CUR);
      }
    }
  }
  return 0;
}

/**
 * Processes a PNG skipping known fields looking for an EOF.
 * Required to manually look for EOF as ImageMagick incorrectly
 * reports the filesize for continuous or suffixed streams.
 *
 * \param path The path of the PNG image
 * \returns The size in bytes of the image
 */
long get_bytes_png(const char *path)
{
  unsigned char header[PNG_HEADER_SIZE] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
  unsigned char header_buf[PNG_HEADER_SIZE];
  char chunk_len[PNG_CHUNK_SIZE];
  char chunk_name[PNG_CHUNK_SIZE];

  FILE *file = fopen(path, "r");

  if (file == NULL)
  {
    warning_log("get_bytes_png: Could not open file");
    return 0;
  }

  /* Read header */
  if (fread(&header_buf, PNG_HEADER_SIZE, 1, file) != 1)
  {
    warning_log("get_bytes_png: Error Reading Header");
    fclose(file);
    return 0;
  }

  /* Confirm header is correct */
  if (memcmp(header_buf, header, PNG_HEADER_SIZE) != 0)
  {
    warning_log("get_bytes_png: Does not match header!");
    return 0;
  }

  /* Continue till something breaks out */
  while (1)
  {
    /* Read in the 4 byte chunk length */
    if (fread(chunk_len, PNG_CHUNK_SIZE, 1, file) != 1)
    {
      warning_log("get_bytes_png: Error reading chunk length");
      fclose(file);
      return 0;
    }

    /* Read in the 4 byte chunk name */
    if (fread(chunk_name, PNG_CHUNK_SIZE, 1, file) != 1)
    {
      warning_log("get_bytes_png: Error reading chunk name");
      fclose(file);
      return 0;
    }

    /* IEND specifies EOF chunk */
    if (strncmp(chunk_name, "IEND", PNG_CHUNK_SIZE) == 0)
    {
      long size = ftell(file) + PNG_CHUNK_SIZE;

      fclose(file);

      return size;
    } else
    {
      /* If not the EOF chunk convert chunk_len to correct Endianess and seek ahead */
      int off = ntohl((int32_t)(*chunk_len));
      fseek(file, off + PNG_CHUNK_SIZE, SEEK_CUR);
    }
  }
  return 0;
}

/**
 * Processes a GIF skipping known fields looking for an EOF.
 * Required to manually look for EOF as ImageMagick incorrectly
 * reports the filesize for continuous or suffixed streams.
 *
 * \param path The path of the gif image
 * \returns The size in bytes of the image
 */
long get_bytes_gif(const char *path)
{
  unsigned char EXT_BLOCK = 0x21;
  unsigned char IMG_BLOCK = 0x2C;
  unsigned char GIF_EOF = 0x3B;
  unsigned char byte;

  FILE *file = fopen(path, "r");

  if (file == NULL)
  {
    warning_log("get_bytes_gif: Couldnt not open file\n");
    return 0;
  }

  {
    unsigned char header87[GIF_HEADER_SIZE] = { 0x47, 0x49, 0x46, 0x38, 0x37, 0x61 };
    unsigned char header89[GIF_HEADER_SIZE] = { 0x47, 0x49, 0x46, 0x38, 0x39, 0x61 };
    unsigned char header_in[GIF_HEADER_SIZE];

    if (fread(header_in, GIF_HEADER_SIZE, 1, file) != 1)
    {
      warning_log("get_gytes_gif: Error Reading Header\n");
      fclose(file);
      return 0;
    }

    if ((memcmp(header_in, header87, GIF_HEADER_SIZE) != 0) && (memcmp(header_in, header89, GIF_HEADER_SIZE) != 0))
    {
      warning_log("get_bytes_gif: Does not match header!\n");
      fclose(file);
      return 0;
    }
  }

  {
    /* Seek past width(2) height(2) */
    fseek(file, 4, SEEK_CUR);

    /* Get packed byte */
    byte = fgetc(file);

    int gct_size = byte & 7;
    int has_gct = ((byte & (1 << 7)) >> 7);

    /* Seek past Background Color Index and Pixel Aspect Ratio */
    fseek(file, 2, SEEK_CUR);

    /* If Global Color Table exists skip it. Size: 3*2^(gct_size+1) */
    if (has_gct == 1)
      fseek(file, 3 * pow(2.0, (gct_size + 1)), SEEK_CUR);
  }

  /* Continue till EOF */
  byte = fgetc(file);
  do
  {
    if (byte == EXT_BLOCK)
    {
      /* Read in block label */
      byte = fgetc(file);

      /* Read in block size and seek past */
      byte = fgetc(file);
      fseek(file, byte + 1, SEEK_CUR);
    } else if (byte == IMG_BLOCK)
    {
      /* Seek past leftpos(2) rightpos(2) width(2) height(2) */
      fseek(file, 8, SEEK_CUR);

      byte = fgetc(file);

      int lct_size = byte & 7;
      int has_lct = ((byte & (1 << 7)) >> 7);

      if (has_lct == 1)
        fseek(file, 3 * pow(2.0, (lct_size + 1)), SEEK_CUR);

      /* Image followed by link list of LZW blocks */
      byte = fgetc(file);       /* Get bit width */
      byte = fgetc(file);       /* Get size of list */

      do
      {
        fseek(file, byte, SEEK_CUR);
        byte = fgetc(file);
      }
      while (byte != 0);
    }

    byte = fgetc(file);
  }
  while (byte != GIF_EOF);

  long size = ftell(file);

  fclose(file);
  return size;
}
