/* Pronghorn Lightmagic Library
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
 * \file lightmagic.c
 * \brief Lightmagic file
 *
 * Light magic is a stripped down version of magic designed for speed. It was
 * originally used for the DFRWS 2012 challenge, which defined the following 
 * types as being of interest:
 *
 * From the DFRWS requirements
 *
 * - - txt - isprintable, unicode???\n
 * - case - isprintable, commas\n
 * - log - isprintable\n
 * - html - tags\n
 * - xml - tags\n
 * - css - isprintable\n
 * - js - isprintable\n
 * - json - isprintable\n
 * - base64 - is within setn
 * - base85 - is within set\n
 * - hex - is within set\n
 *
 * - jpg - 0xff 0xd8 0xff\n
 * - png - 0x89 PNG\n
 * - gif - GIF8\n
 * - fax - ?\n
 * - jbig - ?\n
 * - zip - PK 0x03 0x04\n
 * - zlib - as per zip(?)\n
 * - bz - BZh\n
 * - gzip - 0x1f 0x8b\n
 * - compress - 0x1f 0x9d\n
 * - pdf - %PDF\n
 * - OLE doc - 0xd0 0xcf 0x11 0xe0\n
 * - docx+ - same as pkzip\n
 * - mp3 - FF ex or FF Fx\n
 * - aac - ADIF\n
 * - mpeg - 0x00 0x00 0x00 0x01, or 0x47 0x40 0x00 0x10 , or 0x00 0x00 0x01 0xbx\n
 * - h264 - as per mpeg\n
 * - avi - RIFF\n
 * - wmv - 0x30 0x26 0xb2 0x75\n
 * - flv - 0x46 0x4c 0x56 0x01\n
 * - fat - (offset 54)FAT1, or (offset 82) FAT32\n
 * - ntfs - (offset 3)NTFS\n
 * - ext - (offset 0x438) 0x53 0xef\n
 * - constant - 8,16,32 bit\n
 * - encrypted, random - everything else\n
 * 
 * Added:
 * - Partition Table/BootRecord - (offset 510) 0x55 0xaa\n
 *
 * - Useful references:\n
 * - http://www.garykessler.net/library/file_sigs.html\n
 * - http://en.wikipedia.org/wiki/List_of_file_signatures\n
 */

#include <prong_assert.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <glib.h>

#include "lightmagic.h"

/*
 * From the DFRWS requirements
 *
 * txt - isprintable, unicode???
 * case - isprintable, commas
 * log - isprintable
 * html - tags
 * xml - tags
 * css - isprintable
 * js - isprintable
 * json - isprintable
 * base64 - is within set
 * base85 - is within set
 * hex - is within set
 *
 * jpg - 0xff 0xd8 0xff
 * png - 0x89 PNG
 * gif - GIF8
 * fax - ?
 * jbig - ?
 * zip - PK 0x03 0x04
 * zlib - various - 0x48 0x89, 0x78 0xda, 0x78 0x9c, 0x68 0xde
 * bz - BZh
 * gzip - 0x1f 0x8b
 * compress - 0x1f 0x9d
 * pdf - %PDF
 * OLE doc - 0xd0 0xcf 0x11 0xe0
 * docx+ - same as pkzip
 * mp3 - FF ex or FF Fx
 * aac - ADIF
 * mpeg - 0x00 0x00 0x00 0x01, or 0x47 0x40 0x00 0x10 , or 0x00 0x00 0x01 0xbx
 * h264 - as per mpeg
 * avi - RIFF
 * wmv - 0x30 0x26 0xb2 0x75
 * flv - 0x46 0x4c 0x56 0x01
 * fat - (offset 54)FAT1, or (offset 82) FAT32
 * ntfs - (offset 3)NTFS
 * ext - (offset 0x438) 0x53 0xef
 * constant - 8,16,32 bit\n
 * encrypted, random - everything else?\n
 * 
 * Partition Table/BootRecord - (offset 510) 0x55 0xaa
 * Useful references:
 * http://www.garykessler.net/library/file_sigs.html
 * http://en.wikipedia.org/wiki/List_of_file_signatures
 */

/**
 * A lookup table to quickly determine what characteristics
 * character can have. This is tricky, but pretty awesome.
 *
 * Bit code:
 * 1 - text
 * 2 - base64
 * 4 - base85
 * 8 - hex
 *
 * Note to self, base85 0-9 A-Z a-z !#$%&()*+-;<=>?@^_`{|}~
 */

/** Defines an element in the Look-Up-Table as being TEXT */
#define LUT_TEXT_TEXT 0x01
/** Defines an element in the Look-Up-Table as being BASE64 */
#define LUT_TEXT_BASE64 0x02
/** Defines an element in the Look-Up-Table as being BASE85 */
#define LUT_TEXT_BASE85 0x04
/** Defines an element in the Look-Up-Table as being HEX */
#define LUT_TEXT_HEX 0x08

/** Look up table size */
#define LUT_SIZE 256
/** The lookup table when identifying buffers containing text */
static unsigned char text_lookup_table[LUT_SIZE];

/** A flag indicating the text lookup table is filled */
static int text_lookup_table_filled = 0;

/**
 * Used to determine whether the supplied character is suitable for use with Base64.
 *
 * This function also makes allowances for common variants to Base64 as shown in
 * https//en.wikipedia.org/wiki/Base64
 *
 * \param c The character to test
 * \returns 1 if a valid Base64 character, 0 otherwise.
 */
static int isbase64(unsigned char c)
{
  if ((c >= 'A') & (c <= 'Z'))
  {
    return 1;
  }

  if ((c >= 'a') & (c <= 'z'))
  {
    return 1;
  }

  if ((c >= '0') & (c <= '9'))
  {
    return 1;
  }

  switch (c)
  {
  case '+':
  case '/':
  case '=':
  case '_':                    // The below are variants (https://en.wikipedia.org/wiki/Base64)
  case '-':
  case '.':
  case ':':
  case '!':
    return 1;
  }

  return 0;
}

/**
 * Used to determine whether the supplied character is suitable for use with Base85.
 *
 * \param c The character to test
 * \returns 1 if a valid Base85 character, 0 otherwise.
 */
static int isbase85(unsigned char c)
{
  if ((c >= 'A') & (c <= 'Z'))
  {
    return 1;
  }

  if ((c >= 'a') & (c <= 'z'))
  {
    return 1;
  }

  if ((c >= '0') & (c <= '9'))
  {
    return 1;
  }

  switch (c)
  {
  case '!':
  case '#':
  case '$':
  case '%':
  case '&':
  case '(':
  case ')':
  case '*':
  case '+':
  case '-':
  case ';':
  case '<':
  case '=':
  case '>':
  case '?':
  case '@':
  case '^':
  case '_':
  case '`':
  case '{':
  case '|':
  case '}':
  case '~':
  case '\0':
    return 1;
  }

  return 0;

}

/**
 * Creates the text lookup table.
 *
 * This should only need to be called once. The results could be made static to
 * eliminate the need to have lightmagic re-create this static table every time
 * the program runs, but the overhead is pretty minimal it's probably not worth it.
 *
 * Only ASCII is supported - there is no intention to support EBCDIC.
 */
static void make_text_lookup_table(void)
{
  memset(text_lookup_table, 0, sizeof(text_lookup_table));

  int i;

  for (i = 0; i < LUT_SIZE; i++)
  {
    // Formatting characters
    if ((i == ' ') || (i == '\r') || (i == '\n'))
    {
      text_lookup_table[i] |= LUT_TEXT_TEXT | LUT_TEXT_BASE64 | LUT_TEXT_BASE85 | LUT_TEXT_HEX;
    }
    // General text
    if ((g_ascii_isprint(i) || g_ascii_ispunct(i) || g_ascii_isspace(i)) != 0)
    {
      text_lookup_table[i] |= LUT_TEXT_TEXT;
    }
    // Base64
    if (isbase64(i) != 0)
    {
      text_lookup_table[i] |= LUT_TEXT_BASE64;
    }
    // Base85
    if (isbase85(i) != 0)
    {
      text_lookup_table[i] |= LUT_TEXT_BASE85;
    }
    // Hex digits
    if (isxdigit(i) != 0)
    {
      text_lookup_table[i] |= LUT_TEXT_HEX;
    }
  }
}

void g_array_append(GArray * array, unsigned int val)
{
  unsigned int array_val = val;

  g_array_append_val(array, array_val);
}

GArray *lightmagic_detect(const unsigned char *buffer, unsigned int buffer_size, unsigned int window_size)
{
  prong_assert(buffer != NULL);

  if (window_size < buffer_size)
  {
    buffer_size = window_size;
  }

  if (text_lookup_table_filled == 0)
  {
    make_text_lookup_table();
    text_lookup_table_filled = 1;
  }

  GArray *array = g_array_new(FALSE, TRUE, sizeof(int));

  // Minimum size of buffer to identify is 32
  if (window_size < 32)
  {
    g_array_append(array, MAGIC_TYPE_UNIDENTIFIED);
    return array;
  }

  int flags = LUT_TEXT_TEXT | LUT_TEXT_BASE64 | LUT_TEXT_BASE85 | LUT_TEXT_HEX;

  for (int i = 0; (flags != 0) && (i < 32); i++)
  {
    flags &= text_lookup_table[buffer[i]];
    if ((flags & LUT_TEXT_TEXT) == 0)
    {
      flags = 0;
    }
  }

  if (flags & LUT_TEXT_TEXT)
  {
    g_array_append(array, MAGIC_TYPE_TEXT);
    if (flags & LUT_TEXT_BASE64)
    {
      g_array_append(array, MAGIC_TYPE_BASE64);
    }
    if (flags & LUT_TEXT_BASE85)
    {
      g_array_append(array, MAGIC_TYPE_BASE85);
    }
    if (flags & LUT_TEXT_HEX)
    {
      g_array_append(array, MAGIC_TYPE_HEX);
    }
  }
  // Check for filesystems
  const char FAT_MAGIC_1[] = "FAT1";

  if ((window_size >= (54 + strlen(FAT_MAGIC_1))) && (memcmp(buffer + 54, FAT_MAGIC_1, strlen(FAT_MAGIC_1)) == 0))
  {
    g_array_append(array, MAGIC_TYPE_FAT12);
    g_array_append(array, MAGIC_TYPE_FAT16);
  }
  const char FAT_MAGIC_2[] = "FAT32";

  if ((window_size >= (82 + strlen(FAT_MAGIC_2))) && (memcmp(buffer + 82, FAT_MAGIC_2, strlen(FAT_MAGIC_2)) == 0))
  {
    g_array_append(array, MAGIC_TYPE_FAT32);
  }

  const char NTFS_MAGIC[] = "NTFS";

  if ((window_size >= (3 + strlen(NTFS_MAGIC))) && (memcmp(buffer + 3, NTFS_MAGIC, strlen(NTFS_MAGIC)) == 0))
  {
    g_array_append(array, MAGIC_TYPE_NTFS);
  }

  const char EXT_MAGIC[] = "\x53\xef";

  if ((window_size >= (0x438 + strlen(EXT_MAGIC))) && (memcmp(buffer + 0x438, EXT_MAGIC, strlen(EXT_MAGIC)) == 0))
  {
    g_array_append(array, MAGIC_TYPE_EXT);
  }
  // Check for constants. If a constant is found, processing stops as the others below cannot be true
  // Check for 8/16/32 bit consts!
  int next_check_size = 0;
  int processed_size = 4;

  do
  {
    processed_size += next_check_size;
    if ((processed_size << 1) > buffer_size)
    {
      next_check_size = buffer_size - processed_size;
    } else
    {
      next_check_size = processed_size;
    }
  }
  while ((processed_size != buffer_size) && (memcmp(buffer, buffer + processed_size, next_check_size) == 0));

  if (processed_size == buffer_size)
  {
    g_array_append(array, MAGIC_TYPE_CONSTANT);
    return array;
  } else
  {
    g_array_append(array, MAGIC_TYPE_UNIDENTIFIED);
  }


  // I think this is correct... if a bit hacky
  // Converts data to big endian to make the 
  // magic numbers look better
  unsigned int magic_tiny_fingerprint = ntohl(*((int *) buffer));

  switch (magic_tiny_fingerprint)
  {
  case 0x89504E47:             // 0x89 PNG
    g_array_append(array, MAGIC_TYPE_PNG);
    break;
  case 0x47494638:             // GIF8
    g_array_append(array, MAGIC_TYPE_GIF);
    break;
  case 0x504B0304:             // PK 0x03 0x04
    g_array_append(array, MAGIC_TYPE_ZIP);
    break;
    // case 0x25504446:             // %PDF
    // g_array_append(array, MAGIC_TYPE_PDF);
    // break;
  case 0xD0CF11E0:             // 0xd0 0xcf 0x11 0xe0
    g_array_append(array, MAGIC_TYPE_OLE);
    break;
	case 0x00000020:						 // 0x00 0x00 0x00 0x20
  case 0x41444946:             // ADIF
    g_array_append(array, MAGIC_TYPE_AAC);
    break;
  case 0x00000001:             // 0x00 0x00 0x00 0x01
  case 0x47400010:             // 0x47 0x40 0x00 0x10
    g_array_append(array, MAGIC_TYPE_MPEG);
    break;
  case 0x52494646:             // RIFF
    g_array_append(array, MAGIC_TYPE_AVI);
    break;
  case 0x3026B275:             // 0x30 0x26 0xb2 0x75
    g_array_append(array, MAGIC_TYPE_WMV);
    break;
  case 0x464C5601:             // 0x46 0x4c 0x56 0x01
    g_array_append(array, MAGIC_TYPE_FLV);
    break;
  }

  switch (magic_tiny_fingerprint & 0xFFFFFFF0)
  {
  case 0x000001B0:             // 0x00 0x00 0x01 0xB0
    g_array_append(array, MAGIC_TYPE_MPEG);
    break;
  }

  switch (magic_tiny_fingerprint & 0xFFFFFF00)
  {
  case 0xffd8ff00:             // 0xff 0xd8 0xff
    g_array_append(array, MAGIC_TYPE_JPG);
    break;
  case 0x425A6800:             // BZh
    g_array_append(array, MAGIC_TYPE_BZIP2);
    break;
  }

  switch (magic_tiny_fingerprint & 0xFFFF0000)
  {
  case 0x1F8B0000:             // 0x1f 0x8b
    g_array_append(array, MAGIC_TYPE_GZIP);
    break;
  case 0x1F9D0000:             // 0x1f 0x9d
    g_array_append(array, MAGIC_TYPE_COMPRESS);
    break;
  case 0x68DE0000:             // 0x68 0xde
  case 0x48890000:             // 0x48 0x89
  case 0x78DA0000:             // 0x78 0xda
  case 0x789c0000:             // 0x78 0x9c
    g_array_append(array, MAGIC_TYPE_ZLIB);
    break;
  }

  switch (magic_tiny_fingerprint & 0xFFF00000)
  {
  case 0xFFE00000:             // 0xff 0xf?, or
  case 0xFFF00000:             // 0xff 0xe?
    g_array_append(array, MAGIC_TYPE_MP3);
    break;
  }

  // FAX?
  // JBIG?

  // Check if we have a BR/PT
  if (window_size >= 512)
  {
    if ((buffer[510] == 0x55) && (buffer[511] == 0xaa)) // High chance we have an BR block
    {
      g_array_append(array, MAGIC_TYPE_PART);
    }
  }
  // PDF files can be valid as long as %PDF appears in the 1st 1KB of the file
  int pdf_process_size = 1024;

  if (window_size < 1024)
  {
    pdf_process_size = window_size;
  }

  pdf_process_size -= 4;

  unsigned int offset = 0;

  while (offset < pdf_process_size)
  {
    unsigned char *ptr = (unsigned char *) memchr(buffer + offset, '%', pdf_process_size - offset);

    if (ptr == NULL)
    {
      break;
    }
    if (memcmp(ptr, "%PDF", 4) == 0)
    {
      g_array_append(array, MAGIC_TYPE_PDF);
      break;
    }
    offset += (ptr - buffer) + 1;
  }

  return array;
}

/**
 * A human readable description of the various data types.
 */
static const char *symbolic_names[] = {
  "Unknown",                    // 0
  "Text",                       // 1
  "Base 64",                    // 2
  "Base 85",                    // 3
  "ASCII coded HEX",            // 4
  "JPG",                        // 5
  "PNG",                        // 6
  "Gif",                        // 7
  "FAX",                        // 8
  "JBIG",                       // 9
  "Zip or OfficeX",             // 10
  "BZip",                       // 11
  "Gzip",                       // 12
  "Compress",                   // 13
  "ZLIB",                       // 14
  "PDF",                        // 15
  "OLE",                        // 16
  "MP3",                        // 17
  "AAC",                        // 18
  "Mpeg",                       // 19
  "H.264",                      // 20
  "AVI",                        // 21
  "WMV",                        // 22
  "FLV",                        // 23
  "FAT12",                      // 24
  "FAT16",                      // 25
  "FAT32",                      // 26
  "NTFS",                       // 27
  "EXT2/3/4",                   // 28
  "Unidentified",               // 29
  "Constant",                   // 30
  "Boot Record/Partition Table",        // 31
  "All"                         // 32
};

/**
 * A text representation of the flags used for file type specification.
 */
static const char *text_descriptive_names[] = {
  "MAGIC_UNKNOWN_TYPE",         // 0
  "MAGIC_TYPE_TEXT",            // 1
  "MAGIC_TYPE_BASE64",          // 2
  "MAGIC_TYPE_BASE85",          // 3
  "MAGIC_TYPE_HEX",             // 4

  // Pictures
  "MAGIC_TYPE_JPG",             // 5
  "MAGIC_TYPE_PNG",             // 6
  "MAGIC_TYPE_GIF",             // 7
  "MAGIC_TYPE_FAX",             // 8
  "MAGIC_TYPE_JBIG",            // 9

  // Compression types
  "MAGIC_TYPE_ZIP",             // 10
  "MAGIC_TYPE_BZIP2",           // 11
  "MAGIC_TYPE_GZIP",            // 12
  "MAGIC_TYPE_COMPRESS",        // 13
  "MAGIC_TYPE_ZLIB",            // 14

  // Document types
  "MAGIC_TYPE_PDF",             // 15
  "MAGIC_TYPE_OLE",             // 16

  // Movie/music types
  "MAGIC_TYPE_MP3",             // 17
  "MAGIC_TYPE_AAC",             // 18
  "MAGIC_TYPE_MPEG",            // 19
  "MAGIC_TYPE_H264",            // 20
  "MAGIC_TYPE_AVI",             // 21
  "MAGIC_TYPE_WMV",             // 22
  "MAGIC_TYPE_FLV",             // 23

  // Filesystem types
  "MAGIC_TYPE_FAT12",           // 24
  "MAGIC_TYPE_FAT16",           // 25
  "MAGIC_TYPE_FAT32",           // 26
  "MAGIC_TYPE_NTFS",            // 27
  "MAGIC_TYPE_EXT",             // 28

  // Other types
  "MAGIC_TYPE_UNIDENTIFIED",    // 29
  "MAGIC_TYPE_CONSTANT",        // 30

  // Partitions - Added
  "MAGIC_TYPE_PART",            // 31

  // Special type ALL
  "MAGIC_TYPE_ALL"              // 32
};

/**
 * An internal helper function to lookup an entry in a table.
 *
 * \param code The type code to lookup
 * \param table_to_use The table to use
 * \returns The element in the table.
 */
static const char *__lightmagic_lookup_name(unsigned int code, const char **table_to_use)
{
  switch (code)
  {
  case MAGIC_TYPE_TEXT:
    return table_to_use[1];
  case MAGIC_TYPE_BASE64:
    return table_to_use[2];
  case MAGIC_TYPE_BASE85:
    return table_to_use[3];
  case MAGIC_TYPE_HEX:
    return table_to_use[4];
  case MAGIC_TYPE_JPG:
    return table_to_use[5];
  case MAGIC_TYPE_PNG:
    return table_to_use[6];
  case MAGIC_TYPE_GIF:
    return table_to_use[7];
  case MAGIC_TYPE_FAX:
    return table_to_use[8];
  case MAGIC_TYPE_JBIG:
    return table_to_use[9];
  case MAGIC_TYPE_ZIP:         // Also MSOfficeX
    return table_to_use[10];
  case MAGIC_TYPE_BZIP2:
    return table_to_use[11];
  case MAGIC_TYPE_GZIP:
    return table_to_use[12];
  case MAGIC_TYPE_COMPRESS:
    return table_to_use[13];
  case MAGIC_TYPE_ZLIB:
    return table_to_use[14];
  case MAGIC_TYPE_PDF:
    return table_to_use[15];
  case MAGIC_TYPE_OLE:
    return table_to_use[16];
  case MAGIC_TYPE_MP3:
    return table_to_use[17];
  case MAGIC_TYPE_AAC:
    return table_to_use[18];
  case MAGIC_TYPE_MPEG:
    return table_to_use[19];
  case MAGIC_TYPE_H264:
    return table_to_use[20];
  case MAGIC_TYPE_AVI:
    return table_to_use[21];
  case MAGIC_TYPE_WMV:
    return table_to_use[22];
  case MAGIC_TYPE_FLV:
    return table_to_use[23];
  case MAGIC_TYPE_FAT12:
    return table_to_use[24];
  case MAGIC_TYPE_FAT16:
    return table_to_use[25];
  case MAGIC_TYPE_FAT32:
    return table_to_use[26];
  case MAGIC_TYPE_NTFS:
    return table_to_use[27];
  case MAGIC_TYPE_EXT:
    return table_to_use[28];
  case MAGIC_TYPE_UNIDENTIFIED:
    return table_to_use[29];
  case MAGIC_TYPE_CONSTANT:
    return table_to_use[30];
  case MAGIC_TYPE_PART:
    return table_to_use[31];
  }

  return table_to_use[0];
}

const char *lightmagic_human_friendly_descriptive_name(unsigned int code)
{
  return __lightmagic_lookup_name(code, symbolic_names);
}

const char *lightmagic_text_representation(unsigned int code)
{
  return __lightmagic_lookup_name(code, text_descriptive_names);
}

unsigned int lightmagic_int_value(const char *text_representation)
{
  if (!strcasecmp(text_representation, "MAGIC_TYPE_TEXT"))
    return MAGIC_TYPE_TEXT;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_BASE64"))
    return MAGIC_TYPE_BASE64;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_BASE85"))
    return MAGIC_TYPE_BASE85;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_HEX"))
    return MAGIC_TYPE_HEX;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_JPG"))
    return MAGIC_TYPE_JPG;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_PNG"))
    return MAGIC_TYPE_PNG;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_GIF"))
    return MAGIC_TYPE_GIF;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_FAX"))
    return MAGIC_TYPE_FAX;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_JBIG"))
    return MAGIC_TYPE_JBIG;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_ZIP"))
    return MAGIC_TYPE_ZIP;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_BZIP2"))
    return MAGIC_TYPE_BZIP2;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_GZIP"))
    return MAGIC_TYPE_GZIP;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_COMPRESS"))
    return MAGIC_TYPE_COMPRESS;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_ZLIB"))
    return MAGIC_TYPE_ZLIB;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_PDF"))
    return MAGIC_TYPE_PDF;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_OLE"))
    return MAGIC_TYPE_OLE;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_MSOFFICEX"))
    return MAGIC_TYPE_ZIP;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_MP3"))
    return MAGIC_TYPE_MP3;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_AAC"))
    return MAGIC_TYPE_AAC;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_MPEG"))
    return MAGIC_TYPE_MPEG;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_H264"))
    return MAGIC_TYPE_H264;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_AVI"))
    return MAGIC_TYPE_AVI;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_WMV"))
    return MAGIC_TYPE_WMV;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_FLV"))
    return MAGIC_TYPE_FLV;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_FAT12"))
    return MAGIC_TYPE_FAT12;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_FAT16"))
    return MAGIC_TYPE_FAT16;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_FAT32"))
    return MAGIC_TYPE_FAT32;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_NTFS"))
    return MAGIC_TYPE_NTFS;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_EXT"))
    return MAGIC_TYPE_EXT;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_UNIDENTIFIED"))
    return MAGIC_TYPE_UNIDENTIFIED;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_CONSTANT"))
    return MAGIC_TYPE_CONSTANT;
  if (!strcasecmp(text_representation, "MAGIC_TYPE_PART"))
    return MAGIC_TYPE_PART;
  return -1;
}
