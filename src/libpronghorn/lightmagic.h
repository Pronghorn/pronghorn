/* Pronghorn Lightmagic Header
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
 * \file lightmagic.h
 * \brief Lightmagic header file
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
 * - compress - 0x1f 0x8d\n
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
 * - encrypted, random - everything else?\n
 * 
 * - Useful references:\n
 * - http://www.garykessler.net/library/file_sigs.html\n
 * - http://en.wikipedia.org/wiki/List_of_file_signatures\n
 */

#ifndef LIGHTMAGIC_H
#define LIGHTMAGIC_H

#include <stdio.h>
#include <glib.h>

/**
 * \defgroup LightMagicDefines Hash defines for lightmagic types
 *
 * Types that may be returned are listed below. If you add or remove 
 * one, be sure to update the two functions that translate name to 
 * int and vice versa.
 * \{
 */

/** Text types, such as txt, csv, log, html, xml, css, js, json, base64, base85, hex */
#define MAGIC_TYPE_TEXT 0x01
/** BASE64 type, should always exist with MAGIC_TYPE_TEXT also declared */
#define MAGIC_TYPE_BASE64 0x02
/** BASE85 type, should always exist with MAGIC_TYPE_TEXT also declared */
#define MAGIC_TYPE_BASE85 0x03
/** Hex type, should always exist with MAGIC_TYPE_TEXT also declared */
#define MAGIC_TYPE_HEX 0x04

/** Jpeg picture format type */
#define MAGIC_TYPE_JPG 0x10
/** PNG picture format type */
#define MAGIC_TYPE_PNG 0x11
/** GIF picture format type */
#define MAGIC_TYPE_GIF 0x12
/** FAX (?) picture format type */
#define MAGIC_TYPE_FAX 0x13
/** JBIG picture format type */
#define MAGIC_TYPE_JBIG 0x14

/** ZIP compression format type */
#define MAGIC_TYPE_ZIP 0x20
/** BZIP2 compression format type */
#define MAGIC_TYPE_BZIP2 0x21
/** GZIP compression format type */
#define MAGIC_TYPE_GZIP 0x22
/** COMPRESS compression format type */
#define MAGIC_TYPE_COMPRESS 0x23
/** ZLIB compression format type */
#define MAGIC_TYPE_ZLIB 0x24

/** PDF document type */
#define MAGIC_TYPE_PDF 0x30
/** OLE (old MS office) document type */
#define MAGIC_TYPE_OLE 0x31
/** New MS Office document type (also resolves to MAGIC_TYPE_ZIP) */
#define MAGIC_TYPE_MSOFFICEX MAGIC_TYPE_ZIP

/** MP3 media type */
#define MAGIC_TYPE_MP3 0x40
/** AAC media type */
#define MAGIC_TYPE_AAC 0x41
/** MPEG media type */
#define MAGIC_TYPE_MPEG 0x42
/** H.264 media type */
#define MAGIC_TYPE_H264 0x43
/** AVI media type */
#define MAGIC_TYPE_AVI 0x44
/** WMV media type */
#define MAGIC_TYPE_WMV 0x45
/** FLV media type */
#define MAGIC_TYPE_FLV 0x46

/** FAT12 filesystem type */
#define MAGIC_TYPE_FAT12 0x50
/** FAT16 filesystem type */
#define MAGIC_TYPE_FAT16 0x51
/** FAT32 filesystem type */
#define MAGIC_TYPE_FAT32 0x52
/** NTFS filesystem type */
#define MAGIC_TYPE_NTFS 0x53
/** EXT2/3/4 filesystem type */
#define MAGIC_TYPE_EXT 0x54
/** Partition Table*/
#define MAGIC_TYPE_PART 0x55

/** Unidentified type. */
#define MAGIC_TYPE_UNIDENTIFIED 0x60
/** Constant types, including 16bit constants */
#define MAGIC_TYPE_CONSTANT 0x61

/** ALL type, special case for brute forcing all blocks **/
#define MAGIC_TYPE_ALL 0xFF

/**\}*/

/**
 * This is meant to be a light and fast magic examination.
 *
 * We are only testing the minimal amount necessary to have a high accuracy.
 * We are not seeking perfect accuracy, and we err on the side of caution by
 * including types if they partially match.
 *
 * TODO: JBIG\n
 * TODO: FAX\n
 * TODO: EXE?\n
 *
 * \warning It's the caller's job to g_array_free the return value
 *
 * \param buffer The buffer to perform a magic determination on
 * \param buffer_size The size of the buffer to scan
 * \param window_size The maximum size lightmagic can read if it desires to do so
 * \return An array containing all of the possible matches, specified as an
 * integer. You can use the helper functions to translate these to text.
 *
 */
GArray *lightmagic_detect(const unsigned char *buffer, unsigned int buffer_size, unsigned int window_size) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Returns a human friendly descriptive name of the supplied type code.
 *
 * \param code The code to lookup.
 * \returns A human friendly descriptive name.
 */
const char *lightmagic_human_friendly_descriptive_name(unsigned int code) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Returns a text representation of the supplied type code.
 *
 * \param code The code to lookup.
 * \returns The text representation of that type code.
 */
const char *lightmagic_text_representation(unsigned int code) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Returns the type code for the supplied text representation.
 *
 * \param text_representation The text to convert into a type code.
 * \returns The data type code.
 */
const unsigned int lightmagic_int_value(const char *text_representation) G_GNUC_WARN_UNUSED_RESULT;

/**
 * A helper function as g_array_append_val is a macro that requires a
 * variable to exist as it takes the reference to it.
 *
 * \param array The GArray to append to.
 * \param val The value to append to it.
 */
void g_array_append(GArray * array, unsigned int val);

#endif
