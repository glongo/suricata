/* Copyright (C) 2015 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/** \file
 *
 * \author Giuseppe Longo <giuseppe@glongo.it>
 *
 *
 */

#ifndef __UTIL_FILE_DECOMPRESSION_H__
#define __UTIL_FILE_DECOMPRESSION_H__
enum {
    FILE_IS_NOT_SWF = 0,
    FILE_SWF_NO_COMPRESSION,
    FILE_SWF_ZLIB_COMPRESSION,
    FILE_SWF_LZMA_COMPRESSION,
};

enum {
    FILE_SWF_DECOMP_NOK = 0,
    FILE_SWF_DECOMP_OK,
};

int FileIsFlashFile(uint8_t *buffer, uint32_t buffer_len);
int FileDecompressSWF(uint8_t **buffer, uint32_t *buffer_len, int swf_type,
                      uint32_t decompress_depth, uint32_t compress_depth);

#endif /* __UTIL_FILE_DECOMPRESSION_H__ */
