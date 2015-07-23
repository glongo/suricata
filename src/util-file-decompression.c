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
 * \brief Handle HTTP response body match corresponding to http_server_body
 * keyword.
 *
 */

#include <zlib.h>
#include <lzma.h>

#include "suricata-common.h"
#include "suricata.h"

#include "app-layer-htp.h"

#include "util-file-decompression.h"
#include "util-misc.h"
#include "util-print.h"

#define SWF_ZLIB_MIN_VERSION    0x06
#define SWF_LZMA_MIN_VERSION    0x0D

int FileIsFlashFile(uint8_t *buffer, uint32_t buffer_len)
{
    if (buffer_len >= 3 && buffer[1] == 'W' && buffer[2] == 'S') {
        if (buffer[0] == 'F')
            return FILE_SWF_NO_COMPRESSION;
        else if (buffer[0] == 'C')
            return FILE_SWF_ZLIB_COMPRESSION;
        else if (buffer[0] == 'Z')
            return FILE_SWF_LZMA_COMPRESSION;
        else
            return FILE_IS_NOT_SWF;
    }

    return FILE_IS_NOT_SWF;
}

static uint32_t conversion(uint32_t value)
{
    return ((value >> 24) & 0x000000FF) | ((value >> 8) & 0x0000FF00) | ((value << 8) & 0x00FF0000) | ((value << 24) & 0xFF000000);
}

static uint32_t FileGetSwfDecompressedLen(uint8_t *buffer)
{
    int a = buffer[4];
    int b = buffer[5];
    int c = buffer[6];
    int d = buffer[7];

    return conversion(((a & 0xff) << 24) | ((b & 0xff) << 16) | ((c & 0xff) << 8) | (d & 0xff));
}

static uint8_t FileGetSwfVersion(uint8_t *buffer, uint32_t buffer_len)
{
    if (buffer_len >= 3)
        return buffer[3];

    return 0;
}

static uint8_t* FileDecompressZlibData(uint8_t *compressed_data, uint32_t compressed_data_len,
                                       uint8_t *decompressed_data, uint32_t decompressed_data_len)
{
    z_stream infstream;
    infstream.zalloc = Z_NULL;
    infstream.zfree = Z_NULL;
    infstream.opaque = Z_NULL;

    infstream.avail_in = (uInt)compressed_data_len;
    infstream.next_in = (Bytef *)compressed_data;
    infstream.avail_out = (uInt)decompressed_data_len;
    infstream.next_out = (Bytef *)decompressed_data;

    inflateInit(&infstream);
    int r = inflate(&infstream, Z_NO_FLUSH);
    switch(r) {
        case Z_DATA_ERROR:
            SCLogInfo("Z_DATA_ERROR");
            break;
        case Z_STREAM_ERROR:
            SCLogInfo("Z_STREAM_ERROR");
            break;
        case Z_BUF_ERROR:
            SCLogInfo("Z_BUF_ERROR");
            break;
        default:
            SCLogInfo("another error");
    }

    SCLogInfo("r %d", r);
    inflateEnd(&infstream);
    SCLogInfo("Decomprimo");
//    PrintRawDataFp(stdout, decompressed_data, decompressed_data_len);

    return 0;
}

static void FileCompressLzmaData(uint8_t *compressed_data, uint32_t compressed_data_len,
                                 uint8_t *decompressed_data, uint32_t decompressed_data_len)
{
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret ret = lzma_auto_decoder(&strm, UINT64_MAX, 0);
    if (ret != LZMA_OK) {
        SCLogInfo("exit 1");
        exit(EXIT_FAILURE);
    }

    strm.avail_in = compressed_data_len;
    strm.next_in = compressed_data;
    strm.avail_out = decompressed_data_len;
    strm.next_out = decompressed_data;

    ret = lzma_code(&strm, LZMA_FINISH);
    SCLogInfo("lzma ret %d", ret);
    switch(ret) {
    case LZMA_MEMLIMIT_ERROR:
        SCLogError(SC_ERR_SWF_DECOMPRESSION, "Memory allocation failed");
        break;
    case LZMA_OPTIONS_ERROR:
        SCLogError(SC_ERR_SWF_DECOMPRESSION, "Unsupported decompressor flags");
        break;
    case LZMA_FORMAT_ERROR:
        SCLogError(SC_ERR_SWF_DECOMPRESSION, "The input is an invalid format");
        break;
    case LZMA_DATA_ERROR:
        SCLogError(SC_ERR_SWF_DECOMPRESSION, "Compressed file is corrupt";
        break;
    case LZMA_BUF_ERROR:
        SCLogError(SC_ERR_SWF_DECOMPRESSION, "Compressed file is truncated or otherwise corrupt");
        break;
    case LZMA_OK:
    case LZMA_STREAM_END:
        break;
    default:
        SCLogError(SWF_ERR_SWF_DECOMPRESSION, "Unknown error, maybe a bug?");
        break;
    }
    
    lzma_end(&strm);
}

int FileDecompressSWF(uint8_t **buffer, uint32_t *buffer_len, int swf_type,
                      uint32_t decompress_depth, uint32_t compress_depth)
{
    uint8_t *buf = *buffer;
    uint32_t buf_len = *buffer_len;
    SCLogInfo("buffer_len %d", buf_len);
    PrintRawDataFp(stdout, buf, buf_len);
    exit(EXIT_FAILURE);
    int compression_type = FileIsFlashFile(buf, buf_len);
    if (compression_type == FILE_SWF_NO_COMPRESSION) {
        return 0;
    }
    uint32_t compressed_data_len = (compress_depth == 0) ? buf_len - 4 : compress_depth;
    uint8_t *compressed_data = SCMalloc(compressed_data_len);
    if (compressed_data == NULL) {
        SCLogInfo("can't allocate memory for compressed_data");
        exit(EXIT_FAILURE);
    }
    memcpy(compressed_data, buf + 4, compressed_data_len);

    uint32_t decompressed_swf_len = FileGetSwfDecompressedLen(buf);
    uint32_t decompressed_data_len = (decompress_depth == 0) ? decompressed_swf_len : decompress_depth;
    SCLogInfo("decompressed_data_len %d", decompressed_data_len);
    uint8_t *decompressed_data = SCMalloc(decompressed_data_len);

    if (decompressed_data == NULL) {
        SCLogInfo("can't allocate memory for decompressed_data");
        exit(EXIT_FAILURE);
    }
    uint8_t flash_version = FileGetSwfVersion(buf, buf_len);

    /* zlib decompression */
    SCLogInfo("swf_type %d", swf_type);
    SCLogInfo("compression_type %d", compression_type);
    if ((swf_type == HTTP_DECOMP_SWF_ZLIB || swf_type == HTTP_DECOMP_SWF_BOTH) &&
        compression_type == FILE_SWF_ZLIB_COMPRESSION)
    {
        SCLogInfo("zlib");
        if (flash_version < SWF_ZLIB_MIN_VERSION) {
            SCLogWarning(SC_ERR_SWF_INVALID_VERSION,
                        "ZLIB compression is supported for "
                        "flash version 6 and later only");
            return FILE_SWF_DECOMP_NOK;
        }    
        FileDecompressZlibData(compressed_data, compressed_data_len,
                               decompressed_data, decompressed_data_len);
    } else if ((swf_type == HTTP_DECOMP_SWF_LZMA || swf_type == HTTP_DECOMP_SWF_BOTH) &&
               compression_type == FILE_SWF_LZMA_COMPRESSION)
    {
        SCLogInfo("lzma");
        if (flash_version < SWF_LZMA_MIN_VERSION) {
            SCLogWarning(SC_ERR_SWF_INVALID_VERSION,
                         "LZMA compression is supported for "
                         "flash version 13 and later only");
            return FILE_SWF_DECOMP_NOK;
        }
        FileCompressLzmaData(compressed_data, compressed_data_len,
                             decompressed_data, decompressed_data_len);
    } else {
        SCLogInfo("goto out");
        goto out;
    }

    uint8_t *new_buffer = SCMalloc(decompressed_data_len + 8);
    if (new_buffer == NULL) {
        SCLogInfo("can't alloc memory for the buffer");
        exit(EXIT_FAILURE);
    }
    memcpy(new_buffer, "FWS", 3);
    memcpy(new_buffer + 3, &flash_version, 1);
    memcpy(new_buffer + 4, &decompressed_swf_len, 4);
    memcpy(new_buffer + 8, decompressed_data, decompressed_data_len);

    *buffer = new_buffer;
    *buffer_len = decompressed_data_len + 8;
        SCLogInfo("dopo FileDecompressSWF");
        SCLogInfo("buffer %p", buffer);
        SCLogInfo("-----buffer %d-----", *buffer_len);
        PrintRawDataFp(stdout, *buffer, *buffer_len);
        SCLogInfo("--------------------");
out:
    return FILE_SWF_DECOMP_OK;
}
