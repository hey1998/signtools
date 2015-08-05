#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <malloc.h>
#include <sys/stat.h>

#define MZ_MAX(a,b) (((a)>(b))?(a):(b))
#define MZ_MIN(a,b) (((a)<(b))?(a):(b))
#define MZ_CLEAR_OBJ(obj) memset(&(obj), 0, sizeof(obj))
#define MZ_ZIP_ARRAY_SET_ELEMENT_SIZE(array_ptr, element_size) (array_ptr)->m_element_size = element_size
#define MZ_ZIP_ARRAY_ELEMENT(array_ptr, element_type, index) ((element_type *)((array_ptr)->m_p))[index]
#define MZ_SWAP_UINT32(a, b) do { mz_uint32 t = a; a = b; b = t; } while (0)
#define MZ_CRC32_INIT (0)
#define MZ_DEFLATED 8

typedef int mz_bool;
typedef unsigned char mz_uint8;
typedef signed short mz_int16;
typedef unsigned short mz_uint16;
typedef unsigned int mz_uint32;
typedef unsigned int mz_uint;
#if defined(_MSC_VER)
typedef __int64 mz_int64;
typedef unsigned __int64 mz_uint64;
#define fseeko64 _fseeki64
#define ftello64 _ftelli64
#else
typedef long long mz_int64;
typedef unsigned long long mz_uint64;
#endif
#define MZ_FALSE (0)
#define MZ_TRUE (1)

#define MZ_READ_LE16(p) ((mz_uint32)(((const mz_uint8 *)(p))[0]) | ((mz_uint32)(((const mz_uint8 *)(p))[1]) << 8U))
#define MZ_READ_LE32(p) ((mz_uint32)(((const mz_uint8 *)(p))[0]) | ((mz_uint32)(((const mz_uint8 *)(p))[1]) << 8U) | ((mz_uint32)(((const mz_uint8 *)(p))[2]) << 16U) | ((mz_uint32)(((const mz_uint8 *)(p))[3]) << 24U))

static void mz_write_le16(mz_uint8 * p, mz_uint16 v)
{
  p[0] = (mz_uint8) v;
  p[1] = (mz_uint8) (v >> 8);
}
static void mz_write_le32(mz_uint8 * p, mz_uint32 v)
{
  p[0] = (mz_uint8) v;
  p[1] = (mz_uint8) (v >> 8);
  p[2] = (mz_uint8) (v >> 16);
  p[3] = (mz_uint8) (v >> 24);
}
#define MZ_WRITE_LE16(p, v) mz_write_le16((mz_uint8 *)(p), (mz_uint16)(v))
#define MZ_WRITE_LE32(p, v) mz_write_le32((mz_uint8 *)(p), (mz_uint32)(v))

enum { MZ_NO_COMPRESSION = 0, MZ_BEST_SPEED = 1, MZ_BEST_COMPRESSION = 9, MZ_UBER_COMPRESSION = 10, MZ_DEFAULT_LEVEL = 6 };

typedef enum {
  MZ_ZIP_MODE_INVALID = 0,
  MZ_ZIP_MODE_READING = 1,
  MZ_ZIP_MODE_WRITING = 2,
  MZ_ZIP_MODE_WRITING_HAS_BEEN_FINALIZED = 3
} mz_zip_mode;

typedef struct {
  void *m_p;
  size_t m_size, m_capacity;
  mz_uint m_element_size;
} mz_zip_array;

struct mz_zip_internal_state_tag {
  mz_zip_array m_central_dir;
  mz_zip_array m_central_dir_offsets;
  mz_zip_array m_sorted_central_dir_offsets;
  FILE *m_pFile;
  void *m_pMem;
  size_t m_mem_size;
  size_t m_mem_capacity;
};
typedef struct mz_zip_internal_state_tag mz_zip_internal_state;

enum {
  MZ_ZIP_MAX_IO_BUF_SIZE = 64 * 1024,
  MZ_ZIP_MAX_ARCHIVE_FILENAME_SIZE = 260,
  MZ_ZIP_MAX_ARCHIVE_FILE_COMMENT_SIZE = 256
};

typedef struct {
  mz_uint32 m_file_index;
  mz_uint32 m_central_dir_ofs;
  mz_uint16 m_version_made_by;
  mz_uint16 m_version_needed;
  mz_uint16 m_bit_flag;
  mz_uint16 m_method;
  mz_uint32 m_crc32;
  mz_uint64 m_comp_size;
  mz_uint64 m_uncomp_size;
  mz_uint16 m_internal_attr;
  mz_uint32 m_external_attr;
  mz_uint64 m_local_header_ofs;
  mz_uint32 m_comment_size;
  char m_filename[MZ_ZIP_MAX_ARCHIVE_FILENAME_SIZE];
  char m_comment[MZ_ZIP_MAX_ARCHIVE_FILE_COMMENT_SIZE];
} mz_zip_archive_file_stat;

typedef size_t(*mz_file_read_func) (void *pOpaque, mz_uint64 file_ofs, void *pBuf, size_t n);
typedef size_t(*mz_file_write_func) (void *pOpaque, mz_uint64 file_ofs, const void *pBuf, size_t n);

typedef struct {
  mz_uint64 m_archive_size;
  mz_uint64 m_central_directory_file_ofs;
  mz_uint m_total_files;
  mz_zip_mode m_zip_mode;

  mz_uint m_file_offset_alignment;

  mz_file_read_func m_pRead;
  mz_file_write_func m_pWrite;
  void *m_pIO_opaque;

  mz_zip_internal_state *m_pState;

} mz_zip_archive;

typedef struct {
  mz_zip_archive *m_pZip;
  mz_uint64 m_cur_archive_file_ofs;
  mz_uint64 m_comp_size;
} mz_zip_writer_add_state;

enum {
  // ZIP archive identifiers and record sizes
  MZ_ZIP_END_OF_CENTRAL_DIR_HEADER_SIG = 0x06054b50, MZ_ZIP_CENTRAL_DIR_HEADER_SIG = 0x02014b50, MZ_ZIP_LOCAL_DIR_HEADER_SIG = 0x04034b50,
  MZ_ZIP_LOCAL_DIR_HEADER_SIZE = 30, MZ_ZIP_CENTRAL_DIR_HEADER_SIZE = 46, MZ_ZIP_END_OF_CENTRAL_DIR_HEADER_SIZE = 22,
  // Central directory header record offsets
  MZ_ZIP_CDH_SIG_OFS = 0, MZ_ZIP_CDH_VERSION_MADE_BY_OFS = 4, MZ_ZIP_CDH_VERSION_NEEDED_OFS = 6, MZ_ZIP_CDH_BIT_FLAG_OFS = 8,
  MZ_ZIP_CDH_METHOD_OFS = 10, MZ_ZIP_CDH_FILE_TIME_OFS = 12, MZ_ZIP_CDH_FILE_DATE_OFS = 14, MZ_ZIP_CDH_CRC32_OFS = 16,
  MZ_ZIP_CDH_COMPRESSED_SIZE_OFS = 20, MZ_ZIP_CDH_DECOMPRESSED_SIZE_OFS = 24, MZ_ZIP_CDH_FILENAME_LEN_OFS = 28, MZ_ZIP_CDH_EXTRA_LEN_OFS = 30,
  MZ_ZIP_CDH_COMMENT_LEN_OFS = 32, MZ_ZIP_CDH_DISK_START_OFS = 34, MZ_ZIP_CDH_INTERNAL_ATTR_OFS = 36, MZ_ZIP_CDH_EXTERNAL_ATTR_OFS = 38, MZ_ZIP_CDH_LOCAL_HEADER_OFS = 42,
  // Local directory header offsets
  MZ_ZIP_LDH_SIG_OFS = 0, MZ_ZIP_LDH_VERSION_NEEDED_OFS = 4, MZ_ZIP_LDH_BIT_FLAG_OFS = 6, MZ_ZIP_LDH_METHOD_OFS = 8, MZ_ZIP_LDH_FILE_TIME_OFS = 10,
  MZ_ZIP_LDH_FILE_DATE_OFS = 12, MZ_ZIP_LDH_CRC32_OFS = 14, MZ_ZIP_LDH_COMPRESSED_SIZE_OFS = 18, MZ_ZIP_LDH_DECOMPRESSED_SIZE_OFS = 22,
  MZ_ZIP_LDH_FILENAME_LEN_OFS = 26, MZ_ZIP_LDH_EXTRA_LEN_OFS = 28,
  // End of central directory offsets
  MZ_ZIP_ECDH_SIG_OFS = 0, MZ_ZIP_ECDH_NUM_THIS_DISK_OFS = 4, MZ_ZIP_ECDH_NUM_DISK_CDIR_OFS = 6, MZ_ZIP_ECDH_CDIR_NUM_ENTRIES_ON_DISK_OFS = 8,
  MZ_ZIP_ECDH_CDIR_TOTAL_ENTRIES_OFS = 10, MZ_ZIP_ECDH_CDIR_SIZE_OFS = 12, MZ_ZIP_ECDH_CDIR_OFS_OFS = 16, MZ_ZIP_ECDH_COMMENT_SIZE_OFS = 20,
};

typedef enum {
  TINFL_STATUS_FAILED = -1,
  TINFL_STATUS_DONE = 0,
  TINFL_STATUS_NEEDS_MORE_INPUT = 1,
  TINFL_STATUS_HAS_MORE_OUTPUT = 2
} tinfl_status;

enum {
  TINFL_MAX_HUFF_TABLES = 3, TINFL_MAX_HUFF_SYMBOLS_0 = 288, TINFL_MAX_HUFF_SYMBOLS_1 = 32, TINFL_MAX_HUFF_SYMBOLS_2 = 19,
  TINFL_FAST_LOOKUP_BITS = 10, TINFL_FAST_LOOKUP_SIZE = 1 << TINFL_FAST_LOOKUP_BITS
};

typedef struct {
  mz_uint8 m_code_size[TINFL_MAX_HUFF_SYMBOLS_0];
  mz_int16 m_look_up[TINFL_FAST_LOOKUP_SIZE], m_tree[TINFL_MAX_HUFF_SYMBOLS_0 * 2];
} tinfl_huff_table;

typedef mz_uint32 tinfl_bit_buf_t;

struct tinfl_decompressor_tag {
  mz_uint32 m_state, m_num_bits, m_final, m_type, m_dist, m_counter, m_num_extra, m_table_sizes[TINFL_MAX_HUFF_TABLES];
  tinfl_bit_buf_t m_bit_buf;
  size_t m_dist_from_out_buf_start;
  tinfl_huff_table m_tables[TINFL_MAX_HUFF_TABLES];
  mz_uint8 m_raw_header[4], m_len_codes[TINFL_MAX_HUFF_SYMBOLS_0 + TINFL_MAX_HUFF_SYMBOLS_1 + 137];
};
typedef struct tinfl_decompressor_tag tinfl_decompressor;

enum { TDEFL_HUFFMAN_ONLY = 0, TDEFL_DEFAULT_MAX_PROBES = 128, TDEFL_MAX_PROBES_MASK = 0xFFF };
enum { TDEFL_MAX_HUFF_TABLES = 3, TDEFL_MAX_HUFF_SYMBOLS_0 = 288, TDEFL_MAX_HUFF_SYMBOLS_1 = 32, TDEFL_MAX_HUFF_SYMBOLS_2 = 19, TDEFL_LZ_DICT_SIZE = 32768, TDEFL_LZ_DICT_SIZE_MASK = TDEFL_LZ_DICT_SIZE - 1, TDEFL_MIN_MATCH_LEN = 3, TDEFL_MAX_MATCH_LEN = 258 };
enum { TDEFL_LZ_CODE_BUF_SIZE = 24 * 1024, TDEFL_OUT_BUF_SIZE = (TDEFL_LZ_CODE_BUF_SIZE * 13) / 10, TDEFL_MAX_HUFF_SYMBOLS = 288, TDEFL_LZ_HASH_BITS = 12, TDEFL_LEVEL1_HASH_SIZE_MASK = 4095, TDEFL_LZ_HASH_SHIFT = (TDEFL_LZ_HASH_BITS + 2) / 3, TDEFL_LZ_HASH_SIZE = 1 << TDEFL_LZ_HASH_BITS };

typedef enum {
  TDEFL_STATUS_BAD_PARAM = -2,
  TDEFL_STATUS_PUT_BUF_FAILED = -1,
  TDEFL_STATUS_OKAY = 0,
  TDEFL_STATUS_DONE = 1,
} tdefl_status;

typedef enum {
  TDEFL_NO_FLUSH = 0,
  TDEFL_SYNC_FLUSH = 2,
  TDEFL_FULL_FLUSH = 3,
  TDEFL_FINISH = 4
} tdefl_flush;

typedef mz_bool(*tdefl_put_buf_func_ptr) (const void *pBuf, int len, void *pUser);

typedef struct {
  tdefl_put_buf_func_ptr m_pPut_buf_func;
  void *m_pPut_buf_user;
  mz_uint m_max_probes[2];
  mz_uint m_adler32, m_lookahead_pos, m_lookahead_size, m_dict_size;
  mz_uint8 *m_pLZ_code_buf, *m_pLZ_flags, *m_pOutput_buf, *m_pOutput_buf_end;
  mz_uint m_num_flags_left, m_total_lz_bytes, m_lz_code_buf_dict_pos, m_bits_in, m_bit_buffer;
  mz_uint m_saved_match_dist, m_saved_match_len, m_saved_lit, m_output_flush_ofs, m_output_flush_remaining, m_finished, m_block_index;
  tdefl_status m_prev_return_status;
  const void *m_pIn_buf;
  void *m_pOut_buf;
  size_t *m_pIn_buf_size, *m_pOut_buf_size;
  tdefl_flush m_flush;
  const mz_uint8 *m_pSrc;
  size_t m_src_buf_left, m_out_buf_ofs;
  mz_uint8 m_dict[TDEFL_LZ_DICT_SIZE + TDEFL_MAX_MATCH_LEN - 1];
  mz_uint16 m_huff_count[TDEFL_MAX_HUFF_TABLES][TDEFL_MAX_HUFF_SYMBOLS];
  mz_uint16 m_huff_codes[TDEFL_MAX_HUFF_TABLES][TDEFL_MAX_HUFF_SYMBOLS];
  mz_uint8 m_huff_code_sizes[TDEFL_MAX_HUFF_TABLES][TDEFL_MAX_HUFF_SYMBOLS];
  mz_uint8 m_lz_code_buf[TDEFL_LZ_CODE_BUF_SIZE];
  mz_uint16 m_next[TDEFL_LZ_DICT_SIZE];
  mz_uint16 m_hash[TDEFL_LZ_HASH_SIZE];
  mz_uint8 m_output_buf[TDEFL_OUT_BUF_SIZE];
} tdefl_compressor;

static const mz_uint s_tdefl_num_probes[11] = { 0, 1, 6, 16, 32, 64, 128, 256, 512, 768, 1500 };

unsigned long mz_crc32(unsigned long crc, const mz_uint8 * ptr, size_t buf_len)
{
  static const mz_uint32 s_crc32[16] = { 0, 0x1db71064, 0x3b6e20c8, 0x26d930ac, 0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
    0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c, 0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c
  };
  mz_uint32 crcu32 = (mz_uint32) crc;
  if (!ptr)
    return MZ_CRC32_INIT;
  crcu32 = ~crcu32;
  while (buf_len--) {
    mz_uint8 b = *ptr++;
    crcu32 = (crcu32 >> 4) ^ s_crc32[(crcu32 & 0xF) ^ (b & 0xF)];
    crcu32 = (crcu32 >> 4) ^ s_crc32[(crcu32 & 0xF) ^ (b >> 4)];
  }
  return ~crcu32;
}

#define TINFL_CR_BEGIN switch(r->m_state) { case 0:
#define TINFL_CR_RETURN(state_index, result) do { status = result; r->m_state = state_index; goto common_exit; case state_index:; } while (0)
#define TINFL_CR_RETURN_FOREVER(state_index, result) do { for ( ; ; ) { TINFL_CR_RETURN(state_index, result); } } while (0)
#define TINFL_CR_FINISH }

#define TINFL_GET_BYTE(state_index, c) do { \
  if (pIn_buf_cur >= pIn_buf_end) { \
    for ( ; ; ) { \
      if (comp_remaining) { \
        TINFL_CR_RETURN(state_index, TINFL_STATUS_NEEDS_MORE_INPUT); \
        if (pIn_buf_cur < pIn_buf_end) { \
          c = *pIn_buf_cur++; \
          break; \
        } \
      } else { \
        c = 0; \
        break; \
      } \
    } \
  } else c = *pIn_buf_cur++; } while (0)

#define TINFL_NEED_BITS(state_index, n) do { mz_uint c; TINFL_GET_BYTE(state_index, c); bit_buf |= (((tinfl_bit_buf_t)c) << num_bits); num_bits += 8; } while (num_bits < (mz_uint)(n))
#define TINFL_SKIP_BITS(state_index, n) do { if (num_bits < (mz_uint)(n)) { TINFL_NEED_BITS(state_index, n); } bit_buf >>= (n); num_bits -= (n); } while (0)
#define TINFL_GET_BITS(state_index, b, n) do { if (num_bits < (mz_uint)(n)) { TINFL_NEED_BITS(state_index, n); } b = bit_buf & ((1 << (n)) - 1); bit_buf >>= (n); num_bits -= (n); } while (0)

#define TINFL_HUFF_BITBUF_FILL(state_index, pHuff) \
  do { \
    temp = (pHuff)->m_look_up[bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)]; \
    if (temp >= 0) { \
      code_len = temp >> 9; \
      if ((code_len) && (num_bits >= code_len)) \
      break; \
    } else if (num_bits > TINFL_FAST_LOOKUP_BITS) { \
       code_len = TINFL_FAST_LOOKUP_BITS; \
       do { \
          temp = (pHuff)->m_tree[~temp + ((bit_buf >> code_len++) & 1)]; \
       } while ((temp < 0) && (num_bits >= (code_len + 1))); if (temp >= 0) break; \
    } TINFL_GET_BYTE(state_index, c); bit_buf |= (((tinfl_bit_buf_t)c) << num_bits); num_bits += 8; \
  } while (num_bits < 15);

#define TINFL_HUFF_DECODE(state_index, sym, pHuff) do { \
  int temp; mz_uint code_len, c; \
  if (num_bits < 15) { \
    if ((pIn_buf_end - pIn_buf_cur) < 2) { \
       TINFL_HUFF_BITBUF_FILL(state_index, pHuff); \
    } else { \
       bit_buf |= (((tinfl_bit_buf_t)pIn_buf_cur[0]) << num_bits) | (((tinfl_bit_buf_t)pIn_buf_cur[1]) << (num_bits + 8)); pIn_buf_cur += 2; num_bits += 16; \
    } \
  } \
  if ((temp = (pHuff)->m_look_up[bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)]) >= 0) \
    code_len = temp >> 9, temp &= 511; \
  else { \
    code_len = TINFL_FAST_LOOKUP_BITS; do { temp = (pHuff)->m_tree[~temp + ((bit_buf >> code_len++) & 1)]; } while (temp < 0); \
  } sym = temp; bit_buf >>= code_len; num_bits -= code_len; } while (0)

static tinfl_status tinfl_decompress(tinfl_decompressor * r, const mz_uint8 * pIn_buf_next, size_t * pIn_buf_size, mz_uint8 * pOut_buf_start, mz_uint8 * pOut_buf_next, size_t * pOut_buf_size, const mz_uint comp_remaining)
{
  static const int s_length_base[31] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0, 0 };
  static const int s_length_extra[31] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, 0, 0 };
  static const int s_dist_base[32] = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 0, 0 };
  static const int s_dist_extra[32] = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };
  static const mz_uint8 s_length_dezigzag[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
  static const int s_min_table_sizes[3] = { 257, 1, 4 };

  tinfl_status status = TINFL_STATUS_FAILED;
  mz_uint32 num_bits, dist, counter, num_extra;
  tinfl_bit_buf_t bit_buf;
  const mz_uint8 *pIn_buf_cur = pIn_buf_next, *const pIn_buf_end = pIn_buf_next + *pIn_buf_size;
  mz_uint8 *pOut_buf_cur = pOut_buf_next, *const pOut_buf_end = pOut_buf_next + *pOut_buf_size;
  size_t out_buf_size_mask = -1, dist_from_out_buf_start;

  // Ensure the output buffer's size is a power of 2, unless the output buffer is large enough to hold the entire output file (in which case it doesn't matter).
  if (((out_buf_size_mask + 1) & out_buf_size_mask) || (pOut_buf_next < pOut_buf_start)) {
    *pIn_buf_size = *pOut_buf_size = 0;
    return TINFL_STATUS_FAILED;
  }

  num_bits = r->m_num_bits;
  bit_buf = r->m_bit_buf;
  dist = r->m_dist;
  counter = r->m_counter;
  num_extra = r->m_num_extra;
  dist_from_out_buf_start = r->m_dist_from_out_buf_start;
  TINFL_CR_BEGIN bit_buf = num_bits = dist = counter = num_extra = 0;

  do {
    TINFL_GET_BITS(3, r->m_final, 3);
    r->m_type = r->m_final >> 1;
    if (r->m_type == 0) {
      TINFL_SKIP_BITS(5, num_bits & 7);
      for (counter = 0; counter < 4; ++counter) {
        if (num_bits)
          TINFL_GET_BITS(6, r->m_raw_header[counter], 8);
        else
          TINFL_GET_BYTE(7, r->m_raw_header[counter]);
      }
      if ((counter = (r->m_raw_header[0] | (r->m_raw_header[1] << 8))) != (mz_uint) (0xFFFF ^ (r->m_raw_header[2] | (r->m_raw_header[3] << 8)))) {
        TINFL_CR_RETURN_FOREVER(39, TINFL_STATUS_FAILED);
      }
      while ((counter) && (num_bits)) {
        TINFL_GET_BITS(51, dist, 8);
        while (pOut_buf_cur >= pOut_buf_end) {
          TINFL_CR_RETURN(52, TINFL_STATUS_HAS_MORE_OUTPUT);
        }
        *pOut_buf_cur++ = (mz_uint8) dist;
        counter--;
      }
      while (counter) {
        size_t n;
        while (pOut_buf_cur >= pOut_buf_end) {
          TINFL_CR_RETURN(9, TINFL_STATUS_HAS_MORE_OUTPUT);
        }
        while (pIn_buf_cur >= pIn_buf_end) {
          if (comp_remaining) {
            TINFL_CR_RETURN(38, TINFL_STATUS_NEEDS_MORE_INPUT);
          } else {
            TINFL_CR_RETURN_FOREVER(40, TINFL_STATUS_FAILED);
          }
        }
        n = MZ_MIN(MZ_MIN((size_t) (pOut_buf_end - pOut_buf_cur), (size_t) (pIn_buf_end - pIn_buf_cur)), counter);
        memcpy(pOut_buf_cur, pIn_buf_cur, n);
        pIn_buf_cur += n;
        pOut_buf_cur += n;
        counter -= (mz_uint) n;
      }
    } else if (r->m_type == 3) {
      TINFL_CR_RETURN_FOREVER(10, TINFL_STATUS_FAILED);
    } else {
      if (r->m_type == 1) {
        mz_uint8 *p = r->m_tables[0].m_code_size;
        mz_uint i;
        r->m_table_sizes[0] = 288;
        r->m_table_sizes[1] = 32;
        memset(r->m_tables[1].m_code_size, 5, 32);
        for (i = 0; i <= 143; ++i)
          *p++ = 8;
        for (; i <= 255; ++i)
          *p++ = 9;
        for (; i <= 279; ++i)
          *p++ = 7;
        for (; i <= 287; ++i)
          *p++ = 8;
      } else {
        for (counter = 0; counter < 3; counter++) {
          TINFL_GET_BITS(11, r->m_table_sizes[counter], "\05\05\04"[counter]);
          r->m_table_sizes[counter] += s_min_table_sizes[counter];
        }
        MZ_CLEAR_OBJ(r->m_tables[2].m_code_size);
        for (counter = 0; counter < r->m_table_sizes[2]; counter++) {
          mz_uint s;
          TINFL_GET_BITS(14, s, 3);
          r->m_tables[2].m_code_size[s_length_dezigzag[counter]] = (mz_uint8) s;
        }
        r->m_table_sizes[2] = 19;
      }
      for (; (int) r->m_type >= 0; r->m_type--) {
        int tree_next, tree_cur;
        tinfl_huff_table *pTable;
        mz_uint i, j, used_syms, total, sym_index, next_code[17], total_syms[16];
        pTable = &r->m_tables[r->m_type];
        MZ_CLEAR_OBJ(total_syms);
        MZ_CLEAR_OBJ(pTable->m_look_up);
        MZ_CLEAR_OBJ(pTable->m_tree);
        for (i = 0; i < r->m_table_sizes[r->m_type]; ++i)
          total_syms[pTable->m_code_size[i]]++;
        used_syms = 0, total = 0;
        next_code[0] = next_code[1] = 0;
        for (i = 1; i <= 15; ++i) {
          used_syms += total_syms[i];
          next_code[i + 1] = (total = ((total + total_syms[i]) << 1));
        }
        if ((65536 != total) && (used_syms > 1)) {
          TINFL_CR_RETURN_FOREVER(35, TINFL_STATUS_FAILED);
        }
        for (tree_next = -1, sym_index = 0; sym_index < r->m_table_sizes[r->m_type]; ++sym_index) {
          mz_uint rev_code = 0, l, cur_code, code_size = pTable->m_code_size[sym_index];
          if (!code_size)
            continue;
          cur_code = next_code[code_size]++;
          for (l = code_size; l > 0; l--, cur_code >>= 1)
            rev_code = (rev_code << 1) | (cur_code & 1);
          if (code_size <= TINFL_FAST_LOOKUP_BITS) {
            mz_int16 k = (mz_int16) ((code_size << 9) | sym_index);
            while (rev_code < TINFL_FAST_LOOKUP_SIZE) {
              pTable->m_look_up[rev_code] = k;
              rev_code += (1 << code_size);
            }
            continue;
          }
          if (0 == (tree_cur = pTable->m_look_up[rev_code & (TINFL_FAST_LOOKUP_SIZE - 1)])) {
            pTable->m_look_up[rev_code & (TINFL_FAST_LOOKUP_SIZE - 1)] = (mz_int16) tree_next;
            tree_cur = tree_next;
            tree_next -= 2;
          }
          rev_code >>= (TINFL_FAST_LOOKUP_BITS - 1);
          for (j = code_size; j > (TINFL_FAST_LOOKUP_BITS + 1); j--) {
            tree_cur -= ((rev_code >>= 1) & 1);
            if (!pTable->m_tree[-tree_cur - 1]) {
              pTable->m_tree[-tree_cur - 1] = (mz_int16) tree_next;
              tree_cur = tree_next;
              tree_next -= 2;
            } else
              tree_cur = pTable->m_tree[-tree_cur - 1];
          }
          tree_cur -= ((rev_code >>= 1) & 1);
          pTable->m_tree[-tree_cur - 1] = (mz_int16) sym_index;
        }
        if (r->m_type == 2) {
          for (counter = 0; counter < (r->m_table_sizes[0] + r->m_table_sizes[1]);) {
            mz_uint s;
            TINFL_HUFF_DECODE(16, dist, &r->m_tables[2]);
            if (dist < 16) {
              r->m_len_codes[counter++] = (mz_uint8) dist;
              continue;
            }
            if ((dist == 16) && (!counter)) {
              TINFL_CR_RETURN_FOREVER(17, TINFL_STATUS_FAILED);
            }
            num_extra = "\02\03\07"[dist - 16];
            TINFL_GET_BITS(18, s, num_extra);
            s += "\03\03\013"[dist - 16];
            memset(r->m_len_codes + counter, (dist == 16) ? r->m_len_codes[counter - 1] : 0, s);
            counter += s;
          }
          if ((r->m_table_sizes[0] + r->m_table_sizes[1]) != counter) {
            TINFL_CR_RETURN_FOREVER(21, TINFL_STATUS_FAILED);
          }
          memcpy(r->m_tables[0].m_code_size, r->m_len_codes, r->m_table_sizes[0]);
          memcpy(r->m_tables[1].m_code_size, r->m_len_codes + r->m_table_sizes[0], r->m_table_sizes[1]);
        }
      }
      for (;;) {
        mz_uint8 *pSrc;
        for (;;) {
          if (((pIn_buf_end - pIn_buf_cur) < 4) || ((pOut_buf_end - pOut_buf_cur) < 2)) {
            TINFL_HUFF_DECODE(23, counter, &r->m_tables[0]);
            if (counter >= 256)
              break;
            while (pOut_buf_cur >= pOut_buf_end) {
              TINFL_CR_RETURN(24, TINFL_STATUS_HAS_MORE_OUTPUT);
            }
            *pOut_buf_cur++ = (mz_uint8) counter;
          } else {
            int sym2;
            mz_uint code_len;
            if (num_bits < 15) {
              bit_buf |= (((tinfl_bit_buf_t) MZ_READ_LE16(pIn_buf_cur)) << num_bits);
              pIn_buf_cur += 2;
              num_bits += 16;
            }
            if ((sym2 = r->m_tables[0].m_look_up[bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)]) >= 0)
              code_len = sym2 >> 9;
            else {
              code_len = TINFL_FAST_LOOKUP_BITS;
              do {
                sym2 = r->m_tables[0].m_tree[~sym2 + ((bit_buf >> code_len++) & 1)];
              } while (sym2 < 0);
            }
            counter = sym2;
            bit_buf >>= code_len;
            num_bits -= code_len;
            if (counter & 256)
              break;

            if (num_bits < 15) {
              bit_buf |= (((tinfl_bit_buf_t) MZ_READ_LE16(pIn_buf_cur)) << num_bits);
              pIn_buf_cur += 2;
              num_bits += 16;
            }
            if ((sym2 = r->m_tables[0].m_look_up[bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)]) >= 0)
              code_len = sym2 >> 9;
            else {
              code_len = TINFL_FAST_LOOKUP_BITS;
              do {
                sym2 = r->m_tables[0].m_tree[~sym2 + ((bit_buf >> code_len++) & 1)];
              } while (sym2 < 0);
            }
            bit_buf >>= code_len;
            num_bits -= code_len;

            pOut_buf_cur[0] = (mz_uint8) counter;
            if (sym2 & 256) {
              pOut_buf_cur++;
              counter = sym2;
              break;
            }
            pOut_buf_cur[1] = (mz_uint8) sym2;
            pOut_buf_cur += 2;
          }
        }
        if ((counter &= 511) == 256)
          break;

        num_extra = s_length_extra[counter - 257];
        counter = s_length_base[counter - 257];
        if (num_extra) {
          mz_uint extra_bits;
          TINFL_GET_BITS(25, extra_bits, num_extra);
          counter += extra_bits;
        }

        TINFL_HUFF_DECODE(26, dist, &r->m_tables[1]);
        num_extra = s_dist_extra[dist];
        dist = s_dist_base[dist];
        if (num_extra) {
          mz_uint extra_bits;
          TINFL_GET_BITS(27, extra_bits, num_extra);
          dist += extra_bits;
        }

        dist_from_out_buf_start = pOut_buf_cur - pOut_buf_start;
        if (dist > dist_from_out_buf_start) {
          TINFL_CR_RETURN_FOREVER(37, TINFL_STATUS_FAILED);
        }

        pSrc = pOut_buf_start + ((dist_from_out_buf_start - dist) & out_buf_size_mask);

        if ((MZ_MAX(pOut_buf_cur, pSrc) + counter) > pOut_buf_end) {
          while (counter--) {
            while (pOut_buf_cur >= pOut_buf_end) {
              TINFL_CR_RETURN(53, TINFL_STATUS_HAS_MORE_OUTPUT);
            }
            *pOut_buf_cur++ = pOut_buf_start[(dist_from_out_buf_start++ - dist) & out_buf_size_mask];
          }
          continue;
        }
        do {
          pOut_buf_cur[0] = pSrc[0];
          pOut_buf_cur[1] = pSrc[1];
          pOut_buf_cur[2] = pSrc[2];
          pOut_buf_cur += 3;
          pSrc += 3;
        } while ((int) (counter -= 3) > 2);
        if ((int) counter > 0) {
          pOut_buf_cur[0] = pSrc[0];
          if ((int) counter > 1)
            pOut_buf_cur[1] = pSrc[1];
          pOut_buf_cur += counter;
        }
      }
    }
  } while (!(r->m_final & 1));
  TINFL_CR_RETURN_FOREVER(34, TINFL_STATUS_DONE);
TINFL_CR_FINISH common_exit:
  r->m_num_bits = num_bits;
  r->m_bit_buf = bit_buf;
  r->m_dist = dist;
  r->m_counter = counter;
  r->m_num_extra = num_extra;
  r->m_dist_from_out_buf_start = dist_from_out_buf_start;
  *pIn_buf_size = pIn_buf_cur - pIn_buf_next;
  *pOut_buf_size = pOut_buf_cur - pOut_buf_next;
  return status;
}

// Purposely making these tables static for faster init and thread safety.
static const mz_uint16 s_tdefl_len_sym[256] = {
  257, 258, 259, 260, 261, 262, 263, 264, 265, 265, 266, 266, 267, 267, 268, 268, 269, 269, 269, 269, 270, 270, 270, 270, 271, 271, 271, 271, 272, 272, 272, 272,
  273, 273, 273, 273, 273, 273, 273, 273, 274, 274, 274, 274, 274, 274, 274, 274, 275, 275, 275, 275, 275, 275, 275, 275, 276, 276, 276, 276, 276, 276, 276, 276,
  277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 277, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278,
  279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 279, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280, 280,
  281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281, 281,
  282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282, 282,
  283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283, 283,
  284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 284, 285
};

static const mz_uint8 s_tdefl_len_extra[256] = {
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
  4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 0
};

static const mz_uint8 s_tdefl_small_dist_sym[512] = {
  0, 1, 2, 3, 4, 4, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11,
  11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 13,
  13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
  14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
  14, 14, 14, 14, 14, 14, 14, 14, 14, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
  15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
  16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
  16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
  16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
  17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
  17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
  17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17
};

static const mz_uint8 s_tdefl_small_dist_extra[512] = {
  0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5,
  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
  6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
  6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7
};

static const mz_uint8 s_tdefl_large_dist_sym[128] = {
  0, 0, 18, 19, 20, 20, 21, 21, 22, 22, 22, 22, 23, 23, 23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 25, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
  26, 26, 26, 26, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
  28, 28, 28, 28, 28, 28, 28, 28, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29
};

static const mz_uint8 s_tdefl_large_dist_extra[128] = {
  0, 0, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
  12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
  13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13
};

// Radix sorts tdefl_sym_freq[] array by 16-bit key m_key. Returns ptr to sorted values.
typedef struct {
  mz_uint16 m_key, m_sym_index;
} tdefl_sym_freq;
static tdefl_sym_freq *tdefl_radix_sort_syms(mz_uint num_syms, tdefl_sym_freq * pSyms0, tdefl_sym_freq * pSyms1)
{
  mz_uint32 total_passes = 2, pass_shift, pass, i, hist[256 * 2];
  tdefl_sym_freq *pCur_syms = pSyms0, *pNew_syms = pSyms1;
  MZ_CLEAR_OBJ(hist);
  for (i = 0; i < num_syms; i++) {
    mz_uint freq = pSyms0[i].m_key;
    hist[freq & 0xFF]++;
    hist[256 + ((freq >> 8) & 0xFF)]++;
  }
  while ((total_passes > 1) && (num_syms == hist[(total_passes - 1) * 256]))
    total_passes--;
  for (pass_shift = 0, pass = 0; pass < total_passes; pass++, pass_shift += 8) {
    const mz_uint32 *pHist = &hist[pass << 8];
    mz_uint offsets[256], cur_ofs = 0;
    for (i = 0; i < 256; i++) {
      offsets[i] = cur_ofs;
      cur_ofs += pHist[i];
    }
    for (i = 0; i < num_syms; i++)
      pNew_syms[offsets[(pCur_syms[i].m_key >> pass_shift) & 0xFF]++] = pCur_syms[i];
    {
      tdefl_sym_freq *t = pCur_syms;
      pCur_syms = pNew_syms;
      pNew_syms = t;
    }
  }
  return pCur_syms;
}

// tdefl_calculate_minimum_redundancy() originally written by: Alistair Moffat, alistair@cs.mu.oz.au, Jyrki Katajainen, jyrki@diku.dk, November 1996.
static void tdefl_calculate_minimum_redundancy(tdefl_sym_freq * A, int n)
{
  int root, leaf, next, avbl, used, dpth;
  if (n == 0)
    return;
  else if (n == 1) {
    A[0].m_key = 1;
    return;
  }
  A[0].m_key += A[1].m_key;
  root = 0;
  leaf = 2;
  for (next = 1; next < n - 1; next++) {
    if (leaf >= n || A[root].m_key < A[leaf].m_key) {
      A[next].m_key = A[root].m_key;
      A[root++].m_key = (mz_uint16) next;
    } else
      A[next].m_key = A[leaf++].m_key;
    if (leaf >= n || (root < next && A[root].m_key < A[leaf].m_key)) {
      A[next].m_key = (mz_uint16) (A[next].m_key + A[root].m_key);
      A[root++].m_key = (mz_uint16) next;
    } else
      A[next].m_key = (mz_uint16) (A[next].m_key + A[leaf++].m_key);
  }
  A[n - 2].m_key = 0;
  for (next = n - 3; next >= 0; next--)
    A[next].m_key = A[A[next].m_key].m_key + 1;
  avbl = 1;
  used = dpth = 0;
  root = n - 2;
  next = n - 1;
  while (avbl > 0) {
    while (root >= 0 && (int) A[root].m_key == dpth) {
      used++;
      root--;
    }
    while (avbl > used) {
      A[next--].m_key = (mz_uint16) (dpth);
      avbl--;
    }
    avbl = 2 * used;
    dpth++;
    used = 0;
  }
}

// Limits canonical Huffman code table's max code size.
enum { TDEFL_MAX_SUPPORTED_HUFF_CODESIZE = 32 };
static void tdefl_huffman_enforce_max_code_size(int *pNum_codes, int code_list_len, int max_code_size)
{
  int i;
  mz_uint32 total = 0;
  if (code_list_len <= 1)
    return;
  for (i = max_code_size + 1; i <= TDEFL_MAX_SUPPORTED_HUFF_CODESIZE; i++)
    pNum_codes[max_code_size] += pNum_codes[i];
  for (i = max_code_size; i > 0; i--)
    total += (((mz_uint32) pNum_codes[i]) << (max_code_size - i));
  while (total != (1UL << max_code_size)) {
    pNum_codes[max_code_size]--;
    for (i = max_code_size - 1; i > 0; i--)
      if (pNum_codes[i]) {
        pNum_codes[i]--;
        pNum_codes[i + 1] += 2;
        break;
      }
    total--;
  }
}

static void tdefl_optimize_huffman_table(tdefl_compressor * d, int table_num, int table_len, int code_size_limit, int static_table)
{
  int i, j, l, num_codes[1 + TDEFL_MAX_SUPPORTED_HUFF_CODESIZE];
  mz_uint next_code[TDEFL_MAX_SUPPORTED_HUFF_CODESIZE + 1];
  MZ_CLEAR_OBJ(num_codes);
  if (static_table) {
    for (i = 0; i < table_len; i++)
      num_codes[d->m_huff_code_sizes[table_num][i]]++;
  } else {
    tdefl_sym_freq syms0[TDEFL_MAX_HUFF_SYMBOLS], syms1[TDEFL_MAX_HUFF_SYMBOLS], *pSyms;
    int num_used_syms = 0;
    const mz_uint16 *pSym_count = &d->m_huff_count[table_num][0];
    for (i = 0; i < table_len; i++)
      if (pSym_count[i]) {
        syms0[num_used_syms].m_key = (mz_uint16) pSym_count[i];
        syms0[num_used_syms++].m_sym_index = (mz_uint16) i;
      }

    pSyms = tdefl_radix_sort_syms(num_used_syms, syms0, syms1);
    tdefl_calculate_minimum_redundancy(pSyms, num_used_syms);

    for (i = 0; i < num_used_syms; i++)
      num_codes[pSyms[i].m_key]++;

    tdefl_huffman_enforce_max_code_size(num_codes, num_used_syms, code_size_limit);

    MZ_CLEAR_OBJ(d->m_huff_code_sizes[table_num]);
    MZ_CLEAR_OBJ(d->m_huff_codes[table_num]);
    for (i = 1, j = num_used_syms; i <= code_size_limit; i++)
      for (l = num_codes[i]; l > 0; l--)
        d->m_huff_code_sizes[table_num][pSyms[--j].m_sym_index] = (mz_uint8) (i);
  }

  next_code[1] = 0;
  for (j = 0, i = 2; i <= code_size_limit; i++)
    next_code[i] = j = ((j + num_codes[i - 1]) << 1);

  for (i = 0; i < table_len; i++) {
    mz_uint rev_code = 0, code, code_size;
    if ((code_size = d->m_huff_code_sizes[table_num][i]) == 0)
      continue;
    code = next_code[code_size]++;
    for (l = code_size; l > 0; l--, code >>= 1)
      rev_code = (rev_code << 1) | (code & 1);
    d->m_huff_codes[table_num][i] = (mz_uint16) rev_code;
  }
}

#define TDEFL_PUT_BITS(b, l) do { \
  mz_uint bits = b; mz_uint len = l; assert(bits <= ((1U << len) - 1U)); \
  d->m_bit_buffer |= (bits << d->m_bits_in); d->m_bits_in += len; \
  while (d->m_bits_in >= 8) { \
    if (d->m_pOutput_buf < d->m_pOutput_buf_end) \
      *d->m_pOutput_buf++ = (mz_uint8)(d->m_bit_buffer); \
      d->m_bit_buffer >>= 8; \
      d->m_bits_in -= 8; \
  } \
} while (0)

#define TDEFL_RLE_PREV_CODE_SIZE() { if (rle_repeat_count) { \
  if (rle_repeat_count < 3) { \
    d->m_huff_count[2][prev_code_size] = (mz_uint16)(d->m_huff_count[2][prev_code_size] + rle_repeat_count); \
    while (rle_repeat_count--) packed_code_sizes[num_packed_code_sizes++] = prev_code_size; \
  } else { \
    d->m_huff_count[2][16] = (mz_uint16)(d->m_huff_count[2][16] + 1); packed_code_sizes[num_packed_code_sizes++] = 16; packed_code_sizes[num_packed_code_sizes++] = (mz_uint8)(rle_repeat_count - 3); \
} rle_repeat_count = 0; } }

#define TDEFL_RLE_ZERO_CODE_SIZE() { if (rle_z_count) { \
  if (rle_z_count < 3) { \
    d->m_huff_count[2][0] = (mz_uint16)(d->m_huff_count[2][0] + rle_z_count); while (rle_z_count--) packed_code_sizes[num_packed_code_sizes++] = 0; \
  } else if (rle_z_count <= 10) { \
    d->m_huff_count[2][17] = (mz_uint16)(d->m_huff_count[2][17] + 1); packed_code_sizes[num_packed_code_sizes++] = 17; packed_code_sizes[num_packed_code_sizes++] = (mz_uint8)(rle_z_count - 3); \
  } else { \
    d->m_huff_count[2][18] = (mz_uint16)(d->m_huff_count[2][18] + 1); packed_code_sizes[num_packed_code_sizes++] = 18; packed_code_sizes[num_packed_code_sizes++] = (mz_uint8)(rle_z_count - 11); \
} rle_z_count = 0; } }

static mz_uint8 s_tdefl_packed_code_size_syms_swizzle[] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

static void tdefl_start_dynamic_block(tdefl_compressor * d)
{
  int num_lit_codes, num_dist_codes, num_bit_lengths;
  mz_uint i, total_code_sizes_to_pack, num_packed_code_sizes, rle_z_count, rle_repeat_count, packed_code_sizes_index;
  mz_uint8 code_sizes_to_pack[TDEFL_MAX_HUFF_SYMBOLS_0 + TDEFL_MAX_HUFF_SYMBOLS_1], packed_code_sizes[TDEFL_MAX_HUFF_SYMBOLS_0 + TDEFL_MAX_HUFF_SYMBOLS_1], prev_code_size = 0xFF;

  d->m_huff_count[0][256] = 1;

  tdefl_optimize_huffman_table(d, 0, TDEFL_MAX_HUFF_SYMBOLS_0, 15, MZ_FALSE);
  tdefl_optimize_huffman_table(d, 1, TDEFL_MAX_HUFF_SYMBOLS_1, 15, MZ_FALSE);

  for (num_lit_codes = 286; num_lit_codes > 257; num_lit_codes--)
    if (d->m_huff_code_sizes[0][num_lit_codes - 1])
      break;
  for (num_dist_codes = 30; num_dist_codes > 1; num_dist_codes--)
    if (d->m_huff_code_sizes[1][num_dist_codes - 1])
      break;

  memcpy(code_sizes_to_pack, &d->m_huff_code_sizes[0][0], num_lit_codes);
  memcpy(code_sizes_to_pack + num_lit_codes, &d->m_huff_code_sizes[1][0], num_dist_codes);
  total_code_sizes_to_pack = num_lit_codes + num_dist_codes;
  num_packed_code_sizes = 0;
  rle_z_count = 0;
  rle_repeat_count = 0;

  memset(&d->m_huff_count[2][0], 0, sizeof(d->m_huff_count[2][0]) * TDEFL_MAX_HUFF_SYMBOLS_2);
  for (i = 0; i < total_code_sizes_to_pack; i++) {
    mz_uint8 code_size = code_sizes_to_pack[i];
    if (!code_size) {
      TDEFL_RLE_PREV_CODE_SIZE();
      if (++rle_z_count == 138) {
        TDEFL_RLE_ZERO_CODE_SIZE();
      }
    } else {
      TDEFL_RLE_ZERO_CODE_SIZE();
      if (code_size != prev_code_size) {
        TDEFL_RLE_PREV_CODE_SIZE();
        d->m_huff_count[2][code_size] = (mz_uint16) (d->m_huff_count[2][code_size] + 1);
        packed_code_sizes[num_packed_code_sizes++] = code_size;
      } else if (++rle_repeat_count == 6) {
        TDEFL_RLE_PREV_CODE_SIZE();
      }
    }
    prev_code_size = code_size;
  }
  if (rle_repeat_count) {
    TDEFL_RLE_PREV_CODE_SIZE();
  } else {
    TDEFL_RLE_ZERO_CODE_SIZE();
  }

  tdefl_optimize_huffman_table(d, 2, TDEFL_MAX_HUFF_SYMBOLS_2, 7, MZ_FALSE);

  TDEFL_PUT_BITS(2, 2);

  TDEFL_PUT_BITS(num_lit_codes - 257, 5);
  TDEFL_PUT_BITS(num_dist_codes - 1, 5);

  for (num_bit_lengths = 18; num_bit_lengths >= 0; num_bit_lengths--)
    if (d->m_huff_code_sizes[2][s_tdefl_packed_code_size_syms_swizzle[num_bit_lengths]])
      break;
  num_bit_lengths = MZ_MAX(4, (num_bit_lengths + 1));
  TDEFL_PUT_BITS(num_bit_lengths - 4, 4);
  for (i = 0; (int) i < num_bit_lengths; i++)
    TDEFL_PUT_BITS(d->m_huff_code_sizes[2][s_tdefl_packed_code_size_syms_swizzle[i]], 3);

  for (packed_code_sizes_index = 0; packed_code_sizes_index < num_packed_code_sizes;) {
    mz_uint code = packed_code_sizes[packed_code_sizes_index++];
    assert(code < TDEFL_MAX_HUFF_SYMBOLS_2);
    TDEFL_PUT_BITS(d->m_huff_codes[2][code], d->m_huff_code_sizes[2][code]);
    if (code >= 16)
      TDEFL_PUT_BITS(packed_code_sizes[packed_code_sizes_index++], "\02\03\07"[code - 16]);
  }
}

static void tdefl_start_static_block(tdefl_compressor * d)
{
  mz_uint i;
  mz_uint8 *p = &d->m_huff_code_sizes[0][0];

  for (i = 0; i <= 143; ++i)
    *p++ = 8;
  for (; i <= 255; ++i)
    *p++ = 9;
  for (; i <= 279; ++i)
    *p++ = 7;
  for (; i <= 287; ++i)
    *p++ = 8;

  memset(d->m_huff_code_sizes[1], 5, 32);

  tdefl_optimize_huffman_table(d, 0, 288, 15, MZ_TRUE);
  tdefl_optimize_huffman_table(d, 1, 32, 15, MZ_TRUE);

  TDEFL_PUT_BITS(1, 2);
}

static const mz_uint mz_bitmasks[17] = { 0x0000, 0x0001, 0x0003, 0x0007, 0x000F, 0x001F, 0x003F, 0x007F, 0x00FF, 0x01FF, 0x03FF, 0x07FF, 0x0FFF, 0x1FFF, 0x3FFF, 0x7FFF, 0xFFFF };

static mz_bool tdefl_compress_lz_codes(tdefl_compressor * d)
{
  mz_uint flags;
  mz_uint8 *pLZ_codes;

  flags = 1;
  for (pLZ_codes = d->m_lz_code_buf; pLZ_codes < d->m_pLZ_code_buf; flags >>= 1) {
    if (flags == 1)
      flags = *pLZ_codes++ | 0x100;
    if (flags & 1) {
      mz_uint sym, num_extra_bits;
      mz_uint match_len = pLZ_codes[0], match_dist = (pLZ_codes[1] | (pLZ_codes[2] << 8));
      pLZ_codes += 3;

      assert(d->m_huff_code_sizes[0][s_tdefl_len_sym[match_len]]);
      TDEFL_PUT_BITS(d->m_huff_codes[0][s_tdefl_len_sym[match_len]], d->m_huff_code_sizes[0][s_tdefl_len_sym[match_len]]);
      TDEFL_PUT_BITS(match_len & mz_bitmasks[s_tdefl_len_extra[match_len]], s_tdefl_len_extra[match_len]);

      if (match_dist < 512) {
        sym = s_tdefl_small_dist_sym[match_dist];
        num_extra_bits = s_tdefl_small_dist_extra[match_dist];
      } else {
        sym = s_tdefl_large_dist_sym[match_dist >> 8];
        num_extra_bits = s_tdefl_large_dist_extra[match_dist >> 8];
      }
      assert(d->m_huff_code_sizes[1][sym]);
      TDEFL_PUT_BITS(d->m_huff_codes[1][sym], d->m_huff_code_sizes[1][sym]);
      TDEFL_PUT_BITS(match_dist & mz_bitmasks[num_extra_bits], num_extra_bits);
    } else {
      mz_uint lit = *pLZ_codes++;
      assert(d->m_huff_code_sizes[0][lit]);
      TDEFL_PUT_BITS(d->m_huff_codes[0][lit], d->m_huff_code_sizes[0][lit]);
    }
  }

  TDEFL_PUT_BITS(d->m_huff_codes[0][256], d->m_huff_code_sizes[0][256]);

  return (d->m_pOutput_buf < d->m_pOutput_buf_end);
}

static mz_bool tdefl_compress_block(tdefl_compressor * d, mz_bool static_block)
{
  if (static_block)
    tdefl_start_static_block(d);
  else
    tdefl_start_dynamic_block(d);
  return tdefl_compress_lz_codes(d);
}

static int tdefl_flush_block(tdefl_compressor * d, int flush)
{
  mz_uint saved_bit_buf, saved_bits_in;
  mz_uint8 *pSaved_output_buf;
  mz_bool comp_block_succeeded = MZ_FALSE;
  int n;
  mz_uint8 *pOutput_buf_start = ((d->m_pPut_buf_func == NULL) && ((*d->m_pOut_buf_size - d->m_out_buf_ofs) >= TDEFL_OUT_BUF_SIZE)) ? ((mz_uint8 *) d->m_pOut_buf + d->m_out_buf_ofs) : d->m_output_buf;

  d->m_pOutput_buf = pOutput_buf_start;
  d->m_pOutput_buf_end = d->m_pOutput_buf + TDEFL_OUT_BUF_SIZE - 16;

  assert(!d->m_output_flush_remaining);
  d->m_output_flush_ofs = 0;
  d->m_output_flush_remaining = 0;

  *d->m_pLZ_flags = (mz_uint8) (*d->m_pLZ_flags >> d->m_num_flags_left);
  d->m_pLZ_code_buf -= (d->m_num_flags_left == 8);

  TDEFL_PUT_BITS(flush == TDEFL_FINISH, 1);

  pSaved_output_buf = d->m_pOutput_buf;
  saved_bit_buf = d->m_bit_buffer;
  saved_bits_in = d->m_bits_in;

  comp_block_succeeded = tdefl_compress_block(d, (d->m_total_lz_bytes < 48));

  // If the block gets expanded, forget the current contents of the output buffer and send a raw block instead.
  if (((d->m_total_lz_bytes) && ((d->m_pOutput_buf - pSaved_output_buf + 1U) >= d->m_total_lz_bytes)) && ((d->m_lookahead_pos - d->m_lz_code_buf_dict_pos) <= d->m_dict_size)) {
    mz_uint i;
    d->m_pOutput_buf = pSaved_output_buf;
    d->m_bit_buffer = saved_bit_buf, d->m_bits_in = saved_bits_in;
    TDEFL_PUT_BITS(0, 2);
    if (d->m_bits_in) {
      TDEFL_PUT_BITS(0, 8 - d->m_bits_in);
    }
    for (i = 2; i; --i, d->m_total_lz_bytes ^= 0xFFFF) {
      TDEFL_PUT_BITS(d->m_total_lz_bytes & 0xFFFF, 16);
    }
    for (i = 0; i < d->m_total_lz_bytes; ++i) {
      TDEFL_PUT_BITS(d->m_dict[(d->m_lz_code_buf_dict_pos + i) & TDEFL_LZ_DICT_SIZE_MASK], 8);
    }
  }
  // Check for the extremely unlikely (if not impossible) case of the compressed block not fitting into the output buffer when using dynamic codes.
  else if (!comp_block_succeeded) {
    d->m_pOutput_buf = pSaved_output_buf;
    d->m_bit_buffer = saved_bit_buf, d->m_bits_in = saved_bits_in;
    tdefl_compress_block(d, MZ_TRUE);
  }

  if (flush) {
    if (flush == TDEFL_FINISH) {
      if (d->m_bits_in) {
        TDEFL_PUT_BITS(0, 8 - d->m_bits_in);
      }
    } else {
      mz_uint i, z = 0;
      TDEFL_PUT_BITS(0, 3);
      if (d->m_bits_in) {
        TDEFL_PUT_BITS(0, 8 - d->m_bits_in);
      }
      for (i = 2; i; --i, z ^= 0xFFFF) {
        TDEFL_PUT_BITS(z & 0xFFFF, 16);
      }
    }
  }

  assert(d->m_pOutput_buf < d->m_pOutput_buf_end);

  memset(&d->m_huff_count[0][0], 0, sizeof(d->m_huff_count[0][0]) * TDEFL_MAX_HUFF_SYMBOLS_0);
  memset(&d->m_huff_count[1][0], 0, sizeof(d->m_huff_count[1][0]) * TDEFL_MAX_HUFF_SYMBOLS_1);

  d->m_pLZ_code_buf = d->m_lz_code_buf + 1;
  d->m_pLZ_flags = d->m_lz_code_buf;
  d->m_num_flags_left = 8;
  d->m_lz_code_buf_dict_pos += d->m_total_lz_bytes;
  d->m_total_lz_bytes = 0;
  d->m_block_index++;

  if ((n = (int) (d->m_pOutput_buf - pOutput_buf_start)) != 0) {
    if (d->m_pPut_buf_func) {
      *d->m_pIn_buf_size = d->m_pSrc - (const mz_uint8 *) d->m_pIn_buf;
      if (!(*d->m_pPut_buf_func) (d->m_output_buf, n, d->m_pPut_buf_user))
        return (d->m_prev_return_status = TDEFL_STATUS_PUT_BUF_FAILED);
    } else if (pOutput_buf_start == d->m_output_buf) {
      int bytes_to_copy = (int) MZ_MIN((size_t) n, (size_t) (*d->m_pOut_buf_size - d->m_out_buf_ofs));
      memcpy((mz_uint8 *) d->m_pOut_buf + d->m_out_buf_ofs, d->m_output_buf, bytes_to_copy);
      d->m_out_buf_ofs += bytes_to_copy;
      if ((n -= bytes_to_copy) != 0) {
        d->m_output_flush_ofs = bytes_to_copy;
        d->m_output_flush_remaining = n;
      }
    } else {
      d->m_out_buf_ofs += n;
    }
  }

  return d->m_output_flush_remaining;
}

static void tdefl_find_match(tdefl_compressor * d, mz_uint lookahead_pos, mz_uint max_dist, mz_uint max_match_len, mz_uint * pMatch_dist, mz_uint * pMatch_len)
{
  mz_uint dist, pos = lookahead_pos & TDEFL_LZ_DICT_SIZE_MASK, match_len = *pMatch_len, probe_pos = pos, next_probe_pos, probe_len;
  mz_uint num_probes_left = d->m_max_probes[match_len >= 32];
  const mz_uint8 *s = d->m_dict + pos, *p, *q;
  mz_uint8 c0 = d->m_dict[pos + match_len], c1 = d->m_dict[pos + match_len - 1];
  assert(max_match_len <= TDEFL_MAX_MATCH_LEN);
  if (max_match_len <= match_len)
    return;
  for (;;) {
    for (;;) {
      if (--num_probes_left == 0)
        return;
#define TDEFL_PROBE \
        next_probe_pos = d->m_next[probe_pos]; \
        if ((!next_probe_pos) || ((dist = (mz_uint16)(lookahead_pos - next_probe_pos)) > max_dist)) return; \
        probe_pos = next_probe_pos & TDEFL_LZ_DICT_SIZE_MASK; \
        if ((d->m_dict[probe_pos + match_len] == c0) && (d->m_dict[probe_pos + match_len - 1] == c1)) break;
      TDEFL_PROBE;
      TDEFL_PROBE;
      TDEFL_PROBE;
    }
    if (!dist)
      break;
    p = s;
    q = d->m_dict + probe_pos;
    for (probe_len = 0; probe_len < max_match_len; probe_len++)
      if (*p++ != *q++)
        break;
    if (probe_len > match_len) {
      *pMatch_dist = dist;
      if ((*pMatch_len = match_len = probe_len) == max_match_len)
        return;
      c0 = d->m_dict[pos + match_len];
      c1 = d->m_dict[pos + match_len - 1];
    }
  }
}

static void tdefl_record_literal(tdefl_compressor * d, mz_uint8 lit)
{
  d->m_total_lz_bytes++;
  *d->m_pLZ_code_buf++ = lit;
  *d->m_pLZ_flags = (mz_uint8) (*d->m_pLZ_flags >> 1);
  if (--d->m_num_flags_left == 0) {
    d->m_num_flags_left = 8;
    d->m_pLZ_flags = d->m_pLZ_code_buf++;
  }
  d->m_huff_count[0][lit]++;
}

static void tdefl_record_match(tdefl_compressor * d, mz_uint match_len, mz_uint match_dist)
{
  mz_uint32 s0, s1;

  assert((match_len >= TDEFL_MIN_MATCH_LEN) && (match_dist >= 1) && (match_dist <= TDEFL_LZ_DICT_SIZE));

  d->m_total_lz_bytes += match_len;

  d->m_pLZ_code_buf[0] = (mz_uint8) (match_len - TDEFL_MIN_MATCH_LEN);

  match_dist -= 1;
  d->m_pLZ_code_buf[1] = (mz_uint8) (match_dist & 0xFF);
  d->m_pLZ_code_buf[2] = (mz_uint8) (match_dist >> 8);
  d->m_pLZ_code_buf += 3;

  *d->m_pLZ_flags = (mz_uint8) ((*d->m_pLZ_flags >> 1) | 0x80);
  if (--d->m_num_flags_left == 0) {
    d->m_num_flags_left = 8;
    d->m_pLZ_flags = d->m_pLZ_code_buf++;
  }

  s0 = s_tdefl_small_dist_sym[match_dist & 511];
  s1 = s_tdefl_large_dist_sym[(match_dist >> 8) & 127];
  d->m_huff_count[1][(match_dist < 512) ? s0 : s1]++;

  if (match_len >= TDEFL_MIN_MATCH_LEN)
    d->m_huff_count[0][s_tdefl_len_sym[match_len - TDEFL_MIN_MATCH_LEN]]++;
}

static mz_bool tdefl_compress_normal(tdefl_compressor * d)
{
  const mz_uint8 *pSrc = d->m_pSrc;
  size_t src_buf_left = d->m_src_buf_left;
  tdefl_flush flush = d->m_flush;

  while ((src_buf_left) || ((flush) && (d->m_lookahead_size))) {
    mz_uint len_to_move, cur_match_dist, cur_match_len, cur_pos;
    // Update dictionary and hash chains. Keeps the lookahead size equal to TDEFL_MAX_MATCH_LEN.
    if ((d->m_lookahead_size + d->m_dict_size) >= (TDEFL_MIN_MATCH_LEN - 1)) {
      mz_uint dst_pos = (d->m_lookahead_pos + d->m_lookahead_size) & TDEFL_LZ_DICT_SIZE_MASK, ins_pos = d->m_lookahead_pos + d->m_lookahead_size - 2;
      mz_uint hash = (d->m_dict[ins_pos & TDEFL_LZ_DICT_SIZE_MASK] << TDEFL_LZ_HASH_SHIFT) ^ d->m_dict[(ins_pos + 1) & TDEFL_LZ_DICT_SIZE_MASK];
      mz_uint num_bytes_to_process = (mz_uint) MZ_MIN(src_buf_left, TDEFL_MAX_MATCH_LEN - d->m_lookahead_size);
      const mz_uint8 *pSrc_end = pSrc + num_bytes_to_process;
      src_buf_left -= num_bytes_to_process;
      d->m_lookahead_size += num_bytes_to_process;
      while (pSrc != pSrc_end) {
        mz_uint8 c = *pSrc++;
        d->m_dict[dst_pos] = c;
        if (dst_pos < (TDEFL_MAX_MATCH_LEN - 1))
          d->m_dict[TDEFL_LZ_DICT_SIZE + dst_pos] = c;
        hash = ((hash << TDEFL_LZ_HASH_SHIFT) ^ c) & (TDEFL_LZ_HASH_SIZE - 1);
        d->m_next[ins_pos & TDEFL_LZ_DICT_SIZE_MASK] = d->m_hash[hash];
        d->m_hash[hash] = (mz_uint16) (ins_pos);
        dst_pos = (dst_pos + 1) & TDEFL_LZ_DICT_SIZE_MASK;
        ins_pos++;
      }
    } else {
      while ((src_buf_left) && (d->m_lookahead_size < TDEFL_MAX_MATCH_LEN)) {
        mz_uint8 c = *pSrc++;
        mz_uint dst_pos = (d->m_lookahead_pos + d->m_lookahead_size) & TDEFL_LZ_DICT_SIZE_MASK;
        src_buf_left--;
        d->m_dict[dst_pos] = c;
        if (dst_pos < (TDEFL_MAX_MATCH_LEN - 1))
          d->m_dict[TDEFL_LZ_DICT_SIZE + dst_pos] = c;
        if ((++d->m_lookahead_size + d->m_dict_size) >= TDEFL_MIN_MATCH_LEN) {
          mz_uint ins_pos = d->m_lookahead_pos + (d->m_lookahead_size - 1) - 2;
          mz_uint hash = ((d->m_dict[ins_pos & TDEFL_LZ_DICT_SIZE_MASK] << (TDEFL_LZ_HASH_SHIFT * 2)) ^ (d->m_dict[(ins_pos + 1) & TDEFL_LZ_DICT_SIZE_MASK] << TDEFL_LZ_HASH_SHIFT) ^ c) & (TDEFL_LZ_HASH_SIZE - 1);
          d->m_next[ins_pos & TDEFL_LZ_DICT_SIZE_MASK] = d->m_hash[hash];
          d->m_hash[hash] = (mz_uint16) (ins_pos);
        }
      }
    }
    d->m_dict_size = MZ_MIN(TDEFL_LZ_DICT_SIZE - d->m_lookahead_size, d->m_dict_size);
    if ((!flush) && (d->m_lookahead_size < TDEFL_MAX_MATCH_LEN))
      break;

    // Simple lazy/greedy parsing state machine.
    len_to_move = 1;
    cur_match_dist = 0;
    cur_match_len = d->m_saved_match_len ? d->m_saved_match_len : (TDEFL_MIN_MATCH_LEN - 1);
    cur_pos = d->m_lookahead_pos & TDEFL_LZ_DICT_SIZE_MASK;
    tdefl_find_match(d, d->m_lookahead_pos, d->m_dict_size, d->m_lookahead_size, &cur_match_dist, &cur_match_len);
    if (((cur_match_len == TDEFL_MIN_MATCH_LEN) && (cur_match_dist >= 8U * 1024U)) || (cur_pos == cur_match_dist)) {
      cur_match_dist = cur_match_len = 0;
    }
    if (d->m_saved_match_len) {
      if (cur_match_len > d->m_saved_match_len) {
        tdefl_record_literal(d, (mz_uint8) d->m_saved_lit);
        if (cur_match_len >= 128) {
          tdefl_record_match(d, cur_match_len, cur_match_dist);
          d->m_saved_match_len = 0;
          len_to_move = cur_match_len;
        } else {
          d->m_saved_lit = d->m_dict[cur_pos];
          d->m_saved_match_dist = cur_match_dist;
          d->m_saved_match_len = cur_match_len;
        }
      } else {
        tdefl_record_match(d, d->m_saved_match_len, d->m_saved_match_dist);
        len_to_move = d->m_saved_match_len - 1;
        d->m_saved_match_len = 0;
      }
    } else if (!cur_match_dist)
      tdefl_record_literal(d, d->m_dict[MZ_MIN(cur_pos, sizeof(d->m_dict) - 1)]);
    else if (cur_match_len >= 128) {
      tdefl_record_match(d, cur_match_len, cur_match_dist);
      len_to_move = cur_match_len;
    } else {
      d->m_saved_lit = d->m_dict[MZ_MIN(cur_pos, sizeof(d->m_dict) - 1)];
      d->m_saved_match_dist = cur_match_dist;
      d->m_saved_match_len = cur_match_len;
    }
    // Move the lookahead forward by len_to_move bytes.
    d->m_lookahead_pos += len_to_move;
    assert(d->m_lookahead_size >= len_to_move);
    d->m_lookahead_size -= len_to_move;
    d->m_dict_size = MZ_MIN(d->m_dict_size + len_to_move, TDEFL_LZ_DICT_SIZE);
    // Check if it's time to flush the current LZ codes to the internal output buffer.
    if ((d->m_pLZ_code_buf > &d->m_lz_code_buf[TDEFL_LZ_CODE_BUF_SIZE - 8]) || ((d->m_total_lz_bytes > 31 * 1024) && (((((mz_uint) (d->m_pLZ_code_buf - d->m_lz_code_buf) * 115) >> 7) >= d->m_total_lz_bytes)))) {
      int n;
      d->m_pSrc = pSrc;
      d->m_src_buf_left = src_buf_left;
      if ((n = tdefl_flush_block(d, 0)) != 0)
        return (n < 0) ? MZ_FALSE : MZ_TRUE;
    }
  }

  d->m_pSrc = pSrc;
  d->m_src_buf_left = src_buf_left;
  return MZ_TRUE;
}

static tdefl_status tdefl_flush_output_buffer(tdefl_compressor * d)
{
  if (d->m_pIn_buf_size) {
    *d->m_pIn_buf_size = d->m_pSrc - (const mz_uint8 *) d->m_pIn_buf;
  }

  if (d->m_pOut_buf_size) {
    size_t n = MZ_MIN(*d->m_pOut_buf_size - d->m_out_buf_ofs, d->m_output_flush_remaining);
    memcpy((mz_uint8 *) d->m_pOut_buf + d->m_out_buf_ofs, d->m_output_buf + d->m_output_flush_ofs, n);
    d->m_output_flush_ofs += (mz_uint) n;
    d->m_output_flush_remaining -= (mz_uint) n;
    d->m_out_buf_ofs += n;

    *d->m_pOut_buf_size = d->m_out_buf_ofs;
  }

  return (d->m_finished && !d->m_output_flush_remaining) ? TDEFL_STATUS_DONE : TDEFL_STATUS_OKAY;
}

static tdefl_status tdefl_compress(tdefl_compressor * d, const void *pIn_buf, size_t * pIn_buf_size, tdefl_flush flush)
{
  if (!d) {
    if (pIn_buf_size)
      *pIn_buf_size = 0;
    return TDEFL_STATUS_BAD_PARAM;
  }

  d->m_pIn_buf = pIn_buf;
  d->m_pIn_buf_size = pIn_buf_size;
  d->m_pSrc = (const mz_uint8 *) (pIn_buf);
  d->m_src_buf_left = pIn_buf_size ? *pIn_buf_size : 0;
  d->m_out_buf_ofs = 0;
  d->m_flush = flush;

  if (!(d->m_pPut_buf_func) || (d->m_prev_return_status != TDEFL_STATUS_OKAY) || (flush != TDEFL_FINISH) || (pIn_buf_size && *pIn_buf_size && !pIn_buf)) {
    if (pIn_buf_size)
      *pIn_buf_size = 0;
    return (d->m_prev_return_status = TDEFL_STATUS_BAD_PARAM);
  }

  if ((d->m_output_flush_remaining) || (d->m_finished))
    return (d->m_prev_return_status = tdefl_flush_output_buffer(d));

  if (!tdefl_compress_normal(d))
    return d->m_prev_return_status;

  if ((flush) && (!d->m_lookahead_size) && (!d->m_src_buf_left) && (!d->m_output_flush_remaining)) {
    if (tdefl_flush_block(d, flush) < 0)
      return d->m_prev_return_status;
    d->m_finished = (flush == TDEFL_FINISH);
    if (flush == TDEFL_FULL_FLUSH) {
      MZ_CLEAR_OBJ(d->m_hash);
      MZ_CLEAR_OBJ(d->m_next);
      d->m_dict_size = 0;
    }
  }

  return (d->m_prev_return_status = tdefl_flush_output_buffer(d));
}

static tdefl_status tdefl_init(tdefl_compressor * d, tdefl_put_buf_func_ptr pPut_buf_func, void *pPut_buf_user, int flags)
{
  d->m_pPut_buf_func = pPut_buf_func;
  d->m_pPut_buf_user = pPut_buf_user;
  d->m_max_probes[0] = 1 + ((flags & 0xFFF) + 2) / 3;
  d->m_max_probes[1] = 1 + (((flags & 0xFFF) >> 2) + 2) / 3;
  MZ_CLEAR_OBJ(d->m_hash);
  d->m_lookahead_pos = d->m_lookahead_size = d->m_dict_size = d->m_total_lz_bytes = d->m_lz_code_buf_dict_pos = d->m_bits_in = 0;
  d->m_output_flush_ofs = d->m_output_flush_remaining = d->m_finished = d->m_block_index = d->m_bit_buffer = 0;
  d->m_pLZ_code_buf = d->m_lz_code_buf + 1;
  d->m_pLZ_flags = d->m_lz_code_buf;
  d->m_num_flags_left = 8;
  d->m_pOutput_buf = d->m_output_buf;
  d->m_pOutput_buf_end = d->m_output_buf;
  d->m_prev_return_status = TDEFL_STATUS_OKAY;
  d->m_saved_match_dist = d->m_saved_match_len = d->m_saved_lit = 0;
  d->m_adler32 = 1;
  d->m_pIn_buf = NULL;
  d->m_pOut_buf = NULL;
  d->m_pIn_buf_size = NULL;
  d->m_pOut_buf_size = NULL;
  d->m_flush = TDEFL_NO_FLUSH;
  d->m_pSrc = NULL;
  d->m_src_buf_left = 0;
  d->m_out_buf_ofs = 0;
  memset(&d->m_huff_count[0][0], 0, sizeof(d->m_huff_count[0][0]) * TDEFL_MAX_HUFF_SYMBOLS_0);
  memset(&d->m_huff_count[1][0], 0, sizeof(d->m_huff_count[1][0]) * TDEFL_MAX_HUFF_SYMBOLS_1);
  return TDEFL_STATUS_OKAY;
}

static mz_bool mz_zip_writer_validate_archive_name(const char *pArchive_name)
{
  // Basic ZIP archive filename validity checks: Valid filenames cannot start with a forward slash, cannot contain a drive letter, and cannot use DOS-style backward slashes.
  if (*pArchive_name == '/')
    return MZ_FALSE;
  while (*pArchive_name) {
    if ((*pArchive_name == '\\') || (*pArchive_name == ':'))
      return MZ_FALSE;
    pArchive_name++;
  }
  return MZ_TRUE;
}

static mz_uint mz_zip_writer_compute_padding_needed_for_file_alignment(mz_zip_archive * pZip)
{
  mz_uint32 n;
  if (!pZip->m_file_offset_alignment)
    return 0;
  n = (mz_uint32) (pZip->m_archive_size & (pZip->m_file_offset_alignment - 1));
  return (pZip->m_file_offset_alignment - n) & (pZip->m_file_offset_alignment - 1);
}

static mz_bool mz_zip_writer_write_zeros(mz_zip_archive * pZip, mz_uint64 cur_file_ofs, mz_uint32 n)
{
  char buf[4096];
  memset(buf, 0, MZ_MIN(sizeof(buf), n));
  while (n) {
    mz_uint32 s = MZ_MIN(sizeof(buf), n);
    if (pZip->m_pWrite(pZip->m_pIO_opaque, cur_file_ofs, buf, s) != s)
      return MZ_FALSE;
    cur_file_ofs += s;
    n -= s;
  }
  return MZ_TRUE;
}

static size_t mz_zip_file_write_func(void *pOpaque, mz_uint64 file_ofs, const void *pBuf, size_t n)
{
  mz_zip_archive *pZip = (mz_zip_archive *) pOpaque;
  mz_int64 cur_ofs = ftello64(pZip->m_pState->m_pFile);
  if (((mz_int64) file_ofs < 0) || (((cur_ofs != (mz_int64) file_ofs)) && (fseeko64(pZip->m_pState->m_pFile, (mz_int64) file_ofs, SEEK_SET))))
    return 0;
  return fwrite(pBuf, 1, n, pZip->m_pState->m_pFile);
}

static void mz_zip_array_clear(mz_zip_archive * pZip, mz_zip_array * pArray)
{
  free(pArray->m_p);
  memset(pArray, 0, sizeof(mz_zip_array));
}

static mz_bool mz_zip_array_ensure_capacity(mz_zip_archive * pZip, mz_zip_array * pArray, size_t min_new_capacity, mz_uint growing)
{
  void *pNew_p;
  size_t new_capacity = min_new_capacity;
  assert(pArray->m_element_size);
  if (pArray->m_capacity >= min_new_capacity)
    return MZ_TRUE;
  if (growing) {
    new_capacity = MZ_MAX(1, pArray->m_capacity);
    while (new_capacity < min_new_capacity)
      new_capacity *= 2;
  }
  if (NULL == (pNew_p = realloc(pArray->m_p, pArray->m_element_size * new_capacity)))
    return MZ_FALSE;
  pArray->m_p = pNew_p;
  pArray->m_capacity = new_capacity;
  return MZ_TRUE;
}

static mz_bool mz_zip_array_reserve(mz_zip_archive * pZip, mz_zip_array * pArray, size_t new_capacity, mz_uint growing)
{
  if (new_capacity > pArray->m_capacity) {
    if (!mz_zip_array_ensure_capacity(pZip, pArray, new_capacity, growing))
      return MZ_FALSE;
  }
  return MZ_TRUE;
}

static mz_bool mz_zip_array_resize(mz_zip_archive * pZip, mz_zip_array * pArray, size_t new_size, mz_uint growing)
{
  if (new_size > pArray->m_capacity) {
    if (!mz_zip_array_ensure_capacity(pZip, pArray, new_size, growing))
      return MZ_FALSE;
  }
  pArray->m_size = new_size;
  return MZ_TRUE;
}

static mz_bool mz_zip_array_ensure_room(mz_zip_archive * pZip, mz_zip_array * pArray, size_t n)
{
  return mz_zip_array_reserve(pZip, pArray, pArray->m_size + n, MZ_TRUE);
}

static mz_bool mz_zip_array_push_back(mz_zip_archive * pZip, mz_zip_array * pArray, const void *pElements, size_t n)
{
  size_t orig_size = pArray->m_size;
  if (!mz_zip_array_resize(pZip, pArray, orig_size + n, MZ_TRUE))
    return MZ_FALSE;
  memcpy((mz_uint8 *) pArray->m_p + orig_size * pArray->m_element_size, pElements, n * pArray->m_element_size);
  return MZ_TRUE;
}

mz_bool mz_zip_reader_end(mz_zip_archive * pZip)
{
  if ((!pZip) || (!pZip->m_pState) || (pZip->m_zip_mode != MZ_ZIP_MODE_READING))
    return MZ_FALSE;

  if (pZip->m_pState) {
    mz_zip_internal_state *pState = pZip->m_pState;
    pZip->m_pState = NULL;
    mz_zip_array_clear(pZip, &pState->m_central_dir);
    mz_zip_array_clear(pZip, &pState->m_central_dir_offsets);
    mz_zip_array_clear(pZip, &pState->m_sorted_central_dir_offsets);
    if (pState->m_pFile) {
      fclose(pState->m_pFile);
      pState->m_pFile = NULL;
    }
    free(pState);
  }
  pZip->m_zip_mode = MZ_ZIP_MODE_INVALID;

  return MZ_TRUE;
}

static size_t mz_zip_heap_write_func(void *pOpaque, mz_uint64 file_ofs, const void *pBuf, size_t n)
{
  mz_zip_archive *pZip = (mz_zip_archive *) pOpaque;
  mz_zip_internal_state *pState = pZip->m_pState;
  mz_uint64 new_size = MZ_MAX(file_ofs + n, pState->m_mem_size);
  if ((!n) || ((sizeof(size_t) == sizeof(mz_uint32)) && (new_size > 0x7FFFFFFF)))
    return 0;
  if (new_size > pState->m_mem_capacity) {
    void *pNew_block;
    size_t new_capacity = MZ_MAX(64, pState->m_mem_capacity);
    while (new_capacity < new_size)
      new_capacity *= 2;
    if (NULL == (pNew_block = realloc(pState->m_pMem, new_capacity)))
      return 0;
    pState->m_pMem = pNew_block;
    pState->m_mem_capacity = new_capacity;
  }
  memcpy((mz_uint8 *) pState->m_pMem + file_ofs, pBuf, n);
  pState->m_mem_size = (size_t) new_size;
  return n;
}

mz_bool mz_zip_writer_init_from_reader(mz_zip_archive * pZip, const char *pFilename)
{
  mz_zip_internal_state *pState;
  if ((!pZip) || (!pZip->m_pState) || (pZip->m_zip_mode != MZ_ZIP_MODE_READING))
    return MZ_FALSE;
  // No sense in trying to write to an archive that's already at the support max size
  if ((pZip->m_total_files == 0xFFFF) || ((pZip->m_archive_size + MZ_ZIP_CENTRAL_DIR_HEADER_SIZE + MZ_ZIP_LOCAL_DIR_HEADER_SIZE) > 0xFFFFFFFF))
    return MZ_FALSE;

  pState = pZip->m_pState;

  if (pState->m_pFile) {
    // Archive is being read from stdio - try to reopen as writable.
    if (pZip->m_pIO_opaque != pZip)
      return MZ_FALSE;
    if (!pFilename)
      return MZ_FALSE;
    pZip->m_pWrite = mz_zip_file_write_func;
    if (NULL == (pState->m_pFile = freopen(pFilename, "r+b", pState->m_pFile))) {
      // The mz_zip_archive is now in a bogus state because pState->m_pFile is NULL, so just close it.
      mz_zip_reader_end(pZip);
      return MZ_FALSE;
    }
  } else if (pState->m_pMem) {
    // Archive lives in a memory block. Assume it's from the heap that we can resize using the realloc callback.
    if (pZip->m_pIO_opaque != pZip)
      return MZ_FALSE;
    pState->m_mem_capacity = pState->m_mem_size;
    pZip->m_pWrite = mz_zip_heap_write_func;
  }
  // Archive is being read via a user provided read function - make sure the user has specified a write function too.
  else if (!pZip->m_pWrite)
    return MZ_FALSE;

  // Start writing new files at the archive's current central directory location.
  pZip->m_archive_size = pZip->m_central_directory_file_ofs;
  pZip->m_zip_mode = MZ_ZIP_MODE_WRITING;
  pZip->m_central_directory_file_ofs = 0;

  return MZ_TRUE;
}

mz_bool mz_zip_writer_init(mz_zip_archive * pZip)
{
  if ((!pZip) || (pZip->m_pState) || (!pZip->m_pWrite) || (pZip->m_zip_mode != MZ_ZIP_MODE_INVALID))
    return MZ_FALSE;

  if (pZip->m_file_offset_alignment) {
    // Ensure user specified file offset alignment is a power of 2.
    if (pZip->m_file_offset_alignment & (pZip->m_file_offset_alignment - 1))
      return MZ_FALSE;
  }

  pZip->m_zip_mode = MZ_ZIP_MODE_WRITING;
  pZip->m_archive_size = 0;
  pZip->m_central_directory_file_ofs = 0;
  pZip->m_total_files = 0;

  if (NULL == (pZip->m_pState = (mz_zip_internal_state *) malloc(sizeof(mz_zip_internal_state))))
    return MZ_FALSE;
  memset(pZip->m_pState, 0, sizeof(mz_zip_internal_state));
  MZ_ZIP_ARRAY_SET_ELEMENT_SIZE(&pZip->m_pState->m_central_dir, sizeof(mz_uint8));
  MZ_ZIP_ARRAY_SET_ELEMENT_SIZE(&pZip->m_pState->m_central_dir_offsets, sizeof(mz_uint32));
  MZ_ZIP_ARRAY_SET_ELEMENT_SIZE(&pZip->m_pState->m_sorted_central_dir_offsets, sizeof(mz_uint32));
  return MZ_TRUE;
}

mz_bool mz_zip_writer_end(mz_zip_archive * pZip)
{
  mz_zip_internal_state *pState;
  mz_bool status = MZ_TRUE;
  if ((!pZip) || (!pZip->m_pState) || ((pZip->m_zip_mode != MZ_ZIP_MODE_WRITING) && (pZip->m_zip_mode != MZ_ZIP_MODE_WRITING_HAS_BEEN_FINALIZED)))
    return MZ_FALSE;

  pState = pZip->m_pState;
  pZip->m_pState = NULL;
  mz_zip_array_clear(pZip, &pState->m_central_dir);
  mz_zip_array_clear(pZip, &pState->m_central_dir_offsets);
  mz_zip_array_clear(pZip, &pState->m_sorted_central_dir_offsets);
  if (pState->m_pFile) {
    fclose(pState->m_pFile);
    pState->m_pFile = NULL;
  }
  if ((pZip->m_pWrite == mz_zip_heap_write_func) && (pState->m_pMem)) {
    free(pState->m_pMem);
    pState->m_pMem = NULL;
  }

  free(pState);
  pZip->m_zip_mode = MZ_ZIP_MODE_INVALID;
  return status;
}

mz_bool mz_zip_writer_init_file(mz_zip_archive * pZip, const char *pFilename)
{
  FILE *pFile;
  pZip->m_pWrite = mz_zip_file_write_func;
  pZip->m_pIO_opaque = pZip;
  if (!mz_zip_writer_init(pZip))
    return MZ_FALSE;
  if (NULL == (pFile = fopen(pFilename, "wb"))) {
    mz_zip_writer_end(pZip);
    return MZ_FALSE;
  }
  pZip->m_pState->m_pFile = pFile;
  return MZ_TRUE;
}

static mz_bool mz_zip_reader_init_internal(mz_zip_archive * pZip)
{
  if ((!pZip) || (pZip->m_pState) || (pZip->m_zip_mode != MZ_ZIP_MODE_INVALID))
    return MZ_FALSE;

  pZip->m_zip_mode = MZ_ZIP_MODE_READING;
  pZip->m_archive_size = 0;
  pZip->m_central_directory_file_ofs = 0;
  pZip->m_total_files = 0;

  if (NULL == (pZip->m_pState = (mz_zip_internal_state *) malloc(sizeof(mz_zip_internal_state))))
    return MZ_FALSE;
  memset(pZip->m_pState, 0, sizeof(mz_zip_internal_state));
  MZ_ZIP_ARRAY_SET_ELEMENT_SIZE(&pZip->m_pState->m_central_dir, sizeof(mz_uint8));
  MZ_ZIP_ARRAY_SET_ELEMENT_SIZE(&pZip->m_pState->m_central_dir_offsets, sizeof(mz_uint32));
  MZ_ZIP_ARRAY_SET_ELEMENT_SIZE(&pZip->m_pState->m_sorted_central_dir_offsets, sizeof(mz_uint32));
  return MZ_TRUE;
}

static size_t mz_zip_file_read_func(void *pOpaque, mz_uint64 file_ofs, void *pBuf, size_t n)
{
  mz_zip_archive *pZip = (mz_zip_archive *) pOpaque;
  mz_int64 cur_ofs = ftello64(pZip->m_pState->m_pFile);
  if (((mz_int64) file_ofs < 0) || (((cur_ofs != (mz_int64) file_ofs)) && (fseeko64(pZip->m_pState->m_pFile, (mz_int64) file_ofs, SEEK_SET))))
    return 0;
  return fread(pBuf, 1, n, pZip->m_pState->m_pFile);
}

static mz_bool mz_zip_reader_read_central_dir(mz_zip_archive * pZip)
{
  mz_uint cdir_size, num_this_disk, cdir_disk_index;
  mz_uint64 cdir_ofs;
  mz_int64 cur_file_ofs;
  const mz_uint8 *p;
  mz_uint32 buf_u32[4096 / sizeof(mz_uint32)];
  mz_uint8 *pBuf = (mz_uint8 *) buf_u32;
  // Basic sanity checks - reject files which are too small, and check the first 4 bytes of the file to make sure a local header is there.
  if (pZip->m_archive_size < MZ_ZIP_END_OF_CENTRAL_DIR_HEADER_SIZE)
    return MZ_FALSE;
  // Find the end of central directory record by scanning the file from the end towards the beginning.
  cur_file_ofs = MZ_MAX((mz_int64) pZip->m_archive_size - (mz_int64) sizeof(buf_u32), 0);
  for (;;) {
    int i, n = (int) MZ_MIN(sizeof(buf_u32), pZip->m_archive_size - cur_file_ofs);
    if (pZip->m_pRead(pZip->m_pIO_opaque, cur_file_ofs, pBuf, n) != (mz_uint) n)
      return MZ_FALSE;
    for (i = n - 4; i >= 0; --i)
      if (MZ_READ_LE32(pBuf + i) == MZ_ZIP_END_OF_CENTRAL_DIR_HEADER_SIG)
        break;
    if (i >= 0) {
      cur_file_ofs += i;
      break;
    }
    if ((!cur_file_ofs) || ((pZip->m_archive_size - cur_file_ofs) >= (0xFFFF + MZ_ZIP_END_OF_CENTRAL_DIR_HEADER_SIZE)))
      return MZ_FALSE;
    cur_file_ofs = MZ_MAX(cur_file_ofs - (sizeof(buf_u32) - 3), 0);
  }
  // Read and verify the end of central directory record.
  if (pZip->m_pRead(pZip->m_pIO_opaque, cur_file_ofs, pBuf, MZ_ZIP_END_OF_CENTRAL_DIR_HEADER_SIZE) != MZ_ZIP_END_OF_CENTRAL_DIR_HEADER_SIZE)
    return MZ_FALSE;
  if ((MZ_READ_LE32(pBuf + MZ_ZIP_ECDH_SIG_OFS) != MZ_ZIP_END_OF_CENTRAL_DIR_HEADER_SIG) || ((pZip->m_total_files = MZ_READ_LE16(pBuf + MZ_ZIP_ECDH_CDIR_TOTAL_ENTRIES_OFS)) != MZ_READ_LE16(pBuf + MZ_ZIP_ECDH_CDIR_NUM_ENTRIES_ON_DISK_OFS)))
    return MZ_FALSE;

  num_this_disk = MZ_READ_LE16(pBuf + MZ_ZIP_ECDH_NUM_THIS_DISK_OFS);
  cdir_disk_index = MZ_READ_LE16(pBuf + MZ_ZIP_ECDH_NUM_DISK_CDIR_OFS);
  if (((num_this_disk | cdir_disk_index) != 0) && ((num_this_disk != 1) || (cdir_disk_index != 1)))
    return MZ_FALSE;

  if ((cdir_size = MZ_READ_LE32(pBuf + MZ_ZIP_ECDH_CDIR_SIZE_OFS)) < pZip->m_total_files * MZ_ZIP_CENTRAL_DIR_HEADER_SIZE)
    return MZ_FALSE;

  cdir_ofs = MZ_READ_LE32(pBuf + MZ_ZIP_ECDH_CDIR_OFS_OFS);
  if ((cdir_ofs + (mz_uint64) cdir_size) > pZip->m_archive_size)
    return MZ_FALSE;

  pZip->m_central_directory_file_ofs = cdir_ofs;

  if (pZip->m_total_files) {
    mz_uint i, n;
    // Read the entire central directory into a heap block, and allocate another heap block to hold the unsorted central dir file record offsets, and another to hold the sorted indices.
    if ((!mz_zip_array_resize(pZip, &pZip->m_pState->m_central_dir, cdir_size, MZ_FALSE)) || (!mz_zip_array_resize(pZip, &pZip->m_pState->m_central_dir_offsets, pZip->m_total_files, MZ_FALSE)) || (!mz_zip_array_resize(pZip, &pZip->m_pState->m_sorted_central_dir_offsets, pZip->m_total_files, MZ_FALSE)))
      return MZ_FALSE;
    if (pZip->m_pRead(pZip->m_pIO_opaque, cdir_ofs, pZip->m_pState->m_central_dir.m_p, cdir_size) != cdir_size)
      return MZ_FALSE;

    // Now create an index into the central directory file records, do some basic sanity checking on each record, and check for zip64 entries (which are not yet supported).
    p = (const mz_uint8 *) pZip->m_pState->m_central_dir.m_p;
    for (n = cdir_size, i = 0; i < pZip->m_total_files; ++i) {
      mz_uint total_header_size, comp_size, decomp_size, disk_index;
      if ((n < MZ_ZIP_CENTRAL_DIR_HEADER_SIZE) || (MZ_READ_LE32(p) != MZ_ZIP_CENTRAL_DIR_HEADER_SIG))
        return MZ_FALSE;
      MZ_ZIP_ARRAY_ELEMENT(&pZip->m_pState->m_central_dir_offsets, mz_uint32, i) = (mz_uint32) (p - (const mz_uint8 *) pZip->m_pState->m_central_dir.m_p);
      MZ_ZIP_ARRAY_ELEMENT(&pZip->m_pState->m_sorted_central_dir_offsets, mz_uint32, i) = i;
      comp_size = MZ_READ_LE32(p + MZ_ZIP_CDH_COMPRESSED_SIZE_OFS);
      decomp_size = MZ_READ_LE32(p + MZ_ZIP_CDH_DECOMPRESSED_SIZE_OFS);
      if (((!MZ_READ_LE32(p + MZ_ZIP_CDH_METHOD_OFS)) && (decomp_size != comp_size)) || (decomp_size && !comp_size) || (decomp_size == 0xFFFFFFFF) || (comp_size == 0xFFFFFFFF))
        return MZ_FALSE;
      disk_index = MZ_READ_LE16(p + MZ_ZIP_CDH_DISK_START_OFS);
      if ((disk_index != num_this_disk) && (disk_index != 1))
        return MZ_FALSE;
      if (((mz_uint64) MZ_READ_LE32(p + MZ_ZIP_CDH_LOCAL_HEADER_OFS) + MZ_ZIP_LOCAL_DIR_HEADER_SIZE + comp_size) > pZip->m_archive_size)
        return MZ_FALSE;
      if ((total_header_size = MZ_ZIP_CENTRAL_DIR_HEADER_SIZE + MZ_READ_LE16(p + MZ_ZIP_CDH_FILENAME_LEN_OFS) + MZ_READ_LE16(p + MZ_ZIP_CDH_EXTRA_LEN_OFS) + MZ_READ_LE16(p + MZ_ZIP_CDH_COMMENT_LEN_OFS)) > n)
        return MZ_FALSE;
      n -= total_header_size;
      p += total_header_size;
    }
  }
  return MZ_TRUE;
}

mz_bool mz_zip_reader_init_file(mz_zip_archive * pZip, const char *pFilename)
{
  mz_uint64 file_size;
  FILE *pFile = fopen(pFilename, "rb");
  if (!pFile)
    return MZ_FALSE;
  if (fseeko64(pFile, (mz_int64) 0, SEEK_END))
    return MZ_FALSE;
  file_size = ftello64(pFile);
  if (!mz_zip_reader_init_internal(pZip)) {
    fclose(pFile);
    return MZ_FALSE;
  }
  pZip->m_pRead = mz_zip_file_read_func;
  pZip->m_pIO_opaque = pZip;
  pZip->m_pState->m_pFile = pFile;
  pZip->m_archive_size = file_size;
  if (!mz_zip_reader_read_central_dir(pZip)) {
    mz_zip_reader_end(pZip);
    return MZ_FALSE;
  }
  return MZ_TRUE;
}

static mz_bool mz_zip_writer_add_put_buf_callback(const void *pBuf, int len, void *pUser)
{
  mz_zip_writer_add_state *pState = (mz_zip_writer_add_state *) pUser;
  if ((int) pState->m_pZip->m_pWrite(pState->m_pZip->m_pIO_opaque, pState->m_cur_archive_file_ofs, pBuf, len) != len)
    return MZ_FALSE;
  pState->m_cur_archive_file_ofs += len;
  pState->m_comp_size += len;
  return MZ_TRUE;
}

static mz_bool mz_zip_writer_create_local_dir_header(mz_zip_archive * pZip, mz_uint8 * pDst, mz_uint16 filename_size, mz_uint64 uncomp_size, mz_uint64 comp_size, mz_uint32 uncomp_crc32, mz_uint16 method)
{
  (void) pZip;
  memset(pDst, 0, MZ_ZIP_LOCAL_DIR_HEADER_SIZE);
  MZ_WRITE_LE32(pDst + MZ_ZIP_LDH_SIG_OFS, MZ_ZIP_LOCAL_DIR_HEADER_SIG);
  MZ_WRITE_LE16(pDst + MZ_ZIP_LDH_VERSION_NEEDED_OFS, method ? 20 : 0);
  MZ_WRITE_LE16(pDst + MZ_ZIP_LDH_METHOD_OFS, method);
  MZ_WRITE_LE32(pDst + MZ_ZIP_LDH_CRC32_OFS, uncomp_crc32);
  MZ_WRITE_LE32(pDst + MZ_ZIP_LDH_COMPRESSED_SIZE_OFS, comp_size);
  MZ_WRITE_LE32(pDst + MZ_ZIP_LDH_DECOMPRESSED_SIZE_OFS, uncomp_size);
  MZ_WRITE_LE16(pDst + MZ_ZIP_LDH_FILENAME_LEN_OFS, filename_size);
  return MZ_TRUE;
}

static mz_bool mz_zip_writer_create_central_dir_header(mz_zip_archive * pZip, mz_uint8 * pDst, mz_uint16 filename_size, mz_uint64 uncomp_size, mz_uint64 comp_size, mz_uint32 uncomp_crc32, mz_uint16 method, mz_uint64 local_header_ofs, mz_uint32 ext_attributes)
{
  (void) pZip;
  memset(pDst, 0, MZ_ZIP_CENTRAL_DIR_HEADER_SIZE);
  MZ_WRITE_LE32(pDst + MZ_ZIP_CDH_SIG_OFS, MZ_ZIP_CENTRAL_DIR_HEADER_SIG);
  MZ_WRITE_LE16(pDst + MZ_ZIP_CDH_VERSION_NEEDED_OFS, method ? 20 : 0);
  MZ_WRITE_LE16(pDst + MZ_ZIP_CDH_METHOD_OFS, method);
  MZ_WRITE_LE32(pDst + MZ_ZIP_CDH_CRC32_OFS, uncomp_crc32);
  MZ_WRITE_LE32(pDst + MZ_ZIP_CDH_COMPRESSED_SIZE_OFS, comp_size);
  MZ_WRITE_LE32(pDst + MZ_ZIP_CDH_DECOMPRESSED_SIZE_OFS, uncomp_size);
  MZ_WRITE_LE16(pDst + MZ_ZIP_CDH_FILENAME_LEN_OFS, filename_size);
  MZ_WRITE_LE32(pDst + MZ_ZIP_CDH_EXTERNAL_ATTR_OFS, ext_attributes);
  MZ_WRITE_LE32(pDst + MZ_ZIP_CDH_LOCAL_HEADER_OFS, local_header_ofs);
  return MZ_TRUE;
}

static mz_bool mz_zip_writer_add_to_central_dir(mz_zip_archive * pZip, const char *pFilename, mz_uint16 filename_size, mz_uint64 uncomp_size, mz_uint64 comp_size, mz_uint32 uncomp_crc32, mz_uint16 method, mz_uint64 local_header_ofs, mz_uint32 ext_attributes)
{
  mz_zip_internal_state *pState = pZip->m_pState;
  mz_uint32 central_dir_ofs = (mz_uint32) pState->m_central_dir.m_size;
  size_t orig_central_dir_size = pState->m_central_dir.m_size;
  mz_uint8 central_dir_header[MZ_ZIP_CENTRAL_DIR_HEADER_SIZE];

  // No zip64 support yet
  if ((local_header_ofs > 0xFFFFFFFF) || (((mz_uint64) pState->m_central_dir.m_size + MZ_ZIP_CENTRAL_DIR_HEADER_SIZE + filename_size) > 0xFFFFFFFF))
    return MZ_FALSE;

  if (!mz_zip_writer_create_central_dir_header(pZip, central_dir_header, filename_size, uncomp_size, comp_size, uncomp_crc32, method, local_header_ofs, ext_attributes))
    return MZ_FALSE;

  if ((!mz_zip_array_push_back(pZip, &pState->m_central_dir, central_dir_header, MZ_ZIP_CENTRAL_DIR_HEADER_SIZE)) || (!mz_zip_array_push_back(pZip, &pState->m_central_dir, pFilename, filename_size)) || (!mz_zip_array_push_back(pZip, &pState->m_central_dir_offsets, &central_dir_ofs, 1))) {
    // Try to push the central directory array back into its original state.
    mz_zip_array_resize(pZip, &pState->m_central_dir, orig_central_dir_size, MZ_FALSE);
    return MZ_FALSE;
  }

  return MZ_TRUE;
}

mz_bool mz_zip_writer_add_mem(mz_zip_archive * pZip, const char *pArchive_name, const void *pBuf, size_t buf_size, mz_uint level_and_flags)
{
  mz_uint64 uncomp_size = 0;
  mz_uint32 uncomp_crc32 = 0;
  mz_uint16 method = 0;
  mz_uint level, ext_attributes = 0, num_alignment_padding_bytes;
  mz_uint64 local_dir_header_ofs = pZip->m_archive_size, cur_archive_file_ofs = pZip->m_archive_size, comp_size = 0;
  size_t archive_name_size;
  mz_uint8 local_dir_header[MZ_ZIP_LOCAL_DIR_HEADER_SIZE];
  tdefl_compressor *pComp = NULL;
  mz_bool store_data_uncompressed;
  mz_zip_internal_state *pState;

  if ((int) level_and_flags < 0)
    level_and_flags = MZ_DEFAULT_LEVEL;
  level = level_and_flags & 0xF;
  store_data_uncompressed = !level;

  if ((!pZip) || (!pZip->m_pState) || (pZip->m_zip_mode != MZ_ZIP_MODE_WRITING) || ((buf_size) && (!pBuf)) || (!pArchive_name) || (pZip->m_total_files == 0xFFFF) || (level > MZ_UBER_COMPRESSION))
    return MZ_FALSE;

  pState = pZip->m_pState;

  // No zip64 support yet
  if (buf_size > 0xFFFFFFFF)
    return MZ_FALSE;
  if (!mz_zip_writer_validate_archive_name(pArchive_name))
    return MZ_FALSE;

  archive_name_size = strlen(pArchive_name);
  if (archive_name_size > 0xFFFF)
    return MZ_FALSE;

  num_alignment_padding_bytes = mz_zip_writer_compute_padding_needed_for_file_alignment(pZip);

  // no zip64 support yet
  if ((pZip->m_total_files == 0xFFFF) || ((pZip->m_archive_size + num_alignment_padding_bytes + MZ_ZIP_LOCAL_DIR_HEADER_SIZE + MZ_ZIP_CENTRAL_DIR_HEADER_SIZE + archive_name_size) > 0xFFFFFFFF))
    return MZ_FALSE;

  if ((archive_name_size) && (pArchive_name[archive_name_size - 1] == '/')) {
    // Set DOS Subdirectory attribute bit.
    ext_attributes |= 0x10;
    // Subdirectories cannot contain data.
    if (buf_size)
      return MZ_FALSE;
  }
  // Try to do any allocations before writing to the archive, so if an allocation fails the file remains unmodified. (A good idea if we're doing an in-place modification.)
  if ((!mz_zip_array_ensure_room(pZip, &pState->m_central_dir, MZ_ZIP_CENTRAL_DIR_HEADER_SIZE + archive_name_size)) || (!mz_zip_array_ensure_room(pZip, &pState->m_central_dir_offsets, 1)))
    return MZ_FALSE;

  if ((!store_data_uncompressed) && (buf_size)) {
    if (NULL == (pComp = (tdefl_compressor *) malloc(sizeof(tdefl_compressor))))
      return MZ_FALSE;
  }

  if (!mz_zip_writer_write_zeros(pZip, cur_archive_file_ofs, num_alignment_padding_bytes + sizeof(local_dir_header))) {
    free(pComp);
    return MZ_FALSE;
  }
  local_dir_header_ofs += num_alignment_padding_bytes;
  if (pZip->m_file_offset_alignment) {
    assert((local_dir_header_ofs & (pZip->m_file_offset_alignment - 1)) == 0);
  }
  cur_archive_file_ofs += num_alignment_padding_bytes + sizeof(local_dir_header);

  MZ_CLEAR_OBJ(local_dir_header);
  if (pZip->m_pWrite(pZip->m_pIO_opaque, cur_archive_file_ofs, pArchive_name, archive_name_size) != archive_name_size) {
    free(pComp);
    return MZ_FALSE;
  }
  cur_archive_file_ofs += archive_name_size;

  uncomp_crc32 = (mz_uint32) mz_crc32(MZ_CRC32_INIT, (const mz_uint8 *) pBuf, buf_size);
  uncomp_size = buf_size;
  if (uncomp_size <= 3) {
    level = 0;
    store_data_uncompressed = MZ_TRUE;
  }
  if (store_data_uncompressed) {
    if (pZip->m_pWrite(pZip->m_pIO_opaque, cur_archive_file_ofs, pBuf, buf_size) != buf_size) {
      free(pComp);
      return MZ_FALSE;
    }
    cur_archive_file_ofs += buf_size;
    comp_size = buf_size;
  } else if (buf_size) {
    mz_zip_writer_add_state state;

    state.m_pZip = pZip;
    state.m_cur_archive_file_ofs = cur_archive_file_ofs;
    state.m_comp_size = 0;

    if ((tdefl_init(pComp, mz_zip_writer_add_put_buf_callback, &state, s_tdefl_num_probes[(level >= 0) ? MZ_MIN(10, level) : MZ_DEFAULT_LEVEL]) != TDEFL_STATUS_OKAY) || (tdefl_compress(pComp, pBuf, &buf_size, TDEFL_FINISH) != TDEFL_STATUS_DONE)) {
      free(pComp);
      return MZ_FALSE;
    }

    comp_size = state.m_comp_size;
    cur_archive_file_ofs = state.m_cur_archive_file_ofs;

    method = MZ_DEFLATED;
  }

  free(pComp);
  pComp = NULL;

  // no zip64 support yet
  if ((comp_size > 0xFFFFFFFF) || (cur_archive_file_ofs > 0xFFFFFFFF))
    return MZ_FALSE;

  if (!mz_zip_writer_create_local_dir_header(pZip, local_dir_header, (mz_uint16) archive_name_size, uncomp_size, comp_size, uncomp_crc32, method))
    return MZ_FALSE;

  if (pZip->m_pWrite(pZip->m_pIO_opaque, local_dir_header_ofs, local_dir_header, sizeof(local_dir_header)) != sizeof(local_dir_header))
    return MZ_FALSE;

  if (!mz_zip_writer_add_to_central_dir(pZip, pArchive_name, (mz_uint16) archive_name_size, uncomp_size, comp_size, uncomp_crc32, method, local_dir_header_ofs, ext_attributes))
    return MZ_FALSE;

  pZip->m_total_files++;
  pZip->m_archive_size = cur_archive_file_ofs;

  return MZ_TRUE;
}

mz_bool mz_zip_writer_finalize_archive(mz_zip_archive * pZip)
{
  mz_zip_internal_state *pState;
  mz_uint64 central_dir_ofs, central_dir_size;
  mz_uint8 hdr[MZ_ZIP_END_OF_CENTRAL_DIR_HEADER_SIZE];

  if ((!pZip) || (!pZip->m_pState) || (pZip->m_zip_mode != MZ_ZIP_MODE_WRITING))
    return MZ_FALSE;

  pState = pZip->m_pState;

  // no zip64 support yet
  if ((pZip->m_total_files > 0xFFFF) || ((pZip->m_archive_size + pState->m_central_dir.m_size + MZ_ZIP_END_OF_CENTRAL_DIR_HEADER_SIZE) > 0xFFFFFFFF))
    return MZ_FALSE;

  central_dir_ofs = 0;
  central_dir_size = 0;
  if (pZip->m_total_files) {
    // Write central directory
    central_dir_ofs = pZip->m_archive_size;
    central_dir_size = pState->m_central_dir.m_size;
    pZip->m_central_directory_file_ofs = central_dir_ofs;
    if (pZip->m_pWrite(pZip->m_pIO_opaque, central_dir_ofs, pState->m_central_dir.m_p, (size_t) central_dir_size) != central_dir_size)
      return MZ_FALSE;
    pZip->m_archive_size += central_dir_size;
  }
  // Write end of central directory record
  MZ_CLEAR_OBJ(hdr);
  MZ_WRITE_LE32(hdr + MZ_ZIP_ECDH_SIG_OFS, MZ_ZIP_END_OF_CENTRAL_DIR_HEADER_SIG);
  MZ_WRITE_LE16(hdr + MZ_ZIP_ECDH_CDIR_NUM_ENTRIES_ON_DISK_OFS, pZip->m_total_files);
  MZ_WRITE_LE16(hdr + MZ_ZIP_ECDH_CDIR_TOTAL_ENTRIES_OFS, pZip->m_total_files);
  MZ_WRITE_LE32(hdr + MZ_ZIP_ECDH_CDIR_SIZE_OFS, central_dir_size);
  MZ_WRITE_LE32(hdr + MZ_ZIP_ECDH_CDIR_OFS_OFS, central_dir_ofs);

  if (pZip->m_pWrite(pZip->m_pIO_opaque, pZip->m_archive_size, hdr, sizeof(hdr)) != sizeof(hdr))
    return MZ_FALSE;
  if ((pState->m_pFile) && (fflush(pState->m_pFile) == EOF))
    return MZ_FALSE;

  pZip->m_archive_size += sizeof(hdr);

  pZip->m_zip_mode = MZ_ZIP_MODE_WRITING_HAS_BEEN_FINALIZED;
  return MZ_TRUE;
}

mz_bool mz_zip_add_mem_to_archive_file_in_place(const char *pZip_filename, const char *pArchive_name, const void *pBuf, size_t buf_size, mz_uint level_and_flags)
{
  mz_bool status, created_new_archive = MZ_FALSE;
  mz_zip_archive zip_archive;
  struct stat file_stat;
  MZ_CLEAR_OBJ(zip_archive);
  if ((int) level_and_flags < 0)
    level_and_flags = MZ_DEFAULT_LEVEL;
  if ((!pZip_filename) || (!pArchive_name) || ((buf_size) && (!pBuf)) || ((level_and_flags & 0xF) > MZ_UBER_COMPRESSION))
    return MZ_FALSE;
  if (!mz_zip_writer_validate_archive_name(pArchive_name))
    return MZ_FALSE;
  if (stat(pZip_filename, &file_stat) != 0) {
    // Create a new archive.
    if (!mz_zip_writer_init_file(&zip_archive, pZip_filename))
      return MZ_FALSE;
    created_new_archive = MZ_TRUE;
  } else {
    // Append to an existing archive.
    if (!mz_zip_reader_init_file(&zip_archive, pZip_filename))
      return MZ_FALSE;
    if (!mz_zip_writer_init_from_reader(&zip_archive, pZip_filename)) {
      mz_zip_reader_end(&zip_archive);
      return MZ_FALSE;
    }
  }
  status = mz_zip_writer_add_mem(&zip_archive, pArchive_name, pBuf, buf_size, level_and_flags);
  // Always finalize, even if adding failed for some reason, so we have a valid central directory. (This may not always succeed, but we can try.)
  if (!mz_zip_writer_finalize_archive(&zip_archive))
    status = MZ_FALSE;
  if (!mz_zip_writer_end(&zip_archive))
    status = MZ_FALSE;
  if ((!status) && (created_new_archive))
    remove(pZip_filename);
  return status;
}

mz_uint mz_zip_reader_get_num_files(mz_zip_archive * pZip)
{
  return pZip ? pZip->m_total_files : 0;
}

static const mz_uint8 *mz_zip_reader_get_cdh(mz_zip_archive * pZip, mz_uint file_index)
{
  if ((!pZip) || (!pZip->m_pState) || (file_index >= pZip->m_total_files) || (pZip->m_zip_mode != MZ_ZIP_MODE_READING))
    return NULL;
  return &MZ_ZIP_ARRAY_ELEMENT(&pZip->m_pState->m_central_dir, mz_uint8, MZ_ZIP_ARRAY_ELEMENT(&pZip->m_pState->m_central_dir_offsets, mz_uint32, file_index));
}

mz_bool mz_zip_reader_is_file_a_directory(mz_zip_archive * pZip, mz_uint file_index)
{
  mz_uint filename_len, internal_attr, external_attr;
  const mz_uint8 *p = mz_zip_reader_get_cdh(pZip, file_index);
  if (!p)
    return MZ_FALSE;

  internal_attr = MZ_READ_LE16(p + MZ_ZIP_CDH_INTERNAL_ATTR_OFS);
  external_attr = MZ_READ_LE32(p + MZ_ZIP_CDH_EXTERNAL_ATTR_OFS);
  if ((!internal_attr) && ((external_attr & 0x10) != 0))
    return MZ_TRUE;

  filename_len = MZ_READ_LE16(p + MZ_ZIP_CDH_FILENAME_LEN_OFS);
  if (filename_len) {
    if (*(p + MZ_ZIP_CENTRAL_DIR_HEADER_SIZE + filename_len - 1) == '/')
      return MZ_TRUE;
  }

  return MZ_FALSE;
}

mz_bool mz_zip_reader_file_stat(mz_zip_archive * pZip, mz_uint file_index, mz_zip_archive_file_stat * pStat)
{
  mz_uint n;
  const mz_uint8 *p = mz_zip_reader_get_cdh(pZip, file_index);
  if ((!p) || (!pStat))
    return MZ_FALSE;

  // Unpack the central directory record.
  pStat->m_file_index = file_index;
  pStat->m_central_dir_ofs = MZ_ZIP_ARRAY_ELEMENT(&pZip->m_pState->m_central_dir_offsets, mz_uint32, file_index);
  pStat->m_version_made_by = MZ_READ_LE16(p + MZ_ZIP_CDH_VERSION_MADE_BY_OFS);
  pStat->m_version_needed = MZ_READ_LE16(p + MZ_ZIP_CDH_VERSION_NEEDED_OFS);
  pStat->m_bit_flag = MZ_READ_LE16(p + MZ_ZIP_CDH_BIT_FLAG_OFS);
  pStat->m_method = MZ_READ_LE16(p + MZ_ZIP_CDH_METHOD_OFS);
  pStat->m_crc32 = MZ_READ_LE32(p + MZ_ZIP_CDH_CRC32_OFS);
  pStat->m_comp_size = MZ_READ_LE32(p + MZ_ZIP_CDH_COMPRESSED_SIZE_OFS);
  pStat->m_uncomp_size = MZ_READ_LE32(p + MZ_ZIP_CDH_DECOMPRESSED_SIZE_OFS);
  pStat->m_internal_attr = MZ_READ_LE16(p + MZ_ZIP_CDH_INTERNAL_ATTR_OFS);
  pStat->m_external_attr = MZ_READ_LE32(p + MZ_ZIP_CDH_EXTERNAL_ATTR_OFS);
  pStat->m_local_header_ofs = MZ_READ_LE32(p + MZ_ZIP_CDH_LOCAL_HEADER_OFS);

  // Copy as much of the filename and comment as possible.
  n = MZ_READ_LE16(p + MZ_ZIP_CDH_FILENAME_LEN_OFS);
  n = MZ_MIN(n, MZ_ZIP_MAX_ARCHIVE_FILENAME_SIZE - 1);
  memcpy(pStat->m_filename, p + MZ_ZIP_CENTRAL_DIR_HEADER_SIZE, n);
  pStat->m_filename[n] = '\0';

  n = MZ_READ_LE16(p + MZ_ZIP_CDH_COMMENT_LEN_OFS);
  n = MZ_MIN(n, MZ_ZIP_MAX_ARCHIVE_FILE_COMMENT_SIZE - 1);
  pStat->m_comment_size = n;
  memcpy(pStat->m_comment, p + MZ_ZIP_CENTRAL_DIR_HEADER_SIZE + MZ_READ_LE16(p + MZ_ZIP_CDH_FILENAME_LEN_OFS) + MZ_READ_LE16(p + MZ_ZIP_CDH_EXTRA_LEN_OFS), n);
  pStat->m_comment[n] = '\0';

  return MZ_TRUE;
}

static mz_bool mz_zip_reader_string_equal(const char *pA, const char *pB, mz_uint len)
{
  return !memcmp(pA, pB, len);
}

int mz_zip_reader_locate_file(mz_zip_archive * pZip, const char *pName)
{
  mz_uint file_index;
  size_t name_len;
  if ((!pZip) || (!pZip->m_pState) || (!pName) || (pZip->m_zip_mode != MZ_ZIP_MODE_READING))
    return -1;
  name_len = strlen(pName);
  if (name_len > 0xFFFF)
    return -1;
  for (file_index = 0; file_index < pZip->m_total_files; file_index++) {
    const mz_uint8 *pHeader = &MZ_ZIP_ARRAY_ELEMENT(&pZip->m_pState->m_central_dir, mz_uint8, MZ_ZIP_ARRAY_ELEMENT(&pZip->m_pState->m_central_dir_offsets, mz_uint32, file_index));
    mz_uint filename_len = MZ_READ_LE16(pHeader + MZ_ZIP_CDH_FILENAME_LEN_OFS);
    const char *pFilename = (const char *) pHeader + MZ_ZIP_CENTRAL_DIR_HEADER_SIZE;
    if (filename_len < name_len)
      continue;
    if ((filename_len == name_len) && (mz_zip_reader_string_equal(pName, pFilename, filename_len)))
      return file_index;
  }
  return -1;
}

mz_bool mz_zip_reader_extract_to_mem_no_alloc(mz_zip_archive * pZip, mz_uint file_index, void *pBuf, size_t buf_size)
{
  int status = TINFL_STATUS_DONE;
  mz_uint64 needed_size, cur_file_ofs, comp_remaining, out_buf_ofs = 0, read_buf_size, read_buf_ofs = 0, read_buf_avail;
  mz_zip_archive_file_stat file_stat;
  void *pRead_buf;
  mz_uint32 local_header_u32[(MZ_ZIP_LOCAL_DIR_HEADER_SIZE + sizeof(mz_uint32) - 1) / sizeof(mz_uint32)];
  mz_uint8 *pLocal_header = (mz_uint8 *) local_header_u32;
  tinfl_decompressor inflator;

  if ((buf_size) && (!pBuf))
    return MZ_FALSE;

  if (!mz_zip_reader_file_stat(pZip, file_index, &file_stat))
    return MZ_FALSE;

  if (!file_stat.m_comp_size)
    return MZ_TRUE;

  // Encryption and patch files are not supported.
  if (file_stat.m_bit_flag & (1 | 32))
    return MZ_FALSE;

  // This function only supports stored and deflate.
  if ((file_stat.m_method != 0) && (file_stat.m_method != MZ_DEFLATED))
    return MZ_FALSE;

  // Ensure supplied output buffer is large enough.
  needed_size = file_stat.m_uncomp_size;
  if (buf_size < needed_size)
    return MZ_FALSE;

  // Read and parse the local directory entry.
  cur_file_ofs = file_stat.m_local_header_ofs;
  if (pZip->m_pRead(pZip->m_pIO_opaque, cur_file_ofs, pLocal_header, MZ_ZIP_LOCAL_DIR_HEADER_SIZE) != MZ_ZIP_LOCAL_DIR_HEADER_SIZE)
    return MZ_FALSE;
  if (MZ_READ_LE32(pLocal_header) != MZ_ZIP_LOCAL_DIR_HEADER_SIG)
    return MZ_FALSE;

  cur_file_ofs += MZ_ZIP_LOCAL_DIR_HEADER_SIZE + MZ_READ_LE16(pLocal_header + MZ_ZIP_LDH_FILENAME_LEN_OFS) + MZ_READ_LE16(pLocal_header + MZ_ZIP_LDH_EXTRA_LEN_OFS);
  if ((cur_file_ofs + file_stat.m_comp_size) > pZip->m_archive_size)
    return MZ_FALSE;

  if (!file_stat.m_method) {
    // The file is stored or the caller has requested the compressed data.
    if (pZip->m_pRead(pZip->m_pIO_opaque, cur_file_ofs, pBuf, (size_t) needed_size) != needed_size)
      return MZ_FALSE;
    return (mz_crc32(MZ_CRC32_INIT, (const mz_uint8 *) pBuf, (size_t) file_stat.m_uncomp_size) == file_stat.m_crc32);
  }
  // Decompress the file either directly from memory or from a file input buffer.
  (&inflator)->m_state = 0;

  if (pZip->m_pState->m_pMem) {
    // Read directly from the archive in memory.
    pRead_buf = (mz_uint8 *) pZip->m_pState->m_pMem + cur_file_ofs;
    read_buf_size = read_buf_avail = file_stat.m_comp_size;
    comp_remaining = 0;
  } else {
    // Temporarily allocate a read buffer.
    read_buf_size = MZ_MIN(file_stat.m_comp_size, MZ_ZIP_MAX_IO_BUF_SIZE);
    if (((sizeof(size_t) == sizeof(mz_uint32))) && (read_buf_size > 0x7FFFFFFF))
      return MZ_FALSE;
    if (NULL == (pRead_buf = malloc((size_t) read_buf_size)))
      return MZ_FALSE;
    read_buf_avail = 0;
    comp_remaining = file_stat.m_comp_size;
  }

  do {
    size_t in_buf_size, out_buf_size = (size_t) (file_stat.m_uncomp_size - out_buf_ofs);
    if ((!read_buf_avail) && (!pZip->m_pState->m_pMem)) {
      read_buf_avail = MZ_MIN(read_buf_size, comp_remaining);
      if (pZip->m_pRead(pZip->m_pIO_opaque, cur_file_ofs, pRead_buf, (size_t) read_buf_avail) != read_buf_avail) {
        status = TINFL_STATUS_FAILED;
        break;
      }
      cur_file_ofs += read_buf_avail;
      comp_remaining -= read_buf_avail;
      read_buf_ofs = 0;
    }
    in_buf_size = (size_t) read_buf_avail;
    status = tinfl_decompress(&inflator, (mz_uint8 *) pRead_buf + read_buf_ofs, &in_buf_size, (mz_uint8 *) pBuf, (mz_uint8 *) pBuf + out_buf_ofs, &out_buf_size, comp_remaining);
    read_buf_avail -= in_buf_size;
    read_buf_ofs += in_buf_size;
    out_buf_ofs += out_buf_size;
  } while (status == TINFL_STATUS_NEEDS_MORE_INPUT);

  if (status == TINFL_STATUS_DONE) {
    // Make sure the entire file was decompressed, and check its CRC.
    if ((out_buf_ofs != file_stat.m_uncomp_size) || (mz_crc32(MZ_CRC32_INIT, (const mz_uint8 *) pBuf, (size_t) file_stat.m_uncomp_size) != file_stat.m_crc32))
      status = TINFL_STATUS_FAILED;
  }

  if (!pZip->m_pState->m_pMem)
    free(pRead_buf);

  return status == TINFL_STATUS_DONE;
}

void *mz_zip_reader_extract_to_heap(mz_zip_archive * pZip, mz_uint file_index, size_t * pSize)
{
  mz_uint64 alloc_size;
  const mz_uint8 *p = mz_zip_reader_get_cdh(pZip, file_index);
  void *pBuf;

  if (pSize)
    *pSize = 0;
  if (!p)
    return NULL;

  alloc_size = MZ_READ_LE32(p + MZ_ZIP_CDH_DECOMPRESSED_SIZE_OFS);
  if (((sizeof(size_t) == sizeof(mz_uint32))) && (alloc_size > 0x7FFFFFFF))
    return NULL;
  if (NULL == (pBuf = malloc((size_t) alloc_size)))
    return NULL;

  if (!mz_zip_reader_extract_to_mem_no_alloc(pZip, file_index, pBuf, (size_t) alloc_size)) {
    free(pBuf);
    return NULL;
  }

  if (pSize)
    *pSize = (size_t) alloc_size;
  return pBuf;
}

void *mz_zip_reader_extract_file_to_heap(mz_zip_archive * pZip, const char *pFilename, size_t * pSize)
{
  int file_index = mz_zip_reader_locate_file(pZip, pFilename);
  if (file_index < 0) {
    if (pSize)
      *pSize = 0;
    return MZ_FALSE;
  }
  return mz_zip_reader_extract_to_heap(pZip, file_index, pSize);
}
