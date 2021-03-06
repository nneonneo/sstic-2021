/*
   This file has been generated by IDA.
   It contains local type definitions from
   the type library 'service'
*/

#define __int8 char
#define __int16 short
#define __int32 int
#define __int64 long long

struct $17E8534BCB72EE42B6B6995F8B90F203;

/* 1 */
struct __attribute__((aligned(8))) Elf64_Sym
{
  unsigned __int32 st_name;
  unsigned __int8 st_info;
  unsigned __int8 st_other;
  unsigned __int16 st_shndx;
  unsigned __int64 st_value;
  unsigned __int64 st_size;
};

/* 2 */
struct Elf64_Rela
{
  unsigned __int64 r_offset;
  unsigned __int64 r_info;
  __int64 r_addend;
};

/* 3 */
struct Elf64_Dyn
{
  unsigned __int64 d_tag;
  unsigned __int64 d_un;
};

/* 5 */
typedef $17E8534BCB72EE42B6B6995F8B90F203 __sigset_t;

/* 4 */
typedef __sigset_t sigset_t;

/* 6 */
struct $17E8534BCB72EE42B6B6995F8B90F203
{
  unsigned __int64 __val[16];
};

/* 8 */
typedef unsigned __int64 size_t;

/* 7 */
struct iovec
{
  void *iov_base;
  size_t iov_len;
};

/* 11 */
typedef unsigned __int64 __rlim64_t;

/* 10 */
typedef __rlim64_t rlim64_t;

/* 9 */
struct rlimit64
{
  rlim64_t rlim_cur;
  rlim64_t rlim_max;
};

/* 13 */
typedef __int64 __time_t;

/* 14 */
typedef __int64 __syscall_slong_t;

/* 12 */
struct timespec
{
  __time_t tv_sec;
  __syscall_slong_t tv_nsec;
};

/* 15 */
struct __va_list_tag
{
  unsigned int gp_offset;
  unsigned int fp_offset;
  void *overflow_arg_area;
  void *reg_save_area;
};

/* 16 */
typedef __va_list_tag gcc_va_list[1];

/* 18 */
typedef unsigned __int16 sa_family_t;

/* 20 */
typedef unsigned __int16 uint16_t;

/* 19 */
typedef uint16_t in_port_t;

/* 23 */
typedef unsigned int uint32_t;

/* 22 */
typedef uint32_t in_addr_t;

/* 21 */
struct in_addr
{
  in_addr_t s_addr;
};

/* 17 */
struct sockaddr_in
{
  sa_family_t sin_family;
  in_port_t sin_port;
  in_addr sin_addr;
  unsigned __int8 sin_zero[8];
};

/* 24 */
struct req
{
  unsigned __int8 reqno;
  char payload[16];
};

/* 25 */
union __attribute__((aligned(8))) __m64
{
  unsigned __int64 m64_u64;
  float m64_f32[2];
  __int8 m64_i8[8];
  __int16 m64_i16[4];
  __int32 m64_i32[2];
  __int64 m64_i64;
  unsigned __int8 m64_u8[8];
  unsigned __int16 m64_u16[4];
  unsigned __int32 m64_u32[2];
};

/* 26 */
union __attribute__((aligned(16))) __m128
{
  float m128_f32[4];
  unsigned __int64 m128_u64[2];
  __int8 m128_i8[16];
  __int16 m128_i16[8];
  __int32 m128_i32[4];
  __int64 m128_i64[2];
  unsigned __int8 m128_u8[16];
  unsigned __int16 m128_u16[8];
  unsigned __int32 m128_u32[4];
};

/* 27 */
struct __m128d
{
  double m128d_f64[2];
};

/* 28 */
union __attribute__((aligned(16))) __m128i
{
  __int8 m128i_i8[16];
  __int16 m128i_i16[8];
  __int32 m128i_i32[4];
  __int64 m128i_i64[2];
  unsigned __int8 m128i_u8[16];
  unsigned __int16 m128i_u16[8];
  unsigned __int32 m128i_u32[4];
  unsigned __int64 m128i_u64[2];
};

/* 29 */
union __attribute__((aligned(32))) __m256
{
  float m256_f32[8];
};

/* 30 */
union __attribute__((aligned(32))) __m256d
{
  double m256d_f64[4];
};

/* 31 */
union __attribute__((aligned(32))) __m256i
{
  __int8 m256i_i8[32];
  __int16 m256i_i16[16];
  __int32 m256i_i32[8];
  __int64 m256i_i64[4];
  unsigned __int8 m256i_u8[32];
  unsigned __int16 m256i_u16[16];
  unsigned __int32 m256i_u32[8];
  unsigned __int64 m256i_u64[4];
};

/* 32 */
struct __attribute__((aligned(8))) filedesc
{
  uint64_t ident;
  int64_t perms;
};

/* 33 */
struct request
{
  uint64_t ident;
  uint64_t perms;
};

/* 35 */
typedef unsigned __int64 __dev_t;

/* 36 */
typedef unsigned __int64 __ino_t;

/* 37 */
typedef unsigned __int64 __nlink_t;

/* 38 */
typedef unsigned int __mode_t;

/* 39 */
typedef unsigned int __uid_t;

/* 40 */
typedef unsigned int __gid_t;

/* 41 */
typedef __int64 __off_t;

/* 42 */
typedef __int64 __blksize_t;

/* 43 */
typedef __int64 __blkcnt_t;

/* 34 */
struct stat
{
  __dev_t st_dev;
  __ino_t st_ino;
  __nlink_t st_nlink;
  __mode_t st_mode;
  __uid_t st_uid;
  __gid_t st_gid;
  int __pad0;
  __dev_t st_rdev;
  __off_t st_size;
  __blksize_t st_blksize;
  __blkcnt_t st_blocks;
  timespec st_atim;
  timespec st_mtim;
  timespec st_ctim;
  __syscall_slong_t __unused[3];
};

/* 46 */
typedef __int64 __suseconds_t;

/* 45 */
struct timeval
{
  __time_t tv_sec;
  __suseconds_t tv_usec;
};

/* 44 */
struct itimerval
{
  timeval it_interval;
  timeval it_value;
};

