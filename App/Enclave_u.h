#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "user_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_MALLOC_DEFINED__
#define OCALL_MALLOC_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_malloc, (OMem* mem));
#endif
#ifndef OCALL_RESLUTCP_DEFINED__
#define OCALL_RESLUTCP_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_reslutcp, (OMem* mem, unsigned char* str, int count, uint8_t* ecount));
#endif
#ifndef OCALL_OPEN_DEFINED__
#define OCALL_OPEN_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_open, (const char* filename, int flags, mode_t mode, int* perrno));
#endif
#ifndef OCALL_FALLOCATE_DEFINED__
#define OCALL_FALLOCATE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fallocate, (int fd, int mode, off_t offset, off_t len, int* perrno));
#endif
#ifndef OCALL_FCNTL_FLOCK_DEFINED__
#define OCALL_FCNTL_FLOCK_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fcntl_flock, (int fd, int cmd, struct flock* p, int* perrno));
#endif
#ifndef OCALL_FCNTL_INT_DEFINED__
#define OCALL_FCNTL_INT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fcntl_int, (int fd, int cmd, int pa, int* perrno));
#endif
#ifndef OCALL_FCNTL_VOID_DEFINED__
#define OCALL_FCNTL_VOID_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fcntl_void, (int fd, int cmd, int* perrno));
#endif
#ifndef OCALL_STAT_DEFINED__
#define OCALL_STAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_stat, (const char* pathname, struct stat* buf, int* perrno));
#endif
#ifndef OCALL_FSTAT_DEFINED__
#define OCALL_FSTAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fstat, (int fd, struct stat* buf, int* perrno));
#endif
#ifndef OCALL_FCHMOD_DEFINED__
#define OCALL_FCHMOD_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fchmod, (int fd, unsigned int mode, int* perrno));
#endif
#ifndef OCALL_MKDIR_DEFINED__
#define OCALL_MKDIR_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mkdir, (const char* pathname, mode_t mode, int* perrno));
#endif
#ifndef OCALL_READ_DEFINED__
#define OCALL_READ_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read, (int file, void* buf, size_t count, int* perrno));
#endif
#ifndef OCALL_WRITE_DEFINED__
#define OCALL_WRITE_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write, (int file, const void* buf, size_t count, int* perrno));
#endif
#ifndef OCALL_CLOSE_DEFINED__
#define OCALL_CLOSE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_close, (int fd, int* perrno));
#endif
#ifndef OCALL_FCHOWN_DEFINED__
#define OCALL_FCHOWN_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fchown, (int fd, uid_t owner, gid_t group, int* perrno));
#endif
#ifndef OCALL_GETCWD_DEFINED__
#define OCALL_GETCWD_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getcwd, (char* buf, size_t size, int* perrno));
#endif
#ifndef OCALL_TRUNCATE_DEFINED__
#define OCALL_TRUNCATE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_truncate, (const char* path, off_t length, int* perrno));
#endif
#ifndef OCALL_FTRUNCATE_DEFINED__
#define OCALL_FTRUNCATE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ftruncate, (int fd, off_t length, int* perrno));
#endif
#ifndef OCALL_PREAD_DEFINED__
#define OCALL_PREAD_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pread, (int fd, void* buf, size_t count, off_t offset, int* perrno));
#endif
#ifndef OCALL_PWRITE_DEFINED__
#define OCALL_PWRITE_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pwrite, (int fd, const void* buf, size_t count, off_t offset, int* perrno));
#endif
#ifndef OCALL_ACCESS_DEFINED__
#define OCALL_ACCESS_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_access, (const char* pathname, int mode, int* perrno));
#endif
#ifndef OCALL_UNLINK_DEFINED__
#define OCALL_UNLINK_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_unlink, (const char* pathname, int* perrno));
#endif
#ifndef OCALL_RMDIR_DEFINED__
#define OCALL_RMDIR_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_rmdir, (const char* pathname, int* perrno));
#endif
#ifndef OCALL_GETEUID_DEFINED__
#define OCALL_GETEUID_DEFINED__
uid_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_geteuid, (void));
#endif
#ifndef OCALL_LSEEK_DEFINED__
#define OCALL_LSEEK_DEFINED__
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lseek, (int fd, off_t offset, int whence, int* perrno));
#endif
#ifndef OCALL_FSYNC_DEFINED__
#define OCALL_FSYNC_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fsync, (int fd, int* perrno));
#endif
#ifndef OCALL_GETPID_DEFINED__
#define OCALL_GETPID_DEFINED__
pid_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getpid, (void));
#endif
#ifndef OCALL_SLEEP_DEFINED__
#define OCALL_SLEEP_DEFINED__
unsigned int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sleep, (unsigned int seconds));
#endif
#ifndef OCALL_RTRESLUT_DEFINED__
#define OCALL_RTRESLUT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_rtreslut, (char* title, size_t count, char* r, size_t size));
#endif
#ifndef OCALL_STRCAT_DEFINED__
#define OCALL_STRCAT_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_strcat, (char* dest, size_t count, const char* src));
#endif
#ifndef OCALL_TIME_DEFINED__
#define OCALL_TIME_DEFINED__
time_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_time, (time_t* t, int* perrno));
#endif
#ifndef OCALL_UTIMES_DEFINED__
#define OCALL_UTIMES_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_utimes, (const char* filename, const struct timeval* times, int* perrno));
#endif
#ifndef OCALL_GETTIMEOFDAY_DEFINED__
#define OCALL_GETTIMEOFDAY_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_gettimeofday, (struct timeval* tv, int* perrno));
#endif
#ifndef OCALL_GETENV_DEFINED__
#define OCALL_GETENV_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getenv, (const char* name, int* perrno));
#endif

sgx_status_t ecall_sqlite3_exec_once(sgx_enclave_id_t eid, int* retval, const char* dbname, const char* sql);
sgx_status_t ecall_sqlite3_open(sgx_enclave_id_t eid, int* retval, const char* filename, struct tDB* pdb);
sgx_status_t ecall_sqlite3_open_enc(sgx_enclave_id_t eid, int* retval, const unsigned char* filenameEn, int len, unsigned char* ivec, struct tDB* pdb);
sgx_status_t ecall_sqlite3_prepare(sgx_enclave_id_t eid, int* retval, struct tDB* pdb, const char* zSql, int nBytes);
sgx_status_t ecall_sqlite3_prepare_v2(sgx_enclave_id_t eid, int* retval, struct tDB* pdb, const char* zSql, int nBytes);
sgx_status_t ecall_sqlite3_step(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_sqlite3_finalize(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_sqlite3_exec(sgx_enclave_id_t eid, int* retval, struct tDB* pdb, const char* sql, char* errmsg, size_t count);
sgx_status_t ecall_sqlite3_exec_enc(sgx_enclave_id_t eid, int* retval, struct tDB* pdb, const unsigned char* cipher, int len, unsigned char* ivec, char* errmsg, size_t count, unsigned char* pm, int m_len);
sgx_status_t ecall_sqlite3_close(sgx_enclave_id_t eid, int* retval, struct tDB* pdb);
sgx_status_t ecall_sqlite3_errmsg(sgx_enclave_id_t eid, struct tDB* pdb, char* errmsg, size_t count);
sgx_status_t ecall_sqlite3_ctr_encrypt(sgx_enclave_id_t eid, int* retval, const char* sql, const char* sgx_ctr_key, uint8_t* p_dst, size_t count);
sgx_status_t ecall_sqlite3_ctr_decrypt(sgx_enclave_id_t eid, int* retval, unsigned char* cipher, const char* sgx_ctr_key, uint8_t* p_dst, size_t count);
sgx_status_t ecall_sqlite3_ctr_decrypt_2(sgx_enclave_id_t eid, int* retval, unsigned char* ecount, unsigned char* cipher, const unsigned char* sgx_ctr_key, uint8_t* p_dst, size_t count);
sgx_status_t ecall_transfer_cipher(sgx_enclave_id_t eid, const unsigned char* key, const unsigned char* cipher, unsigned char* ecount, size_t length);
sgx_status_t ecall_vfs_sgx_test(sgx_enclave_id_t eid, int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
