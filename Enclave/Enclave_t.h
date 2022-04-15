#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__
#define __VIVI_SGX_IN_ENCLAVE__
#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "user_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ecall_sqlite3_exec_once(const char* dbname, const char* sql);
int ecall_sqlite3_open(const char* filename, struct tDB* pdb);
int ecall_sqlite3_open_enc(const unsigned char* filenameEn, int len, unsigned char* ivec, struct tDB* pdb);
int ecall_sqlite3_prepare(struct tDB* pdb, const char* zSql, int nBytes);
int ecall_sqlite3_prepare_v2(struct tDB* pdb, const char* zSql, int nBytes);
int ecall_sqlite3_step(void);
int ecall_sqlite3_finalize(void);
int ecall_sqlite3_exec(struct tDB* pdb, const char* sql, char* errmsg, size_t count);
int ecall_sqlite3_exec_enc(struct tDB* pdb, const unsigned char* cipher, int len, unsigned char* ivec, char* errmsg, size_t count, unsigned char* pm, int m_len);
int ecall_sqlite3_close(struct tDB* pdb);
void ecall_sqlite3_errmsg(struct tDB* pdb, char* errmsg, size_t count);
int ecall_sqlite3_ctr_encrypt(const char* sql, const char* sgx_ctr_key, uint8_t* p_dst, size_t count);
int ecall_sqlite3_ctr_decrypt(unsigned char* cipher, const char* sgx_ctr_key, uint8_t* p_dst, size_t count);
int ecall_sqlite3_ctr_decrypt_2(unsigned char* ecount, unsigned char* cipher, const unsigned char* sgx_ctr_key, uint8_t* p_dst, size_t count);
void ecall_transfer_cipher(const unsigned char* key, const unsigned char* cipher, unsigned char* ecount, size_t length);
int ecall_vfs_sgx_test(void);

sgx_status_t SGX_CDECL ocall_malloc(OMem* mem);
sgx_status_t SGX_CDECL ocall_reslutcp(int* retval, OMem* mem, unsigned char* str, int count, uint8_t* ecount);
sgx_status_t SGX_CDECL ocall_open(int* retval, const char* filename, int flags, mode_t mode, int* perrno);
sgx_status_t SGX_CDECL ocall_fallocate(int* retval, int fd, int mode, off_t offset, off_t len, int* perrno);
sgx_status_t SGX_CDECL ocall_fcntl_flock(int* retval, int fd, int cmd, struct flock* p, int* perrno);
sgx_status_t SGX_CDECL ocall_fcntl_int(int* retval, int fd, int cmd, int pa, int* perrno);
sgx_status_t SGX_CDECL ocall_fcntl_void(int* retval, int fd, int cmd, int* perrno);
sgx_status_t SGX_CDECL ocall_stat(int* retval, const char* pathname, struct stat* buf, int* perrno);
sgx_status_t SGX_CDECL ocall_fstat(int* retval, int fd, struct stat* buf, int* perrno);
sgx_status_t SGX_CDECL ocall_fchmod(int* retval, int fd, unsigned int mode, int* perrno);
sgx_status_t SGX_CDECL ocall_mkdir(int* retval, const char* pathname, mode_t mode, int* perrno);
sgx_status_t SGX_CDECL ocall_read(ssize_t* retval, int file, void* buf, size_t count, int* perrno);
sgx_status_t SGX_CDECL ocall_write(ssize_t* retval, int file, const void* buf, size_t count, int* perrno);
sgx_status_t SGX_CDECL ocall_close(int* retval, int fd, int* perrno);
sgx_status_t SGX_CDECL ocall_fchown(int* retval, int fd, uid_t owner, gid_t group, int* perrno);
sgx_status_t SGX_CDECL ocall_getcwd(char** retval, char* buf, size_t size, int* perrno);
sgx_status_t SGX_CDECL ocall_truncate(int* retval, const char* path, off_t length, int* perrno);
sgx_status_t SGX_CDECL ocall_ftruncate(int* retval, int fd, off_t length, int* perrno);
sgx_status_t SGX_CDECL ocall_pread(ssize_t* retval, int fd, void* buf, size_t count, off_t offset, int* perrno);
sgx_status_t SGX_CDECL ocall_pwrite(ssize_t* retval, int fd, const void* buf, size_t count, off_t offset, int* perrno);
sgx_status_t SGX_CDECL ocall_access(int* retval, const char* pathname, int mode, int* perrno);
sgx_status_t SGX_CDECL ocall_unlink(int* retval, const char* pathname, int* perrno);
sgx_status_t SGX_CDECL ocall_rmdir(int* retval, const char* pathname, int* perrno);
sgx_status_t SGX_CDECL ocall_geteuid(uid_t* retval);
sgx_status_t SGX_CDECL ocall_lseek(off_t* retval, int fd, off_t offset, int whence, int* perrno);
sgx_status_t SGX_CDECL ocall_fsync(int* retval, int fd, int* perrno);
sgx_status_t SGX_CDECL ocall_getpid(pid_t* retval);
sgx_status_t SGX_CDECL ocall_sleep(unsigned int* retval, unsigned int seconds);
sgx_status_t SGX_CDECL ocall_rtreslut(int* retval, char* title, size_t count, char* r, size_t size);
sgx_status_t SGX_CDECL ocall_strcat(char** retval, char* dest, size_t count, const char* src);
sgx_status_t SGX_CDECL ocall_time(time_t* retval, time_t* t, int* perrno);
sgx_status_t SGX_CDECL ocall_utimes(int* retval, const char* filename, const struct timeval* times, int* perrno);
sgx_status_t SGX_CDECL ocall_gettimeofday(int* retval, struct timeval* tv, int* perrno);
sgx_status_t SGX_CDECL ocall_getenv(char** retval, const char* name, int* perrno);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
