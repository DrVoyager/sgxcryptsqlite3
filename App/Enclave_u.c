#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_sqlite3_exec_once_t {
	int ms_retval;
	const char* ms_dbname;
	size_t ms_dbname_len;
	const char* ms_sql;
	size_t ms_sql_len;
} ms_ecall_sqlite3_exec_once_t;

typedef struct ms_ecall_sqlite3_open_t {
	int ms_retval;
	const char* ms_filename;
	size_t ms_filename_len;
	struct tDB* ms_pdb;
} ms_ecall_sqlite3_open_t;

typedef struct ms_ecall_sqlite3_open_enc_t {
	int ms_retval;
	const unsigned char* ms_filenameEn;
	size_t ms_filenameEn_len;
	int ms_len;
	unsigned char* ms_ivec;
	size_t ms_ivec_len;
	struct tDB* ms_pdb;
} ms_ecall_sqlite3_open_enc_t;

typedef struct ms_ecall_sqlite3_prepare_t {
	int ms_retval;
	struct tDB* ms_pdb;
	const char* ms_zSql;
	size_t ms_zSql_len;
	int ms_nBytes;
} ms_ecall_sqlite3_prepare_t;

typedef struct ms_ecall_sqlite3_prepare_v2_t {
	int ms_retval;
	struct tDB* ms_pdb;
	const char* ms_zSql;
	size_t ms_zSql_len;
	int ms_nBytes;
} ms_ecall_sqlite3_prepare_v2_t;

typedef struct ms_ecall_sqlite3_step_t {
	int ms_retval;
} ms_ecall_sqlite3_step_t;

typedef struct ms_ecall_sqlite3_finalize_t {
	int ms_retval;
} ms_ecall_sqlite3_finalize_t;

typedef struct ms_ecall_sqlite3_exec_t {
	int ms_retval;
	struct tDB* ms_pdb;
	const char* ms_sql;
	size_t ms_sql_len;
	char* ms_errmsg;
	size_t ms_count;
} ms_ecall_sqlite3_exec_t;

typedef struct ms_ecall_sqlite3_exec_enc_t {
	int ms_retval;
	struct tDB* ms_pdb;
	const unsigned char* ms_cipher;
	size_t ms_cipher_len;
	int ms_len;
	unsigned char* ms_ivec;
	size_t ms_ivec_len;
	char* ms_errmsg;
	size_t ms_count;
	unsigned char* ms_pm;
	int ms_m_len;
} ms_ecall_sqlite3_exec_enc_t;

typedef struct ms_ecall_sqlite3_close_t {
	int ms_retval;
	struct tDB* ms_pdb;
} ms_ecall_sqlite3_close_t;

typedef struct ms_ecall_sqlite3_errmsg_t {
	struct tDB* ms_pdb;
	char* ms_errmsg;
	size_t ms_count;
} ms_ecall_sqlite3_errmsg_t;

typedef struct ms_ecall_sqlite3_ctr_encrypt_t {
	int ms_retval;
	const char* ms_sql;
	size_t ms_sql_len;
	const char* ms_sgx_ctr_key;
	size_t ms_sgx_ctr_key_len;
	uint8_t* ms_p_dst;
	size_t ms_count;
} ms_ecall_sqlite3_ctr_encrypt_t;

typedef struct ms_ecall_sqlite3_ctr_decrypt_t {
	int ms_retval;
	unsigned char* ms_cipher;
	size_t ms_cipher_len;
	const char* ms_sgx_ctr_key;
	size_t ms_sgx_ctr_key_len;
	uint8_t* ms_p_dst;
	size_t ms_count;
} ms_ecall_sqlite3_ctr_decrypt_t;

typedef struct ms_ecall_sqlite3_ctr_decrypt_2_t {
	int ms_retval;
	unsigned char* ms_ecount;
	size_t ms_ecount_len;
	unsigned char* ms_cipher;
	size_t ms_cipher_len;
	const unsigned char* ms_sgx_ctr_key;
	size_t ms_sgx_ctr_key_len;
	uint8_t* ms_p_dst;
	size_t ms_count;
} ms_ecall_sqlite3_ctr_decrypt_2_t;

typedef struct ms_ecall_transfer_cipher_t {
	const unsigned char* ms_key;
	const unsigned char* ms_cipher;
	unsigned char* ms_ecount;
	size_t ms_length;
} ms_ecall_transfer_cipher_t;

typedef struct ms_ecall_vfs_sgx_test_t {
	int ms_retval;
} ms_ecall_vfs_sgx_test_t;

typedef struct ms_ocall_malloc_t {
	OMem* ms_mem;
} ms_ocall_malloc_t;

typedef struct ms_ocall_reslutcp_t {
	int ms_retval;
	OMem* ms_mem;
	unsigned char* ms_str;
	int ms_count;
	uint8_t* ms_ecount;
} ms_ocall_reslutcp_t;

typedef struct ms_ocall_open_t {
	int ms_retval;
	const char* ms_filename;
	int ms_flags;
	mode_t ms_mode;
	int* ms_perrno;
} ms_ocall_open_t;

typedef struct ms_ocall_fallocate_t {
	int ms_retval;
	int ms_fd;
	int ms_mode;
	off_t ms_offset;
	off_t ms_len;
	int* ms_perrno;
} ms_ocall_fallocate_t;

typedef struct ms_ocall_fcntl_flock_t {
	int ms_retval;
	int ms_fd;
	int ms_cmd;
	struct flock* ms_p;
	int* ms_perrno;
} ms_ocall_fcntl_flock_t;

typedef struct ms_ocall_fcntl_int_t {
	int ms_retval;
	int ms_fd;
	int ms_cmd;
	int ms_pa;
	int* ms_perrno;
} ms_ocall_fcntl_int_t;

typedef struct ms_ocall_fcntl_void_t {
	int ms_retval;
	int ms_fd;
	int ms_cmd;
	int* ms_perrno;
} ms_ocall_fcntl_void_t;

typedef struct ms_ocall_stat_t {
	int ms_retval;
	const char* ms_pathname;
	struct stat* ms_buf;
	int* ms_perrno;
} ms_ocall_stat_t;

typedef struct ms_ocall_fstat_t {
	int ms_retval;
	int ms_fd;
	struct stat* ms_buf;
	int* ms_perrno;
} ms_ocall_fstat_t;

typedef struct ms_ocall_fchmod_t {
	int ms_retval;
	int ms_fd;
	unsigned int ms_mode;
	int* ms_perrno;
} ms_ocall_fchmod_t;

typedef struct ms_ocall_mkdir_t {
	int ms_retval;
	const char* ms_pathname;
	mode_t ms_mode;
	int* ms_perrno;
} ms_ocall_mkdir_t;

typedef struct ms_ocall_read_t {
	ssize_t ms_retval;
	int ms_file;
	void* ms_buf;
	size_t ms_count;
	int* ms_perrno;
} ms_ocall_read_t;

typedef struct ms_ocall_write_t {
	ssize_t ms_retval;
	int ms_file;
	const void* ms_buf;
	size_t ms_count;
	int* ms_perrno;
} ms_ocall_write_t;

typedef struct ms_ocall_close_t {
	int ms_retval;
	int ms_fd;
	int* ms_perrno;
} ms_ocall_close_t;

typedef struct ms_ocall_fchown_t {
	int ms_retval;
	int ms_fd;
	uid_t ms_owner;
	gid_t ms_group;
	int* ms_perrno;
} ms_ocall_fchown_t;

typedef struct ms_ocall_getcwd_t {
	char* ms_retval;
	char* ms_buf;
	size_t ms_size;
	int* ms_perrno;
} ms_ocall_getcwd_t;

typedef struct ms_ocall_truncate_t {
	int ms_retval;
	const char* ms_path;
	off_t ms_length;
	int* ms_perrno;
} ms_ocall_truncate_t;

typedef struct ms_ocall_ftruncate_t {
	int ms_retval;
	int ms_fd;
	off_t ms_length;
	int* ms_perrno;
} ms_ocall_ftruncate_t;

typedef struct ms_ocall_pread_t {
	ssize_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
	off_t ms_offset;
	int* ms_perrno;
} ms_ocall_pread_t;

typedef struct ms_ocall_pwrite_t {
	ssize_t ms_retval;
	int ms_fd;
	const void* ms_buf;
	size_t ms_count;
	off_t ms_offset;
	int* ms_perrno;
} ms_ocall_pwrite_t;

typedef struct ms_ocall_access_t {
	int ms_retval;
	const char* ms_pathname;
	int ms_mode;
	int* ms_perrno;
} ms_ocall_access_t;

typedef struct ms_ocall_unlink_t {
	int ms_retval;
	const char* ms_pathname;
	int* ms_perrno;
} ms_ocall_unlink_t;

typedef struct ms_ocall_rmdir_t {
	int ms_retval;
	const char* ms_pathname;
	int* ms_perrno;
} ms_ocall_rmdir_t;

typedef struct ms_ocall_geteuid_t {
	uid_t ms_retval;
} ms_ocall_geteuid_t;

typedef struct ms_ocall_lseek_t {
	off_t ms_retval;
	int ms_fd;
	off_t ms_offset;
	int ms_whence;
	int* ms_perrno;
} ms_ocall_lseek_t;

typedef struct ms_ocall_fsync_t {
	int ms_retval;
	int ms_fd;
	int* ms_perrno;
} ms_ocall_fsync_t;

typedef struct ms_ocall_getpid_t {
	pid_t ms_retval;
} ms_ocall_getpid_t;

typedef struct ms_ocall_sleep_t {
	unsigned int ms_retval;
	unsigned int ms_seconds;
} ms_ocall_sleep_t;

typedef struct ms_ocall_rtreslut_t {
	int ms_retval;
	char* ms_title;
	size_t ms_count;
	char* ms_r;
	size_t ms_size;
} ms_ocall_rtreslut_t;

typedef struct ms_ocall_strcat_t {
	char* ms_retval;
	char* ms_dest;
	size_t ms_count;
	const char* ms_src;
} ms_ocall_strcat_t;

typedef struct ms_ocall_time_t {
	time_t ms_retval;
	time_t* ms_t;
	int* ms_perrno;
} ms_ocall_time_t;

typedef struct ms_ocall_utimes_t {
	int ms_retval;
	const char* ms_filename;
	const struct timeval* ms_times;
	int* ms_perrno;
} ms_ocall_utimes_t;

typedef struct ms_ocall_gettimeofday_t {
	int ms_retval;
	struct timeval* ms_tv;
	int* ms_perrno;
} ms_ocall_gettimeofday_t;

typedef struct ms_ocall_getenv_t {
	char* ms_retval;
	const char* ms_name;
	int* ms_perrno;
} ms_ocall_getenv_t;

static sgx_status_t SGX_CDECL Enclave_ocall_malloc(void* pms)
{
	ms_ocall_malloc_t* ms = SGX_CAST(ms_ocall_malloc_t*, pms);
	ocall_malloc(ms->ms_mem);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_reslutcp(void* pms)
{
	ms_ocall_reslutcp_t* ms = SGX_CAST(ms_ocall_reslutcp_t*, pms);
	ms->ms_retval = ocall_reslutcp(ms->ms_mem, ms->ms_str, ms->ms_count, ms->ms_ecount);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_open(void* pms)
{
	ms_ocall_open_t* ms = SGX_CAST(ms_ocall_open_t*, pms);
	ms->ms_retval = ocall_open(ms->ms_filename, ms->ms_flags, ms->ms_mode, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fallocate(void* pms)
{
	ms_ocall_fallocate_t* ms = SGX_CAST(ms_ocall_fallocate_t*, pms);
	ms->ms_retval = ocall_fallocate(ms->ms_fd, ms->ms_mode, ms->ms_offset, ms->ms_len, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fcntl_flock(void* pms)
{
	ms_ocall_fcntl_flock_t* ms = SGX_CAST(ms_ocall_fcntl_flock_t*, pms);
	ms->ms_retval = ocall_fcntl_flock(ms->ms_fd, ms->ms_cmd, ms->ms_p, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fcntl_int(void* pms)
{
	ms_ocall_fcntl_int_t* ms = SGX_CAST(ms_ocall_fcntl_int_t*, pms);
	ms->ms_retval = ocall_fcntl_int(ms->ms_fd, ms->ms_cmd, ms->ms_pa, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fcntl_void(void* pms)
{
	ms_ocall_fcntl_void_t* ms = SGX_CAST(ms_ocall_fcntl_void_t*, pms);
	ms->ms_retval = ocall_fcntl_void(ms->ms_fd, ms->ms_cmd, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_stat(void* pms)
{
	ms_ocall_stat_t* ms = SGX_CAST(ms_ocall_stat_t*, pms);
	ms->ms_retval = ocall_stat(ms->ms_pathname, ms->ms_buf, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fstat(void* pms)
{
	ms_ocall_fstat_t* ms = SGX_CAST(ms_ocall_fstat_t*, pms);
	ms->ms_retval = ocall_fstat(ms->ms_fd, ms->ms_buf, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fchmod(void* pms)
{
	ms_ocall_fchmod_t* ms = SGX_CAST(ms_ocall_fchmod_t*, pms);
	ms->ms_retval = ocall_fchmod(ms->ms_fd, ms->ms_mode, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mkdir(void* pms)
{
	ms_ocall_mkdir_t* ms = SGX_CAST(ms_ocall_mkdir_t*, pms);
	ms->ms_retval = ocall_mkdir(ms->ms_pathname, ms->ms_mode, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read(void* pms)
{
	ms_ocall_read_t* ms = SGX_CAST(ms_ocall_read_t*, pms);
	ms->ms_retval = ocall_read(ms->ms_file, ms->ms_buf, ms->ms_count, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_write(void* pms)
{
	ms_ocall_write_t* ms = SGX_CAST(ms_ocall_write_t*, pms);
	ms->ms_retval = ocall_write(ms->ms_file, ms->ms_buf, ms->ms_count, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_close(void* pms)
{
	ms_ocall_close_t* ms = SGX_CAST(ms_ocall_close_t*, pms);
	ms->ms_retval = ocall_close(ms->ms_fd, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fchown(void* pms)
{
	ms_ocall_fchown_t* ms = SGX_CAST(ms_ocall_fchown_t*, pms);
	ms->ms_retval = ocall_fchown(ms->ms_fd, ms->ms_owner, ms->ms_group, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getcwd(void* pms)
{
	ms_ocall_getcwd_t* ms = SGX_CAST(ms_ocall_getcwd_t*, pms);
	ms->ms_retval = ocall_getcwd(ms->ms_buf, ms->ms_size, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_truncate(void* pms)
{
	ms_ocall_truncate_t* ms = SGX_CAST(ms_ocall_truncate_t*, pms);
	ms->ms_retval = ocall_truncate(ms->ms_path, ms->ms_length, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_ftruncate(void* pms)
{
	ms_ocall_ftruncate_t* ms = SGX_CAST(ms_ocall_ftruncate_t*, pms);
	ms->ms_retval = ocall_ftruncate(ms->ms_fd, ms->ms_length, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pread(void* pms)
{
	ms_ocall_pread_t* ms = SGX_CAST(ms_ocall_pread_t*, pms);
	ms->ms_retval = ocall_pread(ms->ms_fd, ms->ms_buf, ms->ms_count, ms->ms_offset, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pwrite(void* pms)
{
	ms_ocall_pwrite_t* ms = SGX_CAST(ms_ocall_pwrite_t*, pms);
	ms->ms_retval = ocall_pwrite(ms->ms_fd, ms->ms_buf, ms->ms_count, ms->ms_offset, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_access(void* pms)
{
	ms_ocall_access_t* ms = SGX_CAST(ms_ocall_access_t*, pms);
	ms->ms_retval = ocall_access(ms->ms_pathname, ms->ms_mode, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_unlink(void* pms)
{
	ms_ocall_unlink_t* ms = SGX_CAST(ms_ocall_unlink_t*, pms);
	ms->ms_retval = ocall_unlink(ms->ms_pathname, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_rmdir(void* pms)
{
	ms_ocall_rmdir_t* ms = SGX_CAST(ms_ocall_rmdir_t*, pms);
	ms->ms_retval = ocall_rmdir(ms->ms_pathname, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_geteuid(void* pms)
{
	ms_ocall_geteuid_t* ms = SGX_CAST(ms_ocall_geteuid_t*, pms);
	ms->ms_retval = ocall_geteuid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_lseek(void* pms)
{
	ms_ocall_lseek_t* ms = SGX_CAST(ms_ocall_lseek_t*, pms);
	ms->ms_retval = ocall_lseek(ms->ms_fd, ms->ms_offset, ms->ms_whence, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fsync(void* pms)
{
	ms_ocall_fsync_t* ms = SGX_CAST(ms_ocall_fsync_t*, pms);
	ms->ms_retval = ocall_fsync(ms->ms_fd, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getpid(void* pms)
{
	ms_ocall_getpid_t* ms = SGX_CAST(ms_ocall_getpid_t*, pms);
	ms->ms_retval = ocall_getpid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sleep(void* pms)
{
	ms_ocall_sleep_t* ms = SGX_CAST(ms_ocall_sleep_t*, pms);
	ms->ms_retval = ocall_sleep(ms->ms_seconds);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_rtreslut(void* pms)
{
	ms_ocall_rtreslut_t* ms = SGX_CAST(ms_ocall_rtreslut_t*, pms);
	ms->ms_retval = ocall_rtreslut(ms->ms_title, ms->ms_count, ms->ms_r, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_strcat(void* pms)
{
	ms_ocall_strcat_t* ms = SGX_CAST(ms_ocall_strcat_t*, pms);
	ms->ms_retval = ocall_strcat(ms->ms_dest, ms->ms_count, ms->ms_src);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_time(void* pms)
{
	ms_ocall_time_t* ms = SGX_CAST(ms_ocall_time_t*, pms);
	ms->ms_retval = ocall_time(ms->ms_t, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_utimes(void* pms)
{
	ms_ocall_utimes_t* ms = SGX_CAST(ms_ocall_utimes_t*, pms);
	ms->ms_retval = ocall_utimes(ms->ms_filename, ms->ms_times, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_gettimeofday(void* pms)
{
	ms_ocall_gettimeofday_t* ms = SGX_CAST(ms_ocall_gettimeofday_t*, pms);
	ms->ms_retval = ocall_gettimeofday(ms->ms_tv, ms->ms_perrno);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getenv(void* pms)
{
	ms_ocall_getenv_t* ms = SGX_CAST(ms_ocall_getenv_t*, pms);
	ms->ms_retval = ocall_getenv(ms->ms_name, ms->ms_perrno);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[34];
} ocall_table_Enclave = {
	34,
	{
		(void*)Enclave_ocall_malloc,
		(void*)Enclave_ocall_reslutcp,
		(void*)Enclave_ocall_open,
		(void*)Enclave_ocall_fallocate,
		(void*)Enclave_ocall_fcntl_flock,
		(void*)Enclave_ocall_fcntl_int,
		(void*)Enclave_ocall_fcntl_void,
		(void*)Enclave_ocall_stat,
		(void*)Enclave_ocall_fstat,
		(void*)Enclave_ocall_fchmod,
		(void*)Enclave_ocall_mkdir,
		(void*)Enclave_ocall_read,
		(void*)Enclave_ocall_write,
		(void*)Enclave_ocall_close,
		(void*)Enclave_ocall_fchown,
		(void*)Enclave_ocall_getcwd,
		(void*)Enclave_ocall_truncate,
		(void*)Enclave_ocall_ftruncate,
		(void*)Enclave_ocall_pread,
		(void*)Enclave_ocall_pwrite,
		(void*)Enclave_ocall_access,
		(void*)Enclave_ocall_unlink,
		(void*)Enclave_ocall_rmdir,
		(void*)Enclave_ocall_geteuid,
		(void*)Enclave_ocall_lseek,
		(void*)Enclave_ocall_fsync,
		(void*)Enclave_ocall_getpid,
		(void*)Enclave_ocall_sleep,
		(void*)Enclave_ocall_rtreslut,
		(void*)Enclave_ocall_strcat,
		(void*)Enclave_ocall_time,
		(void*)Enclave_ocall_utimes,
		(void*)Enclave_ocall_gettimeofday,
		(void*)Enclave_ocall_getenv,
	}
};
sgx_status_t ecall_sqlite3_exec_once(sgx_enclave_id_t eid, int* retval, const char* dbname, const char* sql)
{
	sgx_status_t status;
	ms_ecall_sqlite3_exec_once_t ms;
	ms.ms_dbname = dbname;
	ms.ms_dbname_len = dbname ? strlen(dbname) + 1 : 0;
	ms.ms_sql = sql;
	ms.ms_sql_len = sql ? strlen(sql) + 1 : 0;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_sqlite3_open(sgx_enclave_id_t eid, int* retval, const char* filename, struct tDB* pdb)
{
	sgx_status_t status;
	ms_ecall_sqlite3_open_t ms;
	ms.ms_filename = filename;
	ms.ms_filename_len = filename ? strlen(filename) + 1 : 0;
	ms.ms_pdb = pdb;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_sqlite3_open_enc(sgx_enclave_id_t eid, int* retval, const unsigned char* filenameEn, int len, unsigned char* ivec, struct tDB* pdb)
{
	sgx_status_t status;
	ms_ecall_sqlite3_open_enc_t ms;
	ms.ms_filenameEn = filenameEn;
	ms.ms_filenameEn_len = filenameEn ? strlen(filenameEn) + 1 : 0;
	ms.ms_len = len;
	ms.ms_ivec = ivec;
	ms.ms_ivec_len = ivec ? strlen(ivec) + 1 : 0;
	ms.ms_pdb = pdb;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_sqlite3_prepare(sgx_enclave_id_t eid, int* retval, struct tDB* pdb, const char* zSql, int nBytes)
{
	sgx_status_t status;
	ms_ecall_sqlite3_prepare_t ms;
	ms.ms_pdb = pdb;
	ms.ms_zSql = zSql;
	ms.ms_zSql_len = zSql ? strlen(zSql) + 1 : 0;
	ms.ms_nBytes = nBytes;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_sqlite3_prepare_v2(sgx_enclave_id_t eid, int* retval, struct tDB* pdb, const char* zSql, int nBytes)
{
	sgx_status_t status;
	ms_ecall_sqlite3_prepare_v2_t ms;
	ms.ms_pdb = pdb;
	ms.ms_zSql = zSql;
	ms.ms_zSql_len = zSql ? strlen(zSql) + 1 : 0;
	ms.ms_nBytes = nBytes;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_sqlite3_step(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_sqlite3_step_t ms;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_sqlite3_finalize(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_sqlite3_finalize_t ms;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_sqlite3_exec(sgx_enclave_id_t eid, int* retval, struct tDB* pdb, const char* sql, char* errmsg, size_t count)
{
	sgx_status_t status;
	ms_ecall_sqlite3_exec_t ms;
	ms.ms_pdb = pdb;
	ms.ms_sql = sql;
	ms.ms_sql_len = sql ? strlen(sql) + 1 : 0;
	ms.ms_errmsg = errmsg;
	ms.ms_count = count;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_sqlite3_exec_enc(sgx_enclave_id_t eid, int* retval, struct tDB* pdb, const unsigned char* cipher, int len, unsigned char* ivec, char* errmsg, size_t count, unsigned char* pm, int m_len)
{
	sgx_status_t status;
	ms_ecall_sqlite3_exec_enc_t ms;
	ms.ms_pdb = pdb;
	ms.ms_cipher = cipher;
	ms.ms_cipher_len = cipher ? strlen(cipher) + 1 : 0;
	ms.ms_len = len;
	ms.ms_ivec = ivec;
	ms.ms_ivec_len = ivec ? strlen(ivec) + 1 : 0;
	ms.ms_errmsg = errmsg;
	ms.ms_count = count;
	ms.ms_pm = pm;
	ms.ms_m_len = m_len;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_sqlite3_close(sgx_enclave_id_t eid, int* retval, struct tDB* pdb)
{
	sgx_status_t status;
	ms_ecall_sqlite3_close_t ms;
	ms.ms_pdb = pdb;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_sqlite3_errmsg(sgx_enclave_id_t eid, struct tDB* pdb, char* errmsg, size_t count)
{
	sgx_status_t status;
	ms_ecall_sqlite3_errmsg_t ms;
	ms.ms_pdb = pdb;
	ms.ms_errmsg = errmsg;
	ms.ms_count = count;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_sqlite3_ctr_encrypt(sgx_enclave_id_t eid, int* retval, const char* sql, const char* sgx_ctr_key, uint8_t* p_dst, size_t count)
{
	sgx_status_t status;
	ms_ecall_sqlite3_ctr_encrypt_t ms;
	ms.ms_sql = sql;
	ms.ms_sql_len = sql ? strlen(sql) + 1 : 0;
	ms.ms_sgx_ctr_key = sgx_ctr_key;
	ms.ms_sgx_ctr_key_len = sgx_ctr_key ? strlen(sgx_ctr_key) + 1 : 0;
	ms.ms_p_dst = p_dst;
	ms.ms_count = count;
	status = sgx_ecall(eid, 11, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_sqlite3_ctr_decrypt(sgx_enclave_id_t eid, int* retval, unsigned char* cipher, const char* sgx_ctr_key, uint8_t* p_dst, size_t count)
{
	sgx_status_t status;
	ms_ecall_sqlite3_ctr_decrypt_t ms;
	ms.ms_cipher = cipher;
	ms.ms_cipher_len = cipher ? strlen(cipher) + 1 : 0;
	ms.ms_sgx_ctr_key = sgx_ctr_key;
	ms.ms_sgx_ctr_key_len = sgx_ctr_key ? strlen(sgx_ctr_key) + 1 : 0;
	ms.ms_p_dst = p_dst;
	ms.ms_count = count;
	status = sgx_ecall(eid, 12, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_sqlite3_ctr_decrypt_2(sgx_enclave_id_t eid, int* retval, unsigned char* ecount, unsigned char* cipher, const unsigned char* sgx_ctr_key, uint8_t* p_dst, size_t count)
{
	sgx_status_t status;
	ms_ecall_sqlite3_ctr_decrypt_2_t ms;
	ms.ms_ecount = ecount;
	ms.ms_ecount_len = ecount ? strlen(ecount) + 1 : 0;
	ms.ms_cipher = cipher;
	ms.ms_cipher_len = cipher ? strlen(cipher) + 1 : 0;
	ms.ms_sgx_ctr_key = sgx_ctr_key;
	ms.ms_sgx_ctr_key_len = sgx_ctr_key ? strlen(sgx_ctr_key) + 1 : 0;
	ms.ms_p_dst = p_dst;
	ms.ms_count = count;
	status = sgx_ecall(eid, 13, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_transfer_cipher(sgx_enclave_id_t eid, const unsigned char* key, const unsigned char* cipher, unsigned char* ecount, size_t length)
{
	sgx_status_t status;
	ms_ecall_transfer_cipher_t ms;
	ms.ms_key = key;
	ms.ms_cipher = cipher;
	ms.ms_ecount = ecount;
	ms.ms_length = length;
	status = sgx_ecall(eid, 14, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_vfs_sgx_test(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_vfs_sgx_test_t ms;
	status = sgx_ecall(eid, 15, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

