#include "Enclave_t.h"
#define __VIVI_SGX_IN_ENCLAVE__
#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_sqlite3_exec_once(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sqlite3_exec_once_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sqlite3_exec_once_t* ms = SGX_CAST(ms_ecall_sqlite3_exec_once_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_dbname = ms->ms_dbname;
	size_t _len_dbname = ms->ms_dbname_len ;
	char* _in_dbname = NULL;
	const char* _tmp_sql = ms->ms_sql;
	size_t _len_sql = ms->ms_sql_len ;
	char* _in_sql = NULL;

	CHECK_UNIQUE_POINTER(_tmp_dbname, _len_dbname);
	CHECK_UNIQUE_POINTER(_tmp_sql, _len_sql);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_dbname != NULL && _len_dbname != 0) {
		_in_dbname = (char*)malloc(_len_dbname);
		if (_in_dbname == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_dbname, _len_dbname, _tmp_dbname, _len_dbname)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_dbname[_len_dbname - 1] = '\0';
		if (_len_dbname != strlen(_in_dbname) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_sql != NULL && _len_sql != 0) {
		_in_sql = (char*)malloc(_len_sql);
		if (_in_sql == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sql, _len_sql, _tmp_sql, _len_sql)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_sql[_len_sql - 1] = '\0';
		if (_len_sql != strlen(_in_sql) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ecall_sqlite3_exec_once((const char*)_in_dbname, (const char*)_in_sql);

err:
	if (_in_dbname) free(_in_dbname);
	if (_in_sql) free(_in_sql);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sqlite3_open(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sqlite3_open_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sqlite3_open_t* ms = SGX_CAST(ms_ecall_sqlite3_open_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_filename = ms->ms_filename;
	size_t _len_filename = ms->ms_filename_len ;
	char* _in_filename = NULL;
	struct tDB* _tmp_pdb = ms->ms_pdb;
	size_t _len_pdb = sizeof(struct tDB);
	struct tDB* _in_pdb = NULL;

	CHECK_UNIQUE_POINTER(_tmp_filename, _len_filename);
	CHECK_UNIQUE_POINTER(_tmp_pdb, _len_pdb);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_filename != NULL && _len_filename != 0) {
		_in_filename = (char*)malloc(_len_filename);
		if (_in_filename == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_filename, _len_filename, _tmp_filename, _len_filename)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_filename[_len_filename - 1] = '\0';
		if (_len_filename != strlen(_in_filename) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_pdb != NULL && _len_pdb != 0) {
		if ((_in_pdb = (struct tDB*)malloc(_len_pdb)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pdb, 0, _len_pdb);
	}

	ms->ms_retval = ecall_sqlite3_open((const char*)_in_filename, _in_pdb);
	if (_in_pdb) {
		if (memcpy_s(_tmp_pdb, _len_pdb, _in_pdb, _len_pdb)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_filename) free(_in_filename);
	if (_in_pdb) free(_in_pdb);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sqlite3_open_enc(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sqlite3_open_enc_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sqlite3_open_enc_t* ms = SGX_CAST(ms_ecall_sqlite3_open_enc_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const unsigned char* _tmp_filenameEn = ms->ms_filenameEn;
	size_t _len_filenameEn = ms->ms_filenameEn_len ;
	unsigned char* _in_filenameEn = NULL;
	unsigned char* _tmp_ivec = ms->ms_ivec;
	size_t _len_ivec = ms->ms_ivec_len ;
	unsigned char* _in_ivec = NULL;
	struct tDB* _tmp_pdb = ms->ms_pdb;
	size_t _len_pdb = sizeof(struct tDB);
	struct tDB* _in_pdb = NULL;

	CHECK_UNIQUE_POINTER(_tmp_filenameEn, _len_filenameEn);
	CHECK_UNIQUE_POINTER(_tmp_ivec, _len_ivec);
	CHECK_UNIQUE_POINTER(_tmp_pdb, _len_pdb);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_filenameEn != NULL && _len_filenameEn != 0) {
		_in_filenameEn = (unsigned char*)malloc(_len_filenameEn);
		if (_in_filenameEn == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_filenameEn, _len_filenameEn, _tmp_filenameEn, _len_filenameEn)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_filenameEn[_len_filenameEn - 1] = '\0';
		if (_len_filenameEn != strlen(_in_filenameEn) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_ivec != NULL && _len_ivec != 0) {
		_in_ivec = (unsigned char*)malloc(_len_ivec);
		if (_in_ivec == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ivec, _len_ivec, _tmp_ivec, _len_ivec)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_ivec[_len_ivec - 1] = '\0';
		if (_len_ivec != strlen(_in_ivec) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_pdb != NULL && _len_pdb != 0) {
		if ((_in_pdb = (struct tDB*)malloc(_len_pdb)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pdb, 0, _len_pdb);
	}

	ms->ms_retval = ecall_sqlite3_open_enc((const unsigned char*)_in_filenameEn, ms->ms_len, _in_ivec, _in_pdb);
	if (_in_pdb) {
		if (memcpy_s(_tmp_pdb, _len_pdb, _in_pdb, _len_pdb)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_filenameEn) free(_in_filenameEn);
	if (_in_ivec) free(_in_ivec);
	if (_in_pdb) free(_in_pdb);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sqlite3_prepare(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sqlite3_prepare_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sqlite3_prepare_t* ms = SGX_CAST(ms_ecall_sqlite3_prepare_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct tDB* _tmp_pdb = ms->ms_pdb;
	size_t _len_pdb = sizeof(struct tDB);
	struct tDB* _in_pdb = NULL;
	const char* _tmp_zSql = ms->ms_zSql;
	size_t _len_zSql = ms->ms_zSql_len ;
	char* _in_zSql = NULL;

	CHECK_UNIQUE_POINTER(_tmp_pdb, _len_pdb);
	CHECK_UNIQUE_POINTER(_tmp_zSql, _len_zSql);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_pdb != NULL && _len_pdb != 0) {
		_in_pdb = (struct tDB*)malloc(_len_pdb);
		if (_in_pdb == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_pdb, _len_pdb, _tmp_pdb, _len_pdb)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_zSql != NULL && _len_zSql != 0) {
		_in_zSql = (char*)malloc(_len_zSql);
		if (_in_zSql == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_zSql, _len_zSql, _tmp_zSql, _len_zSql)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_zSql[_len_zSql - 1] = '\0';
		if (_len_zSql != strlen(_in_zSql) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ecall_sqlite3_prepare(_in_pdb, (const char*)_in_zSql, ms->ms_nBytes);

err:
	if (_in_pdb) free(_in_pdb);
	if (_in_zSql) free(_in_zSql);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sqlite3_prepare_v2(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sqlite3_prepare_v2_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sqlite3_prepare_v2_t* ms = SGX_CAST(ms_ecall_sqlite3_prepare_v2_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct tDB* _tmp_pdb = ms->ms_pdb;
	size_t _len_pdb = sizeof(struct tDB);
	struct tDB* _in_pdb = NULL;
	const char* _tmp_zSql = ms->ms_zSql;
	size_t _len_zSql = ms->ms_zSql_len ;
	char* _in_zSql = NULL;

	CHECK_UNIQUE_POINTER(_tmp_pdb, _len_pdb);
	CHECK_UNIQUE_POINTER(_tmp_zSql, _len_zSql);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_pdb != NULL && _len_pdb != 0) {
		_in_pdb = (struct tDB*)malloc(_len_pdb);
		if (_in_pdb == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_pdb, _len_pdb, _tmp_pdb, _len_pdb)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_zSql != NULL && _len_zSql != 0) {
		_in_zSql = (char*)malloc(_len_zSql);
		if (_in_zSql == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_zSql, _len_zSql, _tmp_zSql, _len_zSql)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_zSql[_len_zSql - 1] = '\0';
		if (_len_zSql != strlen(_in_zSql) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ecall_sqlite3_prepare_v2(_in_pdb, (const char*)_in_zSql, ms->ms_nBytes);

err:
	if (_in_pdb) free(_in_pdb);
	if (_in_zSql) free(_in_zSql);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sqlite3_step(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sqlite3_step_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sqlite3_step_t* ms = SGX_CAST(ms_ecall_sqlite3_step_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_sqlite3_step();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sqlite3_finalize(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sqlite3_finalize_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sqlite3_finalize_t* ms = SGX_CAST(ms_ecall_sqlite3_finalize_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_sqlite3_finalize();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sqlite3_exec(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sqlite3_exec_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sqlite3_exec_t* ms = SGX_CAST(ms_ecall_sqlite3_exec_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct tDB* _tmp_pdb = ms->ms_pdb;
	size_t _len_pdb = sizeof(struct tDB);
	struct tDB* _in_pdb = NULL;
	const char* _tmp_sql = ms->ms_sql;
	size_t _len_sql = ms->ms_sql_len ;
	char* _in_sql = NULL;
	char* _tmp_errmsg = ms->ms_errmsg;
	size_t _tmp_count = ms->ms_count;
	size_t _len_errmsg = _tmp_count * sizeof(char);
	char* _in_errmsg = NULL;

	if (sizeof(*_tmp_errmsg) != 0 &&
		(size_t)_tmp_count > (SIZE_MAX / sizeof(*_tmp_errmsg))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_pdb, _len_pdb);
	CHECK_UNIQUE_POINTER(_tmp_sql, _len_sql);
	CHECK_UNIQUE_POINTER(_tmp_errmsg, _len_errmsg);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_pdb != NULL && _len_pdb != 0) {
		_in_pdb = (struct tDB*)malloc(_len_pdb);
		if (_in_pdb == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_pdb, _len_pdb, _tmp_pdb, _len_pdb)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sql != NULL && _len_sql != 0) {
		_in_sql = (char*)malloc(_len_sql);
		if (_in_sql == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sql, _len_sql, _tmp_sql, _len_sql)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_sql[_len_sql - 1] = '\0';
		if (_len_sql != strlen(_in_sql) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_errmsg != NULL && _len_errmsg != 0) {
		if ( _len_errmsg % sizeof(*_tmp_errmsg) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_errmsg = (char*)malloc(_len_errmsg)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_errmsg, 0, _len_errmsg);
	}

	ms->ms_retval = ecall_sqlite3_exec(_in_pdb, (const char*)_in_sql, _in_errmsg, _tmp_count);
	if (_in_errmsg) {
		if (memcpy_s(_tmp_errmsg, _len_errmsg, _in_errmsg, _len_errmsg)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_pdb) free(_in_pdb);
	if (_in_sql) free(_in_sql);
	if (_in_errmsg) free(_in_errmsg);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sqlite3_exec_enc(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sqlite3_exec_enc_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sqlite3_exec_enc_t* ms = SGX_CAST(ms_ecall_sqlite3_exec_enc_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct tDB* _tmp_pdb = ms->ms_pdb;
	size_t _len_pdb = sizeof(struct tDB);
	struct tDB* _in_pdb = NULL;
	const unsigned char* _tmp_cipher = ms->ms_cipher;
	size_t _len_cipher = ms->ms_cipher_len ;
	unsigned char* _in_cipher = NULL;
	unsigned char* _tmp_ivec = ms->ms_ivec;
	size_t _len_ivec = ms->ms_ivec_len ;
	unsigned char* _in_ivec = NULL;
	char* _tmp_errmsg = ms->ms_errmsg;
	size_t _tmp_count = ms->ms_count;
	size_t _len_errmsg = _tmp_count * sizeof(char);
	char* _in_errmsg = NULL;
	unsigned char* _tmp_pm = ms->ms_pm;
	size_t _len_pm = 8 * sizeof(unsigned char);
	unsigned char* _in_pm = NULL;

	if (sizeof(*_tmp_errmsg) != 0 &&
		(size_t)_tmp_count > (SIZE_MAX / sizeof(*_tmp_errmsg))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_pm) != 0 &&
		8 > (SIZE_MAX / sizeof(*_tmp_pm))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_pdb, _len_pdb);
	CHECK_UNIQUE_POINTER(_tmp_cipher, _len_cipher);
	CHECK_UNIQUE_POINTER(_tmp_ivec, _len_ivec);
	CHECK_UNIQUE_POINTER(_tmp_errmsg, _len_errmsg);
	CHECK_UNIQUE_POINTER(_tmp_pm, _len_pm);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_pdb != NULL && _len_pdb != 0) {
		_in_pdb = (struct tDB*)malloc(_len_pdb);
		if (_in_pdb == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_pdb, _len_pdb, _tmp_pdb, _len_pdb)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_cipher != NULL && _len_cipher != 0) {
		_in_cipher = (unsigned char*)malloc(_len_cipher);
		if (_in_cipher == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_cipher, _len_cipher, _tmp_cipher, _len_cipher)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_cipher[_len_cipher - 1] = '\0';
		if (_len_cipher != strlen(_in_cipher) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_ivec != NULL && _len_ivec != 0) {
		_in_ivec = (unsigned char*)malloc(_len_ivec);
		if (_in_ivec == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ivec, _len_ivec, _tmp_ivec, _len_ivec)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_ivec[_len_ivec - 1] = '\0';
		if (_len_ivec != strlen(_in_ivec) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_errmsg != NULL && _len_errmsg != 0) {
		if ( _len_errmsg % sizeof(*_tmp_errmsg) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_errmsg = (char*)malloc(_len_errmsg)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_errmsg, 0, _len_errmsg);
	}
	if (_tmp_pm != NULL && _len_pm != 0) {
		if ( _len_pm % sizeof(*_tmp_pm) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_pm = (unsigned char*)malloc(_len_pm);
		if (_in_pm == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_pm, _len_pm, _tmp_pm, _len_pm)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ecall_sqlite3_exec_enc(_in_pdb, (const unsigned char*)_in_cipher, ms->ms_len, _in_ivec, _in_errmsg, _tmp_count, _in_pm, ms->ms_m_len);
	if (_in_errmsg) {
		if (memcpy_s(_tmp_errmsg, _len_errmsg, _in_errmsg, _len_errmsg)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_pm) {
		if (memcpy_s(_tmp_pm, _len_pm, _in_pm, _len_pm)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_pdb) free(_in_pdb);
	if (_in_cipher) free(_in_cipher);
	if (_in_ivec) free(_in_ivec);
	if (_in_errmsg) free(_in_errmsg);
	if (_in_pm) free(_in_pm);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sqlite3_close(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sqlite3_close_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sqlite3_close_t* ms = SGX_CAST(ms_ecall_sqlite3_close_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct tDB* _tmp_pdb = ms->ms_pdb;
	size_t _len_pdb = sizeof(struct tDB);
	struct tDB* _in_pdb = NULL;

	CHECK_UNIQUE_POINTER(_tmp_pdb, _len_pdb);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_pdb != NULL && _len_pdb != 0) {
		_in_pdb = (struct tDB*)malloc(_len_pdb);
		if (_in_pdb == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_pdb, _len_pdb, _tmp_pdb, _len_pdb)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ecall_sqlite3_close(_in_pdb);

err:
	if (_in_pdb) free(_in_pdb);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sqlite3_errmsg(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sqlite3_errmsg_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sqlite3_errmsg_t* ms = SGX_CAST(ms_ecall_sqlite3_errmsg_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct tDB* _tmp_pdb = ms->ms_pdb;
	size_t _len_pdb = sizeof(struct tDB);
	struct tDB* _in_pdb = NULL;
	char* _tmp_errmsg = ms->ms_errmsg;
	size_t _tmp_count = ms->ms_count;
	size_t _len_errmsg = _tmp_count * sizeof(char);
	char* _in_errmsg = NULL;

	if (sizeof(*_tmp_errmsg) != 0 &&
		(size_t)_tmp_count > (SIZE_MAX / sizeof(*_tmp_errmsg))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_pdb, _len_pdb);
	CHECK_UNIQUE_POINTER(_tmp_errmsg, _len_errmsg);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_pdb != NULL && _len_pdb != 0) {
		_in_pdb = (struct tDB*)malloc(_len_pdb);
		if (_in_pdb == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_pdb, _len_pdb, _tmp_pdb, _len_pdb)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_errmsg != NULL && _len_errmsg != 0) {
		if ( _len_errmsg % sizeof(*_tmp_errmsg) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_errmsg = (char*)malloc(_len_errmsg)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_errmsg, 0, _len_errmsg);
	}

	ecall_sqlite3_errmsg(_in_pdb, _in_errmsg, _tmp_count);
	if (_in_errmsg) {
		if (memcpy_s(_tmp_errmsg, _len_errmsg, _in_errmsg, _len_errmsg)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_pdb) free(_in_pdb);
	if (_in_errmsg) free(_in_errmsg);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sqlite3_ctr_encrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sqlite3_ctr_encrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sqlite3_ctr_encrypt_t* ms = SGX_CAST(ms_ecall_sqlite3_ctr_encrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_sql = ms->ms_sql;
	size_t _len_sql = ms->ms_sql_len ;
	char* _in_sql = NULL;
	const char* _tmp_sgx_ctr_key = ms->ms_sgx_ctr_key;
	size_t _len_sgx_ctr_key = ms->ms_sgx_ctr_key_len ;
	char* _in_sgx_ctr_key = NULL;
	uint8_t* _tmp_p_dst = ms->ms_p_dst;
	size_t _tmp_count = ms->ms_count;
	size_t _len_p_dst = _tmp_count;
	uint8_t* _in_p_dst = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sql, _len_sql);
	CHECK_UNIQUE_POINTER(_tmp_sgx_ctr_key, _len_sgx_ctr_key);
	CHECK_UNIQUE_POINTER(_tmp_p_dst, _len_p_dst);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sql != NULL && _len_sql != 0) {
		_in_sql = (char*)malloc(_len_sql);
		if (_in_sql == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sql, _len_sql, _tmp_sql, _len_sql)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_sql[_len_sql - 1] = '\0';
		if (_len_sql != strlen(_in_sql) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_sgx_ctr_key != NULL && _len_sgx_ctr_key != 0) {
		_in_sgx_ctr_key = (char*)malloc(_len_sgx_ctr_key);
		if (_in_sgx_ctr_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sgx_ctr_key, _len_sgx_ctr_key, _tmp_sgx_ctr_key, _len_sgx_ctr_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_sgx_ctr_key[_len_sgx_ctr_key - 1] = '\0';
		if (_len_sgx_ctr_key != strlen(_in_sgx_ctr_key) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_p_dst != NULL && _len_p_dst != 0) {
		if ( _len_p_dst % sizeof(*_tmp_p_dst) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_p_dst = (uint8_t*)malloc(_len_p_dst)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_dst, 0, _len_p_dst);
	}

	ms->ms_retval = ecall_sqlite3_ctr_encrypt((const char*)_in_sql, (const char*)_in_sgx_ctr_key, _in_p_dst, _tmp_count);
	if (_in_p_dst) {
		if (memcpy_s(_tmp_p_dst, _len_p_dst, _in_p_dst, _len_p_dst)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sql) free(_in_sql);
	if (_in_sgx_ctr_key) free(_in_sgx_ctr_key);
	if (_in_p_dst) free(_in_p_dst);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sqlite3_ctr_decrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sqlite3_ctr_decrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sqlite3_ctr_decrypt_t* ms = SGX_CAST(ms_ecall_sqlite3_ctr_decrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_cipher = ms->ms_cipher;
	size_t _len_cipher = ms->ms_cipher_len ;
	unsigned char* _in_cipher = NULL;
	const char* _tmp_sgx_ctr_key = ms->ms_sgx_ctr_key;
	size_t _len_sgx_ctr_key = ms->ms_sgx_ctr_key_len ;
	char* _in_sgx_ctr_key = NULL;
	uint8_t* _tmp_p_dst = ms->ms_p_dst;
	size_t _tmp_count = ms->ms_count;
	size_t _len_p_dst = _tmp_count;
	uint8_t* _in_p_dst = NULL;

	CHECK_UNIQUE_POINTER(_tmp_cipher, _len_cipher);
	CHECK_UNIQUE_POINTER(_tmp_sgx_ctr_key, _len_sgx_ctr_key);
	CHECK_UNIQUE_POINTER(_tmp_p_dst, _len_p_dst);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_cipher != NULL && _len_cipher != 0) {
		_in_cipher = (unsigned char*)malloc(_len_cipher);
		if (_in_cipher == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_cipher, _len_cipher, _tmp_cipher, _len_cipher)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_cipher[_len_cipher - 1] = '\0';
		if (_len_cipher != strlen(_in_cipher) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_sgx_ctr_key != NULL && _len_sgx_ctr_key != 0) {
		_in_sgx_ctr_key = (char*)malloc(_len_sgx_ctr_key);
		if (_in_sgx_ctr_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sgx_ctr_key, _len_sgx_ctr_key, _tmp_sgx_ctr_key, _len_sgx_ctr_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_sgx_ctr_key[_len_sgx_ctr_key - 1] = '\0';
		if (_len_sgx_ctr_key != strlen(_in_sgx_ctr_key) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_p_dst != NULL && _len_p_dst != 0) {
		if ( _len_p_dst % sizeof(*_tmp_p_dst) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_p_dst = (uint8_t*)malloc(_len_p_dst);
		if (_in_p_dst == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_dst, _len_p_dst, _tmp_p_dst, _len_p_dst)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ecall_sqlite3_ctr_decrypt(_in_cipher, (const char*)_in_sgx_ctr_key, _in_p_dst, _tmp_count);
	if (_in_p_dst) {
		if (memcpy_s(_tmp_p_dst, _len_p_dst, _in_p_dst, _len_p_dst)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_cipher) free(_in_cipher);
	if (_in_sgx_ctr_key) free(_in_sgx_ctr_key);
	if (_in_p_dst) free(_in_p_dst);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sqlite3_ctr_decrypt_2(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sqlite3_ctr_decrypt_2_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sqlite3_ctr_decrypt_2_t* ms = SGX_CAST(ms_ecall_sqlite3_ctr_decrypt_2_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_ecount = ms->ms_ecount;
	size_t _len_ecount = ms->ms_ecount_len ;
	unsigned char* _in_ecount = NULL;
	unsigned char* _tmp_cipher = ms->ms_cipher;
	size_t _len_cipher = ms->ms_cipher_len ;
	unsigned char* _in_cipher = NULL;
	const unsigned char* _tmp_sgx_ctr_key = ms->ms_sgx_ctr_key;
	size_t _len_sgx_ctr_key = ms->ms_sgx_ctr_key_len ;
	unsigned char* _in_sgx_ctr_key = NULL;
	uint8_t* _tmp_p_dst = ms->ms_p_dst;
	size_t _tmp_count = ms->ms_count;
	size_t _len_p_dst = _tmp_count;
	uint8_t* _in_p_dst = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ecount, _len_ecount);
	CHECK_UNIQUE_POINTER(_tmp_cipher, _len_cipher);
	CHECK_UNIQUE_POINTER(_tmp_sgx_ctr_key, _len_sgx_ctr_key);
	CHECK_UNIQUE_POINTER(_tmp_p_dst, _len_p_dst);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ecount != NULL && _len_ecount != 0) {
		_in_ecount = (unsigned char*)malloc(_len_ecount);
		if (_in_ecount == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ecount, _len_ecount, _tmp_ecount, _len_ecount)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_ecount[_len_ecount - 1] = '\0';
		if (_len_ecount != strlen(_in_ecount) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_cipher != NULL && _len_cipher != 0) {
		_in_cipher = (unsigned char*)malloc(_len_cipher);
		if (_in_cipher == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_cipher, _len_cipher, _tmp_cipher, _len_cipher)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_cipher[_len_cipher - 1] = '\0';
		if (_len_cipher != strlen(_in_cipher) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_sgx_ctr_key != NULL && _len_sgx_ctr_key != 0) {
		_in_sgx_ctr_key = (unsigned char*)malloc(_len_sgx_ctr_key);
		if (_in_sgx_ctr_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sgx_ctr_key, _len_sgx_ctr_key, _tmp_sgx_ctr_key, _len_sgx_ctr_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_sgx_ctr_key[_len_sgx_ctr_key - 1] = '\0';
		if (_len_sgx_ctr_key != strlen(_in_sgx_ctr_key) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_p_dst != NULL && _len_p_dst != 0) {
		if ( _len_p_dst % sizeof(*_tmp_p_dst) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_p_dst = (uint8_t*)malloc(_len_p_dst);
		if (_in_p_dst == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_dst, _len_p_dst, _tmp_p_dst, _len_p_dst)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ecall_sqlite3_ctr_decrypt_2(_in_ecount, _in_cipher, (const unsigned char*)_in_sgx_ctr_key, _in_p_dst, _tmp_count);
	if (_in_p_dst) {
		if (memcpy_s(_tmp_p_dst, _len_p_dst, _in_p_dst, _len_p_dst)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ecount) free(_in_ecount);
	if (_in_cipher) free(_in_cipher);
	if (_in_sgx_ctr_key) free(_in_sgx_ctr_key);
	if (_in_p_dst) free(_in_p_dst);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_transfer_cipher(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_transfer_cipher_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_transfer_cipher_t* ms = SGX_CAST(ms_ecall_transfer_cipher_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const unsigned char* _tmp_key = ms->ms_key;
	size_t _tmp_length = ms->ms_length;
	size_t _len_key = _tmp_length * sizeof(unsigned char);
	unsigned char* _in_key = NULL;
	const unsigned char* _tmp_cipher = ms->ms_cipher;
	size_t _len_cipher = _tmp_length * sizeof(unsigned char);
	unsigned char* _in_cipher = NULL;
	unsigned char* _tmp_ecount = ms->ms_ecount;
	size_t _len_ecount = _tmp_length * sizeof(unsigned char);
	unsigned char* _in_ecount = NULL;

	if (sizeof(*_tmp_key) != 0 &&
		(size_t)_tmp_length > (SIZE_MAX / sizeof(*_tmp_key))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_cipher) != 0 &&
		(size_t)_tmp_length > (SIZE_MAX / sizeof(*_tmp_cipher))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_ecount) != 0 &&
		(size_t)_tmp_length > (SIZE_MAX / sizeof(*_tmp_ecount))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);
	CHECK_UNIQUE_POINTER(_tmp_cipher, _len_cipher);
	CHECK_UNIQUE_POINTER(_tmp_ecount, _len_ecount);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_key != NULL && _len_key != 0) {
		if ( _len_key % sizeof(*_tmp_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_key = (unsigned char*)malloc(_len_key);
		if (_in_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_key, _len_key, _tmp_key, _len_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_cipher != NULL && _len_cipher != 0) {
		if ( _len_cipher % sizeof(*_tmp_cipher) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_cipher = (unsigned char*)malloc(_len_cipher);
		if (_in_cipher == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_cipher, _len_cipher, _tmp_cipher, _len_cipher)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_ecount != NULL && _len_ecount != 0) {
		if ( _len_ecount % sizeof(*_tmp_ecount) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_ecount = (unsigned char*)malloc(_len_ecount);
		if (_in_ecount == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ecount, _len_ecount, _tmp_ecount, _len_ecount)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_transfer_cipher((const unsigned char*)_in_key, (const unsigned char*)_in_cipher, _in_ecount, _tmp_length);
	if (_in_ecount) {
		if (memcpy_s(_tmp_ecount, _len_ecount, _in_ecount, _len_ecount)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_key) free(_in_key);
	if (_in_cipher) free(_in_cipher);
	if (_in_ecount) free(_in_ecount);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_vfs_sgx_test(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_vfs_sgx_test_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_vfs_sgx_test_t* ms = SGX_CAST(ms_ecall_vfs_sgx_test_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_vfs_sgx_test();


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[16];
} g_ecall_table = {
	16,
	{
		{(void*)(uintptr_t)sgx_ecall_sqlite3_exec_once, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_sqlite3_open, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_sqlite3_open_enc, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_sqlite3_prepare, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_sqlite3_prepare_v2, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_sqlite3_step, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_sqlite3_finalize, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_sqlite3_exec, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_sqlite3_exec_enc, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_sqlite3_close, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_sqlite3_errmsg, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_sqlite3_ctr_encrypt, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_sqlite3_ctr_decrypt, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_sqlite3_ctr_decrypt_2, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_transfer_cipher, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_vfs_sgx_test, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[34][16];
} g_dyn_entry_table = {
	34,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_malloc(OMem* mem)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_mem = 20;

	ms_ocall_malloc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_malloc_t);
	void *__tmp = NULL;

	void *__tmp_mem = NULL;

	CHECK_ENCLAVE_POINTER(mem, _len_mem);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (mem != NULL) ? _len_mem : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_malloc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_malloc_t));
	ocalloc_size -= sizeof(ms_ocall_malloc_t);

	if (mem != NULL) {
		ms->ms_mem = (OMem*)__tmp;
		__tmp_mem = __tmp;
		if (memcpy_s(__tmp, ocalloc_size, mem, _len_mem)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_mem);
		ocalloc_size -= _len_mem;
	} else {
		ms->ms_mem = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (mem) {
			if (memcpy_s((void*)mem, _len_mem, __tmp_mem, _len_mem)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_reslutcp(int* retval, OMem* mem, unsigned char* str, int count, uint8_t* ecount)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_mem = 20;
	size_t _len_str = count;
	size_t _len_ecount = 16;

	ms_ocall_reslutcp_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_reslutcp_t);
	void *__tmp = NULL;

	void *__tmp_mem = NULL;

	CHECK_ENCLAVE_POINTER(mem, _len_mem);
	CHECK_ENCLAVE_POINTER(str, _len_str);
	CHECK_ENCLAVE_POINTER(ecount, _len_ecount);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (mem != NULL) ? _len_mem : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ecount != NULL) ? _len_ecount : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_reslutcp_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_reslutcp_t));
	ocalloc_size -= sizeof(ms_ocall_reslutcp_t);

	if (mem != NULL) {
		ms->ms_mem = (OMem*)__tmp;
		__tmp_mem = __tmp;
		if (memcpy_s(__tmp, ocalloc_size, mem, _len_mem)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_mem);
		ocalloc_size -= _len_mem;
	} else {
		ms->ms_mem = NULL;
	}
	
	if (str != NULL) {
		ms->ms_str = (unsigned char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	ms->ms_count = count;
	if (ecount != NULL) {
		ms->ms_ecount = (uint8_t*)__tmp;
		if (_len_ecount % sizeof(*ecount) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, ecount, _len_ecount)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ecount);
		ocalloc_size -= _len_ecount;
	} else {
		ms->ms_ecount = NULL;
	}
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (mem) {
			if (memcpy_s((void*)mem, _len_mem, __tmp_mem, _len_mem)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_open(int* retval, const char* filename, int flags, mode_t mode, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;
	size_t _len_perrno = sizeof(int);

	ms_ocall_open_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_open_t);
	void *__tmp = NULL;

	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(filename, _len_filename);
	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (filename != NULL) ? _len_filename : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_open_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_open_t));
	ocalloc_size -= sizeof(ms_ocall_open_t);

	if (filename != NULL) {
		ms->ms_filename = (const char*)__tmp;
		if (_len_filename % sizeof(*filename) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, filename, _len_filename)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_filename);
		ocalloc_size -= _len_filename;
	} else {
		ms->ms_filename = NULL;
	}
	
	ms->ms_flags = flags;
	ms->ms_mode = mode;
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fallocate(int* retval, int fd, int mode, off_t offset, off_t len, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_perrno = sizeof(int);

	ms_ocall_fallocate_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fallocate_t);
	void *__tmp = NULL;

	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fallocate_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fallocate_t));
	ocalloc_size -= sizeof(ms_ocall_fallocate_t);

	ms->ms_fd = fd;
	ms->ms_mode = mode;
	ms->ms_offset = offset;
	ms->ms_len = len;
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fcntl_flock(int* retval, int fd, int cmd, struct flock* p, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_p = sizeof(struct flock);
	size_t _len_perrno = sizeof(int);

	ms_ocall_fcntl_flock_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fcntl_flock_t);
	void *__tmp = NULL;

	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(p, _len_p);
	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p != NULL) ? _len_p : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fcntl_flock_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fcntl_flock_t));
	ocalloc_size -= sizeof(ms_ocall_fcntl_flock_t);

	ms->ms_fd = fd;
	ms->ms_cmd = cmd;
	if (p != NULL) {
		ms->ms_p = (struct flock*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, p, _len_p)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_p);
		ocalloc_size -= _len_p;
	} else {
		ms->ms_p = NULL;
	}
	
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fcntl_int(int* retval, int fd, int cmd, int pa, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_perrno = sizeof(int);

	ms_ocall_fcntl_int_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fcntl_int_t);
	void *__tmp = NULL;

	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fcntl_int_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fcntl_int_t));
	ocalloc_size -= sizeof(ms_ocall_fcntl_int_t);

	ms->ms_fd = fd;
	ms->ms_cmd = cmd;
	ms->ms_pa = pa;
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fcntl_void(int* retval, int fd, int cmd, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_perrno = sizeof(int);

	ms_ocall_fcntl_void_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fcntl_void_t);
	void *__tmp = NULL;

	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fcntl_void_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fcntl_void_t));
	ocalloc_size -= sizeof(ms_ocall_fcntl_void_t);

	ms->ms_fd = fd;
	ms->ms_cmd = cmd;
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_stat(int* retval, const char* pathname, struct stat* buf, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;
	size_t _len_buf = sizeof(struct stat);
	size_t _len_perrno = sizeof(int);

	ms_ocall_stat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_stat_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;
	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);
	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_stat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_stat_t));
	ocalloc_size -= sizeof(ms_ocall_stat_t);

	if (pathname != NULL) {
		ms->ms_pathname = (const char*)__tmp;
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}
	
	if (buf != NULL) {
		ms->ms_buf = (struct stat*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fstat(int* retval, int fd, struct stat* buf, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = sizeof(struct stat);
	size_t _len_perrno = sizeof(int);

	ms_ocall_fstat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fstat_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;
	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);
	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fstat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fstat_t));
	ocalloc_size -= sizeof(ms_ocall_fstat_t);

	ms->ms_fd = fd;
	if (buf != NULL) {
		ms->ms_buf = (struct stat*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fchmod(int* retval, int fd, unsigned int mode, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_perrno = sizeof(int);

	ms_ocall_fchmod_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fchmod_t);
	void *__tmp = NULL;

	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fchmod_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fchmod_t));
	ocalloc_size -= sizeof(ms_ocall_fchmod_t);

	ms->ms_fd = fd;
	ms->ms_mode = mode;
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mkdir(int* retval, const char* pathname, mode_t mode, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;
	size_t _len_perrno = sizeof(int);

	ms_ocall_mkdir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mkdir_t);
	void *__tmp = NULL;

	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);
	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mkdir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mkdir_t));
	ocalloc_size -= sizeof(ms_ocall_mkdir_t);

	if (pathname != NULL) {
		ms->ms_pathname = (const char*)__tmp;
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}
	
	ms->ms_mode = mode;
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read(ssize_t* retval, int file, void* buf, size_t count, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;
	size_t _len_perrno = sizeof(int);

	ms_ocall_read_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;
	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);
	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read_t));
	ocalloc_size -= sizeof(ms_ocall_read_t);

	ms->ms_file = file;
	if (buf != NULL) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_count = count;
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_write(ssize_t* retval, int file, const void* buf, size_t count, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;
	size_t _len_perrno = sizeof(int);

	ms_ocall_write_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write_t);
	void *__tmp = NULL;

	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);
	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write_t));
	ocalloc_size -= sizeof(ms_ocall_write_t);

	ms->ms_file = file;
	if (buf != NULL) {
		ms->ms_buf = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_count = count;
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_close(int* retval, int fd, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_perrno = sizeof(int);

	ms_ocall_close_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_close_t);
	void *__tmp = NULL;

	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_close_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_close_t));
	ocalloc_size -= sizeof(ms_ocall_close_t);

	ms->ms_fd = fd;
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fchown(int* retval, int fd, uid_t owner, gid_t group, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_perrno = sizeof(int);

	ms_ocall_fchown_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fchown_t);
	void *__tmp = NULL;

	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fchown_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fchown_t));
	ocalloc_size -= sizeof(ms_ocall_fchown_t);

	ms->ms_fd = fd;
	ms->ms_owner = owner;
	ms->ms_group = group;
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getcwd(char** retval, char* buf, size_t size, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = size * sizeof(char);
	size_t _len_perrno = sizeof(int);

	ms_ocall_getcwd_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getcwd_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;
	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);
	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getcwd_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getcwd_t));
	ocalloc_size -= sizeof(ms_ocall_getcwd_t);

	if (buf != NULL) {
		ms->ms_buf = (char*)__tmp;
		__tmp_buf = __tmp;
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_size = size;
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_truncate(int* retval, const char* path, off_t length, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_perrno = sizeof(int);

	ms_ocall_truncate_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_truncate_t);
	void *__tmp = NULL;

	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(path, _len_path);
	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_truncate_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_truncate_t));
	ocalloc_size -= sizeof(ms_ocall_truncate_t);

	if (path != NULL) {
		ms->ms_path = (const char*)__tmp;
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}
	
	ms->ms_length = length;
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_ftruncate(int* retval, int fd, off_t length, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_perrno = sizeof(int);

	ms_ocall_ftruncate_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_ftruncate_t);
	void *__tmp = NULL;

	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_ftruncate_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_ftruncate_t));
	ocalloc_size -= sizeof(ms_ocall_ftruncate_t);

	ms->ms_fd = fd;
	ms->ms_length = length;
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pread(ssize_t* retval, int fd, void* buf, size_t count, off_t offset, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;
	size_t _len_perrno = sizeof(int);

	ms_ocall_pread_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pread_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;
	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);
	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pread_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pread_t));
	ocalloc_size -= sizeof(ms_ocall_pread_t);

	ms->ms_fd = fd;
	if (buf != NULL) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_count = count;
	ms->ms_offset = offset;
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(18, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pwrite(ssize_t* retval, int fd, const void* buf, size_t count, off_t offset, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;
	size_t _len_perrno = sizeof(int);

	ms_ocall_pwrite_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pwrite_t);
	void *__tmp = NULL;

	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);
	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pwrite_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pwrite_t));
	ocalloc_size -= sizeof(ms_ocall_pwrite_t);

	ms->ms_fd = fd;
	if (buf != NULL) {
		ms->ms_buf = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_count = count;
	ms->ms_offset = offset;
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(19, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_access(int* retval, const char* pathname, int mode, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;
	size_t _len_perrno = sizeof(int);

	ms_ocall_access_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_access_t);
	void *__tmp = NULL;

	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);
	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_access_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_access_t));
	ocalloc_size -= sizeof(ms_ocall_access_t);

	if (pathname != NULL) {
		ms->ms_pathname = (const char*)__tmp;
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}
	
	ms->ms_mode = mode;
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(20, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_unlink(int* retval, const char* pathname, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;
	size_t _len_perrno = sizeof(int);

	ms_ocall_unlink_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_unlink_t);
	void *__tmp = NULL;

	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);
	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_unlink_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_unlink_t));
	ocalloc_size -= sizeof(ms_ocall_unlink_t);

	if (pathname != NULL) {
		ms->ms_pathname = (const char*)__tmp;
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}
	
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(21, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_rmdir(int* retval, const char* pathname, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;
	size_t _len_perrno = sizeof(int);

	ms_ocall_rmdir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_rmdir_t);
	void *__tmp = NULL;

	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);
	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_rmdir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_rmdir_t));
	ocalloc_size -= sizeof(ms_ocall_rmdir_t);

	if (pathname != NULL) {
		ms->ms_pathname = (const char*)__tmp;
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}
	
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(22, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_geteuid(uid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_geteuid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_geteuid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_geteuid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_geteuid_t));
	ocalloc_size -= sizeof(ms_ocall_geteuid_t);

	status = sgx_ocall(23, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_lseek(off_t* retval, int fd, off_t offset, int whence, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_perrno = sizeof(int);

	ms_ocall_lseek_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_lseek_t);
	void *__tmp = NULL;

	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_lseek_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_lseek_t));
	ocalloc_size -= sizeof(ms_ocall_lseek_t);

	ms->ms_fd = fd;
	ms->ms_offset = offset;
	ms->ms_whence = whence;
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(24, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fsync(int* retval, int fd, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_perrno = sizeof(int);

	ms_ocall_fsync_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fsync_t);
	void *__tmp = NULL;

	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fsync_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fsync_t));
	ocalloc_size -= sizeof(ms_ocall_fsync_t);

	ms->ms_fd = fd;
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(25, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getpid(pid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_getpid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getpid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getpid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getpid_t));
	ocalloc_size -= sizeof(ms_ocall_getpid_t);

	status = sgx_ocall(26, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sleep(unsigned int* retval, unsigned int seconds)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sleep_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sleep_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sleep_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sleep_t));
	ocalloc_size -= sizeof(ms_ocall_sleep_t);

	ms->ms_seconds = seconds;
	status = sgx_ocall(27, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_rtreslut(int* retval, char* title, size_t count, char* r, size_t size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_title = count;
	size_t _len_r = size;

	ms_ocall_rtreslut_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_rtreslut_t);
	void *__tmp = NULL;

	void *__tmp_title = NULL;
	void *__tmp_r = NULL;

	CHECK_ENCLAVE_POINTER(title, _len_title);
	CHECK_ENCLAVE_POINTER(r, _len_r);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (title != NULL) ? _len_title : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (r != NULL) ? _len_r : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_rtreslut_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_rtreslut_t));
	ocalloc_size -= sizeof(ms_ocall_rtreslut_t);

	if (title != NULL) {
		ms->ms_title = (char*)__tmp;
		__tmp_title = __tmp;
		if (_len_title % sizeof(*title) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_title, 0, _len_title);
		__tmp = (void *)((size_t)__tmp + _len_title);
		ocalloc_size -= _len_title;
	} else {
		ms->ms_title = NULL;
	}
	
	ms->ms_count = count;
	if (r != NULL) {
		ms->ms_r = (char*)__tmp;
		__tmp_r = __tmp;
		if (_len_r % sizeof(*r) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_r, 0, _len_r);
		__tmp = (void *)((size_t)__tmp + _len_r);
		ocalloc_size -= _len_r;
	} else {
		ms->ms_r = NULL;
	}
	
	ms->ms_size = size;
	status = sgx_ocall(28, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (title) {
			if (memcpy_s((void*)title, _len_title, __tmp_title, _len_title)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (r) {
			if (memcpy_s((void*)r, _len_r, __tmp_r, _len_r)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_strcat(char** retval, char* dest, size_t count, const char* src)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dest = count;
	size_t _len_src = src ? strlen(src) + 1 : 0;

	ms_ocall_strcat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_strcat_t);
	void *__tmp = NULL;

	void *__tmp_dest = NULL;

	CHECK_ENCLAVE_POINTER(dest, _len_dest);
	CHECK_ENCLAVE_POINTER(src, _len_src);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dest != NULL) ? _len_dest : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (src != NULL) ? _len_src : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_strcat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_strcat_t));
	ocalloc_size -= sizeof(ms_ocall_strcat_t);

	if (dest != NULL) {
		ms->ms_dest = (char*)__tmp;
		__tmp_dest = __tmp;
		if (_len_dest % sizeof(*dest) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, dest, _len_dest)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_dest);
		ocalloc_size -= _len_dest;
	} else {
		ms->ms_dest = NULL;
	}
	
	ms->ms_count = count;
	if (src != NULL) {
		ms->ms_src = (const char*)__tmp;
		if (_len_src % sizeof(*src) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, src, _len_src)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_src);
		ocalloc_size -= _len_src;
	} else {
		ms->ms_src = NULL;
	}
	
	status = sgx_ocall(29, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (dest) {
			if (memcpy_s((void*)dest, _len_dest, __tmp_dest, _len_dest)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_time(time_t* retval, time_t* t, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_t = sizeof(time_t);
	size_t _len_perrno = sizeof(int);

	ms_ocall_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_time_t);
	void *__tmp = NULL;

	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(t, _len_t);
	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (t != NULL) ? _len_t : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_time_t));
	ocalloc_size -= sizeof(ms_ocall_time_t);

	if (t != NULL) {
		ms->ms_t = (time_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, t, _len_t)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_t);
		ocalloc_size -= _len_t;
	} else {
		ms->ms_t = NULL;
	}
	
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(30, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_utimes(int* retval, const char* filename, const struct timeval* times, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;
	size_t _len_times = 2 * sizeof(struct timeval);
	size_t _len_perrno = sizeof(int);

	ms_ocall_utimes_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_utimes_t);
	void *__tmp = NULL;

	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(filename, _len_filename);
	CHECK_ENCLAVE_POINTER(times, _len_times);
	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (filename != NULL) ? _len_filename : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (times != NULL) ? _len_times : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_utimes_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_utimes_t));
	ocalloc_size -= sizeof(ms_ocall_utimes_t);

	if (filename != NULL) {
		ms->ms_filename = (const char*)__tmp;
		if (_len_filename % sizeof(*filename) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, filename, _len_filename)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_filename);
		ocalloc_size -= _len_filename;
	} else {
		ms->ms_filename = NULL;
	}
	
	if (times != NULL) {
		ms->ms_times = (const struct timeval*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, times, _len_times)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_times);
		ocalloc_size -= _len_times;
	} else {
		ms->ms_times = NULL;
	}
	
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(31, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_gettimeofday(int* retval, struct timeval* tv, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_tv = sizeof(struct timeval);
	size_t _len_perrno = sizeof(int);

	ms_ocall_gettimeofday_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_gettimeofday_t);
	void *__tmp = NULL;

	void *__tmp_tv = NULL;
	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(tv, _len_tv);
	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (tv != NULL) ? _len_tv : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_gettimeofday_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_gettimeofday_t));
	ocalloc_size -= sizeof(ms_ocall_gettimeofday_t);

	if (tv != NULL) {
		ms->ms_tv = (struct timeval*)__tmp;
		__tmp_tv = __tmp;
		memset(__tmp_tv, 0, _len_tv);
		__tmp = (void *)((size_t)__tmp + _len_tv);
		ocalloc_size -= _len_tv;
	} else {
		ms->ms_tv = NULL;
	}
	
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(32, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (tv) {
			if (memcpy_s((void*)tv, _len_tv, __tmp_tv, _len_tv)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getenv(char** retval, const char* name, int* perrno)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = name ? strlen(name) + 1 : 0;
	size_t _len_perrno = sizeof(int);

	ms_ocall_getenv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getenv_t);
	void *__tmp = NULL;

	void *__tmp_perrno = NULL;

	CHECK_ENCLAVE_POINTER(name, _len_name);
	CHECK_ENCLAVE_POINTER(perrno, _len_perrno);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (name != NULL) ? _len_name : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (perrno != NULL) ? _len_perrno : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getenv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getenv_t));
	ocalloc_size -= sizeof(ms_ocall_getenv_t);

	if (name != NULL) {
		ms->ms_name = (const char*)__tmp;
		if (_len_name % sizeof(*name) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, name, _len_name)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_name);
		ocalloc_size -= _len_name;
	} else {
		ms->ms_name = NULL;
	}
	
	if (perrno != NULL) {
		ms->ms_perrno = (int*)__tmp;
		__tmp_perrno = __tmp;
		if (_len_perrno % sizeof(*perrno) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_perrno, 0, _len_perrno);
		__tmp = (void *)((size_t)__tmp + _len_perrno);
		ocalloc_size -= _len_perrno;
	} else {
		ms->ms_perrno = NULL;
	}
	
	status = sgx_ocall(33, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (perrno) {
			if (memcpy_s((void*)perrno, _len_perrno, __tmp_perrno, _len_perrno)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

