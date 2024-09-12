/*
 * This file was copied and adapted from the Ruby/OpenSSL project.
 */
/*
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2000-2025 Ruby/OpenSSL Project Authors
 * Copyright (C) 2025 EventMachine project authors
 * All rights reserved.
 */
/*
 * This file is licensed under the same licence as Ruby.
 * (See the file 'COPYING-openssl'.)
 */
#include "em_ossl.h"
#include <stdarg.h> /* for ossl_raise */

#ifdef WITH_SSL

int em_ssl_ssl_ex_binding_idx;
int em_ssl_ssl_ex_ptr_idx;

static ID ID_callback_state;

static ID id_i_ssl_connection;
static ID id_i_verify_hostname;
static ID id_i_context, id_i_hostname;

/*
 * Data Conversion
 */

/* adapted from stdlib openssl's ossl_str_new_i */
static VALUE em_ssl_str_new_i(VALUE size)
{
	return rb_str_new(NULL, (long)size);
}

/* adapted from stdlib openssl's ossl_str_new */
VALUE em_ssl_str_new(const char *ptr, long len, int *pstate)
{
	VALUE str;
	int state;

	str = rb_protect(em_ssl_str_new_i, len, &state);
	if (pstate)
		*pstate = state;
	if (state) {
		if (!pstate)
			rb_set_errinfo(Qnil);
		return Qnil;
	}
	if (ptr)
		memcpy(RSTRING_PTR(str), ptr, len);
	return str;
}

/*
 * main module
 */
VALUE mEmSsl;

/* adapted from stdlib openssl's call_verify_certificate_identity */
static VALUE call_verify_certificate_identity(VALUE ctx_v)
{
	X509_STORE_CTX *ctx = (X509_STORE_CTX *)ctx_v;
	SSL *ssl;
	VALUE ssl_obj, hostname, cert_pem;

	ssl = (SSL*) X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	ssl_obj = (VALUE)SSL_get_ex_data(ssl, em_ssl_ssl_ex_ptr_idx);
	hostname = rb_attr_get(ssl_obj, id_i_hostname);

	if (!RTEST(hostname)) {
		rb_warning("verify_hostname requires hostname to be set");
		return Qtrue;
	}

	cert_pem = em_ssl_x509_to_pem(X509_STORE_CTX_get_current_cert(ctx));
	return rb_funcall(mEmSsl, rb_intern("verify_certificate_identity"), 2,
	                  cert_pem, hostname);
}

/* adapted from stdlib openssl's ossl_ssl_verify_callback */
int em_ssl_ssl_verify_callback(VALUE conn, int preverify_ok, X509_STORE_CTX *ctx)
{
	uintptr_t binding;
	VALUE ssl_obj, sslctx_obj, verify_hostname, ret;
	SSL *ssl;
	int status;

	ssl = (SSL*) X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	ssl_obj = rb_attr_get(conn, id_i_ssl_connection);
	sslctx_obj = rb_attr_get(ssl_obj, id_i_context);
	verify_hostname = rb_attr_get(sslctx_obj, id_i_verify_hostname);

	if (preverify_ok && RTEST(verify_hostname) && !SSL_is_server(ssl) &&
	    X509_STORE_CTX_get_error_depth(ctx)) {
		ret = rb_protect(call_verify_certificate_identity, (VALUE)ctx, &status);
		if (status) {
			rb_ivar_set(ssl_obj, ID_callback_state, INT2NUM(status));
			return 0;
		}
		if (ret != Qtrue) {
			preverify_ok = 0;
#if defined(X509_V_ERR_HOSTNAME_MISMATCH)
			X509_STORE_CTX_set_error(ctx, X509_V_ERR_HOSTNAME_MISMATCH);
#else
			X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REJECTED);
#endif
		}
	}

	return em_ssl_verify_cb_call(conn, preverify_ok, ctx);
}

#endif /* WITH_SSL */

void Init_em_ssl(void)
{
#ifdef WITH_SSL
	/*
	 * Init main module
	 */
	VALUE rb_mEM = rb_const_get(rb_cObject, rb_intern("EventMachine"));
	rb_global_variable(&mEmSsl);
	mEmSsl = rb_define_module_under (rb_mEM, "SSL");

	ID_callback_state = rb_intern_const("callback_state");

#define DefIVarID(name) do \
	id_i_##name = rb_intern_const("@"#name); while (0)

	DefIVarID(ssl_connection);

	DefIVarID(context);
	DefIVarID(hostname);

	DefIVarID(verify_hostname);

	Init_em_ssl_x509();
#endif /* WITH_SSL */
}
