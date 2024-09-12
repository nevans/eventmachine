/*****************************************************************************

$Id$

File:     rubymain.cpp
Date:     06Apr06

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/

#include "project.h"
#include "eventmachine.h"
#include <ruby.h>

/* Adapted from NUM2BSIG / BSIG2NUM in ext/fiddle/conversions.h,
 * we'll call it a BSIG for Binding Signature here. */
#if SIZEOF_VOIDP == SIZEOF_LONG
# define BSIG2NUM(x)   (ULONG2NUM((unsigned long)(x)))
# define NUM2BSIG(x)   (NUM2ULONG(x))
# ifdef OS_WIN32
#  define PRIFBSIG      "I32u"
# else
#  define PRIFBSIG      "lu"
# endif
#else
# define BSIG2NUM(x)   (ULL2NUM((unsigned long long)(x)))
# define NUM2BSIG(x)   (NUM2ULL(x))
# ifdef OS_WIN32
#  define PRIFBSIG      "I64u"
# else
#  define PRIFBSIG      "llu"
# endif
#endif

/* Adapted from SWIG's changes for Ruby 2.7 compatibility.
 * Before Ruby 2.7, rb_rescue takes (VALUE (*))(ANYARGS)
 * whereas in Ruby 2.7, rb_rescue takes (VALUE (*))(VALUE)
 * */
#if defined(__cplusplus) && !defined(RB_METHOD_DEFINITION_DECL)
#  define VALUEFUNC(f) ((VALUE (*)(ANYARGS)) f)
#else
#  define VALUEFUNC(f) (f)
#endif

/*******
Statics
*******/

static VALUE EmModule;
static VALUE EmSslContext;
static VALUE EmConnection;
static VALUE mEmSsl;
static VALUE mEmSslX509;
static VALUE cEmSslX509StoreContext;

static VALUE EmConnsHash;
static VALUE EmTimersHash;

static VALUE EM_eConnectionError;
static VALUE EM_eUnknownTimerFired;
static VALUE EM_eConnectionNotBound;
static VALUE EM_eUnsupported;
static VALUE EM_eInvalidSignature;
static VALUE EM_eInvalidPrivateKey;

static VALUE Intern_at_signature;
static VALUE Intern_at_timers;
static VALUE Intern_at_conns;
static VALUE Intern_at_error_handler;
static VALUE Intern_event_callback;
static VALUE Intern_run_deferred_callbacks;
static VALUE Intern_delete;
static VALUE Intern_call;
static VALUE Intern_at;
static VALUE Intern_receive_data;
static VALUE Intern_ssl_handshake_completed;
static VALUE Intern_ssl_verify_peer;
static VALUE Intern_notify_readable;
static VALUE Intern_notify_writable;
static VALUE Intern_proxy_target_unbound;
static VALUE Intern_proxy_completed;
static VALUE Intern_connection_completed;

static ID id_i_cert_store;
static ID id_i_ca_file;
static ID id_i_ca_path;
static ID id_i_verify_mode;
static ID id_i_cert;
static ID id_i_key;
static ID id_i_verify_hostname;
static ID id_i_private_key_file;
static ID id_i_private_key_pass;
static ID id_i_cert_chain_file;

static ID id_i_max_proto_version;
static ID id_i_min_proto_version;
static ID id_i_options;
static ID id_i_ciphers;
static ID id_i_ecdh_curve;
static ID id_i_dhparam;

static VALUE rb_cProcessStatus;

static int em_ssl_ssl_ex_ptr_idx;

#ifdef IS_RUBY_3_OR_LATER
/* Structure definition from MRI Ruby 3.0 process.c */
struct rb_process_status {
    rb_pid_t pid;
    int status;
    int error;
};
#endif

struct em_event {
	uintptr_t signature;
	int event;
	const char *data_str;
	unsigned long data_num;
};

static inline VALUE ensure_conn(const uintptr_t signature)
{
	VALUE conn = rb_hash_aref (EmConnsHash, BSIG2NUM (signature));
	if (conn == Qnil)
		rb_raise (EM_eConnectionNotBound, "unknown connection: %" PRIFBSIG, signature);
	return conn;
}

/****************
em_ssl_verify_cb_call
****************/

#ifdef WITH_SSL

// adapted from stdlib openssl's ossl_str_new_i
static VALUE em_ssl_str_new_i(VALUE size)
{
	return rb_str_new(NULL, (long)size);
}

// adapted from stdlib openssl's ossl_str_new
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

// adapted from stdlib openssl's ossl_membio2str
VALUE em_ssl_membio2str(BIO *bio)
{
	VALUE ret;
	int state;
	BUF_MEM *buf;

	BIO_get_mem_ptr(bio, &buf);
	ret = em_ssl_str_new(buf->data, buf->length, &state);
	BIO_free(bio);
	if (state)
		rb_jump_tag(state);

	return ret;
}

// adapted from stdlib openssl's ossl_x509_to_pem
static VALUE em_ssl_x509_to_pem(X509 *x509)
{
	BIO *out;
	VALUE str;

	out = BIO_new(BIO_s_mem());
	if (!out) rb_raise(rb_eRuntimeError, "%s", "EventMachine X509 cert error");

	if (!PEM_write_bio_X509(out, x509)) {
		BIO_free(out);
		rb_raise(rb_eRuntimeError, "%s", "EventMachine X509 cert error");
	}
	str = em_ssl_membio2str(out);

	return str;
}

// similar to stdlib openssl's ossl_x509stctx_new
static VALUE em_ssl_x509stctx_new(X509_STORE_CTX *ctx)
{
	int   error_code   = X509_STORE_CTX_get_error(ctx);
	VALUE error        = INT2NUM(error_code);
	VALUE error_string = rb_str_new2(X509_verify_cert_error_string(error_code));
	VALUE error_depth  = INT2NUM(X509_STORE_CTX_get_error_depth(ctx));
	X509 *x509         = X509_STORE_CTX_get_current_cert(ctx);
	VALUE current_cert = em_ssl_x509_to_pem(x509);

	VALUE args[4] = { current_cert, error_depth, error, error_string, };
	return rb_class_new_instance(4, args, cEmSslX509StoreContext);
}

// adapted from stdlib openssl's ossl_x509stctx_new_i
static VALUE em_ssl_x509stctx_new_i(VALUE arg)
{
	return em_ssl_x509stctx_new((X509_STORE_CTX *)arg);
}

// adapted from stdlib openssl's ossl_verify_cb_args
struct em_ssl_verify_cb_args {
	VALUE conn;
	VALUE preverify_ok;
	VALUE store_ctx;
};

// similar to stdlib openssl's call_verify_cb_proc
static VALUE em_ssl_call_verify_peer(VALUE arg)
{
	struct em_ssl_verify_cb_args *args = (struct em_ssl_verify_cb_args *)arg;
	if (rb_obj_method_arity(args->conn, Intern_ssl_verify_peer) == 1) {
		// Backwards compatibility:
		VALUE cert = rb_funcall(args->store_ctx, rb_intern("current_cert"), 0);
		VALUE pem = rb_funcall(cert, rb_intern("to_pem"), 0);
		return rb_funcall(args->conn, Intern_ssl_verify_peer,
		                  1, pem);
	} else {
		return rb_funcall(args->conn, Intern_ssl_verify_peer,
		                  2, args->preverify_ok, args->store_ctx);
	}
}

// adapted from stdlib openssl's ossl_verify_cb_call
extern "C" int em_ssl_verify_cb_call(VALUE conn, int ok, X509_STORE_CTX *ctx)
{
	VALUE rctx, ret;
	struct em_ssl_verify_cb_args args;
	int state;

	if (NIL_P(conn))
		return ok;

	ret = Qfalse;
	rctx = rb_protect(em_ssl_x509stctx_new_i, (VALUE)ctx, &state);
	if (state) {
		rb_set_errinfo(Qnil);
		rb_warn("StoreContext initialization failure");
	}
	else {
		args.conn = conn;
		args.preverify_ok = ok ? Qtrue : Qfalse;
		args.store_ctx = rctx;
		ret = rb_protect(em_ssl_call_verify_peer, (VALUE)&args, &state);
		if (state) {
			rb_set_errinfo(Qnil);
			rb_warn("exception in verify_peer is ignored");
		}
		// RTYPEDDATA_DATA(rctx) = NULL; // rctx isn't RTYPEDDATA here
	}
	if (ret == Qtrue) {
		X509_STORE_CTX_set_error(ctx, X509_V_OK);
		ok = 1;
	}
	else {
		if (X509_STORE_CTX_get_error(ctx) == X509_V_OK)
			X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REJECTED);
		ok = 0;
	}

	return ok;
}

#endif

/****************
t_event_callback
****************/

static inline VALUE event_callback (VALUE e_value)
{
	struct em_event *e = (struct em_event *)e_value;
	const uintptr_t signature = e->signature;
	int event = e->event;
	const char *data_str = e->data_str;
	const unsigned long data_num = e->data_num;

	switch (event) {
		case EM_CONNECTION_READ:
		{
			VALUE conn = rb_hash_aref (EmConnsHash, BSIG2NUM (signature));
			if (conn == Qnil)
				rb_raise (EM_eConnectionNotBound, "received %lu bytes of data for unknown signature: %" PRIFBSIG, data_num, signature);
			rb_funcall (conn, Intern_receive_data, 1, rb_str_new (data_str, data_num));
			return Qnil;
		}
		case EM_CONNECTION_ACCEPTED:
		{
			rb_funcall (EmModule, Intern_event_callback, 3, BSIG2NUM(signature), INT2FIX(event), ULONG2NUM(data_num));
			return Qnil;
		}
		case EM_CONNECTION_UNBOUND:
		{
			rb_funcall (EmModule, Intern_event_callback, 3, BSIG2NUM(signature), INT2FIX(event), ULONG2NUM(data_num));
			return Qnil;
		}
		case EM_CONNECTION_COMPLETED:
		{
			VALUE conn = ensure_conn(signature);
			rb_funcall (conn, Intern_connection_completed, 0);
			return Qnil;
		}
		case EM_CONNECTION_NOTIFY_READABLE:
		{
			VALUE conn = ensure_conn(signature);
			rb_funcall (conn, Intern_notify_readable, 0);
			return Qnil;
		}
		case EM_CONNECTION_NOTIFY_WRITABLE:
		{
			VALUE conn = ensure_conn(signature);
			rb_funcall (conn, Intern_notify_writable, 0);
			return Qnil;
		}
		case EM_LOOPBREAK_SIGNAL:
		{
			rb_funcall (EmModule, Intern_run_deferred_callbacks, 0);
			return Qnil;
		}
		case EM_TIMER_FIRED:
		{
			VALUE timer = rb_funcall (EmTimersHash, Intern_delete, 1, ULONG2NUM (data_num));
			if (timer == Qnil) {
				rb_raise (EM_eUnknownTimerFired, "no such timer: %lu", data_num);
			} else if (timer == Qfalse) {
				/* Timer Canceled */
			} else {
				rb_funcall (timer, Intern_call, 0);
			}
			return Qnil;
		}
		#ifdef WITH_SSL
		case EM_SSL_HANDSHAKE_COMPLETED:
		{
			VALUE conn = ensure_conn(signature);
			rb_funcall (conn, Intern_ssl_handshake_completed, 0);
			return Qnil;
		}
		case EM_SSL_VERIFY:
		{
			VALUE conn = ensure_conn(signature);
			X509_STORE_CTX *ctx = (X509_STORE_CTX *)data_str;
			if (em_ssl_verify_cb_call(conn, data_num, ctx))
				evma_accept_ssl_peer (signature);

			return Qnil;
		}
		#endif
		case EM_PROXY_TARGET_UNBOUND:
		{
			VALUE conn = ensure_conn(signature);
			rb_funcall (conn, Intern_proxy_target_unbound, 0);
			return Qnil;
		}
		case EM_PROXY_COMPLETED:
		{
			VALUE conn = ensure_conn(signature);
			rb_funcall (conn, Intern_proxy_completed, 0);
			return Qnil;
		}
	}

	return Qnil;
}

/*******************
event_error_handler
*******************/

static VALUE event_error_handler(VALUE self UNUSED, VALUE err)
{
	VALUE error_handler = rb_ivar_get(EmModule, Intern_at_error_handler);
	rb_funcall (error_handler, Intern_call, 1, err);
	return Qnil;
}

/**********************
event_callback_wrapper
**********************/

static void event_callback_wrapper (const uintptr_t signature, int event, const char *data_str, const unsigned long data_num)
{
	struct em_event e;
	e.signature = signature;
	e.event = event;
	e.data_str = data_str;
	e.data_num = data_num;

	if (!rb_ivar_defined(EmModule, Intern_at_error_handler))
		event_callback((VALUE)&e);
	else
		rb_rescue(VALUEFUNC(event_callback), (VALUE)&e, VALUEFUNC(event_error_handler), Qnil);
}

/**************************
t_initialize_event_machine
**************************/

static VALUE t_initialize_event_machine (VALUE self UNUSED)
{
	EmConnsHash = rb_ivar_get (EmModule, Intern_at_conns);
	EmTimersHash = rb_ivar_get (EmModule, Intern_at_timers);
	assert(EmConnsHash != Qnil);
	assert(EmTimersHash != Qnil);
	evma_initialize_library ((EMCallback)event_callback_wrapper);
	return Qnil;
}


/******************
t_run_machine_once
******************/

static VALUE t_run_machine_once (VALUE self UNUSED)
{
	return evma_run_machine_once () ? Qtrue : Qfalse;
}


/*************
t_run_machine
*************/

static VALUE t_run_machine (VALUE self UNUSED)
{
	evma_run_machine();
	return Qnil;
}

/*****************************
t_get_timer_count
*****************************/

static VALUE t_get_timer_count ()
{
	return SIZET2NUM (evma_get_timer_count ());
}

/*******************
t_add_oneshot_timer
*******************/

static VALUE t_add_oneshot_timer (VALUE self UNUSED, VALUE interval)
{
	const uintptr_t f = evma_install_oneshot_timer (FIX2LONG (interval));
	if (!f)
		rb_raise (rb_eRuntimeError, "%s", "ran out of timers; use #set_max_timers to increase limit");
	return BSIG2NUM (f);
}


/**************
t_start_server
**************/

static VALUE t_start_server (VALUE self UNUSED, VALUE server, VALUE port)
{
	const uintptr_t f = evma_create_tcp_server (StringValueCStr(server), FIX2INT(port));
	if (!f)
		rb_raise (rb_eRuntimeError, "%s", "no acceptor (port is in use or requires root privileges)");
	return BSIG2NUM (f);
}

/*************
t_stop_server
*************/

static VALUE t_stop_server (VALUE self UNUSED, VALUE signature)
{
	evma_stop_tcp_server (NUM2BSIG (signature));
	return Qnil;
}


/*******************
t_start_unix_server
*******************/

static VALUE t_start_unix_server (VALUE self UNUSED, VALUE filename)
{
	const uintptr_t f = evma_create_unix_domain_server (StringValueCStr(filename));
	if (!f)
		rb_raise (rb_eRuntimeError, "%s", "no unix-domain acceptor");
	return BSIG2NUM (f);
}

/********************
t_attach_sd
********************/

static VALUE t_attach_sd(VALUE self UNUSED, VALUE sd)
{
	const uintptr_t f = evma_attach_sd(FIX2INT(sd));
	if (!f)
		rb_raise (rb_eRuntimeError, "%s", "no socket descriptor acceptor");
	return BSIG2NUM (f);
}


/***********
t_send_data
***********/

static VALUE t_send_data (VALUE self UNUSED, VALUE signature, VALUE data, VALUE data_length)
{
	int b = evma_send_data_to_connection (NUM2BSIG (signature), StringValuePtr (data), FIX2INT (data_length));
	return INT2NUM (b);
}


/***********
t_start_tls
***********/

static VALUE t_start_tls (VALUE self UNUSED, VALUE signature)
{
	try {
		evma_start_tls (NUM2BSIG (signature));
	} catch (const std::runtime_error& e) {
		rb_raise (EM_eInvalidPrivateKey, e.what(), signature);
	}
	return Qnil;
}

/***************************
 extract_ssl_context_struct
 **************************/

// converted into a C string here, so ssl.cpp doesn't need to deal with ruby API
static VALUE
em_sslctx_convert_ciphers_list(VALUE v)
{
    VALUE str, elem;
    int i;

    if (NIL_P(v))
		return v;
    else if (RB_TYPE_P(v, T_ARRAY)) {
        str = rb_str_new(0, 0);
        for (i = 0; i < RARRAY_LEN(v); i++) {
            elem = rb_ary_entry(v, i);
            if (RB_TYPE_P(elem, T_ARRAY)) elem = rb_ary_entry(elem, 0);
            elem = rb_String(elem);
            rb_str_append(str, elem);
            if (i < RARRAY_LEN(v)-1) rb_str_cat2(str, ":");
        }
    } else {
        str = v;
        StringValue(str);
    }
	return str;
}

#define EM_SSL_CTX_GC_GUARD(val) \
	if (!NIL_P(ivar)) rb_ary_push(gc_guard, val)

#define EM_SSL_CTX_COPY_IVAR(RB_CAST, NAME, NILVAL) do {\
	ivar = rb_ivar_defined(obj, id_i_##NAME) ? \
		rb_ivar_get(obj, id_i_##NAME) : Qnil; \
	ctx->NAME = NIL_P(ivar) ? NILVAL : RB_CAST(ivar); \
} while (0)

#define EM_SSL_CTX_COPY_IVAR_STR(NAME) do {\
	EM_SSL_CTX_COPY_IVAR(StringValueCStr, NAME, NULL); \
	EM_SSL_CTX_GC_GUARD(ivar); \
} while (0)

// n.b. the caller must hold onto the returned VALUE array, to guard the
// underlying C strings from GC.
static VALUE
extract_ssl_context_struct (VALUE obj, em_ssl_ctx_t *ctx) {
	if (!rb_obj_is_kind_of(obj, EmSslContext)) {
		rb_raise(rb_eTypeError, "Not an EventMachine::SSL::Context");
	}

	VALUE ivar = Qnil;
	VALUE gc_guard = rb_ary_tmp_new(rb_ivar_count(obj));

	EM_SSL_CTX_COPY_IVAR(RB_NUM2INT,   min_proto_version, 0);
	EM_SSL_CTX_COPY_IVAR(RB_NUM2INT,   max_proto_version, 0);
	EM_SSL_CTX_COPY_IVAR(RB_NUM2ULONG, options,           0);
	EM_SSL_CTX_COPY_IVAR(RB_NUM2INT,   verify_mode,       SSL_VERIFY_NONE);
	EM_SSL_CTX_COPY_IVAR(RB_TEST,      verify_hostname,   false);

	EM_SSL_CTX_COPY_IVAR(RB_TEST,      cert_store,        true);
	EM_SSL_CTX_COPY_IVAR_STR(ca_file);
	EM_SSL_CTX_COPY_IVAR_STR(ca_path);

	EM_SSL_CTX_COPY_IVAR_STR(cert);
	EM_SSL_CTX_COPY_IVAR_STR(cert_chain_file);
	EM_SSL_CTX_COPY_IVAR_STR(key);
	EM_SSL_CTX_COPY_IVAR_STR(private_key_file);

	EM_SSL_CTX_COPY_IVAR(StringValuePtr, private_key_pass, "");
	ctx->private_key_pass_len = NIL_P(ivar) ? 0 : RSTRING_LENINT(ivar);

	EM_SSL_CTX_COPY_IVAR_STR(ecdh_curve);
	EM_SSL_CTX_COPY_IVAR_STR(dhparam);

	ivar = rb_ivar_defined(obj, id_i_ciphers) ?
		rb_ivar_get(obj, id_i_ciphers) : Qnil;
	ivar = em_sslctx_convert_ciphers_list(ivar);
	if (!NIL_P(ivar)) {
		ctx->ciphers = StringValueCStr(ivar);
		EM_SSL_CTX_GC_GUARD(ivar);
	} else {
		ctx->ciphers = NULL;
	}

	return gc_guard;
}

#undef EM_SSL_CTX_COPY_IVAR_STR
#undef EM_SSL_CTX_COPY_IVAR
#undef EM_SSL_CTX_GC_GUARD

/***************
t_set_tls_parms
***************/

static VALUE t_set_tls_parms(
		VALUE self UNUSED,
		VALUE signature,
		VALUE context,
		VALUE snihostname) {
	VALUE gc_guard = Qundef;
	try {
		char *c_hostname = NIL_P(snihostname) ? NULL : StringValueCStr(snihostname);
		em_ssl_ctx_t ctx;
		gc_guard = extract_ssl_context_struct(context, &ctx);
		evma_set_tls_parms(NUM2BSIG(signature), ctx, c_hostname);
	} catch (const std::runtime_error& e) {
		rb_raise (rb_eRuntimeError,
				"EventMachine.set_tls_parms: %s", e.what());
		RB_GC_GUARD(gc_guard);
	}
	return Qnil;
}

/***************
t_get_peer_cert
***************/

#ifdef WITH_SSL
static VALUE t_get_peer_cert (VALUE self UNUSED, VALUE signature)
{
	VALUE ret = Qnil;

	X509 *cert = NULL;
	BUF_MEM *buf;
	BIO *out;

	cert = evma_get_peer_cert (NUM2BSIG (signature));

	if (cert != NULL) {
		out = BIO_new(BIO_s_mem());
		PEM_write_bio_X509(out, cert);
		BIO_get_mem_ptr(out, &buf);
		ret = rb_str_new(buf->data, buf->length);
		X509_free(cert);
		BIO_free(out);
	}

	return ret;
}
#else
static VALUE t_get_peer_cert (VALUE self UNUSED, VALUE signature UNUSED)
{
	return Qnil;
}
#endif

/***************
t_get_cipher_bits
***************/

#ifdef WITH_SSL
static VALUE t_get_cipher_bits (VALUE self UNUSED, VALUE signature)
{
	int bits = evma_get_cipher_bits (NUM2BSIG (signature));
	if (bits == -1)
		return Qnil;
	return INT2NUM (bits);
}
#else
static VALUE t_get_cipher_bits (VALUE self UNUSED, VALUE signature UNUSED)
{
	return Qnil;
}
#endif

/***************
t_get_cipher_name
***************/

#ifdef WITH_SSL
static VALUE t_get_cipher_name (VALUE self UNUSED, VALUE signature)
{
	const char *protocol = evma_get_cipher_name (NUM2BSIG (signature));
	if (protocol)
		return rb_str_new2 (protocol);

	return Qnil;
}
#else
static VALUE t_get_cipher_name (VALUE self UNUSED, VALUE signature UNUSED)
{
	return Qnil;
}
#endif

/***************
t_get_cipher_protocol
***************/

#ifdef WITH_SSL
static VALUE t_get_cipher_protocol (VALUE self UNUSED, VALUE signature)
{
	const char *cipher = evma_get_cipher_protocol (NUM2BSIG (signature));
	if (cipher)
		return rb_str_new2 (cipher);

	return Qnil;
}
#else
static VALUE t_get_cipher_protocol (VALUE self UNUSED, VALUE signature UNUSED)
{
	return Qnil;
}
#endif

/***************
t_get_sni_hostname
***************/

#ifdef WITH_SSL
static VALUE t_get_sni_hostname (VALUE self UNUSED, VALUE signature)
{
	const char *sni_hostname = evma_get_sni_hostname (NUM2BSIG (signature));
	if (sni_hostname)
		return rb_str_new2 (sni_hostname);

	return Qnil;
}
#else
static VALUE t_get_sni_hostname (VALUE self UNUSED, VALUE signature UNUSED)
{
	return Qnil;
}
#endif

/**************
t_get_peername
**************/

static VALUE t_get_peername (VALUE self UNUSED, VALUE signature)
{
	char buf[1024];
	socklen_t len = sizeof buf;
	try {
		if (evma_get_peername (NUM2BSIG (signature), (struct sockaddr*)buf, &len)) {
			return rb_str_new (buf, len);
		}
	} catch (std::runtime_error e) {
		rb_raise (rb_eRuntimeError, "%s", e.what());
	}

	return Qnil;
}

/**************
t_get_sockname
**************/

static VALUE t_get_sockname (VALUE self UNUSED, VALUE signature)
{
	char buf[1024];
	socklen_t len = sizeof buf;
	try {
		if (evma_get_sockname (NUM2BSIG (signature), (struct sockaddr*)buf, &len)) {
			return rb_str_new (buf, len);
		}
	} catch (std::runtime_error e) {
		rb_raise (rb_eRuntimeError, "%s", e.what());
	}

	return Qnil;
}

/********************
t_get_subprocess_pid
********************/

static VALUE t_get_subprocess_pid (VALUE self UNUSED, VALUE signature)
{
	pid_t pid;
	if (evma_get_subprocess_pid (NUM2BSIG (signature), &pid)) {
		return INT2NUM (pid);
	}

	return Qnil;
}

/***********************
t_get_subprocess_status
***********************/

static VALUE t_get_subprocess_status (VALUE self UNUSED, VALUE signature)
{
	VALUE proc_status = Qnil;

	int status;
	pid_t pid;

	if (evma_get_subprocess_status (NUM2BSIG (signature), &status)) {
		if (evma_get_subprocess_pid (NUM2BSIG (signature), &pid)) {

#if defined(IS_RUBY_3_3_OR_LATER)
			proc_status = rb_obj_alloc(rb_cProcessStatus);
			struct rb_process_status *data = NULL;
			data = (rb_process_status*)RTYPEDDATA_GET_DATA(proc_status);
			data->pid = pid;
			data->status = status;
#elif defined(IS_RUBY_3_OR_LATER)
			struct rb_process_status *data = NULL;

			/* Defined to match static definition from MRI Ruby 3.0 process.c
			 *
			 * Older C++ compilers before GCC 8 don't allow static initialization of a
			 * struct without every field specified, so the definition here is at runtime
			 */
			static rb_data_type_t rb_process_status_type;
			rb_process_status_type.wrap_struct_name = "Process::Status";
			rb_process_status_type.function.dfree = RUBY_DEFAULT_FREE;
			rb_process_status_type.flags = RUBY_TYPED_FREE_IMMEDIATELY;

			proc_status = TypedData_Make_Struct(rb_cProcessStatus, struct rb_process_status, &rb_process_status_type, data);
			data->pid = pid;
			data->status = status;
#else
			proc_status = rb_obj_alloc(rb_cProcessStatus);
			/* MRI Ruby uses hidden instance vars */
			rb_ivar_set(proc_status, rb_intern_const("status"), INT2FIX(status));
			rb_ivar_set(proc_status, rb_intern_const("pid"), INT2FIX(pid));
#endif

#ifdef RUBINIUS
			/* Rubinius uses standard instance vars */
			rb_iv_set(proc_status, "@pid", INT2FIX(pid));
			if (WIFEXITED(status)) {
				rb_iv_set(proc_status, "@status", INT2FIX(WEXITSTATUS(status)));
			} else if (WIFSIGNALED(status)) {
				rb_iv_set(proc_status, "@termsig", INT2FIX(WTERMSIG(status)));
			} else if (WIFSTOPPED(status)) {
				rb_iv_set(proc_status, "@stopsig", INT2FIX(WSTOPSIG(status)));
			}
#endif
		}
	}
	rb_obj_freeze(proc_status);
	return proc_status;
}

/**********************
t_get_connection_count
**********************/

static VALUE t_get_connection_count (VALUE self UNUSED)
{
	return INT2NUM(evma_get_connection_count());
}

/*****************************
t_get_comm_inactivity_timeout
*****************************/

static VALUE t_get_comm_inactivity_timeout (VALUE self UNUSED, VALUE signature)
{
	return rb_float_new(evma_get_comm_inactivity_timeout(NUM2BSIG (signature)));
}

/*****************************
t_set_comm_inactivity_timeout
*****************************/

static VALUE t_set_comm_inactivity_timeout (VALUE self UNUSED, VALUE signature, VALUE timeout)
{
	float ti = RFLOAT_VALUE(timeout);
	if (evma_set_comm_inactivity_timeout(NUM2BSIG(signature), ti)) {
		return Qtrue;
	}
	return Qfalse;
}

/*****************************
t_get_pending_connect_timeout
*****************************/

static VALUE t_get_pending_connect_timeout (VALUE self UNUSED, VALUE signature)
{
	return rb_float_new(evma_get_pending_connect_timeout(NUM2BSIG (signature)));
}

/*****************************
t_set_pending_connect_timeout
*****************************/

static VALUE t_set_pending_connect_timeout (VALUE self UNUSED, VALUE signature, VALUE timeout)
{
	float ti = RFLOAT_VALUE(timeout);
	if (evma_set_pending_connect_timeout(NUM2BSIG(signature), ti)) {
		return Qtrue;
	}
	return Qfalse;
}

/***************
t_send_datagram
***************/

static VALUE t_send_datagram (VALUE self UNUSED, VALUE signature, VALUE data, VALUE data_length, VALUE address, VALUE port)
{
	int b = evma_send_datagram (NUM2BSIG (signature), StringValuePtr (data), FIX2INT (data_length), StringValueCStr(address), FIX2INT(port));
	if (b < 0)
		rb_raise (EM_eConnectionError, "%s", "error in sending datagram"); // FIXME: this could be more specific.
	return INT2NUM (b);
}


/******************
t_close_connection
******************/

static VALUE t_close_connection (VALUE self UNUSED, VALUE signature, VALUE after_writing)
{
	evma_close_connection (NUM2BSIG (signature), ((after_writing == Qtrue) ? 1 : 0));
	return Qnil;
}

/********************************
t_report_connection_error_status
********************************/

static VALUE t_report_connection_error_status (VALUE self UNUSED, VALUE signature)
{
	int b = evma_report_connection_error_status (NUM2BSIG (signature));
	return INT2NUM (b);
}



/****************
t_connect_server
****************/

static VALUE t_connect_server (VALUE self UNUSED, VALUE server, VALUE port)
{
	// Avoid FIX2INT in this case, because it doesn't deal with type errors properly.
	// Specifically, if the value of port comes in as a string rather than an integer,
	// NUM2INT will throw a type error, but FIX2INT will generate garbage.

	try {
		const uintptr_t f = evma_connect_to_server (NULL, 0, StringValueCStr(server), NUM2INT(port));
		if (!f)
			rb_raise (EM_eConnectionError, "%s", "no connection");
		return BSIG2NUM (f);
	} catch (std::runtime_error e) {
		rb_raise (EM_eConnectionError, "%s", e.what());
	}
	return Qnil;
}

/*********************
t_bind_connect_server
*********************/

static VALUE t_bind_connect_server (VALUE self UNUSED, VALUE bind_addr, VALUE bind_port, VALUE server, VALUE port)
{
	// Avoid FIX2INT in this case, because it doesn't deal with type errors properly.
	// Specifically, if the value of port comes in as a string rather than an integer,
	// NUM2INT will throw a type error, but FIX2INT will generate garbage.

	try {
		const uintptr_t f = evma_connect_to_server (StringValueCStr(bind_addr), NUM2INT(bind_port), StringValueCStr(server), NUM2INT(port));
		if (!f)
			rb_raise (EM_eConnectionError, "%s", "no connection");
		return BSIG2NUM (f);
	} catch (std::runtime_error e) {
		rb_raise (EM_eConnectionError, "%s", e.what());
	}
	return Qnil;
}

/*********************
t_connect_unix_server
*********************/

static VALUE t_connect_unix_server (VALUE self UNUSED, VALUE serversocket)
{
	const uintptr_t f = evma_connect_to_unix_server (StringValueCStr(serversocket));
	if (!f)
		rb_raise (rb_eRuntimeError, "%s", "no connection");
	return BSIG2NUM (f);
}

/***********
t_attach_fd
***********/

static VALUE t_attach_fd (VALUE self UNUSED, VALUE file_descriptor, VALUE watch_mode)
{
	const uintptr_t f = evma_attach_fd (NUM2INT(file_descriptor), watch_mode == Qtrue);
	if (!f)
		rb_raise (rb_eRuntimeError, "%s", "no connection");
	return BSIG2NUM (f);
}

/***********
t_detach_fd
***********/

static VALUE t_detach_fd (VALUE self UNUSED, VALUE signature)
{
	return INT2NUM(evma_detach_fd (NUM2BSIG (signature)));
}

/*********************
t_get_file_descriptor
*********************/
static VALUE t_get_file_descriptor (VALUE self UNUSED, VALUE signature)
{
	return INT2NUM(evma_get_file_descriptor (NUM2BSIG (signature)));
}

/**************
t_get_sock_opt
**************/

static VALUE t_get_sock_opt (VALUE self UNUSED, VALUE signature, VALUE lev, VALUE optname)
{
	int fd = evma_get_file_descriptor (NUM2BSIG (signature));
	int level = NUM2INT(lev), option = NUM2INT(optname);
	socklen_t len = 128;
	char buf[128];

	if (getsockopt(fd, level, option, buf, &len) < 0)
		rb_sys_fail("getsockopt");

	return rb_str_new(buf, len);
}

/**************
t_set_sock_opt
**************/

static VALUE t_set_sock_opt (VALUE self UNUSED, VALUE signature, VALUE lev, VALUE optname, VALUE optval)
{
	int fd = evma_get_file_descriptor (NUM2BSIG (signature));
	int level = NUM2INT(lev), option = NUM2INT(optname);
	int i;
	const void *v;
	socklen_t len;

	switch (TYPE(optval)) {
	case T_FIXNUM:
		i = FIX2INT(optval);
		goto numval;
	case T_FALSE:
		i = 0;
		goto numval;
	case T_TRUE:
		i = 1;
		numval:
		v = (void*)&i; len = sizeof(i);
		break;
	default:
		StringValue(optval);
		v = RSTRING_PTR(optval);
		len = RSTRING_LENINT(optval);
		break;
	}


	if (setsockopt(fd, level, option, (char *)v, len) < 0)
		rb_sys_fail("setsockopt");

	return INT2FIX(0);
}

/********************
t_is_notify_readable
********************/

static VALUE t_is_notify_readable (VALUE self UNUSED, VALUE signature)
{
	return evma_is_notify_readable(NUM2BSIG (signature)) ? Qtrue : Qfalse;
}

/*********************
t_set_notify_readable
*********************/

static VALUE t_set_notify_readable (VALUE self UNUSED, VALUE signature, VALUE mode)
{
	evma_set_notify_readable(NUM2BSIG(signature), mode == Qtrue);
	return Qnil;
}

/********************
t_is_notify_readable
********************/

static VALUE t_is_notify_writable (VALUE self UNUSED, VALUE signature)
{
	return evma_is_notify_writable(NUM2BSIG (signature)) ? Qtrue : Qfalse;
}

/*********************
t_set_notify_writable
*********************/

static VALUE t_set_notify_writable (VALUE self UNUSED, VALUE signature, VALUE mode)
{
	evma_set_notify_writable(NUM2BSIG (signature), mode == Qtrue);
	return Qnil;
}

/*******
t_pause
*******/

static VALUE t_pause (VALUE self UNUSED, VALUE signature)
{
	return evma_pause(NUM2BSIG (signature)) ? Qtrue : Qfalse;
}

/********
t_resume
********/

static VALUE t_resume (VALUE self UNUSED, VALUE signature)
{
	return evma_resume(NUM2BSIG (signature)) ? Qtrue : Qfalse;
}

/**********
t_paused_p
**********/

static VALUE t_paused_p (VALUE self UNUSED, VALUE signature)
{
	return evma_is_paused(NUM2BSIG (signature)) ? Qtrue : Qfalse;
}

/*********************
t_num_close_scheduled
*********************/

static VALUE t_num_close_scheduled (VALUE self UNUSED)
{
	return INT2FIX(evma_num_close_scheduled());
}

/*****************
t_open_udp_socket
*****************/

static VALUE t_open_udp_socket (VALUE self UNUSED, VALUE server, VALUE port)
{
	const uintptr_t f = evma_open_datagram_socket (StringValueCStr(server), FIX2INT(port));
	if (!f)
		rb_raise (rb_eRuntimeError, "%s", "no datagram socket");
	return BSIG2NUM(f);
}



/*****************
t_release_machine
*****************/

static VALUE t_release_machine (VALUE self UNUSED)
{
	evma_release_library();
	return Qnil;
}


/******
t_stop
******/

static VALUE t_stop (VALUE self UNUSED)
{
	evma_stop_machine();
	return Qnil;
}

/******************
t_signal_loopbreak
******************/

static VALUE t_signal_loopbreak (VALUE self UNUSED)
{
	evma_signal_loopbreak();
	return Qnil;
}

/**************
t_library_type
**************/

static VALUE t_library_type (VALUE self UNUSED)
{
	return rb_eval_string (":extension");
}



/*******************
t_set_timer_quantum
*******************/

static VALUE t_set_timer_quantum (VALUE self UNUSED, VALUE interval)
{
	evma_set_timer_quantum (FIX2INT (interval));
	return Qnil;
}

/********************
t_get_max_timer_count
********************/

static VALUE t_get_max_timer_count (VALUE self UNUSED)
{
	return INT2FIX (evma_get_max_timer_count());
}

/********************
t_set_max_timer_count
********************/

static VALUE t_set_max_timer_count (VALUE self UNUSED, VALUE ct)
{
	evma_set_max_timer_count (FIX2INT (ct));
	return Qnil;
}

/********************
t_get/set_simultaneous_accept_count
********************/

static VALUE t_get_simultaneous_accept_count (VALUE self UNUSED)
{
	return INT2FIX (evma_get_simultaneous_accept_count());
}

static VALUE t_set_simultaneous_accept_count (VALUE self UNUSED, VALUE ct)
{
	evma_set_simultaneous_accept_count (FIX2INT (ct));
	return Qnil;
}

/***************
t_setuid_string
***************/

static VALUE t_setuid_string (VALUE self UNUSED, VALUE username)
{
	evma_setuid_string (StringValueCStr (username));
	return Qnil;
}



/**************
t_invoke_popen
**************/

static VALUE t_invoke_popen (VALUE self UNUSED, VALUE cmd)
{
	#ifdef OS_WIN32
	rb_raise (EM_eUnsupported, "popen is not available on this platform");
	#endif

	int len = RARRAY_LEN(cmd);
	if (len >= 2048)
		rb_raise (rb_eRuntimeError, "%s", "too many arguments to popen");
	char *strings [2048];
	for (int i=0; i < len; i++) {
		VALUE ix = INT2FIX (i);
		VALUE s = rb_ary_aref (1, &ix, cmd);
		strings[i] = StringValueCStr (s);
	}
	strings[len] = NULL;

	uintptr_t f = 0;
	try {
		f = evma_popen (strings);
	} catch (std::runtime_error e) {
		rb_raise (rb_eRuntimeError, "%s", e.what());
	}
	if (!f) {
		char *err = strerror (errno);
		char buf[100];
		memset (buf, 0, sizeof(buf));
		snprintf (buf, sizeof(buf)-1, "no popen: %s", (err?err:"???"));
		rb_raise (rb_eRuntimeError, "%s", buf);
	}
	return BSIG2NUM (f);
}


/***************
t_read_keyboard
***************/

static VALUE t_read_keyboard (VALUE self UNUSED)
{
	const uintptr_t f = evma_open_keyboard();
	if (!f)
		rb_raise (rb_eRuntimeError, "%s", "no keyboard reader");
	return BSIG2NUM (f);
}


/****************
t_watch_filename
****************/

static VALUE t_watch_filename (VALUE self UNUSED, VALUE fname)
{
	try {
		return BSIG2NUM(evma_watch_filename(StringValueCStr(fname)));
	} catch (std::runtime_error e) {
		rb_raise (EM_eUnsupported, "%s", e.what());
	}
	return Qnil;
}


/******************
t_unwatch_filename
******************/

static VALUE t_unwatch_filename (VALUE self UNUSED, VALUE sig)
{
	try {
		evma_unwatch_filename(NUM2BSIG (sig));
	} catch (std::runtime_error e) {
		rb_raise (EM_eInvalidSignature, "%s", e.what());
	}

	return Qnil;
}


/***********
t_watch_pid
***********/

static VALUE t_watch_pid (VALUE self UNUSED, VALUE pid)
{
	try {
		return BSIG2NUM(evma_watch_pid(NUM2INT(pid)));
	} catch (std::runtime_error e) {
		rb_raise (EM_eUnsupported, "%s", e.what());
	}
	return Qnil;
}


/*************
t_unwatch_pid
*************/

static VALUE t_unwatch_pid (VALUE self UNUSED, VALUE sig)
{
	evma_unwatch_pid(NUM2BSIG (sig));
	return Qnil;
}


/*************
t_watch_only_p
*************/

static VALUE t_watch_only_p (VALUE self UNUSED, VALUE signature)
{
	return evma_is_watch_only(NUM2BSIG (signature)) ? Qtrue : Qfalse;
}


/**********
t__epoll_p
**********/

static VALUE t__epoll_p (VALUE self UNUSED)
{
	#ifdef HAVE_EPOLL
	return Qtrue;
	#else
	return Qfalse;
	#endif
}

/********
t__epoll
********/

static VALUE t__epoll (VALUE self UNUSED)
{
	if (t__epoll_p(self) == Qfalse)
		return Qfalse;

	evma_set_epoll (1);
	return Qtrue;
}

/***********
t__epoll_set
***********/

static VALUE t__epoll_set (VALUE self, VALUE val)
{
	if (t__epoll_p(self) == Qfalse && val == Qtrue)
		rb_raise (EM_eUnsupported, "%s", "epoll is not supported on this platform");

	evma_set_epoll (val == Qtrue ? 1 : 0);
	return val;
}


/***********
t__kqueue_p
***********/

static VALUE t__kqueue_p (VALUE self UNUSED)
{
	#ifdef HAVE_KQUEUE
	return Qtrue;
	#else
	return Qfalse;
	#endif
}

/*********
t__kqueue
*********/

static VALUE t__kqueue (VALUE self UNUSED)
{
	if (t__kqueue_p(self) == Qfalse)
		return Qfalse;

	evma_set_kqueue (1);
	return Qtrue;
}

/*************
t__kqueue_set
*************/

static VALUE t__kqueue_set (VALUE self, VALUE val)
{
	if (t__kqueue_p(self) == Qfalse && val == Qtrue)
		rb_raise (EM_eUnsupported, "%s", "kqueue is not supported on this platform");

	evma_set_kqueue (val == Qtrue ? 1 : 0);
	return val;
}


/********
t__ssl_p
********/

static VALUE t__ssl_p (VALUE self UNUSED)
{
	#ifdef WITH_SSL
	return Qtrue;
	#else
	return Qfalse;
	#endif
}

/********
t_stopping
********/

static VALUE t_stopping ()
{
	if (evma_stopping()) {
		return Qtrue;
	} else {
		return Qfalse;
	}
}


/****************
t_send_file_data
****************/

static VALUE t_send_file_data (VALUE self UNUSED, VALUE signature, VALUE filename)
{

	/* The current implementation of evma_send_file_data_to_connection enforces a strict
	 * upper limit on the file size it will transmit (currently 32K). The function returns
	 * zero on success, -1 if the requested file exceeds its size limit, and a positive
	 * number for other errors.
	 * TODO: Positive return values are actually errno's, which is probably the wrong way to
	 * do this. For one thing it's ugly. For another, we can't be sure zero is never a real errno.
	 */

	int b = evma_send_file_data_to_connection (NUM2BSIG (signature), StringValueCStr(filename));
	if (b == -1)
		rb_raise(rb_eRuntimeError, "%s", "File too large.  send_file_data() supports files under 32k.");
	if (b > 0) {
		char *err = strerror (b);
		char buf[1024];
		memset (buf, 0, sizeof(buf));
		snprintf (buf, sizeof(buf)-1, ": %s %s", StringValueCStr(filename),(err?err:"???"));

		rb_raise (rb_eIOError, "%s", buf);
	}

	return INT2NUM (0);
}


/*******************
t_set_rlimit_nofile
*******************/

static VALUE t_set_rlimit_nofile (VALUE self UNUSED, VALUE arg)
{
	int arg_int = (NIL_P(arg)) ? -1 : NUM2INT (arg);
	return INT2NUM (evma_set_rlimit_nofile (arg_int));
}

/***************************
conn_get_outbound_data_size
***************************/

static VALUE conn_get_outbound_data_size (VALUE self)
{
	VALUE sig = rb_ivar_get (self, Intern_at_signature);
	return INT2NUM (evma_get_outbound_data_size (NUM2BSIG (sig)));
}


/******************************
conn_associate_callback_target
******************************/

static VALUE conn_associate_callback_target (VALUE self UNUSED, VALUE sig UNUSED)
{
	// No-op for the time being.
	return Qnil;
}


/******************
t_enable_keepalive
******************/

static VALUE t_enable_keepalive (int argc, VALUE *argv, VALUE self)
{
	VALUE idle, intvl, cnt;
	rb_scan_args(argc, argv, "03", &idle, &intvl, &cnt);

	// In ed.cpp, skip 0 values before calling setsockopt
	int i_idle  = NIL_P(idle)  ? 0 : NUM2INT(idle);
	int i_intvl = NIL_P(intvl) ? 0 : NUM2INT(intvl);
	int i_cnt   = NIL_P(cnt)   ? 0 : NUM2INT(cnt);

	VALUE sig = rb_ivar_get (self, Intern_at_signature);
	try {
		return INT2NUM (evma_enable_keepalive(NUM2ULONG(sig), i_idle, i_intvl, i_cnt));
	} catch (std::runtime_error e) {
		rb_raise (rb_eRuntimeError, "%s", e.what());
	}
}

/******************
t_disable_keepalive
******************/

static VALUE t_disable_keepalive (VALUE self)
{
	VALUE sig = rb_ivar_get (self, Intern_at_signature);
	try {
		return INT2NUM (evma_disable_keepalive(NUM2ULONG(sig)));
	} catch (std::runtime_error e) {
		rb_raise (rb_eRuntimeError, "%s", e.what());
	}
}

/***************
t_get_loop_time
****************/

static VALUE t_get_loop_time (VALUE self UNUSED)
{
	uint64_t current_time = evma_get_current_loop_time();
	if (current_time == 0) {
		return Qnil;
	}

	// Generally the industry has moved to 64-bit time_t, this is just in case we're 32-bit time_t.
	if (sizeof(time_t) < 8 && current_time > INT_MAX) {
		return rb_funcall(rb_cTime, Intern_at, 2, INT2NUM(current_time / 1000000), INT2NUM(current_time % 1000000));
	} else {
		return rb_time_new(current_time / 1000000, current_time % 1000000);
	}
}


/*************
t_start_proxy
**************/

static VALUE t_start_proxy (VALUE self UNUSED, VALUE from, VALUE to, VALUE bufsize, VALUE length)
{
	try {
		evma_start_proxy(NUM2BSIG (from), NUM2BSIG (to), NUM2ULONG(bufsize), NUM2ULONG(length));
	} catch (std::runtime_error e) {
		rb_raise (EM_eConnectionError, "%s", e.what());
	}
	return Qnil;
}


/************
t_stop_proxy
*************/

static VALUE t_stop_proxy (VALUE self UNUSED, VALUE from)
{
	try{
		evma_stop_proxy(NUM2BSIG (from));
	} catch (std::runtime_error e) {
		rb_raise (EM_eConnectionError, "%s", e.what());
	}
	return Qnil;
}

/***************
t_proxied_bytes
****************/

static VALUE t_proxied_bytes (VALUE self UNUSED, VALUE from)
{
	try{
		return BSIG2NUM(evma_proxied_bytes(NUM2BSIG (from)));
	} catch (std::runtime_error e) {
		rb_raise (EM_eConnectionError, "%s", e.what());
	}
	return Qnil;
}

/***************
t_get_idle_time
****************/

static VALUE t_get_idle_time (VALUE self UNUSED, VALUE from)
{
	try{
		uint64_t current_time = evma_get_current_loop_time();
		uint64_t time = evma_get_last_activity_time(NUM2BSIG (from));
		if (current_time != 0 && time != 0) {
			if (time >= current_time)
				return BSIG2NUM(0);
			else {
				uint64_t diff = current_time - time;
				float seconds = diff / (1000.0*1000.0);
				return rb_float_new(seconds);
			}
			return Qnil;
		}
	} catch (std::runtime_error e) {
		rb_raise (EM_eConnectionError, "%s", e.what());
	}
	return Qnil;
}

/************************
t_get_heartbeat_interval
*************************/

static VALUE t_get_heartbeat_interval (VALUE self UNUSED)
{
	return rb_float_new(evma_get_heartbeat_interval());
}


/************************
t_set_heartbeat_interval
*************************/

static VALUE t_set_heartbeat_interval (VALUE self UNUSED, VALUE interval)
{
	float iv = RFLOAT_VALUE(interval);
	if (evma_set_heartbeat_interval(iv))
		return Qtrue;
	return Qfalse;
}


/*********************
Init_rubyeventmachine
*********************/

extern "C" void Init_rubyeventmachine()
{
	// Lookup Process::Status for get_subprocess_status
	VALUE rb_mProcess = rb_const_get(rb_cObject, rb_intern("Process"));
	rb_cProcessStatus = rb_const_get(rb_mProcess, rb_intern("Status"));

	// Tuck away some symbol values so we don't have to look 'em up every time we need 'em.
	Intern_at_signature = rb_intern ("@signature");
	Intern_at_timers = rb_intern ("@timers");
	Intern_at_conns = rb_intern ("@conns");
	Intern_at_error_handler = rb_intern("@error_handler");

	Intern_event_callback = rb_intern ("event_callback");
	Intern_run_deferred_callbacks = rb_intern ("run_deferred_callbacks");
	Intern_delete = rb_intern ("delete");
	Intern_call = rb_intern ("call");
	Intern_at = rb_intern("at");
	Intern_receive_data = rb_intern ("receive_data");
	Intern_ssl_handshake_completed = rb_intern ("ssl_handshake_completed");
	Intern_ssl_verify_peer = rb_intern ("ssl_verify_peer");
	Intern_notify_readable = rb_intern ("notify_readable");
	Intern_notify_writable = rb_intern ("notify_writable");
	Intern_proxy_target_unbound = rb_intern ("proxy_target_unbound");
	Intern_proxy_completed = rb_intern ("proxy_completed");
	Intern_connection_completed = rb_intern ("connection_completed");

#define DefIVarID(name) do \
	id_i_##name = rb_intern_const("@"#name); while (0)

	DefIVarID(options);
	DefIVarID(max_proto_version);
	DefIVarID(min_proto_version);

	DefIVarID(cert_store);
	DefIVarID(ca_file);
	DefIVarID(ca_path);
	DefIVarID(verify_mode);
	DefIVarID(verify_hostname);
	DefIVarID(cert);
	DefIVarID(key);
	DefIVarID(verify_hostname);
	DefIVarID(private_key_file);
	DefIVarID(private_key_pass);
	DefIVarID(cert_chain_file);
	DefIVarID(ciphers);
	DefIVarID(ecdh_curve);
	DefIVarID(dhparam);

	// INCOMPLETE, we need to define class Connections inside module EventMachine
	// run_machine and run_machine_without_threads are now identical.
	// Must deprecate the without_threads variant.
	EmModule = rb_define_module ("EventMachine");
	EmConnection = rb_define_class_under (EmModule, "Connection", rb_cObject);
	mEmSsl = rb_define_module_under (EmModule, "SSL");
	mEmSslX509 = rb_define_module_under (mEmSsl, "X509");
	cEmSslX509StoreContext = rb_define_class_under (mEmSslX509, "StoreContext", rb_cObject);

	VALUE EmSsl = rb_define_module_under (EmModule, "SSL");
	EmSslContext = rb_define_class_under (EmSsl, "Context", rb_cObject);

	rb_define_class_under (EmModule, "NoHandlerForAcceptedConnection", rb_eRuntimeError);
	EM_eConnectionError = rb_define_class_under (EmModule, "ConnectionError", rb_eRuntimeError);
	EM_eConnectionNotBound = rb_define_class_under (EmModule, "ConnectionNotBound", rb_eRuntimeError);
	EM_eUnknownTimerFired = rb_define_class_under (EmModule, "UnknownTimerFired", rb_eRuntimeError);
	EM_eUnsupported = rb_define_class_under (EmModule, "Unsupported", rb_eRuntimeError);
	EM_eInvalidSignature = rb_define_class_under (EmModule, "InvalidSignature", rb_eRuntimeError);
	EM_eInvalidPrivateKey = rb_define_class_under (EmModule, "InvalidPrivateKey", rb_eRuntimeError);

	rb_define_module_function (EmModule, "initialize_event_machine", (VALUE(*)(...))t_initialize_event_machine, 0);
	rb_define_module_function (EmModule, "run_machine_once", (VALUE(*)(...))t_run_machine_once, 0);
	rb_define_module_function (EmModule, "run_machine", (VALUE(*)(...))t_run_machine, 0);
	rb_define_module_function (EmModule, "run_machine_without_threads", (VALUE(*)(...))t_run_machine, 0);
	rb_define_module_function (EmModule, "get_timer_count", (VALUE(*)(...))t_get_timer_count, 0);
	rb_define_module_function (EmModule, "add_oneshot_timer", (VALUE(*)(...))t_add_oneshot_timer, 1);
	rb_define_module_function (EmModule, "start_tcp_server", (VALUE(*)(...))t_start_server, 2);
	rb_define_module_function (EmModule, "stop_tcp_server", (VALUE(*)(...))t_stop_server, 1);
	rb_define_module_function (EmModule, "start_unix_server", (VALUE(*)(...))t_start_unix_server, 1);
	rb_define_module_function (EmModule, "attach_sd", (VALUE(*)(...))t_attach_sd, 1);
	rb_define_module_function (EmModule, "set_tls_parms", (VALUE(*)(...))t_set_tls_parms, 3);
	rb_define_module_function (EmModule, "start_tls", (VALUE(*)(...))t_start_tls, 1);
	rb_define_module_function (EmModule, "get_peer_cert", (VALUE(*)(...))t_get_peer_cert, 1);
	rb_define_module_function (EmModule, "get_cipher_bits", (VALUE(*)(...))t_get_cipher_bits, 1);
	rb_define_module_function (EmModule, "get_cipher_name", (VALUE(*)(...))t_get_cipher_name, 1);
	rb_define_module_function (EmModule, "get_cipher_protocol", (VALUE(*)(...))t_get_cipher_protocol, 1);
	rb_define_module_function (EmModule, "get_sni_hostname", (VALUE(*)(...))t_get_sni_hostname, 1);
	rb_define_module_function (EmModule, "send_data", (VALUE(*)(...))t_send_data, 3);
	rb_define_module_function (EmModule, "send_datagram", (VALUE(*)(...))t_send_datagram, 5);
	rb_define_module_function (EmModule, "close_connection", (VALUE(*)(...))t_close_connection, 2);
	rb_define_module_function (EmModule, "report_connection_error_status", (VALUE(*)(...))t_report_connection_error_status, 1);
	rb_define_module_function (EmModule, "connect_server", (VALUE(*)(...))t_connect_server, 2);
	rb_define_module_function (EmModule, "bind_connect_server", (VALUE(*)(...))t_bind_connect_server, 4);
	rb_define_module_function (EmModule, "connect_unix_server", (VALUE(*)(...))t_connect_unix_server, 1);

	rb_define_module_function (EmModule, "attach_fd", (VALUE (*)(...))t_attach_fd, 2);
	rb_define_module_function (EmModule, "detach_fd", (VALUE (*)(...))t_detach_fd, 1);
	rb_define_module_function (EmModule, "get_file_descriptor", (VALUE (*)(...))t_get_file_descriptor, 1);
	rb_define_module_function (EmModule, "get_sock_opt", (VALUE (*)(...))t_get_sock_opt, 3);
	rb_define_module_function (EmModule, "set_sock_opt", (VALUE (*)(...))t_set_sock_opt, 4);
	rb_define_module_function (EmModule, "set_notify_readable", (VALUE (*)(...))t_set_notify_readable, 2);
	rb_define_module_function (EmModule, "set_notify_writable", (VALUE (*)(...))t_set_notify_writable, 2);
	rb_define_module_function (EmModule, "is_notify_readable", (VALUE (*)(...))t_is_notify_readable, 1);
	rb_define_module_function (EmModule, "is_notify_writable", (VALUE (*)(...))t_is_notify_writable, 1);

	rb_define_module_function (EmModule, "pause_connection", (VALUE (*)(...))t_pause, 1);
	rb_define_module_function (EmModule, "resume_connection", (VALUE (*)(...))t_resume, 1);
	rb_define_module_function (EmModule, "connection_paused?", (VALUE (*)(...))t_paused_p, 1);
	rb_define_module_function (EmModule, "num_close_scheduled", (VALUE (*)(...))t_num_close_scheduled, 0);

	rb_define_module_function (EmModule, "start_proxy", (VALUE (*)(...))t_start_proxy, 4);
	rb_define_module_function (EmModule, "stop_proxy", (VALUE (*)(...))t_stop_proxy, 1);
	rb_define_module_function (EmModule, "get_proxied_bytes", (VALUE (*)(...))t_proxied_bytes, 1);

	rb_define_module_function (EmModule, "watch_filename", (VALUE (*)(...))t_watch_filename, 1);
	rb_define_module_function (EmModule, "unwatch_filename", (VALUE (*)(...))t_unwatch_filename, 1);

	rb_define_module_function (EmModule, "watch_pid", (VALUE (*)(...))t_watch_pid, 1);
	rb_define_module_function (EmModule, "unwatch_pid", (VALUE (*)(...))t_unwatch_pid, 1);
	rb_define_module_function (EmModule, "watch_only?", (VALUE (*)(...))t_watch_only_p, 1);

	rb_define_module_function (EmModule, "current_time", (VALUE(*)(...))t_get_loop_time, 0);

	rb_define_module_function (EmModule, "open_udp_socket", (VALUE(*)(...))t_open_udp_socket, 2);
	rb_define_module_function (EmModule, "read_keyboard", (VALUE(*)(...))t_read_keyboard, 0);
	rb_define_module_function (EmModule, "release_machine", (VALUE(*)(...))t_release_machine, 0);
	rb_define_module_function (EmModule, "stop", (VALUE(*)(...))t_stop, 0);
	rb_define_module_function (EmModule, "signal_loopbreak", (VALUE(*)(...))t_signal_loopbreak, 0);
	rb_define_module_function (EmModule, "library_type", (VALUE(*)(...))t_library_type, 0);
	rb_define_module_function (EmModule, "set_timer_quantum", (VALUE(*)(...))t_set_timer_quantum, 1);
	rb_define_module_function (EmModule, "get_max_timer_count", (VALUE(*)(...))t_get_max_timer_count, 0);
	rb_define_module_function (EmModule, "set_max_timer_count", (VALUE(*)(...))t_set_max_timer_count, 1);
	rb_define_module_function (EmModule, "get_simultaneous_accept_count", (VALUE(*)(...))t_get_simultaneous_accept_count, 0);
	rb_define_module_function (EmModule, "set_simultaneous_accept_count", (VALUE(*)(...))t_set_simultaneous_accept_count, 1);
	rb_define_module_function (EmModule, "setuid_string", (VALUE(*)(...))t_setuid_string, 1);
	rb_define_module_function (EmModule, "invoke_popen", (VALUE(*)(...))t_invoke_popen, 1);
	rb_define_module_function (EmModule, "send_file_data", (VALUE(*)(...))t_send_file_data, 2);
	rb_define_module_function (EmModule, "get_heartbeat_interval", (VALUE(*)(...))t_get_heartbeat_interval, 0);
	rb_define_module_function (EmModule, "set_heartbeat_interval", (VALUE(*)(...))t_set_heartbeat_interval, 1);
	rb_define_module_function (EmModule, "get_idle_time", (VALUE(*)(...))t_get_idle_time, 1);

	rb_define_module_function (EmModule, "get_peername", (VALUE(*)(...))t_get_peername, 1);
	rb_define_module_function (EmModule, "get_sockname", (VALUE(*)(...))t_get_sockname, 1);
	rb_define_module_function (EmModule, "get_subprocess_pid", (VALUE(*)(...))t_get_subprocess_pid, 1);
	rb_define_module_function (EmModule, "get_subprocess_status", (VALUE(*)(...))t_get_subprocess_status, 1);
	rb_define_module_function (EmModule, "get_comm_inactivity_timeout", (VALUE(*)(...))t_get_comm_inactivity_timeout, 1);
	rb_define_module_function (EmModule, "set_comm_inactivity_timeout", (VALUE(*)(...))t_set_comm_inactivity_timeout, 2);
	rb_define_module_function (EmModule, "get_pending_connect_timeout", (VALUE(*)(...))t_get_pending_connect_timeout, 1);
	rb_define_module_function (EmModule, "set_pending_connect_timeout", (VALUE(*)(...))t_set_pending_connect_timeout, 2);
	rb_define_module_function (EmModule, "set_rlimit_nofile", (VALUE(*)(...))t_set_rlimit_nofile, 1);
	rb_define_module_function (EmModule, "get_connection_count", (VALUE(*)(...))t_get_connection_count, 0);

	rb_define_module_function (EmModule, "epoll", (VALUE(*)(...))t__epoll, 0);
	rb_define_module_function (EmModule, "epoll=", (VALUE(*)(...))t__epoll_set, 1);
	rb_define_module_function (EmModule, "epoll?", (VALUE(*)(...))t__epoll_p, 0);

	rb_define_module_function (EmModule, "kqueue", (VALUE(*)(...))t__kqueue, 0);
	rb_define_module_function (EmModule, "kqueue=", (VALUE(*)(...))t__kqueue_set, 1);
	rb_define_module_function (EmModule, "kqueue?", (VALUE(*)(...))t__kqueue_p, 0);

	rb_define_module_function (EmModule, "ssl?", (VALUE(*)(...))t__ssl_p, 0);
	rb_define_module_function(EmModule, "stopping?",(VALUE(*)(...))t_stopping, 0);

	rb_define_method (EmConnection, "get_outbound_data_size", (VALUE(*)(...))conn_get_outbound_data_size, 0);
	rb_define_method (EmConnection, "associate_callback_target", (VALUE(*)(...))conn_associate_callback_target, 1);
	rb_define_method (EmConnection, "enable_keepalive", (VALUE(*)(...))t_enable_keepalive, -1);
	rb_define_method (EmConnection, "disable_keepalive", (VALUE(*)(...))t_disable_keepalive, 0);

	// Connection states
	rb_define_const (EmModule, "TimerFired",               INT2NUM(EM_TIMER_FIRED               ));
	rb_define_const (EmModule, "ConnectionData",           INT2NUM(EM_CONNECTION_READ           ));
	rb_define_const (EmModule, "ConnectionUnbound",        INT2NUM(EM_CONNECTION_UNBOUND        ));
	rb_define_const (EmModule, "ConnectionAccepted",       INT2NUM(EM_CONNECTION_ACCEPTED       ));
	rb_define_const (EmModule, "ConnectionCompleted",      INT2NUM(EM_CONNECTION_COMPLETED      ));
	rb_define_const (EmModule, "LoopbreakSignalled",       INT2NUM(EM_LOOPBREAK_SIGNAL          ));
	rb_define_const (EmModule, "ConnectionNotifyReadable", INT2NUM(EM_CONNECTION_NOTIFY_READABLE));
	rb_define_const (EmModule, "ConnectionNotifyWritable", INT2NUM(EM_CONNECTION_NOTIFY_WRITABLE));
	rb_define_const (EmModule, "SslHandshakeCompleted",    INT2NUM(EM_SSL_HANDSHAKE_COMPLETED   ));
	rb_define_const (EmModule, "SslVerify",                INT2NUM(EM_SSL_VERIFY                ));
	// EM_PROXY_TARGET_UNBOUND = 110,
	// EM_PROXY_COMPLETED = 111

	// SSL Protocols
	rb_define_const (EmModule, "EM_PROTO_SSLv2",   INT2NUM(EM_PROTO_SSLv2  ));
	rb_define_const (EmModule, "EM_PROTO_SSLv3",   INT2NUM(EM_PROTO_SSLv3  ));
	rb_define_const (EmModule, "EM_PROTO_TLSv1",   INT2NUM(EM_PROTO_TLSv1  ));
	rb_define_const (EmModule, "EM_PROTO_TLSv1_1", INT2NUM(EM_PROTO_TLSv1_1));
	rb_define_const (EmModule, "EM_PROTO_TLSv1_2", INT2NUM(EM_PROTO_TLSv1_2));
#ifdef TLS1_3_VERSION
	rb_define_const (EmModule, "EM_PROTO_TLSv1_3", INT2NUM(EM_PROTO_TLSv1_3));
#endif

#ifdef OPENSSL_NO_SSL3
	/* True if SSL3 is not available */
	rb_define_const (EmModule, "OPENSSL_NO_SSL3", Qtrue);
	rb_define_const (EmModule, "OPENSSL_NO_SSL2", Qtrue);
#else
	rb_define_const (EmModule, "OPENSSL_NO_SSL3", Qfalse);
#ifdef OPENSSL_NO_SSL2
	rb_define_const (EmModule, "OPENSSL_NO_SSL2", Qtrue);
#else
	rb_define_const (EmModule, "OPENSSL_NO_SSL2", Qfalse);
#endif
#endif

  // OpenSSL Build / Runtime/Load versions

	/* Version of OpenSSL that EventMachine was compiled with */
	rb_define_const(EmModule, "OPENSSL_VERSION", rb_str_new2(OPENSSL_VERSION_TEXT));

#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000
	/* Version of OpenSSL that EventMachine loaded with */
	rb_define_const(EmModule, "OPENSSL_LIBRARY_VERSION", rb_str_new2(OpenSSL_version(OPENSSL_VERSION)));
#else
	rb_define_const(EmModule, "OPENSSL_LIBRARY_VERSION", rb_str_new2(SSLeay_version(SSLEAY_VERSION)));
#endif
}
