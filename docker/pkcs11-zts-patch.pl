#!/usr/bin/perl
#
# Patches php-pkcs11's pkcs11module.c for thread-safe use under FrankenPHP ZTS.
#
# FrankenPHP runs many PHP worker threads inside one process.  Every thread
# shares the same dlopen'd PKCS#11 library handle, yet each thread has its own
# PHP static-property context so each one calls new Module() — and therefore
# C_Initialize — the first time it serves an HSM request.
#
# Four patches are applied:
#
#   Patch 1 — pthread mutex + atomic refcount declarations
#     Adds <pthread.h> and <stdatomic.h> includes, a static mutex for
#     serialising C_Initialize, and an atomic reference counter tracking
#     how many Module objects are live across all worker threads.
#
#   Patch 2 — CKF_OS_LOCKING_OK
#     Passes CK_C_INITIALIZE_ARGS with CKF_OS_LOCKING_OK so the PKCS#11
#     library uses OS-level mutexes for all post-init cryptographic operations.
#
#   Patch 3 — CKR_CRYPTOKI_ALREADY_INITIALIZED tolerance
#     Threads 2..N call C_Initialize on an already-initialised library and
#     receive CKR_CRYPTOKI_ALREADY_INITIALIZED (0x91).  The original code
#     treats this as a fatal error; we tolerate it.  Each successful or
#     tolerated initialisation increments the module reference counter.
#
#   Patch 4 — reference-counted pkcs11_shutdown
#     The original pkcs11_shutdown calls C_Finalize(NULL) and dlclose() —
#     both are process-global operations.  In ZTS every worker thread holds
#     its own Module PHP object; when any one of them is GC'd (e.g. on worker
#     recycle), C_Finalize tears down the library process-wide while other
#     threads are still mid-operation, causing SIGSEGV.
#     The fix: decrement the atomic counter; only call C_Finalize/dlclose
#     when the very last Module across all threads is freed.

use strict;
use warnings;

my $file = $ARGV[0] or die "Usage: $0 <pkcs11module.c>\n";

open(my $fh, '<', $file) or die "Cannot open $file: $!\n";
my $src = do { local $/; <$fh> };
close($fh);

# --- Patch 1a: add pthread.h and stdatomic.h ---
$src =~ s{\Q#include "pkcs11int.h"\E}
         {#include "pkcs11int.h"\n#include <pthread.h>\n#include <stdatomic.h>}
    or die "Patch 1a failed: #include \"pkcs11int.h\" not found\n";

# --- Patch 1b: add global mutex + atomic refcount after the object handlers ---
$src =~ s{\Qstatic zend_object_handlers pkcs11_handlers;\E}
         {static zend_object_handlers pkcs11_handlers;\nstatic pthread_mutex_t pkcs11_cinit_mutex = PTHREAD_MUTEX_INITIALIZER;\nstatic _Atomic int pkcs11_module_refcount = 0;}
    or die "Patch 1b failed: pkcs11_handlers declaration not found\n";

# --- Patches 2 & 3 combined: replace the C_Initialize call site ---
my $old = <<'END_OLD';
    rv = objval->functionList->C_Initialize(NULL);
    if (rv != CKR_OK) {
        pkcs11_error(rv, "Unable to initialise token");
        return;
    }
END_OLD

my $new = <<'END_NEW';
    pthread_mutex_lock(&pkcs11_cinit_mutex);
    CK_C_INITIALIZE_ARGS pkcs11_init_args = {NULL, NULL, NULL, NULL, CKF_OS_LOCKING_OK, NULL};
    rv = objval->functionList->C_Initialize(&pkcs11_init_args);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        pkcs11_error(rv, "Unable to initialise token");
        pthread_mutex_unlock(&pkcs11_cinit_mutex);
        return;
    }
    pthread_mutex_unlock(&pkcs11_cinit_mutex);
    atomic_fetch_add_explicit(&pkcs11_module_refcount, 1, memory_order_relaxed);
END_NEW

chomp $old;
chomp $new;

my $count = ($src =~ s{\Q$old\E}{$new});
die "Patches 2&3 failed: C_Initialize block not found — source may have changed\n"
    unless $count == 1;

# --- Patch 4: reference-counted pkcs11_shutdown ---
# Replace the body so C_Finalize/dlclose are only called when the very last
# Module PHP object across all worker threads is being freed.
my $old4 = <<'END_OLD4';
void pkcs11_shutdown(pkcs11_object *obj) {
    // called before the pkcs11_object is freed
    if (obj->functionList != NULL) {
        obj->functionList->C_Finalize(NULL_PTR);
        obj->functionList = NULL;
    }

    if (obj->pkcs11module != NULL) {
        dlclose(obj->pkcs11module);
    }
}
END_OLD4

my $new4 = <<'END_NEW4';
void pkcs11_shutdown(pkcs11_object *obj) {
    /*
     * ZTS safety: only call C_Finalize/dlclose when every Module object across
     * all worker threads has been freed.  Calling C_Finalize from one thread
     * while other threads still hold open sessions causes a SIGSEGV — the
     * library tears down its internal state while concurrent PKCS#11
     * operations are still in flight.
     */
    if (atomic_fetch_sub_explicit(&pkcs11_module_refcount, 1, memory_order_acq_rel) > 1) {
        obj->functionList = NULL;
        obj->pkcs11module = NULL;
        return;
    }

    if (obj->functionList != NULL) {
        obj->functionList->C_Finalize(NULL_PTR);
        obj->functionList = NULL;
    }

    if (obj->pkcs11module != NULL) {
        dlclose(obj->pkcs11module);
    }
}
END_NEW4

chomp $old4;
chomp $new4;

my $count4 = ($src =~ s{\Q$old4\E}{$new4});
die "Patch 4 failed: pkcs11_shutdown body not found — source may have changed\n"
    unless $count4 == 1;

open(my $out, '>', $file) or die "Cannot write $file: $!\n";
print $out $src;
close($out);

print "pkcs11-zts-patch: all patches applied to $file\n";
