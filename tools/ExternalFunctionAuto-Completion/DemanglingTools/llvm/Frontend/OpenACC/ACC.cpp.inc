#ifdef GEN_FLANG_DIRECTIVE_CLAUSE_SETS
#undef GEN_FLANG_DIRECTIVE_CLAUSE_SETS

namespace llvm {
namespace acc {

  // Sets for atomic

  static AccClauseSet allowedClauses_ACCD_atomic {
  };

  static AccClauseSet allowedOnceClauses_ACCD_atomic {
  };

  static AccClauseSet allowedExclusiveClauses_ACCD_atomic {
  };

  static AccClauseSet requiredClauses_ACCD_atomic {
  };

  // Sets for cache

  static AccClauseSet allowedClauses_ACCD_cache {
  };

  static AccClauseSet allowedOnceClauses_ACCD_cache {
  };

  static AccClauseSet allowedExclusiveClauses_ACCD_cache {
  };

  static AccClauseSet requiredClauses_ACCD_cache {
  };

  // Sets for data

  static AccClauseSet allowedClauses_ACCD_data {
  };

  static AccClauseSet allowedOnceClauses_ACCD_data {
    llvm::acc::Clause::ACCC_if,
  };

  static AccClauseSet allowedExclusiveClauses_ACCD_data {
  };

  static AccClauseSet requiredClauses_ACCD_data {
    llvm::acc::Clause::ACCC_attach,
    llvm::acc::Clause::ACCC_copy,
    llvm::acc::Clause::ACCC_copyin,
    llvm::acc::Clause::ACCC_copyout,
    llvm::acc::Clause::ACCC_create,
    llvm::acc::Clause::ACCC_default,
    llvm::acc::Clause::ACCC_deviceptr,
    llvm::acc::Clause::ACCC_no_create,
    llvm::acc::Clause::ACCC_present,
  };

  // Sets for declare

  static AccClauseSet allowedClauses_ACCD_declare {
    llvm::acc::Clause::ACCC_copy,
    llvm::acc::Clause::ACCC_copyin,
    llvm::acc::Clause::ACCC_copyout,
    llvm::acc::Clause::ACCC_create,
    llvm::acc::Clause::ACCC_present,
    llvm::acc::Clause::ACCC_deviceptr,
    llvm::acc::Clause::ACCC_device_resident,
    llvm::acc::Clause::ACCC_link,
  };

  static AccClauseSet allowedOnceClauses_ACCD_declare {
  };

  static AccClauseSet allowedExclusiveClauses_ACCD_declare {
  };

  static AccClauseSet requiredClauses_ACCD_declare {
  };

  // Sets for enter data

  static AccClauseSet allowedClauses_ACCD_enter_data {
  };

  static AccClauseSet allowedOnceClauses_ACCD_enter_data {
    llvm::acc::Clause::ACCC_async,
    llvm::acc::Clause::ACCC_if,
    llvm::acc::Clause::ACCC_wait,
  };

  static AccClauseSet allowedExclusiveClauses_ACCD_enter_data {
  };

  static AccClauseSet requiredClauses_ACCD_enter_data {
    llvm::acc::Clause::ACCC_attach,
    llvm::acc::Clause::ACCC_create,
    llvm::acc::Clause::ACCC_copyin,
  };

  // Sets for exit data

  static AccClauseSet allowedClauses_ACCD_exit_data {
    llvm::acc::Clause::ACCC_async,
    llvm::acc::Clause::ACCC_if,
    llvm::acc::Clause::ACCC_wait,
    llvm::acc::Clause::ACCC_finalize,
  };

  static AccClauseSet allowedOnceClauses_ACCD_exit_data {
  };

  static AccClauseSet allowedExclusiveClauses_ACCD_exit_data {
  };

  static AccClauseSet requiredClauses_ACCD_exit_data {
    llvm::acc::Clause::ACCC_copyout,
    llvm::acc::Clause::ACCC_delete,
    llvm::acc::Clause::ACCC_detach,
  };

  // Sets for host_data

  static AccClauseSet allowedClauses_ACCD_host_data {
    llvm::acc::Clause::ACCC_if,
    llvm::acc::Clause::ACCC_if_present,
  };

  static AccClauseSet allowedOnceClauses_ACCD_host_data {
  };

  static AccClauseSet allowedExclusiveClauses_ACCD_host_data {
  };

  static AccClauseSet requiredClauses_ACCD_host_data {
    llvm::acc::Clause::ACCC_use_device,
  };

  // Sets for init

  static AccClauseSet allowedClauses_ACCD_init {
  };

  static AccClauseSet allowedOnceClauses_ACCD_init {
    llvm::acc::Clause::ACCC_device_num,
    llvm::acc::Clause::ACCC_device_type,
    llvm::acc::Clause::ACCC_if,
  };

  static AccClauseSet allowedExclusiveClauses_ACCD_init {
  };

  static AccClauseSet requiredClauses_ACCD_init {
  };

  // Sets for kernels

  static AccClauseSet allowedClauses_ACCD_kernels {
    llvm::acc::Clause::ACCC_attach,
    llvm::acc::Clause::ACCC_copy,
    llvm::acc::Clause::ACCC_copyin,
    llvm::acc::Clause::ACCC_copyout,
    llvm::acc::Clause::ACCC_create,
    llvm::acc::Clause::ACCC_device_type,
    llvm::acc::Clause::ACCC_no_create,
    llvm::acc::Clause::ACCC_present,
    llvm::acc::Clause::ACCC_deviceptr,
  };

  static AccClauseSet allowedOnceClauses_ACCD_kernels {
    llvm::acc::Clause::ACCC_async,
    llvm::acc::Clause::ACCC_default,
    llvm::acc::Clause::ACCC_if,
    llvm::acc::Clause::ACCC_num_gangs,
    llvm::acc::Clause::ACCC_num_workers,
    llvm::acc::Clause::ACCC_self,
    llvm::acc::Clause::ACCC_vector_length,
    llvm::acc::Clause::ACCC_wait,
  };

  static AccClauseSet allowedExclusiveClauses_ACCD_kernels {
  };

  static AccClauseSet requiredClauses_ACCD_kernels {
  };

  // Sets for kernels loop

  static AccClauseSet allowedClauses_ACCD_kernels_loop {
    llvm::acc::Clause::ACCC_copy,
    llvm::acc::Clause::ACCC_copyin,
    llvm::acc::Clause::ACCC_copyout,
    llvm::acc::Clause::ACCC_create,
    llvm::acc::Clause::ACCC_device_type,
    llvm::acc::Clause::ACCC_no_create,
    llvm::acc::Clause::ACCC_present,
    llvm::acc::Clause::ACCC_private,
    llvm::acc::Clause::ACCC_deviceptr,
    llvm::acc::Clause::ACCC_attach,
  };

  static AccClauseSet allowedOnceClauses_ACCD_kernels_loop {
    llvm::acc::Clause::ACCC_async,
    llvm::acc::Clause::ACCC_collapse,
    llvm::acc::Clause::ACCC_default,
    llvm::acc::Clause::ACCC_gang,
    llvm::acc::Clause::ACCC_if,
    llvm::acc::Clause::ACCC_independent,
    llvm::acc::Clause::ACCC_num_gangs,
    llvm::acc::Clause::ACCC_num_workers,
    llvm::acc::Clause::ACCC_reduction,
    llvm::acc::Clause::ACCC_self,
    llvm::acc::Clause::ACCC_tile,
    llvm::acc::Clause::ACCC_vector,
    llvm::acc::Clause::ACCC_vector_length,
    llvm::acc::Clause::ACCC_wait,
    llvm::acc::Clause::ACCC_worker,
  };

  static AccClauseSet allowedExclusiveClauses_ACCD_kernels_loop {
    llvm::acc::Clause::ACCC_auto,
    llvm::acc::Clause::ACCC_independent,
    llvm::acc::Clause::ACCC_seq,
  };

  static AccClauseSet requiredClauses_ACCD_kernels_loop {
  };

  // Sets for loop

  static AccClauseSet allowedClauses_ACCD_loop {
    llvm::acc::Clause::ACCC_device_type,
    llvm::acc::Clause::ACCC_private,
  };

  static AccClauseSet allowedOnceClauses_ACCD_loop {
    llvm::acc::Clause::ACCC_collapse,
    llvm::acc::Clause::ACCC_gang,
    llvm::acc::Clause::ACCC_reduction,
    llvm::acc::Clause::ACCC_tile,
    llvm::acc::Clause::ACCC_vector,
    llvm::acc::Clause::ACCC_worker,
  };

  static AccClauseSet allowedExclusiveClauses_ACCD_loop {
    llvm::acc::Clause::ACCC_auto,
    llvm::acc::Clause::ACCC_independent,
    llvm::acc::Clause::ACCC_seq,
  };

  static AccClauseSet requiredClauses_ACCD_loop {
  };

  // Sets for parallel

  static AccClauseSet allowedClauses_ACCD_parallel {
    llvm::acc::Clause::ACCC_attach,
    llvm::acc::Clause::ACCC_copy,
    llvm::acc::Clause::ACCC_copyin,
    llvm::acc::Clause::ACCC_copyout,
    llvm::acc::Clause::ACCC_create,
    llvm::acc::Clause::ACCC_deviceptr,
    llvm::acc::Clause::ACCC_device_type,
    llvm::acc::Clause::ACCC_no_create,
    llvm::acc::Clause::ACCC_present,
    llvm::acc::Clause::ACCC_private,
    llvm::acc::Clause::ACCC_firstprivate,
    llvm::acc::Clause::ACCC_wait,
  };

  static AccClauseSet allowedOnceClauses_ACCD_parallel {
    llvm::acc::Clause::ACCC_async,
    llvm::acc::Clause::ACCC_default,
    llvm::acc::Clause::ACCC_if,
    llvm::acc::Clause::ACCC_num_gangs,
    llvm::acc::Clause::ACCC_num_workers,
    llvm::acc::Clause::ACCC_reduction,
    llvm::acc::Clause::ACCC_self,
    llvm::acc::Clause::ACCC_vector_length,
  };

  static AccClauseSet allowedExclusiveClauses_ACCD_parallel {
  };

  static AccClauseSet requiredClauses_ACCD_parallel {
  };

  // Sets for parallel loop

  static AccClauseSet allowedClauses_ACCD_parallel_loop {
    llvm::acc::Clause::ACCC_attach,
    llvm::acc::Clause::ACCC_copy,
    llvm::acc::Clause::ACCC_copyin,
    llvm::acc::Clause::ACCC_copyout,
    llvm::acc::Clause::ACCC_create,
    llvm::acc::Clause::ACCC_deviceptr,
    llvm::acc::Clause::ACCC_device_type,
    llvm::acc::Clause::ACCC_firstprivate,
    llvm::acc::Clause::ACCC_no_create,
    llvm::acc::Clause::ACCC_present,
    llvm::acc::Clause::ACCC_private,
    llvm::acc::Clause::ACCC_tile,
    llvm::acc::Clause::ACCC_wait,
  };

  static AccClauseSet allowedOnceClauses_ACCD_parallel_loop {
    llvm::acc::Clause::ACCC_async,
    llvm::acc::Clause::ACCC_collapse,
    llvm::acc::Clause::ACCC_default,
    llvm::acc::Clause::ACCC_gang,
    llvm::acc::Clause::ACCC_if,
    llvm::acc::Clause::ACCC_num_gangs,
    llvm::acc::Clause::ACCC_num_workers,
    llvm::acc::Clause::ACCC_reduction,
    llvm::acc::Clause::ACCC_self,
    llvm::acc::Clause::ACCC_vector,
    llvm::acc::Clause::ACCC_vector_length,
    llvm::acc::Clause::ACCC_worker,
  };

  static AccClauseSet allowedExclusiveClauses_ACCD_parallel_loop {
    llvm::acc::Clause::ACCC_auto,
    llvm::acc::Clause::ACCC_independent,
    llvm::acc::Clause::ACCC_seq,
  };

  static AccClauseSet requiredClauses_ACCD_parallel_loop {
  };

  // Sets for routine

  static AccClauseSet allowedClauses_ACCD_routine {
  };

  static AccClauseSet allowedOnceClauses_ACCD_routine {
    llvm::acc::Clause::ACCC_bind,
    llvm::acc::Clause::ACCC_device_type,
    llvm::acc::Clause::ACCC_nohost,
  };

  static AccClauseSet allowedExclusiveClauses_ACCD_routine {
  };

  static AccClauseSet requiredClauses_ACCD_routine {
    llvm::acc::Clause::ACCC_gang,
    llvm::acc::Clause::ACCC_seq,
    llvm::acc::Clause::ACCC_vector,
    llvm::acc::Clause::ACCC_worker,
  };

  // Sets for serial

  static AccClauseSet allowedClauses_ACCD_serial {
    llvm::acc::Clause::ACCC_attach,
    llvm::acc::Clause::ACCC_copy,
    llvm::acc::Clause::ACCC_copyin,
    llvm::acc::Clause::ACCC_copyout,
    llvm::acc::Clause::ACCC_create,
    llvm::acc::Clause::ACCC_deviceptr,
    llvm::acc::Clause::ACCC_device_type,
    llvm::acc::Clause::ACCC_firstprivate,
    llvm::acc::Clause::ACCC_no_create,
    llvm::acc::Clause::ACCC_present,
    llvm::acc::Clause::ACCC_private,
    llvm::acc::Clause::ACCC_wait,
  };

  static AccClauseSet allowedOnceClauses_ACCD_serial {
    llvm::acc::Clause::ACCC_async,
    llvm::acc::Clause::ACCC_default,
    llvm::acc::Clause::ACCC_if,
    llvm::acc::Clause::ACCC_reduction,
    llvm::acc::Clause::ACCC_self,
  };

  static AccClauseSet allowedExclusiveClauses_ACCD_serial {
  };

  static AccClauseSet requiredClauses_ACCD_serial {
  };

  // Sets for serial loop

  static AccClauseSet allowedClauses_ACCD_serial_loop {
    llvm::acc::Clause::ACCC_attach,
    llvm::acc::Clause::ACCC_copy,
    llvm::acc::Clause::ACCC_copyin,
    llvm::acc::Clause::ACCC_copyout,
    llvm::acc::Clause::ACCC_create,
    llvm::acc::Clause::ACCC_deviceptr,
    llvm::acc::Clause::ACCC_device_type,
    llvm::acc::Clause::ACCC_firstprivate,
    llvm::acc::Clause::ACCC_no_create,
    llvm::acc::Clause::ACCC_present,
    llvm::acc::Clause::ACCC_private,
    llvm::acc::Clause::ACCC_wait,
  };

  static AccClauseSet allowedOnceClauses_ACCD_serial_loop {
    llvm::acc::Clause::ACCC_async,
    llvm::acc::Clause::ACCC_collapse,
    llvm::acc::Clause::ACCC_default,
    llvm::acc::Clause::ACCC_gang,
    llvm::acc::Clause::ACCC_if,
    llvm::acc::Clause::ACCC_reduction,
    llvm::acc::Clause::ACCC_self,
    llvm::acc::Clause::ACCC_tile,
    llvm::acc::Clause::ACCC_vector,
    llvm::acc::Clause::ACCC_worker,
  };

  static AccClauseSet allowedExclusiveClauses_ACCD_serial_loop {
    llvm::acc::Clause::ACCC_auto,
    llvm::acc::Clause::ACCC_independent,
    llvm::acc::Clause::ACCC_seq,
  };

  static AccClauseSet requiredClauses_ACCD_serial_loop {
  };

  // Sets for set

  static AccClauseSet allowedClauses_ACCD_set {
  };

  static AccClauseSet allowedOnceClauses_ACCD_set {
    llvm::acc::Clause::ACCC_if,
  };

  static AccClauseSet allowedExclusiveClauses_ACCD_set {
  };

  static AccClauseSet requiredClauses_ACCD_set {
    llvm::acc::Clause::ACCC_default_async,
    llvm::acc::Clause::ACCC_device_num,
    llvm::acc::Clause::ACCC_device_type,
  };

  // Sets for shutdown

  static AccClauseSet allowedClauses_ACCD_shutdown {
  };

  static AccClauseSet allowedOnceClauses_ACCD_shutdown {
    llvm::acc::Clause::ACCC_device_num,
    llvm::acc::Clause::ACCC_device_type,
    llvm::acc::Clause::ACCC_if,
  };

  static AccClauseSet allowedExclusiveClauses_ACCD_shutdown {
  };

  static AccClauseSet requiredClauses_ACCD_shutdown {
  };

  // Sets for unknown

  static AccClauseSet allowedClauses_ACCD_unknown {
  };

  static AccClauseSet allowedOnceClauses_ACCD_unknown {
  };

  static AccClauseSet allowedExclusiveClauses_ACCD_unknown {
  };

  static AccClauseSet requiredClauses_ACCD_unknown {
  };

  // Sets for update

  static AccClauseSet allowedClauses_ACCD_update {
    llvm::acc::Clause::ACCC_device_type,
    llvm::acc::Clause::ACCC_wait,
  };

  static AccClauseSet allowedOnceClauses_ACCD_update {
    llvm::acc::Clause::ACCC_async,
    llvm::acc::Clause::ACCC_if,
    llvm::acc::Clause::ACCC_if_present,
  };

  static AccClauseSet allowedExclusiveClauses_ACCD_update {
  };

  static AccClauseSet requiredClauses_ACCD_update {
    llvm::acc::Clause::ACCC_device,
    llvm::acc::Clause::ACCC_host,
    llvm::acc::Clause::ACCC_self,
  };

  // Sets for wait

  static AccClauseSet allowedClauses_ACCD_wait {
  };

  static AccClauseSet allowedOnceClauses_ACCD_wait {
    llvm::acc::Clause::ACCC_async,
    llvm::acc::Clause::ACCC_if,
  };

  static AccClauseSet allowedExclusiveClauses_ACCD_wait {
  };

  static AccClauseSet requiredClauses_ACCD_wait {
  };
} // namespace acc
} // namespace llvm

#endif // GEN_FLANG_DIRECTIVE_CLAUSE_SETS

#ifdef GEN_FLANG_DIRECTIVE_CLAUSE_MAP
#undef GEN_FLANG_DIRECTIVE_CLAUSE_MAP

struct OpenACCDirectiveClauses {
  const AccClauseSet allowed;
  const AccClauseSet allowedOnce;
  const AccClauseSet allowedExclusive;
  const AccClauseSet requiredOneOf;
};

std::unordered_map<llvm::acc::Directive, OpenACCDirectiveClauses>
    directiveClausesTable = {
  {llvm::acc::Directive::ACCD_atomic,
    {
      llvm::acc::allowedClauses_ACCD_atomic,
      llvm::acc::allowedOnceClauses_ACCD_atomic,
      llvm::acc::allowedExclusiveClauses_ACCD_atomic,
      llvm::acc::requiredClauses_ACCD_atomic,
    }
  },
  {llvm::acc::Directive::ACCD_cache,
    {
      llvm::acc::allowedClauses_ACCD_cache,
      llvm::acc::allowedOnceClauses_ACCD_cache,
      llvm::acc::allowedExclusiveClauses_ACCD_cache,
      llvm::acc::requiredClauses_ACCD_cache,
    }
  },
  {llvm::acc::Directive::ACCD_data,
    {
      llvm::acc::allowedClauses_ACCD_data,
      llvm::acc::allowedOnceClauses_ACCD_data,
      llvm::acc::allowedExclusiveClauses_ACCD_data,
      llvm::acc::requiredClauses_ACCD_data,
    }
  },
  {llvm::acc::Directive::ACCD_declare,
    {
      llvm::acc::allowedClauses_ACCD_declare,
      llvm::acc::allowedOnceClauses_ACCD_declare,
      llvm::acc::allowedExclusiveClauses_ACCD_declare,
      llvm::acc::requiredClauses_ACCD_declare,
    }
  },
  {llvm::acc::Directive::ACCD_enter_data,
    {
      llvm::acc::allowedClauses_ACCD_enter_data,
      llvm::acc::allowedOnceClauses_ACCD_enter_data,
      llvm::acc::allowedExclusiveClauses_ACCD_enter_data,
      llvm::acc::requiredClauses_ACCD_enter_data,
    }
  },
  {llvm::acc::Directive::ACCD_exit_data,
    {
      llvm::acc::allowedClauses_ACCD_exit_data,
      llvm::acc::allowedOnceClauses_ACCD_exit_data,
      llvm::acc::allowedExclusiveClauses_ACCD_exit_data,
      llvm::acc::requiredClauses_ACCD_exit_data,
    }
  },
  {llvm::acc::Directive::ACCD_host_data,
    {
      llvm::acc::allowedClauses_ACCD_host_data,
      llvm::acc::allowedOnceClauses_ACCD_host_data,
      llvm::acc::allowedExclusiveClauses_ACCD_host_data,
      llvm::acc::requiredClauses_ACCD_host_data,
    }
  },
  {llvm::acc::Directive::ACCD_init,
    {
      llvm::acc::allowedClauses_ACCD_init,
      llvm::acc::allowedOnceClauses_ACCD_init,
      llvm::acc::allowedExclusiveClauses_ACCD_init,
      llvm::acc::requiredClauses_ACCD_init,
    }
  },
  {llvm::acc::Directive::ACCD_kernels,
    {
      llvm::acc::allowedClauses_ACCD_kernels,
      llvm::acc::allowedOnceClauses_ACCD_kernels,
      llvm::acc::allowedExclusiveClauses_ACCD_kernels,
      llvm::acc::requiredClauses_ACCD_kernels,
    }
  },
  {llvm::acc::Directive::ACCD_kernels_loop,
    {
      llvm::acc::allowedClauses_ACCD_kernels_loop,
      llvm::acc::allowedOnceClauses_ACCD_kernels_loop,
      llvm::acc::allowedExclusiveClauses_ACCD_kernels_loop,
      llvm::acc::requiredClauses_ACCD_kernels_loop,
    }
  },
  {llvm::acc::Directive::ACCD_loop,
    {
      llvm::acc::allowedClauses_ACCD_loop,
      llvm::acc::allowedOnceClauses_ACCD_loop,
      llvm::acc::allowedExclusiveClauses_ACCD_loop,
      llvm::acc::requiredClauses_ACCD_loop,
    }
  },
  {llvm::acc::Directive::ACCD_parallel,
    {
      llvm::acc::allowedClauses_ACCD_parallel,
      llvm::acc::allowedOnceClauses_ACCD_parallel,
      llvm::acc::allowedExclusiveClauses_ACCD_parallel,
      llvm::acc::requiredClauses_ACCD_parallel,
    }
  },
  {llvm::acc::Directive::ACCD_parallel_loop,
    {
      llvm::acc::allowedClauses_ACCD_parallel_loop,
      llvm::acc::allowedOnceClauses_ACCD_parallel_loop,
      llvm::acc::allowedExclusiveClauses_ACCD_parallel_loop,
      llvm::acc::requiredClauses_ACCD_parallel_loop,
    }
  },
  {llvm::acc::Directive::ACCD_routine,
    {
      llvm::acc::allowedClauses_ACCD_routine,
      llvm::acc::allowedOnceClauses_ACCD_routine,
      llvm::acc::allowedExclusiveClauses_ACCD_routine,
      llvm::acc::requiredClauses_ACCD_routine,
    }
  },
  {llvm::acc::Directive::ACCD_serial,
    {
      llvm::acc::allowedClauses_ACCD_serial,
      llvm::acc::allowedOnceClauses_ACCD_serial,
      llvm::acc::allowedExclusiveClauses_ACCD_serial,
      llvm::acc::requiredClauses_ACCD_serial,
    }
  },
  {llvm::acc::Directive::ACCD_serial_loop,
    {
      llvm::acc::allowedClauses_ACCD_serial_loop,
      llvm::acc::allowedOnceClauses_ACCD_serial_loop,
      llvm::acc::allowedExclusiveClauses_ACCD_serial_loop,
      llvm::acc::requiredClauses_ACCD_serial_loop,
    }
  },
  {llvm::acc::Directive::ACCD_set,
    {
      llvm::acc::allowedClauses_ACCD_set,
      llvm::acc::allowedOnceClauses_ACCD_set,
      llvm::acc::allowedExclusiveClauses_ACCD_set,
      llvm::acc::requiredClauses_ACCD_set,
    }
  },
  {llvm::acc::Directive::ACCD_shutdown,
    {
      llvm::acc::allowedClauses_ACCD_shutdown,
      llvm::acc::allowedOnceClauses_ACCD_shutdown,
      llvm::acc::allowedExclusiveClauses_ACCD_shutdown,
      llvm::acc::requiredClauses_ACCD_shutdown,
    }
  },
  {llvm::acc::Directive::ACCD_unknown,
    {
      llvm::acc::allowedClauses_ACCD_unknown,
      llvm::acc::allowedOnceClauses_ACCD_unknown,
      llvm::acc::allowedExclusiveClauses_ACCD_unknown,
      llvm::acc::requiredClauses_ACCD_unknown,
    }
  },
  {llvm::acc::Directive::ACCD_update,
    {
      llvm::acc::allowedClauses_ACCD_update,
      llvm::acc::allowedOnceClauses_ACCD_update,
      llvm::acc::allowedExclusiveClauses_ACCD_update,
      llvm::acc::requiredClauses_ACCD_update,
    }
  },
  {llvm::acc::Directive::ACCD_wait,
    {
      llvm::acc::allowedClauses_ACCD_wait,
      llvm::acc::allowedOnceClauses_ACCD_wait,
      llvm::acc::allowedExclusiveClauses_ACCD_wait,
      llvm::acc::requiredClauses_ACCD_wait,
    }
  },
};

#endif // GEN_FLANG_DIRECTIVE_CLAUSE_MAP

