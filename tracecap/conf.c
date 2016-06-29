/*
TEMU-Tracecap is Copyright (C) 2006-2010, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU LGPL,
version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.

As an additional exception, the XED and Sleuthkit libraries, including
updated or modified versions, are excluded from the requirements of
the LGPL as if they were standard operating system libraries.
*/

#include "config.h"
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "TEMU_lib.h"
#include "tracecap.h"
#include "conditions.h"
#include "network.h"

/* Default configuration flags */
int conf_trace_only_after_first_taint = 1;
int conf_log_external_calls = 0;
int conf_write_ops_at_insn_end = 0;
int conf_save_state_at_trace_stop = 0;

/* Environment variables */
int tracing_table_lookup = 1;
static int conf_ignore_dns = 0;
static int conf_tainted_only = 0;
static int conf_single_thread_only = 0;
static int conf_tracing_kernel_all = 0;
static int conf_tracing_kernel_tainted = 0;
static int conf_tracing_kernel_partial = 0;


/* SEFI faults related variables */
int SEFI_support_fault_fadd = 1;
int SEFI_support_fault_fmul = 1;
int SEFI_support_fault_cmp = 1;
int SEFI_support_fault_xor = 1;
int SEFI_support_fault_sarl = 1;
int SEFI_support_fault_idivl = 1;
int SEFI_support_fault_imul = 1;
int SEFI_support_dynamic_probability = 0;	// Dyanmic probability (default is NO)

int SEFI_support_number_of_bits_to_flip = 1;
int SEFI_support_sub_range_bits_start = 0;
int SEFI_support_sub_range_bits_end = 127;
double SEFI_support_fault_probability = 100.0;
unsigned long long int SEFI_support_start_index_fadd = 0;
unsigned long long int SEFI_support_start_index_fmul = 0;
unsigned long long int SEFI_support_start_index_cmp = 0;
unsigned long long int SEFI_support_start_index_xor = 0;
unsigned long long int SEFI_support_start_index_sarl = 0;
unsigned long long int SEFI_support_start_index_idivl = 0;
unsigned long long int SEFI_support_start_index_imul = 0;
unsigned long long int SEFI_support_start_index_iaddl = 0;
unsigned long long int SEFI_support_start_index_isubl = 0;
unsigned long long int SEFI_support_start_index_shrl = 0;
unsigned long long int SEFI_support_start_index_andl = 0;
unsigned long long int SEFI_support_start_index_orl = 0;
unsigned long long int SEFI_support_start_index_xorl = 0;
unsigned long long int SEFI_support_start_index_movl = 0;
unsigned long long int SEFI_support_start_index_testl = 0;
unsigned long long int SEFI_support_start_index_notl = 0;
unsigned long long int SEFI_support_start_index_ld = 0;
unsigned long long int SEFI_support_max_dic = 1; 		// The max number of dynamic instruction of interest

/* Deafult SEFI host configuration */
char SEFI_host_user[32] = "guanxyz";	
char SEFI_host_target_directory[128] = "/home/guanxyz/output/";
char SEFI_host_sym_table_directory[256] = "/home/guanxyz/LANL_Work/TEMU/temu-1.0/tracecap/symbol_table";
char SEFI_host_ip[32] = "10.0.33.135";
char SEFI_host_conf[256]= "";


/* Default hook files */
char hook_dirname[256] = TEMU_HOME "/shared/hooks/hook_plugins";
char hook_plugins_filename[256] = PROJECT_HOME "/ini/hook_plugin.ini";

/* Default configuration file */
char ini_main_default_filename[256] = PROJECT_HOME "/ini/main.ini";

/* Default SEFI configuration file */
char ini_SEFI_default_filename[256] = PROJECT_HOME "/ini/SEFI_conf.ini";


void set_ignore_dns(int state)
{
  if (state) {
    conf_ignore_dns = 1;
    term_printf("Ignore DNS flag on.\n");
  }
  else {
    conf_ignore_dns = 0;
    term_printf("Ignore DNS flag off.\n");
  }
}

inline int tracing_ignore_dns()
{
    return conf_ignore_dns;
}

void set_tainted_only(int state)
{
  if (state) {
    conf_tainted_only = 1;
    term_printf("Taint-only flag on.\n");
  }
  else {
    conf_tainted_only = 0;
    term_printf("Taint-only flag off.\n");
  }
}

inline int tracing_tainted_only()
{
    return conf_tainted_only;
}

void set_single_thread_only(int state)
{
  if (state) {
    conf_single_thread_only = 1;
    term_printf("Single-thread-only flag on.\n");
  }
  else {
    conf_single_thread_only = 0;
    term_printf("Single-thread-only flag off.\n");
  }
}

inline int tracing_single_thread_only()
{
    return conf_single_thread_only;
}

void set_kernel_all(int state)
{
  if (state) {
    conf_tracing_kernel_all = 1;
    term_printf("Kernel-all flag on.\n");
  }
  else {
    conf_tracing_kernel_all = 0;
    term_printf("Kernel-all flag off.\n");
  }
}

inline int tracing_kernel_all()
{
    return conf_tracing_kernel_all;
}

void set_kernel_tainted(int state)
{
  if (state) {
    conf_tracing_kernel_tainted = 1;
    term_printf("Kernel-tainted flag on.\n");
  }
  else {
    conf_tracing_kernel_tainted = 0;
    term_printf("Kernel-tainted flag off.\n");
  }
}
inline int tracing_kernel_tainted()
{
    return conf_tracing_kernel_tainted;
}

void set_kernel_partial(int state)
{
  if (state) {
    conf_tracing_kernel_partial = 1;
    term_printf("Kernel-partial flag on.\n");
  }
  else {
    conf_tracing_kernel_partial = 0;
    term_printf("Kernel-partial flag off.\n");
  }
}

inline int tracing_kernel_partial()
{
    return conf_tracing_kernel_partial;
}

inline int tracing_kernel()
{
    return conf_tracing_kernel_all || conf_tracing_kernel_partial ||
        conf_tracing_kernel_tainted;
}

/* Print configuration variables */
void print_conf_vars()
{
  term_printf(
      "TABLE_LOOKUP: %d\n"
      "TRACE_AFTER_FIRST_TAINT: %d\n"
      "LOG_EXTERNAL_CALLS: %d\n"
      "WRITE_OPS_AT_INSN_END: %d\n"
      "SAVE_STATE_AT_TRACE_STOP: %d\n"
      "PROTOS_IGNOREDNS: %d\n"
      "TAINTED_ONLY: %d\n" 
      "SINGLE_THREAD_ONLY: %d\n"
      "TRACING_KERNEL_ALL: %d\n"
      "TRACING_KERNEL_TAINTED: %d\n" 
      "TRACING_KERNEL_PARTIAL: %d\n",
      conf_trace_only_after_first_taint,
      conf_log_external_calls,
      conf_write_ops_at_insn_end,
      conf_save_state_at_trace_stop,
      conf_ignore_dns, 
      conf_tainted_only,
      conf_single_thread_only,
      conf_tracing_kernel_all,
      conf_tracing_kernel_tainted,
      conf_tracing_kernel_partial
  );
}

/* Parse network filter configuration */
void check_filter_conf(struct cnfnode *cn_root) {
  struct cnfresult *cnf_res;

#if TAINT_ENABLED
  /* Transport */
  cnf_res = cnf_find_entry(cn_root, "network/filter_transport");
  if (cnf_res) {
    update_nic_filter("proto",cnf_res->cnfnode->value);
  }
  /* Source port */
  cnf_res = cnf_find_entry(cn_root, "network/filter_sport");
  if (cnf_res) {
    update_nic_filter("sport",cnf_res->cnfnode->value);
  }
  /* Destination port */
  cnf_res = cnf_find_entry(cn_root, "network/filter_dport");
  if (cnf_res) {
    update_nic_filter("dport",cnf_res->cnfnode->value);
  }
  /* Source addres */
  cnf_res = cnf_find_entry(cn_root, "network/filter_saddr");
  if (cnf_res) {
    update_nic_filter("src",cnf_res->cnfnode->value);
  }
  /* Destination addres */
  cnf_res = cnf_find_entry(cn_root, "network/filter_daddr");
  if (cnf_res) {
    update_nic_filter("dst",cnf_res->cnfnode->value);
  }
#endif  
  
}

// By Guan
/* Parse boolean from configuration file */
static void set_bool_from_ini(struct cnfnode *cn_root, char *entry, int* flag) {
  struct cnfresult *cnf_res;

  cnf_res = cnf_find_entry(cn_root, entry);
  if (cnf_res) {
    if (strcasecmp(cnf_res->cnfnode->value, "yes") == 0) {
      *flag = 1;
      term_printf("%s is enabled.\n",entry);
    }
    else if (strcasecmp(cnf_res->cnfnode->value, "no") == 0) {
      *flag = 0;
      term_printf("%s is disabled.\n",entry);
    }
    else {
      term_printf("%s has incorrect value. Try <yes|no>.\n",entry);
    }
  }

}

#if 0
// check bits range in configure file
int SEFI_check_bits_range(const char *content){
  char token[] = "-\n";
  int start, end;
  char str_range[64];
  
  strcpy(str_range, content); 
  
  start = atoi(strtok(str_range, token));
  end = atoi(strtok(NULL, token));
  printf("the bit range is loaded as %d - %d\n", start, end);
  
  if(start>end || (start==0&&end==0))
    return 0;
    
  SEFI_support_sub_range_bits_start = start;
  SEFI_support_sub_range_bits_end = end;
  term_printf("the bit range is loaded as %d (%d) - %d(%d) \n", SEFI_support_sub_range_bits_start,start, SEFI_support_sub_range_bits_end, end);
  return 1;
}
#endif
int SEFI_check_bits_range_start(const char *content){
  int start;
  start = atoi(content);
  
  if(start<0 || start>127)
    return 0;
    
  SEFI_support_sub_range_bits_start = start;
  return 1;
}
int SEFI_check_bits_range_end(const char *content){
  int end;
  end = atoi(content);
  
  if(end<0 || end>127 || end<SEFI_support_sub_range_bits_start)
    return 0;
    
  SEFI_support_sub_range_bits_end = end;
  return 1;
}

// check bits number in configure file
int SEFI_check_number_bits(const char *content){
  int num, size;

  num = atoi(content);
  size = SEFI_support_sub_range_bits_end - SEFI_support_sub_range_bits_start +1;
  
  if(num>size)
    return 0;
  
  SEFI_support_number_of_bits_to_flip = num;
  
  return 1;

}
int SEFI_check_probability(const char *content){
  double num;

  num = atof(content);
//  printf("[]my FP :%lf(%lf)\n", num, SEFI_support_fault_probability);
  if(num>100.0 || num <0)
    return 0;
 
  SEFI_support_fault_probability = num;
  
  return 1;

}
int SEFI_check_start_fadd(const char *content){
  long long int num;
  num = atoll(content);
  if(num<0)
    return 0;
  SEFI_support_start_index_fadd  = num;
  return 1;
}

int SEFI_check_start_fmul(const char *content){
  long long int num;
  num = atoll(content);
  if(num<0)
    return 0;
  SEFI_support_start_index_fmul  = num;
  return 1;
}
int SEFI_check_start_cmp(const char *content){
  long long int num;
  num = atoll(content);
  if(num<0)
    return 0;
  SEFI_support_start_index_cmp  = num;
  return 1;
}

int SEFI_check_start_xor(const char *content){
  long long int num;
  num = atoll(content);
  if(num<0)
    return 0;
  SEFI_support_start_index_xor  = num;
  return 1;
}
int SEFI_check_start_sarl(const char *content){
  long long int num;
  num = atoll(content);
  if(num<0)
    return 0;
  SEFI_support_start_index_sarl  = num;
  return 1;
}
int SEFI_check_start_idivl(const char *content){
  long long int num;
  num = atoll(content);
  if(num<0)
    return 0;
  SEFI_support_start_index_idivl  = num;
  return 1;
}
int SEFI_check_start_imul(const char *content){
  long long int num;
  num = atoll(content);
  if(num<0)
    return 0;
  SEFI_support_start_index_imul  = num;
  return 1;
}
int SEFI_check_start_shrl(const char *content){
  long long int num;
  num = atoll(content);
  if(num<0)
    return 0;
  SEFI_support_start_index_shrl  = num;
  return 1;
}
int SEFI_check_start_iaddl(const char *content){
  long long int num;
  num = atoll(content);
  if(num<0)
    return 0;
  SEFI_support_start_index_iaddl  = num;
  return 1;
}
int SEFI_check_start_isubl(const char *content){
  long long int num;
  num = atoll(content);
  if(num<0)
    return 0;
  SEFI_support_start_index_isubl  = num;
  return 1;
}
int SEFI_check_start_andl(const char *content){
  long long int num;
  num = atoll(content);
  if(num<0)
    return 0;
  SEFI_support_start_index_andl  = num;
  return 1;
}
int SEFI_check_start_orl(const char *content){
  long long int num;
  num = atoll(content);
  if(num<0)
    return 0;
  SEFI_support_start_index_orl  = num;
  return 1;
}
int SEFI_check_start_xorl(const char *content){
  long long int num;
  num = atoll(content);
  if(num<0)
    return 0;
  SEFI_support_start_index_xorl  = num;
  return 1;
}
int SEFI_check_start_movl(const char *content){
  long long int num;
  num = atoll(content);
  if(num<0)
    return 0;
  SEFI_support_start_index_movl  = num;
  return 1;
}

int SEFI_check_start_testl(const char *content){
  long long int num;
  num = atoll(content);
  if(num<0)
    return 0;
  SEFI_support_start_index_testl  = num;
  return 1;
}
int SEFI_check_start_notl(const char *content){
  long long int num;
  num = atoll(content);
  if(num<0)
    return 0;
  SEFI_support_start_index_notl  = num;
  return 1;
}

int SEFI_check_start_ld(const char *content){
  long long int num;
  num = atoll(content);
  if(num<0)
    return 0;
  SEFI_support_start_index_ld  = num;
  return 1;
}

int SEFI_check_max_dic(const char *content){
  long long int num;
  num = atoll(content);
  if(num<0)
    return 0;
  SEFI_support_max_dic = num;
  return 1;
}

/* Parse configuration file 
 * Returns zero if succeeds, -1 if it could not find the file */
int check_SEFI_ini(const char *path_ini)
{
  struct cnfnode *cn_root;
  struct cnfmodule *mod_ini;
  struct cnfresult *cnf_res;

  register_ini(NULL);
  mod_ini = find_cnfmodule("ini");
  cn_root = cnfmodule_parse_file(mod_ini, path_ini);

  if (cn_root == NULL) {
    return -1;
  }

  /* Parse configuration flags */
  /* No longer need to check these */
  /*
  set_bool_from_ini(cn_root, "general/SEFI_support_fault_fadd",
    &SEFI_support_fault_fadd);
  set_bool_from_ini(cn_root, "general/SEFI_support_fault_fmul",
    &SEFI_support_fault_fmul);
  set_bool_from_ini(cn_root, "general/SEFI_support_fault_cmp",
    &SEFI_support_fault_cmp);
  set_bool_from_ini(cn_root, "general/SEFI_support_fault_xor",
    &SEFI_support_fault_xor);
  set_bool_from_ini(cn_root, "general/SEFI_support_fault_sarl",
    &SEFI_support_fault_sarl);
  set_bool_from_ini(cn_root, "general/SEFI_support_fault_idivl",
    &SEFI_support_fault_idivl);
  set_bool_from_ini(cn_root, "general/SEFI_support_fault_imul",
    &SEFI_support_fault_imul);
  */

  set_bool_from_ini(cn_root, "general/SEFI_support_dynamic_probability",
    &SEFI_support_dynamic_probability);

  /* Parse bits-flip range */
  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_range_start");
  if (cnf_res) {
    if(!(SEFI_check_bits_range_start(cnf_res->cnfnode->value))){
    	term_printf("SEFI: range of bits to flip is not valid. default setting is loaded. Check %s \n", hook_dirname, path_ini);
    }
  }
  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_range_end");
  if (cnf_res) {
    if(!(SEFI_check_bits_range_end(cnf_res->cnfnode->value))){
    	term_printf("SEFI: range of bits to flip is not valid. default setting is loaded. Check %s \n", hook_dirname, path_ini);
    }
  }
  /* Parse number of bits to flip */
  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_number_of_bits_to_flip");
  if (cnf_res) {
    if(!(SEFI_check_number_bits(cnf_res->cnfnode->value))){
    	term_printf("SEFI: number of bits to flip is not valid. default setting is loaded. Check %s \n", hook_dirname, path_ini);
    }
  }

  /* Parse the probablity of fault injection */
  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_fault_probability");
  if (cnf_res) {
    if(!(SEFI_check_probability(cnf_res->cnfnode->value))){
    	term_printf("SEFI: fault injection probability is not valid. default setting is loaded. Check %s \n", hook_dirname, path_ini);
    }
  }
  /* Parse the start index of fadd */
  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_start_index_fadd");
  if (cnf_res) {
    if(!(SEFI_check_start_fadd(cnf_res->cnfnode->value))){
    	term_printf("SEFI: start index is not valid. default setting is loaded. Check %s \n", hook_dirname, path_ini);
    }
  } 
  /* Parse the start index of fmul */
  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_start_index_fmul");
  if (cnf_res) {
    if(!(SEFI_check_start_fmul(cnf_res->cnfnode->value))){
    	term_printf("SEFI: start index is not valid. default setting is loaded. Check %s \n", hook_dirname, path_ini);
    }
  }
  /* Parse the start index of fmul */
  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_start_index_cmp");
  if (cnf_res) {
    if(!(SEFI_check_start_cmp(cnf_res->cnfnode->value))){
    	term_printf("SEFI: start index is not valid. default setting is loaded. Check %s \n", hook_dirname, path_ini);
    }
  }
  /* Parse the start index of xor */
  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_start_index_xor");
  if (cnf_res) {
    if(!(SEFI_check_start_xor(cnf_res->cnfnode->value))){
    	term_printf("SEFI: start index is not valid. default setting is loaded. Check %s \n", hook_dirname, path_ini);
    }
  }
  /* Parse the start index of sarl */
  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_start_index_sarl");
  if (cnf_res) {
    if(!(SEFI_check_start_sarl(cnf_res->cnfnode->value))){
    	term_printf("SEFI: start index is not valid. default setting is loaded. Check %s \n", hook_dirname, path_ini);
    }
  }
  /* Parse the start index of idivl */
  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_start_index_idivl");
  if (cnf_res) {
    if(!(SEFI_check_start_idivl(cnf_res->cnfnode->value))){
    	term_printf("SEFI: start index is not valid. default setting is loaded. Check %s \n", hook_dirname, path_ini);
    }
  }
  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_start_index_imul");
  if (cnf_res) {
    if(!(SEFI_check_start_imul(cnf_res->cnfnode->value))){
    	term_printf("SEFI: start index is not valid. default setting is loaded. Check %s \n", hook_dirname, path_ini);
    }
  }
  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_start_index_iaddl");
  if (cnf_res) {
    if(!(SEFI_check_start_iaddl(cnf_res->cnfnode->value))){
    	term_printf("SEFI: start index is not valid. default setting is loaded. Check %s \n", hook_dirname, path_ini);
    }
  }
  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_start_index_isubl");
  if (cnf_res) {
    if(!(SEFI_check_start_isubl(cnf_res->cnfnode->value))){
    	term_printf("SEFI: start index is not valid. default setting is loaded. Check %s \n", hook_dirname, path_ini);
    }
  }
  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_start_index_shrl");
  if (cnf_res) {
    if(!(SEFI_check_start_shrl(cnf_res->cnfnode->value))){
    	term_printf("SEFI: start index is not valid. default setting is loaded. Check %s \n", hook_dirname, path_ini);
    }
  }
  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_start_index_andl");
  if (cnf_res) {
    if(!(SEFI_check_start_andl(cnf_res->cnfnode->value))){
    	term_printf("SEFI: start index is not valid. default setting is loaded. Check %s \n", hook_dirname, path_ini);
    }
  }
  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_start_index_orl");
  if (cnf_res) {
    if(!(SEFI_check_start_orl(cnf_res->cnfnode->value))){
    	term_printf("SEFI: start index is not valid. default setting is loaded. Check %s \n", hook_dirname, path_ini);
    }
  }
  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_start_index_xorl");
  if (cnf_res) {
    if(!(SEFI_check_start_xorl(cnf_res->cnfnode->value))){
    	term_printf("SEFI: start index is not valid. default setting is loaded. Check %s \n", hook_dirname, path_ini);
    }
  }
  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_start_index_movl");
  if (cnf_res) {
    if(!(SEFI_check_start_movl(cnf_res->cnfnode->value))){
    	term_printf("SEFI: start index is not valid. default setting is loaded. Check %s \n", hook_dirname, path_ini);
    }
  }

  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_start_index_testl");
  if (cnf_res) {
    if(!(SEFI_check_start_testl(cnf_res->cnfnode->value))){
    	term_printf("SEFI: start index is not valid. default setting is loaded. Check %s \n", hook_dirname, path_ini);
    }
  }
  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_start_index_notl");
  if (cnf_res) {
    if(!(SEFI_check_start_notl(cnf_res->cnfnode->value))){
    	term_printf("SEFI: start index is not valid. default setting is loaded. Check %s \n", hook_dirname, path_ini);
    }
  }

  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_start_index_ld");
  if (cnf_res) {
    if(!(SEFI_check_start_ld(cnf_res->cnfnode->value))){
    	term_printf("SEFI: start index is not valid. default setting is loaded. Check %s \n", hook_dirname, path_ini);
    }
  }
  /* parse the max number of dynamic instructions of interests -- added by guanxyz 13/3/2014 */   
  cnf_res = cnf_find_entry(cn_root, "general/SEFI_support_max_dic");
  if(cnf_res){
    if(!(SEFI_check_max_dic(cnf_res->cnfnode->value))){
      term_printf("SEFI: max dic is not valid. default setting is loaded. check %s \n", hook_dirname, path_ini); 
    }
  }
  /* Find host configuration: user name  */
  cnf_res = cnf_find_entry(cn_root, "host configuration/SEFI_host_sym_table_directory");
  if (cnf_res)
    strcpy(SEFI_host_sym_table_directory, cnf_res->cnfnode->value);


  /* Find host configuration: user name  */
  cnf_res = cnf_find_entry(cn_root, "host configuration/SEFI_host_user");
  if (cnf_res)
    strcpy(SEFI_host_user, cnf_res->cnfnode->value);

  /* Find host configuration: target directory */
  cnf_res = cnf_find_entry(cn_root, "host configuration/SEFI_host_target_directory");
  if(cnf_res)
    strcpy(SEFI_host_target_directory, cnf_res->cnfnode->value);
  
  /* Find host configuration: host ip  */
  cnf_res = cnf_find_entry(cn_root, "host configuration/SEFI_host_ip");
  if(cnf_res)
    strcpy(SEFI_host_ip, cnf_res->cnfnode->value);
  
  /* Configure the host */
  strcpy(SEFI_host_conf, SEFI_host_user);
  strcat(SEFI_host_conf, "@");
  strcat(SEFI_host_conf, SEFI_host_ip);
  strcat(SEFI_host_conf, ":");
  strcat(SEFI_host_conf, SEFI_host_target_directory);

  term_printf("SEFI configuration is loaded successfully\n");
  term_printf("SEFI configuration: faulty bits from %d to %d (%d bit(s)) with probability %lf\n", 
                          SEFI_support_sub_range_bits_start, 
			  SEFI_support_sub_range_bits_end,
			  SEFI_support_number_of_bits_to_flip,
			  SEFI_support_fault_probability);
  term_printf("SEFI configuration: output is sent to %s \n", SEFI_host_conf);
  destroy_cnftree(cn_root);

  return 0;
}

/* Parse SEFI configuration file 
 * Returns zero if succeeds, -1 if it could not find the file */
int check_ini(const char *path_ini)
{
  struct cnfnode *cn_root;
  struct cnfmodule *mod_ini;
  struct cnfresult *cnf_res;

  register_ini(NULL);
  mod_ini = find_cnfmodule("ini");
  cn_root = cnfmodule_parse_file(mod_ini, path_ini);

  if (cn_root == NULL) {
    return -1;
  }

  /* Parse configuration flags */
  set_bool_from_ini(cn_root, "general/trace_only_after_first_taint",
    &conf_trace_only_after_first_taint);
  set_bool_from_ini(cn_root, "general/log_external_calls",
    &conf_log_external_calls);
  set_bool_from_ini(cn_root, "general/write_ops_at_insn_end",
    &conf_write_ops_at_insn_end);
  set_bool_from_ini(cn_root, "general/save_state_at_trace_stop",
    &conf_save_state_at_trace_stop);
  set_bool_from_ini(cn_root, "tracing/tracing_table_lookup",
    &tracing_table_lookup);
  set_bool_from_ini(cn_root, "tracing/tracing_tainted_only",
    &conf_tainted_only);
  set_bool_from_ini(cn_root, "tracing/tracing_single_thread_only",
    &conf_single_thread_only);
  set_bool_from_ini(cn_root, "tracing/tracing_kernel",
    &conf_tracing_kernel_all);
  set_bool_from_ini(cn_root, "tracing/tracing_kernel_tainted",
    &conf_tracing_kernel_tainted);
  set_bool_from_ini(cn_root, "tracing/tracing_kernel_partial",
    &conf_tracing_kernel_partial);

  /* Parse network configuration */
  set_bool_from_ini(cn_root, "network/ignore_dns",
    &conf_ignore_dns);
  check_filter_conf(cn_root);
#if TAINT_ENABLED  
  print_nic_filter();
#endif  

  /* Find hook configuration file */
  cnf_res = cnf_find_entry(cn_root, "function hooks/plugin_ini");
  if (cnf_res)
  strncpy(hook_plugins_filename, cnf_res->cnfnode->value, 255);
  hook_plugins_filename[255] = '\0';
  term_printf("Loading plugin options from: %s\n", hook_plugins_filename);

  /* Find hooks directory */
  cnf_res = cnf_find_entry(cn_root, "function hooks/plugin_directory");
  if (cnf_res) {
    strncpy(hook_dirname, cnf_res->cnfnode->value, 255);
    hook_dirname[255] = '\0';
  }
  term_printf("Loading plugins from: %s\n", hook_dirname);

  destroy_cnftree(cn_root);

  return 0;
}
