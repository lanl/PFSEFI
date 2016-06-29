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
#include "conf.h"		// ini configure file
#include "procmod.h"
#include "libfstools.h"
#include "slirp.h"
#include "read_linux.h"
#include "reg_ids.h"
#include "shared/procmod.h"
#include "conditions.h"
#include "readwrite.h"
#include "network.h"
#include "errdet.h"
#include "state.h"

/* plugin loading */
//#include <dlfcn.h>
//#include <assert.h>
#include "hookapi.h"
#include "function_map.h"
#include "hook_plugin_loader.h"
#include "hook_helpers.h"

/* Local Ouput Checking */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "TEMU_main.h"

// for dynamic injection probability
#include "probability.h"

static plugin_interface_t tracing_interface;

//Local Function Declaration
int check_local_output(char *file_path);
int remove_output(char *file_path);
void do_get_file(const char *guest_output);

char current_mod[32] = "";
char current_proc[32] = "";

#if TAINT_ENABLED
static int taint_sendkey_id = 0;
int keystroke_offset = 0; // Global counter for keystrokes, used for offset
#endif

uint32_t current_tid = 0; // Current thread id
static char tracefile[256];

/* Loop induction variable variables */
#define MAX_LOOP_IVS 5
size_t num_loop_ivs = 0;
uint32_t loop_ivs_sarray[MAX_LOOP_IVS];

#ifdef MEM_CHECK
/* Module's mem_read tainting info */
int taint_module_is_set = 0;
uint32_t taint_module_base = 0;
uint32_t taint_module_size = 0;
#endif /* #ifdef MEM_CHECK */

/*******************************************/
// For subroutine fault injection  --by Guan
int  fault_inject_is_set = 0;
#include <sys/queue.h>
typedef struct func_list{
 // const char name[128];
  char name[128];
  uint32_t func_addr;
  uint16_t func_size;
  LIST_ENTRY(func_list) pointers;
}func_list;

/* Definition to LIST */
// type: func_list
// name : func_list_head
// head : func_head   // used fo identify the head of list
// field : pointers
static LIST_HEAD(func_list_head, func_list) 
             func_head = LIST_HEAD_INITIALIZER(&func_head);

// Parse the symbol table
typedef struct symbol_table{
  int index;
  uint32_t addr;
  int size;
  char type[64];
  char bind[64];
  char vis[64];
  int ndx;
  char name[128];
}symbol_table;


int free_func_list();
int load_probability();

/*******************************************/
/*  batch command support	           */
/*******************************************/

/*
typedef struct batch_cmd_entry{
  //char inject_script[128];		// example : "inject_faut test1d add 1"
  const char exe_script[128]; 		// example : "cmd2guest ./testcodes/test1f"
  uint8_t flag;				// flag : asyn(1) or syn(0) 
  					//        cmd2guest : syn
					//        others    : asyn  	
  LIST_ENTRY(batch_cmd_entry) pointers;
}batch_cmd_entry;
*/
#define BATCH_CMD_PROGNAME (unsigned char)(1<<0)
#define BATCH_CMD_TYPE     (unsigned char)(1<<1)
#define BATCH_CMD_NUM	   (unsigned char)(1<<2)
#define BATCH_CMD_SUBFUNC  (unsigned char)(1<<3)
#define BATCH_CMD_OUTPUT   (unsigned char)(1<<4)
#define BATCH_CMD_REPEAT   (unsigned char)(1<<5)
#define BATCH_CMD_MAXSITES (unsigned char)(1<<6)
#define BATCH_APP_MASK		BATCH_CMD_PROGNAME|BATCH_CMD_TYPE|BATCH_CMD_NUM
#define BATCH_SUBFUNC_MASK	BATCH_CMD_PROGNAME|BATCH_CMD_TYPE|BATCH_CMD_NUM|BATCH_CMD_SUBFUNC

typedef struct batch_cmd_struct{
  unsigned char cmd_code;
  char batch_progname[128];	// program name
  char batch_fault_type[128];	// type of fault
  uint64_t batch_fault_num;		// number of faults to inject in the target app for each run
  int batch_run_num;		// number of runs of the target app under injection
//  long batch_max_dic;		// number of max number of dynamic instruction
  char batch_fault_subfunc[128];	// subfunction name (if Coarse-grained mode, same as program name )
  //const char batch_output_filename[64];
  char batch_output_filename[128]; // Return output name
}batch_cmd_struct;

batch_cmd_struct sefi_batch;
char local_output_path[256] = "";	// the path of local output
//int batch_repeat_num = 5;
char batch_cmdline[512] = "";
/*******************************************/


static term_cmd_t tracing_info_cmds[] = {
  {NULL, NULL},
};


typedef struct {
  FS_INFO *fs;
  IMG_INFO *img;
  void *bs;
} disk_info_t;

static disk_info_t disk_info[5];

#if TAINT_ENABLED
typedef struct {
  uint64_t cluster;
  taint_record_t rec;
  int count;
  FS_INFO *fs;
} taintcluster_t;

static void tracing_taint_disk (uint64_t addr, uint8_t * record, void *opaque) {
        return;
}

static void taint_disk_block(char filename[], uint64_t block, int size,
  uint32_t origin, int disk_index, uint32_t offset)
{
  int i;
  int j;
  int count;
  taint_record_t records[64];

  printf("%" PRIx64 ":%d[%d] ", block, size, origin);

  bzero(records, sizeof(records));
  for (i = 0; i < 64; i++) {
    records[i].numRecords = 1;
    records[i].taintBytes[0].source = TAINT_SOURCE_FILE_IN;
    records[i].taintBytes[0].origin = origin;
    memset(&(records[i].taintBytes[1]), 0,
      (MAX_NUM_TAINTBYTE_RECORDS-1)*sizeof(TaintByteRecord));
  }
  
  for (i = 0, count = 0; i < size; i += 64, count++) {
    for(j = 0; j < 64; j++) {
      records[j].taintBytes[0].offset = offset + 64 * count + j;
    }
   
    taintcheck_taint_disk((block * disk_info[disk_index].fs->block_size +
                           i + 0x7e00) / 64,
                          (uint64_t) - 1,
                          0, 64, (uint8_t *) records,
                          disk_info[disk_index].bs);
  }
}

void do_taint_file(char *filename, int dev_index, uint32_t taint_id)
{

  FS_INFO *fs;
  int i;
  uint32_t offset;
  extern uint32_t tsk_errno;

  tsk_errno = 0;

  term_printf("Tainting disk %d file %s\n", dev_index, filename);

  if (!(fs = disk_info[dev_index].fs)) {
    term_printf("Could not find disk_info\n");
    return;
  }

  char *path = strdup(filename);
  if (!path) {
    term_printf("Empty path\n");
    return;
  }
  if (!fs_ifind_path(fs, IFIND_PATH | IFIND_PATH, path) &&
      !fs_icat(fs, 0, found_path_inode, 0, 0, 1 << 5))
  {
    for (i = 0, offset=0; i < found_icat_nblock; i++) {
      if (taint_id == 0)        //it means we are tainting a directory
        taint_disk_block(filename, found_icat_blocks[i].addr,
          found_icat_blocks[i].size,
          //we generate an ID in [400, 1000)
          (found_icat_blocks[i].addr % 600) + 400, dev_index, offset);
      else
        taint_disk_block(filename, found_icat_blocks[i].addr,
                         found_icat_blocks[i].size, taint_id, dev_index, offset);

    offset += found_icat_blocks[i].size;
    }
    term_printf("Tainted file %s\n", filename);
  }
  else {
    term_printf("Could not find file\n");
  }
  printf("\n");
  free(path);

}

void do_taint_sendkey(const char *string, int id)
{
  taint_sendkey_id = id;
  do_send_key(string);
}

#endif //TAINT_ENABLED


#ifdef MEM_CHECK
void do_taint_module(uint32_t pid, const char *name)
{
  tmodinfo_t *modinfo = locate_module_byname(name, pid);
  if (modinfo == NULL) {
    taint_module_is_set = 0;
    term_printf("Module '%s' not found in PID=%u. Won't taint any module.\n", 
		name, pid);
  } else {
    taint_module_is_set = 1;
    taint_module_base = modinfo->base;
    taint_module_size = modinfo->size;
    term_printf("Memory inside module '%s' will be tainted on read.\n",
		name);
  }
}
#endif /* #ifdef MEM_CHECK */

int is_kernel_instruction()
{
    return ((*TEMU_cpu_hflags & HF_CPL_MASK) != 3); 
}


#if TAINT_ENABLED
static void tracing_taint_propagate(int nr_src,
                            taint_operand_t * src_oprnds,
                            taint_operand_t * dst_oprnd,
                            int mode)
{
  if (0==tracing_table_lookup && 2==nr_src && PROP_MODE_MOVE==mode) {
    /* if first is untainted, clear taint info of second arg */
    if (src_oprnds[0].taint==0) {
    /* clear taint info of destination */
    if (0==dst_oprnd->type) /* register */
      taintcheck_taint_register(
        dst_oprnd->addr>>2, dst_oprnd->addr&3,
        dst_oprnd->size,
        0, NULL);
    else /* memory */
      taintcheck_taint_memory(
        dst_oprnd->addr,
        dst_oprnd->size,
        0, NULL);
    eh.tp = TP_MEMREAD_INDEX;
    return;
    } else
    nr_src = 1;
  }

  /* Propagate taint, this needs to be done for all instructions */
  default_taint_propagate(nr_src, src_oprnds, dst_oprnd, mode);

  /* No need to set tp in entry header if not tracing */
  if ((!tracing_start_condition) || (tracepid == 0))
    return;

  /* No need to set tp in entry header if not 
   * tracing kernel and kernel instruction */
  if ( is_kernel_instruction() && !tracing_kernel() )
    return;

  /* Instruction propagated taint. Set tp in entry header */
  if (eh.tp == TP_NONE) eh.tp = TP_SRC;

  if(mode == PROP_MODE_MOVE) {
     /* Check if it is a memory write with tainted index */
    if ((dst_oprnd->type == 1)) {
      uint64_t a0_tainted;
      a0_tainted = taintcheck_register_check(R_A0, 0, 4, NULL);
      if (a0_tainted != 0)
        eh.tp = TP_MEMWRITE_INDEX;
    }

    if(nr_src > 1) {
      if (src_oprnds[0].taint == 0) {
        eh.tp = TP_MEMREAD_INDEX;
      }
      else {
        eh.tp = TP_SRC;
      }
    }
  }
}

#endif

static void tracing_guest_message(char *message)
{
  handle_message(message);
  switch (message[0]) {
  case 'P':
    parse_process(message);
    break;
  case 'M':
    parse_module(message);
    break;
  }
}

uint32_t Term_flag = 0;
uint32_t llcounter = 0;
#define SEFI_PROC_STATE_EXIT 2
#define SEFI_PROC_STATE_WAIT 0
// This is a polling function --guanxyz
static int tracing_block_begin()
{
  int ret;
  hookapi_check_call(temu_plugin->monitored_cr3 == TEMU_cpu_cr[3] && 
                    !TEMU_is_in_kernel());

  /* If not tracing kernel and kernel instruction , return */
  if ( is_kernel_instruction() && !tracing_kernel() )
      return 0;
  
  ret = SEFI_check_target_ps(temu_inject->target_name);
  
  if(ret  == SEFI_PROC_STATE_EXIT){
    // To inform the console the program is done
    if(!strcmp(temu_inject->target_name, "scp")){	  
      check_local_output(local_output_path);
    }else{
      term_printf("Target program '%s' exits! %d more runs \n", temu_inject->target_name, sefi_batch.batch_run_num-1);
     // procname_set(sefi_batch.batch_progname);
      if(sefi_batch.batch_run_num >1){
        sefi_batch.batch_run_num--; 
	repeat_batch_cmd();
	return 0;
      }
    }

    if(strcmp(temu_inject->guest_output_name, "")){
      // To copy the output file from guest to host
      term_printf("Copy %s from Guest! \n", temu_inject->guest_output_name);
      do_get_file(temu_inject->guest_output_name);
      strcpy(temu_inject->guest_output_name, "");
      strcpy(temu_inject->target_name, "scp");
    }else
      strcpy(temu_inject->target_name,  "");
    
  }else if(ret == SEFI_PROC_STATE_WAIT){
    return 0;
  }
  	
 
  /* If not tracing by pid or by name, return */
  if((tracepid == 0) && (!procname_is_set())){
    return 0;
  }
  /* Get thread id */
  current_tid = get_current_tid();

  // This func is very important. It will update current process_list. 
  // So module infor can be extracted by calling locate_module or locate_module_byname
  // -- By guanxyz
  update_proc(0); 
  
  tmodinfo_t *mi;
  mi = locate_module(*TEMU_cpu_eip, TEMU_cpu_cr[3],
                     current_proc);
  strncpy(current_mod, mi ? mi->name : "unknown",31);
  current_mod[31] = '\0';
  
  if (procname_is_set()) {
    char temp[64];
    uint32_t pid;
    

    find_process(TEMU_cpu_cr[3], temp, &pid);
    if (procname_match(temp)&&fault_inject_is_set==1) {
      term_printf("Process %s starts...\n", temp);
      // Search for moduel through MM_STRUCT
      tmodinfo_t *my_mi;
      my_mi = locate_module_byname((char *)&temp[0], pid);
      if(my_mi!=NULL){
      	term_printf("Tracing process :%s PID:%d func:%s\n", procname_get(), pid, temu_inject->func_name);
      	term_printf("module: [%s] 0x%08lX -- 0x%08lX \n", 
	               (char *)&my_mi->name[0], 
		       my_mi->base, 
		       my_mi->base+my_mi->size);
	// Logging
	SEFI_writelog("INFO", "Tracing process :%s PID:%d func:%s \n", 
	                                 procname_get(), 
					 pid, 
					 temu_inject->func_name);
	
	// locate the memory region
	if(strcmp(temu_inject->func_name, procname_get())!=0){ // for function mode, the proname!=func_name
	  // Inject faults to funcs in program
	  // load the func's start address and offsets
	  func_list *p = NULL;
	  LIST_FOREACH(p, &func_head, pointers){
      	    //term_printf("----> table elem :%s monitoring ele: %s\n", p->name, temu_inject->func_name);
	    if(strcmp(p->name, temu_inject->func_name)==0){
		temu_inject->start_addr = p->func_addr;
		temu_inject->end_addr = p->func_addr+p->func_size;
      	    //  term_printf("Monitoring :0x%lX -- 0x%lX\n", temu_inject->start_addr, temu_inject->end_addr);
	    }	
	  }
	}else{ 
	  // Inject faults to program.
	  // load the program's start address and offsets
	  temu_inject->start_addr = my_mi->base;
	  temu_inject->end_addr = my_mi->base+my_mi->size;
	}
	
	if(temu_inject->profile_type == SEFI_PROFILE_NONE){
	  SEFI_inject_counter();
	}
      	term_printf("Monitoring :0x%lX -- 0x%lX\n", temu_inject->start_addr, temu_inject->end_addr);
	temu_inject->is_inject_triggered = 1;
	SEFI_inject_allow();
      	SEFI_inject_mem_region();
      }

      procname_clear();
       
    }  
  }
 


  if (modname_is_set()) {
      if (modname_match(current_mod) &&
	  (temu_plugin->monitored_cr3 == TEMU_cpu_cr[3]))
      {
	  tracing_start_condition = 1;
	  modname_clear();
      }
  }

  return 0;
}

static void tracing_send_keystroke(int reg)
{
  /* If not tracing, return */
  if  (tracepid == 0)
    return;

  //term_printf ("Keystroke received: %d\n",taint_sendkey_id);
#if TAINT_ENABLED
  taint_record_t record;

  if (taint_sendkey_id) {
    uint32_t keystroke = TEMU_cpu_regs[reg];
    term_printf ("Tainting keystroke: %d %08X\n", reg,keystroke);
    record.numRecords = 1;
    record.taintBytes[0].source = TAINT_SOURCE_KEYBOARD_IN;
    record.taintBytes[0].origin = taint_sendkey_id;
    record.taintBytes[0].offset = keystroke_offset;
    memset(&(record.taintBytes[1]), 0,
      (MAX_NUM_TAINTBYTE_RECORDS-1)*sizeof(TaintByteRecord));

    taintcheck_taint_register(reg, 0, 1, 1, (uint8_t *) &record);
    taint_sendkey_id = 0;
    keystroke_offset++;
  }
#endif 
}

static void tracing_bdrv_open(int index, void *opaque)
{
  if ((disk_info[index].img =
       img_open("qemu", 1, (const char **) &opaque)) == NULL) {
    tsk_error_print(stderr);
    return;
  }
  if (!(disk_info[index].fs = fs_open(disk_info[index].img, 0x7e00, NULL))
      && !(disk_info[index].fs =
           fs_open(disk_info[index].img, 0x00, NULL))) {
    tsk_error_print(stderr);
    if (tsk_errno == TSK_ERR_FS_UNSUPTYPE)
      fs_print_types(stderr);
    disk_info[index].img->close(disk_info[index].img);
    disk_info[index].img = NULL;
    return;
  }
  disk_info[index].bs = opaque;
}


static void tracing_bdrv_cleanup()
{
  int i;
  for(i=0; i<sizeof(disk_info)/sizeof(disk_info_t); i++) {
    disk_info_t *di = &disk_info[i];
    if(di->img == NULL) continue;
    if(di->fs != NULL) {
      di->fs->close(di->fs);
      di->fs = NULL;
    }
    di->img->close(di->img);
    di->img = NULL;
  }
}

static void stoptracing()
{
  term_printf("Received Signal: STOP\n");
  tracing_stop();
}

static void killtemu()
{
  term_printf("Received Signal: KILL\n");
  exit(EXIT_KILL_SIGNAL);
}


void do_load_hooks (const char *hooks_dirname, const char *plugins_filename)
{
  if (strcmp(plugins_filename, "") != 0)
    strncpy(hook_plugins_filename, plugins_filename, 256);
  if (strcmp(hooks_dirname, "") != 0)
    strncpy(hook_dirname, hooks_dirname, 256);

  // Load hooks if requested via TEMU monitor
  load_hook_plugins(&(temu_plugin->monitored_cr3),
    hook_plugins_filename,
    hook_dirname,
    &g_plugin_info,
    ini);
}

void do_load_config (const char *config_filepath)
{
  int err = 0;

  // Parse configuration file
  err = check_ini(config_filepath);
  if (err) {
    term_printf ("Could not find INI file: %s\nTry again.\n", config_filepath);
  }
}


int uint32_compare(const void* u1, const void* u2) {
  return *((uint32_t *) u1) - *((uint32_t *) u2);
}

void do_add_iv_eip(uint32_t eip)
{
  if (num_loop_ivs >= MAX_LOOP_IVS) {
    term_printf("max no. eips allowed (%d) is reached.\n", MAX_LOOP_IVS);
  }
  else {
    loop_ivs_sarray[num_loop_ivs++] = eip;
    qsort(&(loop_ivs_sarray[0]), num_loop_ivs, sizeof(uint32_t),
      uint32_compare);
  }
}

static int tracing_init()
{
  int err = 0;

  /* local hook API for instrumentation at certain EIP */
  hook_insn_begin = NULL;

  bzero(disk_info, sizeof(disk_info));

  function_map_init();
  init_hookapi();
  procmod_init();

  // setup signal handler to stop tracing
  signal(SIGUSR1, stoptracing);

  // SIGUSR2 is used by QEMU

  // setup signal handler to exit TEMU
  signal(SIGTERM, killtemu);

  procname_clear(); 

  // this is needed for file tainting
  qemu_pread = (qemu_pread_t)TEMU_bdrv_pread;

  // Parse configuration file
  err = check_ini(ini_main_default_filename);
  if (err) {
    term_printf ("Could not find INI file: %s\n"
                 "Use the command 'load_config <filename> to provide it.\n", 
                 ini_main_default_filename);
  }

  // Parse the SEFI bitflip configuration
  err = check_SEFI_ini(ini_SEFI_default_filename); 
  if (err) {
    term_printf ("Could not find INI file: %s\n"
                 "Use the command 'load_SEFI_config <filename> to provide it.\n", 
                 ini_SEFI_default_filename);
  }
  return 0;
}

static void tracing_cleanup()
{
  //TODO: other cleanup stuff, like function hooks, log files
    unload_hook_plugins();
    procmod_cleanup();
    hookapi_cleanup();
    function_map_cleanup();
    tracing_bdrv_cleanup();

    // Free the memory allocated for fault injection fuction list -- Guan
    free_func_list();
}

void do_tracing_stop()
{
  // write the statistic to log
  uint64_t fadd,fmul, cmp, sarl, idivl, imul, iaddl, isubl, shrl, andl, orl, xorl, movl, testl, notl, ld;
  SEFI_get_profile(&fadd, &fmul, &cmp, &sarl, &idivl, &imul, &iaddl, &isubl, &shrl, &andl, &orl, &xorl, &movl, &testl, &notl, &ld);
  SEFI_writelog("PROFILE", "fadd:%llu fmul:%llu cmp:%llu sarl:%llu idivl:%llu imul:%llu iaddl:%llu isubl:%llu shrl:%llu and:%llu, orl:%llu xorl:%llu movl:%llu testl:%llu notl:%llu ld:%llu \n",
      fadd, fmul, cmp, sarl,idivl, imul, iaddl, isubl, shrl, andl, orl, xorl, movl, testl, notl, ld);
  tracing_stop();
}

void do_tracing(uint32_t pid, const char *filename)
{
  /* if pid = 0, stop trace */
  if (0 == pid)
    tracing_stop();
  else {
    int retval = tracing_start(pid, filename);
    if (retval < 0)
      term_printf("Unable to open log file '%s'\n", filename);
  }

  /* Print configuration variables */
  //print_conf_vars(); 
}

/*************************************************************************************************/
// Inject faults 
// --by Guan
/*************************************************************************************************/
void syn_SEFI_conf(){
  /*
  temu_inject->bitflip_conf.fadd_allowed = SEFI_support_fault_fadd;
  temu_inject->bitflip_conf.fmul_allowed = SEFI_support_fault_fmul;
  temu_inject->bitflip_conf.cmp_allowed = SEFI_support_fault_cmp;
  temu_inject->bitflip_conf.xor_allowed = SEFI_support_fault_xor;
  temu_inject->bitflip_conf.sarl_allowed = SEFI_support_fault_sarl;
  temu_inject->bitflip_conf.idivl_allowed = SEFI_support_fault_idivl;
  temu_inject->bitflip_conf.imul_allowed = SEFI_support_fault_imul;
  */
  temu_inject->bitflip_conf.num_bit = SEFI_support_number_of_bits_to_flip;
  
  temu_inject->bitflip_conf.start_bit = SEFI_support_sub_range_bits_start;
  temu_inject->bitflip_conf.end_bit = SEFI_support_sub_range_bits_end;
  // proba_showall(&probability_list_head);
  if(SEFI_support_dynamic_probability){
    int len = proba_size(&probability_list_head);
    if(current_probability_index < len){
  	term_printf("Coming Probability Index :%d", current_probability_index);
    	temu_inject->bitflip_conf.fault_probability = proba_getNth(probability_list_head, current_probability_index);
        current_probability_index++;
    }
    else  // Load the last probability in the list
    	temu_inject->bitflip_conf.fault_probability = proba_getNth(probability_list_head, current_probability_index-1);
  }
  else  // When dynamic probability is used, the configuration for static probability is disabled.	
    temu_inject->bitflip_conf.fault_probability = SEFI_support_fault_probability;
  //term_printf("Current FP:%lf", temu_inject->bitflip_conf.fault_probability);
  temu_inject->bitflip_conf.start_of_fadd = SEFI_support_start_index_fadd;
  temu_inject->bitflip_conf.start_of_fmul = SEFI_support_start_index_fmul;
  temu_inject->bitflip_conf.start_of_cmp = SEFI_support_start_index_cmp;
  temu_inject->bitflip_conf.start_of_xor = SEFI_support_start_index_xor;
  temu_inject->bitflip_conf.start_of_sarl = SEFI_support_start_index_sarl;
  temu_inject->bitflip_conf.start_of_idivl = SEFI_support_start_index_idivl;
  temu_inject->bitflip_conf.start_of_imul = SEFI_support_start_index_imul;
  temu_inject->bitflip_conf.start_of_iaddl = SEFI_support_start_index_iaddl;
  temu_inject->bitflip_conf.start_of_isubl = SEFI_support_start_index_isubl;
  temu_inject->bitflip_conf.start_of_shrl = SEFI_support_start_index_shrl;
  temu_inject->bitflip_conf.start_of_andl = SEFI_support_start_index_andl;
  temu_inject->bitflip_conf.start_of_orl = SEFI_support_start_index_orl;
  temu_inject->bitflip_conf.start_of_xorl = SEFI_support_start_index_xorl;
  temu_inject->bitflip_conf.start_of_movl = SEFI_support_start_index_movl;
  temu_inject->bitflip_conf.start_of_testl = SEFI_support_start_index_testl;
  temu_inject->bitflip_conf.start_of_notl = SEFI_support_start_index_notl;
  temu_inject->bitflip_conf.start_of_ld = SEFI_support_start_index_ld;
  
  /* Not used because of the multi injection */
  /*
  int j = abs(rand()%SEFI_support_max_dic);
  if(SEFI_support_fault_probability == 0){
    term_printf("Injection on dynamic site %d within %d\n", j, SEFI_support_max_dic);
  }
  temu_inject->bitflip_conf.chosen_dic = j+1;
  */
}

int check_duplicated_chosen_candidates(uint64_t *array, uint64_t size, uint64_t val){
  uint64_t *p = array;
  int i;
  for(i=0; i<size; i++){
    if(*(p+i) == (val+1))
	return 1;
  } 
  return 0;
}

int configure_SEFI_multiple_injection(uint64_t num){
  int i = 0;
  uint64_t j;
  temu_inject->counter = num; 
  if(num > SEFI_support_max_dic)
	return -1;
  // Need multiple injections
  temu_inject->chosen_candidates = (uint64_t *)malloc(sizeof(uint64_t)*num);
  if(temu_inject->chosen_candidates == NULL){ 
    return -1;
  }   
  uint64_t *p = temu_inject->chosen_candidates;
  
  // set chosen candidate with random numbers
  if(SEFI_support_fault_probability == 0)
    term_printf("-- Injection on dynamic site");

  while(i<num){
    // generate random numer
    j = (uint64_t)abs(rand()%SEFI_support_max_dic);
    // check if the generated number has a duplication in current candidate array
    if(check_duplicated_chosen_candidates(temu_inject->chosen_candidates, num, j)){
  	term_printf("(Repeated:%d)", j);
	continue;
    }  
    // save the number to candidates
    *(p+i) = j+1;							
    i++;
    term_printf(" %d ", j+1);
  }
  term_printf(" within %d\n", SEFI_support_max_dic);
  for(i=0; i<num; i++){
    printf(" %ld ", *(temu_inject->chosen_candidates+i));
  } 
  return 0;
}

// Command for inject faults in application level
void do_inject_by_name(char *progname, char *fault_type, uint64_t num){ 
  
  load_probability();	// Load the probability

  /* Check prgram name */
  if(progname==NULL){ 
    term_printf ("SEFI: Guest program name is not specified.\n"); 
    return; 
  } 
  // check numbers of faults
  if(num<1 && SEFI_support_fault_probability==0 ){
    term_printf ("SEFI: Number of faults is not accepted (%d).\n", num);
    return;
  }
  // Load fault injection type
  if(!strcmp(fault_type, "fadd"))
    temu_inject->inject_type = SEFI_TYPE_FADD;
  else if(!strcmp(fault_type,"fmul"))
    temu_inject->inject_type = SEFI_TYPE_FMUL;
  else if(!strcmp(fault_type,"cmp"))
    temu_inject->inject_type = SEFI_TYPE_CMP;
  else if(!strcmp(fault_type,"sarl"))
    temu_inject->inject_type = SEFI_TYPE_SARL;
  else if(!strcmp(fault_type, "idivl"))
    temu_inject->inject_type = SEFI_TYPE_IDIVL;  
  else if(!strcmp(fault_type, "imull"))
    temu_inject->inject_type = SEFI_TYPE_IMULL;  
  else if(!strcmp(fault_type, "iaddl"))
    temu_inject->inject_type = SEFI_TYPE_IADDL;  
  else if(!strcmp(fault_type, "isubl"))
    temu_inject->inject_type = SEFI_TYPE_ISUBL;  
  else if(!strcmp(fault_type, "shrl"))
    temu_inject->inject_type = SEFI_TYPE_SHRL;  
  else if(!strcmp(fault_type, "andl"))
    temu_inject->inject_type = SEFI_TYPE_ANDL;  
  else if(!strcmp(fault_type, "orl"))
    temu_inject->inject_type = SEFI_TYPE_ORL;  
  else if(!strcmp(fault_type, "xorl"))
    temu_inject->inject_type = SEFI_TYPE_XORL;  
  else if(!strcmp(fault_type, "movl"))
    temu_inject->inject_type = SEFI_TYPE_MOVL;  
  else if(!strcmp(fault_type, "load")){
    temu_inject->inject_type = SEFI_TYPE_LD;  
  }

  else if(strcmp(fault_type, "hybrid"))
    temu_inject->inject_type = SEFI_HYBRID_BIT_FLIP;
  else{  
    temu_inject->inject_type = SEFI_NONE;
    term_printf ("SEFI: Inject Type not supported. (%s) \n", fault_type);
    return;
  }
  term_printf("Current type:%d \n",  temu_inject->inject_type);
    
  syn_SEFI_conf(); 
  SEFI_inject_conf();
  
  
  // Global indicator for SEFI
  fault_inject_is_set = 1;

  temu_inject->is_inject_allowed = 1;
  SEFI_inject_allow();

  procname_set(progname);
  
  //temu_inject->counter = num;
  SEFI_inject_counter();
  SEFI_inject_type();

  // Generate injection candidates with random kernel
  configure_SEFI_multiple_injection(num);
  
  // Copy the chosen DICs to CPUState
  SEFI_inject_dic(temu_inject->chosen_candidates, num);

  // programe name for logging
  strcpy(temu_inject->func_name, progname);
  //SEFI_inject_funcname();

  if(SEFI_support_fault_probability == 0){
    term_printf ("SEFI: Waiting for process %s to inject %d '%s' fault(s).\n", progname,num, fault_type);
    SEFI_writelog("INFO", "SEFI: Waiting for process %s to inject %d '%s' fault(s).\n", progname,num, fault_type);
  }else{
    term_printf ("SEFI: Waiting for process %s to inject '%s' fault(s) in function %s with probability %0.6e %\n", 
	progname, 
	fault_type, 
	temu_inject->func_name, 
	temu_inject->bitflip_conf.fault_probability
    );
    SEFI_writelog("INFO", "SEFI: Waiting for process %s to inject '%s' fault(s) in function %s with probability %0.6e %\n", 
	progname, 
	fault_type, 
	temu_inject->func_name,temu_inject->bitflip_conf.fault_probability);
  }
}

// Parse the symbol table from file
int SEFI_parse_symbol_table(){  
  symbol_table *ptable = (symbol_table *)malloc(sizeof(symbol_table));

  FILE *pt = NULL;
  char strOfLine[200];
  char token[] = " :\n";
  char temp[64];

  func_list *p = NULL;

  pt = fopen(SEFI_host_sym_table_directory, "r");
  if(pt == NULL)
    term_printf("ERROR [fopen] Cannot find symbol table\n");
  else{
    while(fgets(strOfLine, 200, pt)){
      ptable->index = atoi(strtok(strOfLine, token));
      strcpy(temp,strtok(NULL, token));
      ptable->addr = (unsigned long int)strtol(temp, NULL, 16);
      ptable->size = atoi(strtok(NULL, token));
      strcpy(ptable->type, strtok(NULL,token));
      strcpy(ptable->bind, strtok(NULL,token));
      strcpy(ptable->vis, strtok(NULL,token));
      ptable->ndx = atoi(strtok(NULL, token));
      strcpy(ptable->name, strtok(NULL,token));
      
      // Init the func list by reading the symbol table
      p = (func_list *)malloc(sizeof(func_list));
      strcpy(p->name, ptable->name);
      p->func_addr = ptable->addr;
      p->func_size = ptable->size;
      LIST_INSERT_HEAD(&func_head, p, pointers);
  
      //term_printf("The name of func is :%s the addr is:%ld, the size is:%d\n ", ptable->name, ptable->addr, ptable->size);
    }
    fclose(pt);
    return 1;
  }

  return 0;
}


// Initilize the function list
int init_func_list(){
  
  /* Function list is no longer manually initialized */
  
  /* 
  func_list *p = NULL;

  p = (func_list *)malloc(sizeof(func_list));
  memcpy(p->name, "addfunc", sizeof("addfunc"));
  p->func_addr = (uint32_t)0x08048424;
  p->func_size = 66;
  LIST_INSERT_HEAD(&func_head, p, pointers);
 
  p = (func_list *)malloc(sizeof(func_list));
  memcpy(p->name, "mulfunc", sizeof("mulfunc"));
  p->func_addr = (uint32_t)0x08048466;
  p->func_size = 66;
  LIST_INSERT_HEAD(&func_head, p, pointers);
  */
  SEFI_parse_symbol_table();
  return 1;
}

// Free the memory space of function list
// This function is called in unplugin
int free_func_list()
{
  func_list *p = NULL;
  while(!LIST_EMPTY(&func_head)){
    p = LIST_FIRST(&func_head);
    LIST_REMOVE(p, pointers);
    free(p);
  }
  return 1;
}

// Service to load the func table
// Currently it is mannually initialized
void load_func(){
  init_func_list();
}

int find_func(const char *name){
  func_list *p = NULL;
  
  if(LIST_EMPTY(&func_head))
    return 0;
    	  
  LIST_FOREACH(p, &func_head, pointers){
    if(!strcmp(p->name, name))
      return 1;
  }

  return 0;
}
uint32_t find_func_addr(const char *name){
  func_list *p = NULL;
  
  if(LIST_EMPTY(&func_head))
    return 0;
    	  
  LIST_FOREACH(p, &func_head, pointers){
    if(strcmp(p->name, name))
      return p->func_addr;
  }

  return 0;
}
uint32_t find_func_size(const char *name){
  func_list *p = NULL;
  
  if(LIST_EMPTY(&func_head))
    return 0;
    	  
  LIST_FOREACH(p, &func_head, pointers){
    if(strcmp(p->name, name))
      return p->func_size;
  }

  return 0;
}

// probability 
int load_probability(){
	proba_init_list("probability.txt", &probability_list_head);
	return 0;
}


// The advanced version of do_inject_fault
// Format: program_name fault_type sunroutine number
void do_inject_by_name_and_func( char *progname, 
				 char *fault_type, 
                                 char *func, 
				uint64_t num)
{ 
  load_func(); // only if the injection is located in function level
  load_probability();
  // chech func name
  if(!find_func(func)){
    term_printf ("SEFI: Function %s is not identified.  \n", func);
    return;	  
  }else{
    strcpy(temu_inject->func_name, func);
  }
 
  //check progname
  if(progname==NULL){
    term_printf ("SEFI: Guest program name is not specified.\n");
    return;
  }  
  //strncpy(temu_inject->target_name, progname, sizeof(progname));   // Special for hyper monitor

  // check numbers of faults
  if(num<1 && SEFI_support_fault_probability==0 ){
    term_printf ("SEFI: Number of faults is not accepted (%d).\n", num);
    return;
  }

 // Load fault injection type
  if(!strcmp(fault_type, "fadd"))
    temu_inject->inject_type = SEFI_TYPE_FADD;
  else if(!strcmp(fault_type,"fmul"))
    temu_inject->inject_type = SEFI_TYPE_FMUL;
  else if(!strcmp(fault_type,"cmp"))
    temu_inject->inject_type = SEFI_TYPE_CMP;
  else if(!strcmp(fault_type,"sarl"))
    temu_inject->inject_type = SEFI_TYPE_SARL;
  else if(!strcmp(fault_type, "idivl"))
    temu_inject->inject_type = SEFI_TYPE_IDIVL;  
  else if(!strcmp(fault_type, "imull"))
    temu_inject->inject_type = SEFI_TYPE_IMULL;  
  else if(!strcmp(fault_type, "iaddl"))
    temu_inject->inject_type = SEFI_TYPE_IADDL;  
  else if(!strcmp(fault_type, "isubl"))
    temu_inject->inject_type = SEFI_TYPE_ISUBL;  
  else if(!strcmp(fault_type, "shrl"))
    temu_inject->inject_type = SEFI_TYPE_SHRL;  
  else if(!strcmp(fault_type, "andl"))
    temu_inject->inject_type = SEFI_TYPE_ANDL;  
  else if(!strcmp(fault_type, "orl"))
    temu_inject->inject_type = SEFI_TYPE_ORL;  
  else if(!strcmp(fault_type, "xorl"))
    temu_inject->inject_type = SEFI_TYPE_XORL;  
  else if(!strcmp(fault_type, "movl"))
    temu_inject->inject_type = SEFI_TYPE_MOVL;  
  else if(!strcmp(fault_type, "load"))
    temu_inject->inject_type = SEFI_TYPE_LD;  
  else if(strcmp(fault_type, "hybrid"))
    temu_inject->inject_type = SEFI_HYBRID_BIT_FLIP;
  else{  
    temu_inject->inject_type = SEFI_NONE;
    term_printf ("SEFI: Inject Type not supported. (%s) \n", fault_type);
    return;
  }
  /*
  if(strcmp(fault_type, "add")==0 && SEFI_support_fault_fadd)
    temu_inject->inject_type = SEFI_FADD_BIT_FLIP;
  else if(strcmp(fault_type,"mul")==0 && SEFI_support_fault_fmul)
    temu_inject->inject_type = SEFI_FMUL_BIT_FLIP;
  else if(strcmp(fault_type,"cmp")==0 && SEFI_support_fault_cmp)
    temu_inject->inject_type = SEFI_CMP_BIT_FLIP;
  else if(strcmp(fault_type,"sarl")==0 && SEFI_support_fault_sarl)
    temu_inject->inject_type = SEFI_SARL_BIT_FLIP;
  else if(strcmp(fault_type, "xor") == 0 && SEFI_support_fault_xor)
    temu_inject->inject_type = SEFI_XOR_BIT_FLIP;  
  else if(strcmp(fault_type, "idivl") == 0 && SEFI_support_fault_idivl)
    temu_inject->inject_type = SEFI_IDIVL_BIT_FLIP;  
  else if(strcmp(fault_type, "imul") == 0 && SEFI_support_fault_imul)
    temu_inject->inject_type = SEFI_IMUL_BIT_FLIP;  

  else if(strcmp(fault_type, "hybrid")==0 && SEFI_support_fault_fadd && SEFI_support_fault_fmul)
    temu_inject->inject_type = SEFI_HYBRID_BIT_FLIP;
  else{  
    temu_inject->inject_type = SEFI_NONE;
    term_printf ("SEFI: Inject Type not supported. (%s) \n", fault_type);
    return;
  }
  */
  /*
  if(!strcmp(fault_type, "fadd") && !strcmp(fault_type, "fmul") && !strcmp(fault_type, "cmp")  
      && !strcmp(fault_type, "sarl") && !strcmp(fault_type, "xor") && !strcmp(fault_type, "idivl") 
      && !strcmp(fault_type, "imull") && !strcmp(fault_type, "iaddl") && !strcmp(fault_type, "isubl") 
      && !strcmp(fault_type, "shrl") && !strcmp(fault_type, "andl") && !strcmp(fault_type, "orl") 
      && !strcmp(fault_type, "xorl") && !strcmp(fault_type, "movl"))
    term_printf ("SEFI: Inject Type is %s. \n", fault_type);
  else{   
    term_printf ("SEFI: Inject Type not supported. (%s) \n", fault_type);
    return;
  }
  */

  syn_SEFI_conf(); 
  SEFI_inject_conf();
  // Global indicator for SEFI
  fault_inject_is_set = 1;
  
  temu_inject->is_inject_allowed = 1;
  SEFI_inject_allow();

  procname_set(progname); 
  
  SEFI_inject_counter();
  SEFI_inject_type();

  // Generate injection candidates with random kernel
  configure_SEFI_multiple_injection(num);
  //temu_inject->counter = num;  //Moved to above function
  SEFI_inject_dic(temu_inject->chosen_candidates, num);  // copy the chosen_DICs to CPUState

  // Function name for logging
  SEFI_inject_funcname();

  if(SEFI_support_fault_probability == 0){
  term_printf ("SEFI: Waiting for process %s to inject %d '%s' fault(s) in function %s\n", progname,num, fault_type, temu_inject->func_name);
 
  SEFI_writelog("INFO", "SEFI: Waiting for process %s to inject %d '%s' fault(s) in function %s\n", progname,num, fault_type, temu_inject->func_name);
  }else{ 
  term_printf ("SEFI: Waiting for process %s to inject '%s' fault(s) in function %s with probability %0.6e %\n", progname, fault_type, temu_inject->func_name, temu_inject->bitflip_conf.fault_probability);
 
  SEFI_writelog("INFO", "SEFI: Waiting for process %s to inject '%s' fault(s) in function %s with probability %0.6e %\n", progname, fault_type, temu_inject->func_name,temu_inject->bitflip_conf.fault_probability);

  }
  
}


/* Function */
/* load SEFI configure
 */
void do_load_SEFI_config (const char *config_filepath)
{
  int err = 0;

  // Parse configuration file
  err = check_SEFI_ini(config_filepath);
  if (err) {
    term_printf("ERROR [fopen] Cannot find file (%s)\n", config_filepath);
  }
}

/* Function */
/*
 * Profile mode1
 * To profile the program 
 * Output: number of operations to SEFI.log
 */ 
void do_profile_by_name(const char *progname){
  
  // check progname
  if(progname==NULL){
    term_printf ("SEFI: Guest program name is not specified.\n");
    return;
  }
  // ALways, we want to profile the following types of operations
  /*
  temu_inject->profile_type = (SEFI_PROFILE_FADD 
  				| SEFI_PROFILE_FMUL 
				| SEFI_PROFILE_CMP 
				| SEFI_PROFILE_XOR
				| SEFI_PROFILE_SARL
				| SEFI_PROFILE_IDIVL
				| SEFI_PROFILE_IMULL
				);
  */				
  fault_inject_is_set=1;
  temu_inject->is_inject_allowed = 1;
  SEFI_inject_allow();
  // configure to the CPU configure
  SEFI_conf_profile(); 
  procname_set(progname);
  strncpy(temu_inject->target_name, progname, sizeof(progname));   // Special for hyper monitor

  // programe name for logging  
  strcpy(temu_inject->func_name, progname); // register the progname as the tracing func name
  SEFI_inject_funcname();

}

/*
 * Profile mode2
 * To profile the program's subroutine 
 * Output: number of operations to SEFI.log
 */ 
void do_profile_by_name_and_func(const char *progname, const char *func){
  
  load_func(); // only if the profiling is located in function level
  // chech func name
  if(!find_func(func)){
    term_printf ("SEFI: Function %s is not identified.  \n", func);
    return;	  
  }else{
    strcpy(temu_inject->func_name, func);
  }

  // check progname
  if(progname==NULL){
    term_printf ("SEFI: Guest program name is not specified.\n");
    return;
  }
  // ALways, we want to profile both all kinds of operations
  /*
  temu_inject->profile_type = (SEFI_PROFILE_FADD 
  				| SEFI_PROFILE_FMUL 
				| SEFI_PROFILE_CMP 
				| SEFI_PROFILE_XOR
				| SEFI_PROFILE_SARL
				| SEFI_PROFILE_IDIVL);
  */
  fault_inject_is_set=1;
  temu_inject->is_inject_allowed = 1;
  SEFI_inject_allow();
  // configure to the CPU configure
  SEFI_conf_profile(); 
  procname_set(progname);
  strncpy(temu_inject->target_name, progname, sizeof(progname));   // Special for hyper monitor

  // programe name for logging  
  //strcpy(temu_inject->func_name, progname); // register the progname as the tracing func name
  SEFI_inject_funcname();
 
  SEFI_writelog("INFO", "SEFI: Waiting for process %s to profile in function %s\n", progname, temu_inject->func_name);
  
}

/********************************************************/
/*  Commands(hypervisor) to commands(guest) 
 */
typedef struct {
    const char key;
    const char *name;
} CodeDef;


static const CodeDef code_defs[] = {
    { '.', "dot"},
    { ' ', "spc" },
    { '/', "kp_divide" },
    { '1', "1"},
    { '2', "2"},
    { '3', "3"},
    { '4', "4"},
    { '5', "5"},
    { '6', "6"},
    { '7', "7"},
    { '8', "8"},
    { '9', "9"},
    { '0', "0"},
    { 0, NULL },
};

/* helper function */ 
const char*  get_code(const char *key)
{
    const CodeDef *p;

    for(p = code_defs; p->key != 0; p++) {
        if (*key == p->key)
            return p->name;
    }
    return NULL;
}

/* helper function */ 
const char *extract_progname(const char *string){
  char *pch;
  const char *pname;
  int offset;
  
  pch = strrchr(string, '/');
 // pspace = strchr(string, ' ');
  // program under current directory
  if(!pch){
    pname = string;
  }else{
    offset = pch-string+1;
    pname = string+offset;
  }
   
  return pname;  
}
/* helper function */ 
char *extract_filename(char *string){
  char *pch;
  char *pname;
  int offset;
  
  pch = strrchr(string, '/');
  
  // program under current directory
  if(!pch){
    pname = string;
  }else{
    offset = pch-string+1;
    pname = string+offset;
  }
   
  return pname;  
}

/* Function */ 
/* asyn comand to guest */
void register_target(const char *string)
{
    const char *pname;
      
    // This part is another trick
    // From the commands sent to guest, if it contians
    // variables (i.e., bmm 1 8), pname needs to be again
    // parsed for process name
    pname = extract_progname(string);
    if(strchr(pname, ' ')==NULL){
    	strcpy(temu_inject->target_name, pname);   // Special for hyper monitor
    }else{
	char *pstr;
	pstr = strchr(pname, ' ');
	memcpy(temu_inject->target_name, pname, (pstr-pname) );
	temu_inject->target_name[pstr-pname] = '\0';
    }
    term_printf("Process %s is registered\n", temu_inject->target_name );
}


/* Function */ 
/* asyn comand to guest */
void do_cmd2guest(const char *string)
{
    const char *keyenter = "kp_enter";
    
    term_printf("Current commands : %s\n", string);
    do_send_string(string);

    // poll the triger
    do_send_key(keyenter);
}

/********************************/
/* The old version of cmd2guest */
/* Removed by guanxyz           */
/********************************/
/*
void do_cmd2guest(const char *string)
{
    const char *keybuf;
    char pCmd[512];
    const char *p;
    char *q;
    const char *hyphen = "-";
    const char *keyenter = "kp_enter";
    const char endp = '\0';
    const char *pname;
    p = string;
    q = pCmd;
    
    term_printf("Current commands : %s\n", string);
    do_send_string(string);

    // poll the triger
    do_send_key(keyenter);

    // Some program is under monitoring and investigating
     if(strcmp(temu_inject->target_name, "")!=0){
       term_printf("Another program \"%s\" is under monitoring\n", temu_inject->target_name );
       return;
     }
    // Parse the command line input and re-format it to 
    // the understanding of guest
    while (*p != '\0') {
      if((*p >= 'a'&& *p <='z') || (*p >= 'A' && *p <= 'Z')){
	memcpy(q, p, 1);
	q++;
	memcpy(q, hyphen, 1);	
	q++;
      }else if(get_code(p)){
	keybuf = get_code(p);
	term_printf("current key %c to check is %s\n",*p, keybuf);
	memcpy(q, keybuf, strlen(keybuf));  
	q += strlen(keybuf);
	memcpy(q, hyphen,1);	
	q++;
      }else{
        printf("Unrecognized Character: %c\n", *p);
        return;
      }
      p++;
    }
    // Attach "Enter" key 
    memcpy(q, keyenter, strlen(keyenter));
    q+=strlen(keyenter);
    memcpy(q, (char *)&endp, 1);
    
    // This part is another trick
    // From the commands sent to guest, if it contians
    // variables (i.e., bmm 1 8), pname needs to be again
    // parsed for process name
    pname = extract_progname(string);
    if(strchr(pname, ' ')==NULL){
    	strcpy(temu_inject->target_name, pname);   // Special for hyper monitor
    }else{
	char *pstr;
	pstr = strchr(pname, ' ');
	memcpy(temu_inject->target_name, pname, (pstr-pname) );
	temu_inject->target_name[pstr-pname] = '\0';
    }
    term_printf("Send \"%s\" to guest! Process %s is registered\n", pCmd, temu_inject->target_name );
    //do_send_key(pCmd);
}
*/

/* helper function */ 
void helper_cut_space(char *str){
  char *p;
  p = str;

  while (!isspace(*p))
    p++;

  *p = '\0';

}

/* helper function 
 *
 * But not used anymore
 * */ 
/* Extract each command in batch */
/*
int extract_batch(char *args, struct batch_cmd_struct *pbatch){
  
  char cmd;
  char buf[128];
  const char *p;
  struct batch_cmd_struct *pb = pbatch;
  p = args;
  cmd = (char)*p;
  p+=2;

  if((char)*p =='\0'){
    term_printf("No args\n");
    return 1;
  }
  strcpy(buf, p);
  switch(cmd){
    case 'a':    // To define the target application
  		 //helper_cut_space(buf);
                 term_printf("To define the target application[%s]\n", buf);
		 pb->cmd_code |= BATCH_CMD_PROGNAME;
		 strcpy(pb->batch_progname, buf);
		 break;
    case 't':    // To define the fault type
  		 helper_cut_space(buf);
                 term_printf("To define the fault type [%s]\n", buf);
		 pb->cmd_code |= BATCH_CMD_TYPE;
		 strcpy(pb->batch_fault_type, buf);
		 break;
    case 'f':    // To define the subroutine to inject faults
  		 helper_cut_space(buf);
    		 term_printf("To define the subrountine [%s]\n", buf);
		 pb->cmd_code |= BATCH_CMD_SUBFUNC;
		 strcpy(pb->batch_fault_subfunc, buf);
		 break;		
    case 'm':	 // To define the max_dynamic_injections
		 helper_cut_space(buf);
		 term_printf("To define the maximum dynamic injection site [%s]\n", buf);
	//	 pb->cmd_code |= BATCH_CMD_MAXDIC;
		 SEFI_support_max_dic = atoi(buf); 		 		 
		 break;
    case 'n':    // To define the number of faults in each try
  		 helper_cut_space(buf);
    		 term_printf("To define the number of faults [%s]\n", buf);
		 pb->cmd_code |= BATCH_CMD_NUM;
		 pb->batch_fault_num = atoi(buf);
		 break;
    case 'r':    // To define the total number of runs
   		 helper_cut_space(buf);
    		 term_printf("To define the number of runs under injections [%s]\n", buf);
		 pb->cmd_code |= BATCH_CMD_REPEAT;
		 pb->batch_run_num = atoi(buf);
		 break;
  
    case 'o':    // To define the output file that needs to be sent to HOST		 
  		 helper_cut_space(buf);
    		 term_printf("To define the output [%s]\n", buf);
		 pb->cmd_code |= BATCH_CMD_OUTPUT;
                 strcpy(pb->batch_output_filename, buf);
		 break;
    default : 
    		 term_printf("The cmd is not valid [%c] [%s]\n", cmd, buf);
		 return 1;		 
  }
  term_printf("Command Code is 0x%x [0x%x]\n ", pb->cmd_code, pbatch->cmd_code);
  
  return 0;

}

*/


int repeat_batch_cmd(){
  char cmd_string[64];
  const char *pname;
  char *pstr;
  // Determine the functions to call
  if((sefi_batch.cmd_code & BATCH_CMD_PROGNAME) 
    && (sefi_batch.cmd_code & BATCH_CMD_TYPE) 
    && (sefi_batch.cmd_code & BATCH_CMD_NUM))
    {
      if(sefi_batch.cmd_code & BATCH_CMD_SUBFUNC) // Application Name + Subfunc Name
      { 
	// in case the app is not under current directory 
        pname = extract_progname(sefi_batch.batch_progname); 
	
	// get process name only
	pstr = strchr(pname, ' ');
	memcpy(cmd_string, pname, (pstr-pname) );
	cmd_string[pstr-pname] = '\0';
        term_printf("program name is %s size :%d\n", cmd_string, pstr-pname);
	// set the probe
	do_inject_by_name_and_func(cmd_string, 
				   sefi_batch.batch_fault_type, 
				   sefi_batch.batch_fault_subfunc,
				   sefi_batch.batch_fault_num);
	// command the guest (this is optional)
	register_target(sefi_batch.batch_progname);

      }else{					// Application Name
	// in case the app is not under current directory 
        pname = extract_progname(sefi_batch.batch_progname); 	
	pstr = strchr(pname, ' ');
	memcpy(cmd_string, pname, (pstr-pname) );
	cmd_string[pstr-pname] = '\0';

	// set the probe
        do_inject_by_name(cmd_string, &sefi_batch.batch_fault_type[0], sefi_batch.batch_fault_num);
	// command the guest (this is optional)
	register_target(sefi_batch.batch_progname);
      }
       
    }else{	
	return 1;
    }

  return 0;
}

/* Function */
/* Execute the batch commands */
void do_batch_cmd(const char *cmdline){
    
  int nb_args, err;
  char *p, *pstr;
  char *pch = NULL;
  const char *pname;
  char cmd_string[64];
  char token_cmd[] = "-";
  nb_args = 0;
  p = cmdline;
   //SEFI has to reboot before execute new batch
  do_reboot_SEFI(); 
  proba_clean(); 
 
  // for repeatation feature 
  //if(strcmp(batch_cmdline, "")!=0)
  //   strncpy(batch_cmdline, cmdline, sizeof(cmdline));  

  struct batch_cmd_struct *pbatch = (struct batch_cmd_struct *)malloc(sizeof(struct batch_cmd_struct));
  pbatch->cmd_code = 0;

  srand48((unsigned int)time(NULL)); // for generate the random number by calling drand48()
  srand((unsigned int)time(NULL)); // for generate the random number by calling rand()

  pch  = strtok(p, token_cmd);
  pbatch->cmd_code = 0;
  if(pch == NULL){
    if(pbatch!=NULL)
      free(pbatch);
    do_reboot_SEFI();
    proba_clean(); 
    return;
  }else // In order to solve the problem
    pch = strtok(NULL, token_cmd);

  while(pch != NULL){
    nb_args++;
    // parse the batch
    term_printf("Substring is %s\n", pch); 
    /***************************************************/    
    /*   Parsing the commands			       */
    /***************************************************/    
    {	
          char cmd;
	  char buf[128];
	  const char *p;
	  struct batch_cmd_struct *pb = pbatch;
	  p = pch;
	  cmd = (char)*p;
	  p+=2;

	  if((char)*p =='\0'){
	    term_printf("No args\n");
	    err=1;
	  }
	  strcpy(buf, p);
	  switch(cmd){
	    case 'a':    // To define the target application
			 //helper_cut_space(buf);
			 term_printf("To define the target application[%s]\n", buf);
			 pb->cmd_code |= BATCH_CMD_PROGNAME;
			 strcpy(pb->batch_progname, buf);
			 break;
	    case 't':    // To define the fault type
			 helper_cut_space(buf);
			 term_printf("To define the fault type [%s]\n", buf);
			 pb->cmd_code |= BATCH_CMD_TYPE;
			 strcpy(pb->batch_fault_type, buf);
			 break;
	    case 'f':    // To define the subroutine to inject faults
			 helper_cut_space(buf);
			 term_printf("To define the subrountine [%s]\n", buf);
			 pb->cmd_code |= BATCH_CMD_SUBFUNC;
			 strcpy(pb->batch_fault_subfunc, buf);
			 break;		
	    case 'm':	 // To define the max_dynamic_injections
			 helper_cut_space(buf);
			 term_printf("To define the maximum dynamic injection site [%s]\n", buf);
		//	 pb->cmd_code |= BATCH_CMD_MAXDIC;
			 SEFI_support_max_dic = atoi(buf); 		 		 
			 break;
	    case 'n':    // To define the number of faults in each try
			 helper_cut_space(buf);
			 term_printf("To define the number of faults [%s]\n", buf);
			 pb->cmd_code |= BATCH_CMD_NUM;
			 pb->batch_fault_num = atoi(buf);
			 break;
	    case 'r':    // To define the total number of runs
			 helper_cut_space(buf);
			 term_printf("To define the number of runs under injections [%s]\n", buf);
			 pb->cmd_code |= BATCH_CMD_REPEAT;
			 pb->batch_run_num = atoi(buf);
			 break;
	    case 'o':    // To define the output file that needs to be sent to HOST		 
			 helper_cut_space(buf);
			 term_printf("To define the output [%s]\n", buf);
			 pb->cmd_code |= BATCH_CMD_OUTPUT;
			 strcpy(pb->batch_output_filename, buf);
			 break;
	    default : 
			 term_printf("The cmd is not valid [%c] [%s]\n", cmd, buf);
			 err = 1;		 
	  }
	  term_printf("Command Code is 0x%x [0x%x]\n ", pb->cmd_code, pbatch->cmd_code);
	  
	  // for fixed probability, deal with cmd_code and batch_fault_num
	  if(SEFI_support_fault_probability != 0){
	    pb->cmd_code |= BATCH_CMD_NUM;
	    pb->batch_fault_num = 0;
	    
	  }
	  err=0;

	}
    /***************************************************/    
    //err = extract_batch(pch, pbatch);	// This function is not used anymore
    //
    term_printf("The command code is [%x]\n", pbatch->cmd_code);
    
    if(err){
      term_printf("It is going to reboot SEFI\n");
      /*
      if(pbatch!=NULL)
        free(pbatch);
      */
      do_reboot_SEFI();
      proba_clean(); 
      return;
    }

    pch  = strtok(NULL, token_cmd);
  }

  term_printf("The command code is %x\n", pbatch->cmd_code);
  
  // Keep the record of batch command
  sefi_batch.cmd_code = pbatch->cmd_code;
  sefi_batch.batch_fault_num = pbatch->batch_fault_num;
  sefi_batch.batch_run_num = pbatch->batch_run_num;
  // sefi_batch.batch_max_dic = pbatch->batch_max_dic;
  strcpy(sefi_batch.batch_progname, pbatch->batch_progname);
  strcpy(sefi_batch.batch_fault_type, pbatch->batch_fault_type);
  strcpy(sefi_batch.batch_fault_subfunc, pbatch->batch_fault_subfunc);
  strcpy(sefi_batch.batch_output_filename, pbatch->batch_output_filename);
  // Determine the functions to call
  if((pbatch->cmd_code & BATCH_CMD_PROGNAME) 
    && (pbatch->cmd_code & BATCH_CMD_TYPE) 
    && (pbatch->cmd_code & BATCH_CMD_NUM)
    )
    {
      if(pbatch->cmd_code & BATCH_CMD_SUBFUNC) // Application Name + Subfunc Name
      { 
	// in case the app is not under current directory 
        pname = extract_progname(pbatch->batch_progname); 
	
	// get process name only
	pstr = strchr(pname, ' ');
	memcpy(cmd_string, pname, (pstr-pname) );
	cmd_string[pstr-pname] = '\0';
        term_printf("program name is %s-size :%d, num:%d\n", cmd_string, pstr-pname, pbatch->batch_fault_num);
	// set the probe
	do_inject_by_name_and_func(cmd_string, 
				   pbatch->batch_fault_type, 
				   pbatch->batch_fault_subfunc,
				   pbatch->batch_fault_num);
	// command the guest (this is optional)
	register_target(pbatch->batch_progname);
	//do_cmd2guest(pbatch->batch_progname);

      }else{					// Application Name
	// in case the app is not under current directory 
        pname = extract_progname(pbatch->batch_progname); 
	pstr = strchr(pname, ' ');
	memcpy(cmd_string, pname, (pstr-pname) );
	cmd_string[pstr-pname] = '\0';
        term_printf("program name is %s type is %s num:%d\n", cmd_string,  pbatch->batch_fault_type, pbatch->batch_fault_num);

	// set the probe
        do_inject_by_name(cmd_string, &pbatch->batch_fault_type[0], pbatch->batch_fault_num);
	// command the guest (this is optional)
	register_target(pbatch->batch_progname);
	//do_cmd2guest(pbatch->batch_progname);
      }
       
    }else{	
        if(pbatch!=NULL)
          free(pbatch);
        do_reboot_SEFI();
 	proba_clean(); 
	return;
    }

  // setup the callback of return output (optional)
  if(pbatch->cmd_code & BATCH_CMD_OUTPUT){
    strcpy(temu_inject->guest_output_name, pbatch->batch_output_filename);
    strcpy(local_output_path, SEFI_host_target_directory);
    strcat(local_output_path, pbatch->batch_output_filename);
    // Clear local file
    remove_output(local_output_path); 
    term_printf("Copy %s from guest to %s! \n", temu_inject->guest_output_name, local_output_path);
  }
  // All done!
  if(pbatch!=NULL) 
  	free(pbatch);
}


/* Function */
/* Asyn copy guest file to host */
void do_get_file(const char *guest_output){
  char cmd[256];
  char scp_cmd[] = "scp";
  char space_str[] = " ";
  const char *p;

  const char *keyenter = "kp_enter";

  p = guest_output;
  if(!strcmp(SEFI_host_conf, "")){
    term_printf("ERROR : configuration of host is not valid.\n");
    return; 
  }
  
  // assemble the command line
  strcpy(cmd, scp_cmd);
  strcat(cmd, space_str);
  strcat(cmd, p);
  strcat(cmd, space_str);
  strcat(cmd, SEFI_host_conf);
  //strcat(cmd, guest_output);

  term_printf("Copying %s .....\n", p); 
  do_send_string(cmd);

  // poll the triger
  do_send_key(keyenter);
}


/*************************************************************************************************/

void do_tracing_by_name(const char *progname, const char *filename)
{
  /* If process already running, start tracing */
  uint32_t pid = find_pid_by_name(progname);
  uint32_t minus_one = (uint32_t)(-1);
  if (pid != minus_one) {
    do_tracing(pid,filename);
    return;
  }

  /* Otherwise, start monitoring for process start */
  procname_set(progname); 
  strncpy(tracefile, filename, 256);
  term_printf ("Waiting for process %s to start\n", progname);

#if 0
  /* Print configuration variables */
  print_conf_vars(); 
#endif
}

void do_save_state(uint32_t pid, uint32_t address, const char *filename)
{
  int err;
  err = save_state_at_addr(pid, address, filename);
  if (err)
    term_printf("Invalid pid or unable to open log file '%s'\n", filename);
}

void do_guest_modules(uint32_t pid)
{
  list_guest_modules(pid);
}


void do_clean_iv_eips()
{
  num_loop_ivs = (size_t) 0;
}

#if TAINT_ENABLED
void taint_loop_ivs()
{
    uint64_t mask = 0;
    taint_record_t taintrec[MAX_OPERAND_LEN]; /* taint_rec[] to write */
    int regnum = -1;
    int offset = 0;
    int length = 0;
    int index_itr = 0;
    int i=0;

    if (!bsearch(&(eh.address), &(loop_ivs_sarray[0]), num_loop_ivs,
     sizeof(uint32_t), uint32_compare))
  return;      /* skip if the current eip is not in loop_ivs_sarray[] */

    i = 0;                               /* only care about dest operand */
    if (eh.operand[i].type != TRegister)  /* ignore if it's not register */
  return;                 /* replace with continue; if it's a loop */

    /* get original taint recs */
    //regnum = regmapping[eh.operand[i].addr - 100];
    regnum = get_regnum(eh.operand[i]);
    offset = getOperandOffset(&eh.operand[i]);
    length = eh.operand[i].length;
    taintcheck_register_check(regnum, offset, length,
            (uint8_t *) taintrec);

    term_printf("logic reached\n");
    for (index_itr =0; index_itr < length; ++index_itr) {
  /* we're overwriting any existing taint records in the register */
  /* except loop_iv record from the same eip origin */
  /* in such case, we increment the counter (e.g. offset field) */
  if (taintrec[index_itr].taintBytes[0].source==TAINT_SOURCE_LOOP_IV
      && taintrec[index_itr].taintBytes[0].origin == eh.address) {
      ++(taintrec[index_itr].taintBytes[0].offset);
  } else {
      taintrec[index_itr].taintBytes[0].source =
    TAINT_SOURCE_LOOP_IV;
      taintrec[index_itr].taintBytes[0].origin = eh.address;
      taintrec[index_itr].taintBytes[0].offset = 1;
  }
  taintrec[index_itr].numRecords = 1;
  term_printf("IV tainted is %5s, EIP = 0x%8x, count = %5d\n",
        reg_name_from_id(eh.operand[i].addr),
        eh.address, taintrec[index_itr].taintBytes[0].offset);
    }

    mask = (1ULL<<eh.operand[i].length)-1;
    taintcheck_taint_register(regnum, offset, length, mask,
          (uint8_t *) taintrec);
}
#endif //TAINT_ENABLED

void tracing_insn_begin()
{
  /* If tracing start condition not satisified, or not tracing return */
  if ((!tracing_start_condition) || (tracepid == 0))
    return ;

  /* If not tracing kernel and kernel instruction , return */
  if ( is_kernel_instruction() && !tracing_kernel() )
    return;

  /* Clear flags before processing instruction */

  // Flag to be set if the instruction is written
  insn_already_written = 0;

  // Flag to be set if instruction encounters a page fault
  // NOTE: currently not being used. Tracing uses it to avoid logging twice
  // these instructions, but was missing some
  has_page_fault = 0;

  // Flag to be set if instruction accesses user memory
  access_user_mem = 0;

  /* Call the local hook, if needed */
  if (hook_insn_begin != NULL) {
    uint32_t eip = *TEMU_cpu_eip;
    (*hook_insn_begin)(eip);
  }

  /* Check if this is a system call */
  if (conf_log_external_calls) {
    uint32_t eip = *TEMU_cpu_eip;
    struct names_t *names = query_name(eip);
    uint32_t curr_tid = get_current_tid();
    if ((names != NULL) && (calllog)) {
      if ((names->fun_name != NULL) && (names->mod_name != NULL)) {
	fprintf(calllog,"Process %d TID: %d -> %s::%s @ EIP: 0x%08x\n",
	  tracepid,curr_tid,names->mod_name,names->fun_name,eip);
      }
      else {
	fprintf(calllog,"Process %d TID: %d -> ?::? @ EIP: 0x%08x\n", 
	  tracepid,curr_tid,eip);
      }
    }
  }

  /* Disassemble the instruction */
  if (skip_decode_address == 0) {
    decode_address(*TEMU_cpu_eip, &eh, skip_taint_info);
  }

#if TAINT_ENABLED && defined(TAINT_LOOP_IVS)
  /* If not tracing, skip */
  if (tracepid != 0)
      taint_loop_ivs();
#endif

#ifdef INSN_INFO
  savedeip = *TEMU_cpu_eip;
#endif

}

void tracing_insn_end()
{
  /* If tracing start condition not satisified, or not tracing return */
  if ((!tracing_start_condition) || (tracepid == 0))
    return ;

  /* If not tracing kernel and kernel instruction , return */
  if ( is_kernel_instruction() && !tracing_kernel())
    return;

  /* If partially tracing kernel but did not access user memory, return */
  if (is_kernel_instruction()) {
      if (tracing_kernel_partial() && (!access_user_mem))
	  return;
#if TAINT_ENABLED	  
      if (tracing_kernel_tainted() && (!insn_tainted))
	  return;
#endif	  
  }

  /* If instruction already written, return */
  if (insn_already_written == 1)
    return;

  /* Update the eflags */
  eh.eflags = *TEMU_cpu_eflags;
  eh.df = *TEMU_cpu_df;

  /* Update the thread id */
  eh.tid = current_tid;

  /* Clear eh.tp if inside a function hook */
  if (skip_taint_info > 0) eh.tp = TP_NONE;
  else {
    /* Update eh.tp if rep instruction */
    if ((eh.operand[2].usage == counter) && (eh.operand[2].tainted != 0))
      eh.tp = TP_REP_COUNTER;

    /* Updated eh.tp if sysenter */
    else if ((eh.rawbytes[0] == 0x0f) && (eh.rawbytes[1] == 0x34))
      eh.tp = TP_SYSENTER;
  }

  /* Split written operands if requested */
  if (conf_write_ops_at_insn_end) {
    update_written_operands (&eh);
  }

  /* Write the disassembled instruction to the trace */
  if (tracing_tainted_only()) {
#if TAINT_ENABLED
    if (insn_tainted)
      write_insn(tracelog,&eh);
#endif      
  }
  else {
    if (conf_trace_only_after_first_taint) {
      if ((received_tainted_data == 1) && (has_page_fault == 0)) {
	write_insn(tracelog,&eh);
      }
    }
    else {
      if (has_page_fault == 0) write_insn(tracelog,&eh);
    }
  }

  /* Record the thread ID of the first instruction in the trace, if needed */
  if (tracing_single_thread_only()) {
    if (tid_to_trace == -1 && insn_already_written == 1) {
      // If tid_to_trace is not -1, we record trace only the given thread id.
      tid_to_trace = get_current_tid();
    }
  }

}

int tracing_cjmp(uint32_t t0)
{
  /* No need to set tp in entry header if not tracing */
  if ((!tracing_start_condition) || (tracepid == 0))
    return 0;

  /* No need to set tp in entry header if not 
   * tracing kernel and kernel instruction */
  if ( is_kernel_instruction() && !tracing_kernel() )
    return 0;

  /* Set entry header flag for tainted cjmp */
  eh.tp = TP_CJMP;

  return 0;
}


void set_table_lookup(int state)
{
  if (state) {
    tracing_table_lookup = 1;
    term_printf("Table lookup on.\n");
  }
  else {
    tracing_table_lookup = 0;
    term_printf("Table lookup off.\n");
  }
}


/* Param format
<pid>:<traceFilename>:<detectMask>::<pidToSignal>:<processName>
*/
void tracing_after_loadvm(const char*param)
{
  char buf[256];
  strncpy(buf, param, sizeof(buf) - 1);
  buf[255] = '\0';
  int pid_to_signal = 0;

  char *pid_str = strtok(buf, ":");
  if (!pid_str)
    return;

  char *trace_filename = strtok(0, ":");
  if (!trace_filename)
    return;

  char *detect_mask_str = strtok(0, ":");
  if (!detect_mask_str)
    return;

  char *pid_to_signal_str = strtok(0, ":");

  char *process_name = strtok(0, ":");

  char *end = pid_str;
  int pid = (int) strtol (pid_str, &end, 10);
  if (end == pid_str) {
    pid = -1;
  }

  /* If no PID or Process_name, return */
  if ((process_name == NULL) && (pid == -1)) {
    term_printf("PARAM: %s\n", param);
    term_printf("START: %p END: %p\n", pid_str, end);
    term_printf("No PID or Process_name provided\n");
    return;
  }

  end = detect_mask_str;
  unsigned int detect_mask =
    (unsigned int) strtol (detect_mask_str, &end, 16);
  if (end == detect_mask_str) {
    term_printf("PARAM: %s\n", param);
    term_printf("START: %p END: %p\n", detect_mask_str, end);
    term_printf ("No detect mask provided\n");
    return;
  }

  if (pid_to_signal_str) {
    end = pid_to_signal_str;
    pid_to_signal = (int) strtol (pid_to_signal_str, &end, 10);
    if (end == pid_to_signal_str) {
      pid_to_signal = 0;
    }
  }

  term_printf ("PID: %d MASK: 0x%08x PID2SIGNAL: %d PROCESS_NAME: %s\n",
    pid, detect_mask, pid_to_signal, process_name);

  /* Enable emulation */
  do_enable_emulation();

#if TAINT_ENABLED
  /* Taint the network */
  do_taint_nic(1);

  /* Filter traffic (read from ini configuration file) */
  print_nic_filter();

  /* Enable detection */
  enable_detection(detect_mask);
#endif  


  /* OS dependant initialization */
  if (0 == taskaddr)
    init_kernel_offsets();
  if (0xC0000000 == kernel_mem_start) /* linux */
    update_proc(0);

  /* Load hooks */
  do_load_hooks("","");

  /* Start trace */
  if (process_name == NULL)
    do_tracing(pid, trace_filename);
  else
    do_tracing_by_name(process_name,trace_filename);

  /* Send signal to notify that trace is ready */
  //if (pid_to_signal != 0) kill(pid_to_signal,SIGUSR1);
  int pipe_fd = open("/tmp/temu.pipe",O_WRONLY);
  size_t num_written = write(pipe_fd,"OK",2);
  if (num_written != 2) {
    term_printf ("Error writing to /tmp/temu.pipe\n");
  }
  close(pipe_fd);

}

#ifdef MEM_CHECK
void tracing_mem_read(uint32_t virt_addr, uint32_t phys_addr, int size) {
  int offset = virt_addr - taint_module_base;

  if (taint_module_is_set && 
      virt_addr >= taint_module_base && 
      offset < taint_module_size) {
#if TAINT_ENABLED
    taint_record_t records[MAX_OPERAND_LEN];
    bzero(records, sizeof(records));
    int i;
    for(i=0;i<size;i++) {
      records[i].numRecords = 1;
      records[i].taintBytes[0].source = TAINT_SOURCE_MODULE;
      records[i].taintBytes[0].origin = TAINT_ORIGIN_MODULE;
      records[i].taintBytes[0].offset = offset + i;
    }
    taintcheck_taint_memory(phys_addr, size, (1<<size)-1, (uint8_t*)records);
#endif    
  } else {
    // do nothing
  }
}

void tracing_mem_write(uint32_t virt_addr, uint32_t phys_addr, int size) {
  // do nothing
}
#endif /* #ifdef MEMCHECK */

static term_cmd_t tracing_term_cmds[] = {
  /* operations to set taint source */
#if TAINT_ENABLED  
  {"taint_sendkey", "si", do_taint_sendkey,
   "key id", "send a tainted key to the guest system"},
  {"taint_nic", "i", do_taint_nic,
   "state", "set the network input to be tainted or not"},
  {"taint_file", "sii", do_taint_file,
   "filepath disk_index first_offset", "taint the content of a file on disk"},
   
#ifdef MEM_CHECK
  {"taint_module", "is", do_taint_module,
   "pid module_name", "taint the module on the process memory map"},
#endif /* #ifdef MEM_CHECK */

#endif

  /* operating system information */
  {"guest_ps", "", list_procs,
   "", "list the processes on guest system"},
  {"guest_modules", "i", do_guest_modules,
   "pid", "list the modules of the process with <pid>"},
  {"linux_ps", "", do_linux_ps,
   "", "list the processes on linux guest system"},

#if TAINT_ENABLED
  /* operations for attack detection */
  { "detect", "ss", do_detect,
    "type <on|off>", "turn on/off the detection for the following "
    "type attacks: "
    "tainteip, nullptr, exception, processexit, all. all are off "
    "by default." },
  { "action", "s", do_action,
    "type", "launch one of the following actions after attack detection: "
    "none, terminate(default), stopvm, stoptracing"},
#endif    

  /* operations to record instruction trace */
  { "trace", "iF", do_tracing,
    "pid filepath",
    "save the execution trace of a process into the specified file"},
  { "tracebyname", "sF", do_tracing_by_name,
    "name filepath",
    "save the execution trace of a process into the specified file"},
  { "trace_stop", "", do_tracing_stop,
    "", "stop tracing current process(es)"},
  { "tc_modname", "s", tc_modname,
    "modulename", "start saving execution trace upon entering the "
    "specified module"},
  { "tc_address", "i", tc_address,
    "codeaddress", "start saving execution trace upon reaching the "
    "specified virtual address"},
  { "tc_address_start", "ii", tc_address_start,
    "codeaddress timehit", "start saving execution trace upon reaching "
    "the specified virtual address for the (timehit+1)th times since "
    "the call of this tc_address_start command"},
  { "tc_address_stop", "ii", tc_address_stop,
    "codeaddress timehit", "stop saving execution trace upon reaching the "
    "specified virtual address for the (timehit+1)th times since the "
    "storing of execution trace"},

  /* set taint or tracing filters */
  { "table_lookup", "i", set_table_lookup,
      "state", "set flag to propagate tainted memory index"},
  { "ignore_dns", "i", set_ignore_dns,
      "state", "set flag to ignore received DNS packets"},
#if TAINT_ENABLED      
  { "taint_nic_filter", "ss", (void (*)())update_nic_filter,
      "<clear|proto|sport|dport|src|dst> value", 
      "Update filter for tainting NIC"},
  { "filter_tainted_only", "i", set_tainted_only,
    "state", "set flag to trace only tainted instructions"},
  { "filter_single_thread_only", "i", set_single_thread_only,
    "state", "set flag to trace only instructions from the same thread as the first instruction"},
  { "filter_kernel_tainted", "i", set_kernel_tainted,
    "state", "set flag to trace tainted kernel instructions in addition to "
    "user instructions"},
#endif    
  { "filter_kernel_all", "i", set_kernel_all,
    "state", "set flag to trace all kernel instructions in addition to "
    "user instructions"},
  { "filter_kernel_partial", "i", set_kernel_partial,
    "state", "set flag to trace kernel instructions that modify user "
    "space memory"},

  /* operations to record memory state */
  {"save_state", "iis", do_save_state,
   "pid address filepath",
   "save the state (register and memory) of a process when its execution "
   "hits the specified address "
   "(address needs to be the first address in a basic block)"},

  /* operations for induction variables */
  { "add_iv_eip", "i", do_add_iv_eip,
    "eip", "add a new eip to a list of know induction variable eips"},
  { "clean_iv_eips", "", do_clean_iv_eips,
    "", "clean up a list of induction variable eips"},

  /* operations for hooks */
  { "load_hooks", "FF", do_load_hooks,
    "hooks_dirname  plugins_filepath",
    "change hooks paths (hook directory and plugins.active)"},

  /* load a configuration file */
  { "load_config", "F", do_load_config,
    "configuration_filepath", "load configuration info from given file"},
  
  /* inject fault to process */
  { "inject_fault", "ssi", do_inject_by_name,
    "name faultType number",
    "Inject soft error faults into to specific program. Example : inject_fault foo add 1"},

  /* inject faults to func */
  { "inject_fault2func", "sssi", do_inject_by_name_and_func,
    "name faultType funcname, number",
    "Inject soft error faults into to specific program. Example : inject_fault foo addfunc add 1"},
  
  /* load a SEFI bitflip configuration file */
  { "load_SEFI_config", "F", do_load_SEFI_config,
    "configuration_filepath", "SEFI load configuration info from given file"},
 
  /* profile the application to collect OPS */
  { "profile", "s", do_profile_by_name,
    "programName", "SEFI operation profile"},
  
  /* profile the subroutine in application to collect OPS */
  { "profile2func", "ss", do_profile_by_name_and_func,
    "programName func", "SEFI operation profile "},

  /* Send the command to execute to Guest */
  { "cmd2guest", "s", do_cmd2guest,
    "commandline", "Send the commands to execute in guest"},
  /* Send batch commands */
  { "batch_run", "b", do_batch_cmd, "batch_comd", "-a progname -t faulttype  -f funcname -m MaxNumOfDIC, -n faultnumber -r repeatnumber -o outputname"},
   
  { "get_output", "s", do_get_file, "filename", "copy file from guest"},
  /* load func table */
  /*
  { "load_func", "", do_load_func,
    "",
    "Load func table"},
  */

  {NULL, NULL},
};




plugin_interface_t * init_plugin()
{
  if (0x80000000 == kernel_mem_start)
    comparestring = strcasecmp;
  else
    comparestring = strcmp;

  tracing_interface.plugin_cleanup = tracing_cleanup;
#if TAINT_ENABLED  
  tracing_interface.taint_record_size = sizeof(taint_record_t);
  tracing_interface.taint_propagate = tracing_taint_propagate;
  tracing_interface.taint_disk = tracing_taint_disk;
  tracing_interface.eip_tainted = tainteip_detection;
  tracing_interface.cjmp = tracing_cjmp;
  tracing_interface.nic_recv = tracing_nic_recv;
  tracing_interface.nic_send = tracing_nic_send;
  tracing_interface.send_keystroke = tracing_send_keystroke;
#endif  

  tracing_interface.guest_message = tracing_guest_message;
  tracing_interface.block_begin = tracing_block_begin;
  tracing_interface.insn_begin = tracing_insn_begin;
  tracing_interface.insn_end = tracing_insn_end;
  tracing_interface.term_cmds = tracing_term_cmds;
  tracing_interface.info_cmds = tracing_info_cmds;
  tracing_interface.bdrv_open = tracing_bdrv_open;
  tracing_interface.after_loadvm = tracing_after_loadvm;
#ifdef MEM_CHECK
  tracing_interface.mem_read = tracing_mem_read;
  tracing_interface.mem_write = tracing_mem_write;
#endif /* #ifdef MEM_CHECK */
  removeproc_notify = procexit_detection;

  tracing_init ();
  return &tracing_interface;
}

/* helper function */
/* check local ouput to make sure the success of target operation */
int check_local_output(char *file_path){
  struct stat sb;
  
  if(stat(file_path, &sb) == -1){
    term_printf("Error in acquiring %s (errno : %d) \n", file_path, errno);
    return 1;
  }
  term_printf("Done!\n");
  return 0;

}

/* helper function */
/* remove the older output file */
int remove_output(char *file_path){
  if(remove(file_path) != 0){
    return 1;
  }

  return 0;
}



