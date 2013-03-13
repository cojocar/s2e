/*
 * ARM Versatile Platform/Application Baseboard System emulation.
 *
 * Copyright (c) 2005-2007 CodeSourcery.
 * Written by Paul Brook
 *
 * This code is licensed under the GPL.
 */

// #include "sysbus.h"
// #include "arm-misc.h"
// #include "devices.h"
// #include "net.h"
// #include "sysemu.h"
// #include "pci.h"
// #include "i2c.h"
// #include "boards.h"
// #include "blockdev.h"
// #include "flash.h"
// #include "elf.h"
// #include "qjson.h"
// #include "qlist.h"
// #include "exec-memory.h"
#include "sysbus.h"
#include "devices.h"
#include "boards.h"
#include "qjson.h"
#include "qobject.h"
#include "qint.h"
#include "exec-memory.h"

/* Board init.  */

/* The AB and PB boards both use the same core, just with different
   peripherals and expansion busses.  For now we emulate a subset of the
   PB peripherals and just change the board ID.  */

// static struct arm_boot_info versatile_binfo;

static QDict * load_configuration(const char * filename)
{
    int file = open(filename, O_RDONLY);
    off_t filesize = lseek(file, 0, SEEK_END);
    char * filedata = NULL;
    ssize_t err;
    QObject * obj;
    
    lseek(file, 0, SEEK_SET);
    
    filedata = g_malloc(filesize);
    
    if (!filedata)
    {
        fprintf(stderr, "Out of memory\n");
        exit(1);
    }
    
    err = read(file, filedata, filesize);
    
    if (err != filesize)
    {
        fprintf(stderr, "Reading configuration file failed\n");
        exit(1);
    }
    
    close(file);
    
    obj = qobject_from_jsonv(filedata, NULL);
    
    if (!obj || qobject_type(obj) != QTYPE_QDICT)
    {
        fprintf(stderr, "Error parsing JSON configuration file\n");
        exit(1);
    }
    
    g_free(filedata);
    
    return qobject_to_qdict(obj);
}

/** 
 * Return how many characters of the string are part of the directory path, or 0 if the file is specified without directory.
 */
static int get_dirname_len(const char * filename)
{
    int i;
    
    for (i = strlen(filename) - 1; i >= 0; i--)
    {
        //FIXME: This is only Linux-compatible ...
        if (filename[i] == '/')
        {
            return i + 1;
        }   
    }
    
    return 0;
}

static int is_absolute_path(const char * filename)
{
    return filename[0] == '/';
}

static void board_init(ram_addr_t ram_size,
                     const char *boot_device,
                     const char *kernel_filename, const char *kernel_cmdline,
                     const char *initrd_filename, const char *cpu_model)
{
    CPUArchState * cpu;
    QDict * conf = NULL;
    uint64_t entry_address;
    
    //Load configuration file
    if (kernel_filename)
    {
        conf = load_configuration(kernel_filename);
    }
    else
    {
        conf = qdict_new();
    }
    
    //Configure CPU
    if (qdict_haskey(conf, "cpu_model"))
    {
        cpu_model = qdict_get_str(conf, "cpu_model");
        g_assert(cpu_model);
    }
    
#ifdef TARGET_ARM
    if (!cpu_model) cpu_model = "arm926";
#endif
    
    printf("Configurable: Adding processor %s\n", cpu_model);
    
    cpu = cpu_init(cpu_model);
    
    if (!cpu)
    {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(1);
    }
    
#ifdef CONFIG_S2E
    s2e_register_cpu(g_s2e, g_s2e_state, cpu);
#endif
    
    //Configure memory
    if (qdict_haskey(conf, "memory_map"))
    {
        QListEntry * entry;
        QList * memory_map = qobject_to_qlist(qdict_get(conf, "memory_map"));
        g_assert(memory_map);
        MemoryRegion *sysmem = get_system_memory();
        
        QLIST_FOREACH_ENTRY(memory_map, entry)
        {
            QDict * mapping;
            QList * addresses;
            QListEntry * address_entry;
            uint64_t size;
            uint64_t data_size;
            char * data = NULL;
            const char * name;
            MemoryRegion * ram;
            int is_rom = FALSE; //TODO: Currently ignored, only RAM is used
            uint64_t address;
            
            g_assert(qobject_type(entry->value) == QTYPE_QDICT);
            mapping = qobject_to_qdict(entry->value);
            
            g_assert(qdict_haskey(mapping, "map") && qobject_type(qdict_get(mapping, "map")) == QTYPE_QLIST && !qlist_empty(qobject_to_qlist(qdict_get(mapping, "map"))));
            g_assert(qdict_haskey(mapping, "name") && qobject_type(qdict_get(mapping, "name")) == QTYPE_QSTRING);
            g_assert(!qdict_haskey(mapping, "is_rom") || qobject_type(qdict_get(mapping, "is_rom")) == QTYPE_QBOOL);
            g_assert(qdict_haskey(mapping, "size") && qobject_type(qdict_get(mapping, "size")) == QTYPE_QINT);
            
            addresses = qobject_to_qlist(qdict_get(mapping, "map"));
            name = qdict_get_str(mapping, "name");
            is_rom = qdict_haskey(mapping, "is_rom") && qdict_get_bool(mapping, "is_rom");
            size = qdict_get_int(mapping, "size");
            
            ram =  g_new(MemoryRegion, 1);
            g_assert(ram);
            
            //TODO: If is ROM, insert ROM here instead of RAM
            memory_region_init_ram(ram, name, size);
            
            QLIST_FOREACH_ENTRY(addresses, address_entry)
            {
                g_assert(qobject_type(address_entry->value) == QTYPE_QINT);
                
                address = qint_get_int(qobject_to_qint(address_entry->value));
                
                printf("Configurable: Adding memory region %s (size: 0x%lx) at address 0x%lx\n", name, size, address);
                memory_region_add_subregion(sysmem, address, ram);
                
#ifdef CONFIG_S2E
            s2e_register_ram(g_s2e, g_s2e_state,
                  address, size,
                  (uint64_t) memory_region_get_ram_ptr(ram), 0, 0, name);
#endif
            }

            if (qdict_haskey(mapping, "file"))
            {
                int file;
                const char * filename;
                int dirname_len = get_dirname_len(kernel_filename);
                ssize_t err;
                
                printf("kernel filename: '%s' (%d)\n", kernel_filename, dirname_len);
                g_assert(qobject_type(qdict_get(mapping, "file")) == QTYPE_QSTRING);
                filename = qdict_get_str(mapping, "file");
                
                if (!is_absolute_path(filename))
                {
                    char * relative_filename = g_malloc0(dirname_len + strlen(filename) + 1);
                    g_assert(relative_filename);
                    strncpy(relative_filename, kernel_filename, dirname_len);
                    strcat(relative_filename, filename);
                    
                    printf("Reading relative file: %s\n", relative_filename);
                    file = open(relative_filename, O_RDONLY | O_BINARY);
                    g_free(relative_filename);
                }
                else
                {
                    file = open(filename, O_RDONLY | O_BINARY);
                }
                
                data_size = lseek(file, 0, SEEK_END);
                lseek(file, 0, SEEK_SET);
                
                g_assert(data_size <= size); //Size of data to put into a RAM region needs to fit in the RAM region
                
                printf("Size is: %ld\n", size);
                
                data = g_malloc(size);
                g_assert(data);
                
                err = read(file, data, data_size);
                g_assert(err == data_size); 
                
                close(file);
                
                //And copy the data to the memory, if it is initialized
                cpu_memory_rw_debug(cpu, address, (uint8_t *) data, data_size, TRUE);
            }  
            
        }
    }
    
    //Set PC to entry point
    g_assert(qdict_haskey(conf, "entry_address"));
    g_assert(qobject_type(qdict_get(conf, "entry_address")) == QTYPE_QINT);
    entry_address = qdict_get_int(conf, "entry_address");
    
#ifdef TARGET_ARM
    ((CPUARMState *) cpu)->thumb = (entry_address & 1) != 0 ? 1 : 0;
    ((CPUARMState *) cpu)->regs[15] = entry_address & (~1);
#elif TARGET_I386
    ((CPUX86State *) cpu)->eip = entry_address;
#endif
        
        
/*    ARMCPU *cpu;
    uint32_t entry = 0;

    if (!args->cpu_model) {
        args->cpu_model = "arm926";
    }
    cpu = cpu_arm_init(args->cpu_model);
    if (!cpu) {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(1);
    }
    
    //Get memory map from ELF file
    {
        Elf32_Ehdr ehdr;
        Elf32_Phdr phdr;
        Elf32_Shdr shdr;
        MemoryRegion *sysmem = get_system_memory();
        MemoryRegion *ram;
        QObject * list_obj;
        
        int fd;
        int i;
        
        fd = open(args->kernel_filename, O_RDONLY | O_BINARY);
        if (fd < 0) {
            fprintf(stderr, "Failed to open kernel file '%s'\n", args->kernel_filename);
            exit(1);
        }
        
        if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr))
        {
            fprintf(stderr, "Failed to load ELF header from file '%s'\n", args->kernel_filename);
            exit(1);
        }
        
        entry = ehdr.e_entry;
        
        if (lseek(fd, ehdr.e_phoff, SEEK_SET) != ehdr.e_phoff)
        {
            fprintf(stderr, "Failed to seek to program headers\n");
            exit(1);
        }
        
        for(i = 0; i < ehdr.e_phnum; i++) 
        {
            if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr))
            {
                fprintf(stderr, "Failed to load program header %d at offset 0x%lx\n", i, ehdr.e_phoff + i * sizeof(phdr));
                exit(1);
            }
            
            if (phdr.p_type == PT_LOAD)
            {
                uint32_t addr = phdr.p_vaddr;
                uint32_t size = phdr.p_memsz;
                bool is_rom = !(phdr.p_flags & PF_W);
                char label[50];
                
                snprintf(label, sizeof(label),  "phdr %d ram", i);
//                printf("Adding memory region 0x%x - 0x%x%s    %s\n", addr, addr + size, (is_rom ? " (ROM)" : ""), label);
                ram =  g_new(MemoryRegion, 1);
                memory_region_init_ram(ram, label, size);
                memory_region_add_subregion(sysmem, addr, ram);
            }
        } 
        
        if (lseek(fd, ehdr.e_shoff, SEEK_SET) != ehdr.e_shoff)
        {
            fprintf(stderr, "Failed to seek to section headers\n");
            exit(1);
        }
        
        for(i = 0; i < ehdr.e_shnum; i++) 
        {
            if (read(fd, &shdr, sizeof(shdr)) != sizeof(shdr))
            {
                fprintf(stderr, "Failed to load section header %d at offset 0x%lx\n", i, ehdr.e_shoff + i * sizeof(shdr));
                exit(1);
            }
            
            if (shdr.sh_type == SHT_NOBITS)
            {
                uint32_t addr = shdr.sh_addr;
                uint32_t size = shdr.sh_size;
                char label[50];
                
                snprintf(label, sizeof(label),  "shdr %d ram", i);
//                printf("Adding memory region 0x%x - 0x%x    %s\n", addr, addr + size, label);
                ram =  g_new(MemoryRegion, 1);
                memory_region_init_ram(ram, label, size);
                memory_region_add_subregion(sysmem, addr, ram);
            }
        } 
        
        list_obj = qobject_from_json(args->kernel_cmdline);
        
        if (list_obj && qobject_type(list_obj) == QTYPE_QLIST)
        {
            QListEntry * entry;
            QList * list = qobject_to_qlist(list_obj);
            int num_entry = 0;
            QLIST_FOREACH_ENTRY(list, entry)
            {
                QObject * dict_obj = qlist_entry_obj(entry);
                if (dict_obj && qobject_type(dict_obj) == QTYPE_QDICT)
                {
                    QDict * dict = qobject_to_qdict(dict_obj);
                    uint32_t addr = qdict_get_int(dict, "addr");
                    uint32_t size = qdict_get_int(dict, "size");
                    char label[50];
                
                    snprintf(label, sizeof(label),  "user %d ram", num_entry++);
//                    printf("Adding memory region 0x%x - 0x%x    %s\n", addr, addr + size, label);
                    ram =  g_new(MemoryRegion, 1);
                    memory_region_init_ram(ram, label, size);
                    memory_region_add_subregion(sysmem, addr, ram);
                }
            }
        }

        //We definitely need the first 40 bytes of RAM for the interrupt table
        ram =  g_new(MemoryRegion, 1);
        memory_region_init_ram(ram,  "exception_handlers", 0x40);
        memory_region_add_subregion(sysmem, 0x0, ram);
    }
    
    

    versatile_binfo.ram_size = 128 * 1024 * 1024;
    versatile_binfo.kernel_filename = args->kernel_filename;
    versatile_binfo.kernel_cmdline = args->kernel_cmdline;
    versatile_binfo.initrd_filename = args->initrd_filename;
//    versatile_binfo.board_id = 0x183; // Don't know what this does, but if I set it to 0 there is a segfault 
//     arm_load_kernel(cpu, &versatile_binfo);
//     
// //    printf("Setting PC to entry address 0x%x\n", entry);
//     cpu->env.regs[15] = entry;  
    */  
}

static QEMUMachine configurable_machine = {
    .name = "configurable",
    .desc = "Machine that can be configured to be whatever you want",
    .init = board_init,
};

static void configurable_machine_init(void)
{
    qemu_register_machine(&configurable_machine);
}

machine_init(configurable_machine_init);
