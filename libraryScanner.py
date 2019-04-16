import os,sys
import pefile
import sys
import ctypes
import pydasm
import struct
from socket import *

from pydbg import *
from pydbg.defines import *
import utils
begin=None
end=None


############################################################################
def hook_function_by_name(dbg,dll_name,function_name,handler):
    #in this function, we add a hook to the connect() function:
    hooks   = utils.hook_container()
    #this is the address of the pointer to the target function
    #this address lies in IAT
    #(that means, when we get the address of target function in IAT
    #that is actually the address of the function pointer to the target function
    #so we need to find out the address pointed by this FUNCTION POINTER.)
    pointer_address = "%08x"%import_table[dll_name][function_name]
    #pointer_address = "%08x"%import_table["USER32.dll"]["GetMessageW"]
    #pointer_address_hex = pointer_address.encode('hex')
    pointer_address_hex = int(pointer_address, 16)
    #print "connect lies at " + pointer_address
    #print "pointer_address_hex is: %08x" % pointer_address_hex
    target_function_address = dbg.read_process_memory(pointer_address_hex,4)
    #print "target_function_address is "+target_function_address
    #print int(target_function_address,16)
    target_function_address_hex_str = ""
    for i in range(0,len(target_function_address)):
        #target_function_address_hex_str+=str(ord(target_function_address[i]))
        target_function_address_hex_str += "%02x" % ord(target_function_address[len(target_function_address)-i-1])

    target_function_address_hex = int(target_function_address_hex_str,16)

    print "the target_function_address_hex is :%08x"%target_function_address_hex



    #target_function_address_hex = int(target_function_address,16)
    #print "the pointer points to: %08x" % target_function_address_hex
    instruction = dbg.disasm(pointer_address_hex)
    #print "eip--> "+str(instruction)


    #hooks.add(dbg,target_function_address_hex,3,handler_hook_connect,None)
    hooks.add(dbg,target_function_address_hex,3,handler,None)
    #abc = 2222
    #print "abc"+abc
############################################################
def add_dst_port(port):
    #send the message informing the sniffer to add port to the port list
    command = "T debugger add dst port:%05d" % port
    sh = command.encode("utf-8")
    s.send(sh)
#########################################################################
def handler_hook_bind(dbg,args):
    dbg.my_hook_counter= dbg.my_hook_counter+1
    print "hook_bind!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    print "hook counter: "+ str(dbg.my_hook_counter)
    print "thread counter: "+str(dbg.my_thread_counter)

    return_address = dbg.get_arg(index=0)
    socket = dbg.get_arg(index=1)
    pointer_sockaddr = dbg.get_arg(index=2)
    port_str = dbg.read_process_memory(pointer_sockaddr+2,2)
    ip_str = dbg.read_process_memory(pointer_sockaddr+4,4)


    real_port_str=""
    for i in range(0,len(port_str)):
        #target_function_address_hex_str+=str(ord(target_function_address[i]))
        real_port_str += "%02x" % ord(port_str[i])
    print "the port string is: "+real_port_str

    real_ip_str = ""

    for i in range(0,len(ip_str)):
        #target_function_address_hex_str+=str(ord(target_function_address[i]))
        real_ip_str += "%02x" % ord(ip_str[i])
    real_ip_int = int(real_ip_str,16)
    print inet_ntoa(struct.pack("!I",real_ip_int))

    #this should be the correct port
    print "the port int is: "+str(int(real_port_str,16)) 

#########################################################################
def handler_hook_connect(dbg,args):
    #this is the entry handler for the hook in connect()

    '''
    return_address = dbg.get_arg(index=0)
    socket = dbg.get_arg(index=1)

    pointer_sockaddr = dbg.get_arg(index=2)
    port_str = dbg.read_process_memory(pointer_sockaddr+2,2)
    real_port_str=""
    for i in range(0,len(port_str)):
        #target_function_address_hex_str+=str(ord(target_function_address[i]))
        real_port_str += "%02x" % ord(port_str[i])
    print "the port string is: "+real_port_str
    print "the port int is: "+str(int(real_port_str,16))

    namelen = dbg.get_arg(index=3)

    print "caller EIP--> %08x" % dbg.context.Eip

    print "return address is: %08x"%return_address
    '''

    dbg.my_hook_counter= dbg.my_hook_counter+1
    print "hook_connect!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    print "hook counter: "+ str(dbg.my_hook_counter)
    print "thread counter: "+str(dbg.my_thread_counter)

    #hook_function_by_name(dbg,"WS2_32.dll","WSASend")
    #hook_function_by_name(dbg,"WS2_32.dll","WSASendTo")
    #hook_function_by_name(dbg,"WS2_32.dll","sendto")
    #hook_function_by_name(dbg,"WS2_32.dll","sendto")

    return_address = dbg.get_arg(index=0)
    socket = dbg.get_arg(index=1)

    pointer_sockaddr = dbg.get_arg(index=2)
    #the port number lies in the sa_data in sock_addr,
    #sa_data has an offset 2 in sock_addr
    #and the port has an offset 2 in sa_data
    #so, this is the way we access the port number
    port_str = dbg.read_process_memory(pointer_sockaddr+2,2)
    ip_str = dbg.read_process_memory(pointer_sockaddr+4,4)

    real_port_str=""
    for i in range(0,len(port_str)):
        #target_function_address_hex_str+=str(ord(target_function_address[i]))
        real_port_str += "%02x" % ord(port_str[i])
    print "the port string is: "+real_port_str

    real_ip_str = ""

    for i in range(0,len(ip_str)):
        #target_function_address_hex_str+=str(ord(target_function_address[i]))
        real_ip_str += "%02x" % ord(ip_str[i])
    real_ip_int = int(real_ip_str,16)
    print inet_ntoa(struct.pack("!I",real_ip_int))

    #this should be the correct port
    print "the port int is: "+str(int(real_port_str,16))

    add_dst_port(int(real_port_str,16))



    dbg.single_step(True)
    #hook_function_by_name(dbg,"USER32.dll","DispatchMessageW")


    return  DBG_CONTINUE




########################################################################################################################
def get_export_function_list(dll_name):
    path = "C:\\windows\\system32"
    filename = path+"\\"+dll_name
    d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    try:
        pe = pefile.PE(filename, fast_load=True)
    except:
        print "failed to open dll"
        return []
    pe.parse_data_directories(directories=d)

    print "# %s exports for 'Ordinals to Names' Hopper Script" % os.path.basename(filename)
    print "# Ordinal        Name"
    
    export_function_list = []
    if hasattr(pe,"DIRECTORY_ENTRY_EXPORT"):
        print type(pe.DIRECTORY_ENTRY_EXPORT)
        exports = [(e.ordinal, e.name) for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]
        #export_function_list = []
        for export in sorted(exports):
        #print "%-4d %s" % export
	    print export[1]
            export_function_list.append(export[1])
        return export_function_list 

    else:
        return export_function_list


###################################################################################################################
def on_entry_point(dbg):
    update_function_table(dbg)
    print "the send in WS2_32.dll is at:"
    #print "%08x"%import_table["WS2_32.dll"]["send"]
    hook_function_by_name(dbg,"WS2_32.dll","connect",handler_hook_connect)
    hook_function_by_name(dbg,"WS2_32.dll","bind",handler_hook_bind)
    #hook_function_by_name(dbg,"WS2_32.dll","WSAConnect")
    #hook_function_by_name(dbg,"WS2_32.dll","WSASend")
    #hook_function_by_name(dbg,"WS2_32.dll","WSASendTo")
    #hook_function_by_name(dbg,"WS2_32.dll","sendto")
    #hook_function_by_name(dbg,"WS2_32.dll","sendto")
    #hook_function_by_name(dbg,"USER32.dll","DispatchMessageW")


###################################################################################################################
def on_instruction(dbg,instruction):
    #when step over an instruction,call this function
    address = instructions[i][0]
    asm_instruction = str(instructions[i][1])
    #that is, we encounter a call command
    if asm_instruction.find("call")>=0:
        on_call(dbg,address,asm_instruction)



###################################################################################################################
def on_call(dbg,address,asm_instruction):
    #now it is a address or register without "[" or "]"
    callee = asm_instruction.replace('[','').replace(']','').replace('call ','')
    #if callee.lower() in ["eax","ebx","ecx","edx","ebp","esp","esi","edi"]:
        #pass
    #that means the address belong to a known function
    #elif callee in address_table_hex_str:


###################################################################################################################
def on_library_load(dbg,address):
    pass
###################################################################################################################
def handler_breakpoint (dbg):
    #global begin, end
    #print "breakpoint hit!!! at: " +str(hex(dbg.context.Eip))


    for module in dbg.iterate_modules():
        if module.szModule.lower().endswith(".exe"):
            begin = module.modBaseAddr
            end   = module.modBaseAddr + module.modBaseSize
            print "%s %08x -> %08x" % (module.szModule, begin, end)



        for tid in dbg.enumerate_threads():
            #print "    % 4d -> setting single step" % tid
            handle = dbg.open_thread(tid)
            #dbg.single_step(True, handle)
            dbg.close_handle(handle)
    
    if dbg.context.Eip == entry_addr:
        on_entry_point(dbg)
        dbg.single_step(True)


    #dbg.single_step(True)
    #new_context = user_operate(dbg)
    return DBG_CONTINUE
###################################################################################################################
def handler_single_step (dbg):
    global begin, end
    hook_function_by_name(dbg,"WS2_32.dll","connect",handler_hook_connect)
    hook_function_by_name(dbg,"WS2_32.dll","bind",handler_hook_bind)
    #hook_function_by_name(dbg,"WS2_32.dll","WSAConnect")
    #hook_function_by_name(dbg,"WS2_32.dll","WSASend")
    #hook_function_by_name(dbg,"WS2_32.dll","WSASendTo")
    #hook_function_by_name(dbg,"WS2_32.dll","sendto")
    #hook_function_by_name(dbg,"WS2_32.dll","sendto")
    lines_display = 0
    instructions = dbg.disasm_around(dbg.context.Eip,num_inst=lines_display)
    for i in range(0,2*lines_display+1):
        if i==lines_display:
            #print "EIP-->:"+str(hex(int(instructions[i][0])))+"    "+str(instructions[i][1])+"\n"
            if str(instructions[i][1]).find("call [")>=0:
                callee_addr= instructions[i][1].replace('[','').replace(']','').replace('call ','')
                #print callee_addr
                if callee_addr in address_table_hex_str:
                    pass
                   #print "EIP-->:"+str(hex(int(instructions[i][0])))+"    "+str(instructions[i][1])+"  "+str(address_table_hex_str[callee_addr])+"\n"
            #elif str(instructions[i][1]).find("call")>=0 :
                #print str(instructions[i][1])
                #print "EIP-->:"+str(hex(int(instructions[i][0])))+"    "+str(instructions[i][1])+"  "+str(address_table_hex_str[callee_addr])+"\n"
                #pass
            elif str(instructions[i][1]).find("call")>=0:
                #print str(instructions[i][1])
                pass
                #print "EIP-->:"+str(hex(int(instructions[i][0])))+"    "+str(instructions[i][1])+"\n"
            #pass
        else:
            #print "       "+str(hex(int(instructions[i][0])))+"    "+str(instructions[i][1])+"\n"
            pass

    #dbg.single_step(True)

    return DBG_CONTINUE
##################################################################################################################
def user_operate(dbg):
    lines_display = 5
    instructions = dbg.disasm_around(dbg.context.Eip,num_inst=lines_display)
    for i in range(0,2*lines_display+1):
        if i==lines_display:
            print "EIP-->:"+str(hex(int(instructions[i][0])))+"    "+str(instructions[i][1])+"\n"
            if str(instructions[i][1]).find("call")>=0:
                #print "EIP-->:"+str(hex(int(instructions[i][0])))+"    "+str(instructions[i][1])+"\n"
                pass
            #pass
        else:
            #print "       "+str(hex(int(instructions[i][0])))+"    "+str(instructions[i][1])+"\n"
            pass
    #print "current instruction: "+str(instructions)
    #print "EIP:"+str(dbg.context.Eip)+" CS:"+str(dbg.context.SegCs)+"\n"
    #print "ESP:"+str(dbg.context.Esp)+" SS:"+str(dbg.context.SegSs)+"\n"
    #print "EIP: %016x" % (dbg.context.Eip)+"        "+"ESP:%016x" %(dbg.context.Esp)
    #print "EAX: %016x" % (dbg.context.Eax)+"        "+"EBX:%016x" %(dbg.context.Ebx)
    #print "ECX: %016x" % (dbg.context.Ecx)+"        "+"Edx:%016x" %(dbg.context.Edx)
    #print "ESI: %016x" % (dbg.context.Esi)+"        "+"EDI:%016x" %(dbg.context.Edi)
    #print "EIP: %016x" % (dbg.context.Eip)+"        "+"ESP:%016x" %(dbg.context.Esp)
    #command = raw_input("Enter your command \n")
    return dbg.context
###################################################################################################################
def handler_new_thread (dbg):
    print "thread created"
    print "EIP: "+str(hex(dbg.context.Eip))
    #print "exception_address: "+str(hex(dbg.exception_address))
    #dbg.single_step(True)
    #print "handler_new_thread return"
    #dbg.bp_set(entry_addr)
    #hook_function_by_name(dbg,"WS2_32.dll","WSASend")
    #hook_function_by_name(dbg,"WS2_32.dll","WSASendTo")
    #hook_function_by_name(dbg,"WS2_32.dll","sendto")
    #hook_function_by_name(dbg,"WS2_32.dll","sendto")
    hook_function_by_name(dbg,"WS2_32.dll","connect",handler_hook_connect)
    hook_function_by_name(dbg,"WS2_32.dll","bind",handler_hook_bind)
    dbg.my_thread_counter=dbg.my_thread_counter+1
    #hook_function_by_name(dbg,"USER32.dll","DispatchMessageW")
    for module in dbg.iterate_modules():
        #print "module name is: "+str(module.szModule.lower())
        if module.szModule.lower().endswith(".exe"):
            begin = module.modBaseAddr
            end   = module.modBaseAddr + module.modBaseSize
            print "%s %08x -> %08x" % (module.szModule, begin, end)
    return DBG_CONTINUE
################################################################################
def event_handler_create_process (dbg):
    '''
    This is the default CREATE_PROCESS_DEBUG_EVENT handler.

    @rtype:  DWORD
    @return: Debug event continue status.
    '''

    #dbg.single_step(True)

    dbg._log("event_handler_create_process()")
    print "process created"
    #hook_function_by_name(dbg,"WS2_32.dll","send")
    dbg.bp_set(entry_addr)
    #dbg.bp_set(0x100739D)
    print "EIP: "+str(hex(dbg.context.Eip))
    print "exception_address: "+str(hex(dbg.exception_address))

    # don't need this.
    dbg.close_handle(dbg.dbg.u.CreateProcessInfo.hFile)

    if not dbg.follow_forks:
        return DBG_CONTINUE

    if dbg.callbacks.has_key(CREATE_PROCESS_DEBUG_EVENT):
        #return dbg.callbacks[CREATE_PROCESS_DEBUG_EVENT](dbg)
        pass
    else:
        return DBG_CONTINUE
    return DBG_CONTINUE
###################################################################################################################
def set_entry(pe):
    print "[entry]"
    print "#"*45
 
    off_entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    base_entry = pe.OPTIONAL_HEADER.ImageBase
    print "entry point offset: "+ "%10x" % off_entry
    print "entry point base: "+ "%10x" % base_entry
    print "entry point : "+ "%08x" % (base_entry+off_entry)
    entry_addr = base_entry+off_entry
    return entry_addr
    #show_disasm(pe, off_entry, 100)

###################################################################################################################
def show_disasm(pe, off_img, count):
    print "[disasm %08x - %08x]" % (off_img, off_img + count)
    print "-"*45
    image_base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.get_memory_mapped_image()[off_img:off_img+count]
    offset = 0
    while offset < len(data):
        i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
        raw = ""
        for k in range(0,i.length):
            raw += "%2X " % (struct.unpack("B", data[offset+k])[0])
        print "%25s   %-20s" % ( raw, pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, image_base+off_img))
        offset += i.length
     
###################################################################################################################
def show_imports(pe):
    pe.parse_data_directories()
 
    print "[imports:]"
    print "#"*45
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print "%s" % entry.dll.center(45, "-")
        #print type(entry.dll)
        print "%10s %30s" % ("addr", "function")
        print "-"*45
        for imp in entry.imports:
            print "%10x %30s" % (imp.address, imp.name)
            pass
    #print "\n"
###################################################################################################################
def record_functions(pe):
    print "[imports:]"
    print "#"*45
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print "%s" % entry.dll.center(45, "-")
        import_table[entry.dll]=dict()
        #print type(entry.dll)
        print "%10s %30s" % ("addr", "function")
        print "-"*45
        for imp in entry.imports:
            print "%010x %30s" % (imp.address, imp.name)
            #print type(imp.name)
            import_table[entry.dll][imp.name] = imp.address
            address_table[imp.address] = (entry.dll,imp.name)
            address_table_hex_str[str(hex(imp.address))] = (entry.dll,imp.name)
            #pass
    print "\n"
###################################################################################################################
#not finished
def update_module_table(dbg):
    for module in dbg.iterate_modules():
        if module.szModule.lower().endswith(".exe"):
            begin = module.modBaseAddr
            end   = module.modBaseAddr + module.modBaseSize
            print "%s %08x -> %08x" % (module.szModule, begin, end)
###################################################################################################################
def update_function_table(dbg):
    #now I just clean the address table, we may have a better strategy,
    #but it works...for now
    address_table = dict()
    address_table_str_hex = dict()
    GetModuleHandle = windll.kernel32.GetModuleHandleA
    GetProcAddress =windll.kernel32.GetProcAddress
    GetModuleHandle.argtypes = [c_char_p]
    GetModuleHandle.restype = c_int 
    GetProcAddress.argtypes=[c_int,c_char_p]
    GetProcAddress.restype = c_int
    '''
    for module in import_table:
        for function in import_table[module]:
            print "processing "+str(function)+" in "+str(module)
            module_handle = GetModuleHandle("kernel32.dll")
            function_addr = GetProcAddress(GetModuleHandle("kernel32.dll"),function)
            print hex(function_addr)
            #now we update import_table
            import_table[module][function]=function_addr
            #and now address table
            address_table[function_addr] = (module,function)
            address_table_hex_str[str(hex(function_addr))] = (module,function)
    '''
    for module in dbg.iterate_modules():
        print "now processing module: "+module.szModule.lower()
        if module.szModule.lower().find(".exe")<0:
            print module.szModule.lower();
            export_function_list = get_export_function_list(module.szModule.lower())
            for function in export_function_list:
                function_addr = GetProcAddress(GetModuleHandle(module.szModule.lower()),function)
                #now update import table
                if module.szModule.lower() not in import_table:
                    import_table[module.szModule.lower()] = dict()
                import_table[module.szModule.lower()][function] = function_addr
                #now update address table
                address_table[function_addr] = (module.szModule.lower(),function)
                address_table_hex_str[str(hex(function_addr))] = (module.szModule.lower(),function)


###################################################################################################################
###########################################################################
def my_event_handler_exit_process(dbg):
    print "exit process"
    #print "my pid is: "+str(dbg.my_pid)
    #print "EIP: %08x" % (dbg.context.Eip)+"        "+"ESP:%08x" %(dbg.context.Esp)
    disasm    = dbg.disasm(dbg.context.Eip)
    print "%08x: %s" % (dbg.context.Eip, dbg.disasm(dbg.context.Eip))
    dbg.set_debugger_active(True)
    #dbg.my_on_run=True
    handler_single_step(dbg)
    #dbg.attach(dbg.my_pid)


s = socket(AF_INET,SOCK_DGRAM)  
HOST = '8.8.8.8'  
PORT = 65501
#s.bind((HOST,PORT))    
s.connect((HOST,PORT))

dbg = pydbg()

dbg.set_callback(EXCEPTION_BREAKPOINT,      handler_breakpoint)
dbg.set_callback(EXCEPTION_SINGLE_STEP,     handler_single_step)
dbg.set_callback(CREATE_THREAD_DEBUG_EVENT, handler_new_thread)
dbg.set_callback(EXIT_PROCESS_DEBUG_EVENT,my_event_handler_exit_process)
dbg.set_callback(CREATE_PROCESS_DEBUG_EVENT,event_handler_create_process)
#dbg.set_callback(EXCEPTION_DEBUG_EVENT,handler_exception)
#dbg.set_callback(LOAD_DLL_DEBUG_EVENT,handler_load_dll)

#dbg.attach(pid)
#filename = "C:\\Windows\\System32\\notepad.exe"
filename = "C:\\Telegram Desktop\\Telegram.exe"
#filename = "C:\\Telegram Desktop\\Telegram.exe"
#filename = "E:\\tools\\thunder 9\\Program\\Thunder.exe"
#filename = "C:\\Program Files (x86)\\Thunder Network\\Thunder\\Program\\ThunderStart.exe"
#filename = "C:\\Users\\LCL\\Documents\\codes\\PracticalMalwareAnalysis-Labs.exe"

dbg.load(filename)
#dbg.bp_set(0x140019184)
pe = pefile.PE(filename)
entry_addr = None
import_table = dict()
address_table = dict()
address_table_hex_str = dict()

dbg.my_hook_counter=0
dbg.my_thread_counter=0
#now we have a dict for all loaded library, but the address is not reliable, 
#when we reach the entry point (that means the PE loader has finished its job)
#we should get the correct address using getMouldeHandle and GetProcaddress
#NOTICE:when dealing with a sample with protector, the IAT is not completed before OEP,
#so this procedure can be delayed until we find oep

entry_addr=set_entry(pe)
dbg.bp_set(entry_addr)
#show_imports(pe)
record_functions(pe)



#print "HeadFree is at:"
#print "%10x" %import_table["KERNEL32.dll"]["HeapFree"]


#print "function in 0x41f100 is:"
#print address_table[0x41f100]


#dbg.load("C:\\Program Files (x86)\\Thunder Network\\Thunder\\Program\\ThunderStart.exe")
#dbg.load("C:\\Users\\Administrator\\Downloads\\FaTiaoYun\\FaTiaoYun.exe")
#dbg.load("E:\\tools\\thunder 9\\Program\\Thunder.exe")
#dbg.single_step(True)
dbg.run()
