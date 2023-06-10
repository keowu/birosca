/*
 _   __ _____ _____  _    _ _   _
| | / /|  ___|  _  || |  | | | | |
| |/ / | |__ | | | || |  | | | | |
|    \ |  __|| | | || |/\| | | | |
| |\  \| |___\ \_/ /\  /\  / |_| |
\_| \_/\____/ \___/  \/  \/ \___/
                            2023
Copyright (c) Fluxuss Cyber Tech Desenvolvimento de Software, SLU (FLUXUSS)
Copyright (c) Fluxuss Software Security, LLC
*/
#include <iostream>
#include <memory>
#include "VMPProcess.hh"
#include "VMPDebugger.hh"

auto main() -> int {

    printf(R"EOF(
   ______ ___________ _____ _____ _____   ___    _   ____  _________ 
   | ___ \_   _| ___ \  _  /  ___/  __ \ / _ \  | | | |  \/  || ___ \
   | |_/ / | | | |_/ / | | \ `--.| /  \// /_\ \ | | | | .  . || |_/ /
   | ___ \ | | |    /| | | |`--. \ |    |  _  | | | | | |\/| ||  __/ 
   | |_/ /_| |_| |\ \\ \_/ /\__/ / \__/\| | | | \ \_/ / |  | || |    
   \____/ \___/\_| \_|\___/\____/ \____/\_| |_/  \___/\_|  |_/\_|     
   A DYNAMIC STUDY VMPROTECT 1.X-1.9X Unpacking toolkit                                                   
    )EOF");

    std::cout << "\nHello World!\n\n";

    std::string str("C:\\Users\\path\\myvmp.exe");

    std::unique_ptr<VMPProcess> vmp(new VMPProcess());

    //YOU NEED TO PASS THE PATH OF FILE - VMP TYPE - AND IF YOU NEED TO BYPASS ANTIDEBUG/VM/KERNEL MODE STUFF(via Lain)
    if (!vmp->InitProcess64(str, VMPType::VMPROTECT_1_1, FALSE)) ExitProcess(-1);

    std::unique_ptr<VMPDebugger> vmpd(new VMPDebugger());

    vmpd->InitContext(vmp);

    return 0;
}