#define WIN32_LEAN_AND_MEAN // Prevent windows.h from including winsock.h

#include "Driver.hpp" // Include this first (contains winsock2.h, ws2tcpip.h, windows.h)

#include <iostream>
#include <string>
#include <iomanip> // 用于设置 std::boolalpha
#include <tlhelp32.h> // 用于 PROCESSENTRY32, CreateToolhelp32Snapshot


#include <fstream> // 用于文件操作
#include <vector>  // 用于缓冲区
#include <algorithm> // 用于 std::min

#include <Zydis/Zydis.h>



//qq 群 849446012

auto& Driver = Driver::DriverController::Instance();


struct c_vec3 { // basic vector struct
    float x, y, z;
};

DWORD g_targetPid = 0; // 存储目标进程的 PID

typedef void (*DecFunc_t)(void* data, DWORD size, WORD handle, ULONG64 EncTable);
constexpr uintptr_t MAGIC_MASK = 0x0000FF0000000000;
constexpr uintptr_t MAGIC = 0x00004A0000000000;
ZydisDecoder g_decoder;
ZydisFormatter g_formatter;
uint64_t remote_value = 0;



// 获取寄存器值的辅助函数
uintptr_t GetRegisterValue(PCONTEXT context, ZydisRegister reg) {
    switch (reg) {
    case ZYDIS_REGISTER_RAX: return context->Rax;
    case ZYDIS_REGISTER_RBX: return context->Rbx;
    case ZYDIS_REGISTER_RCX: return context->Rcx;
    case ZYDIS_REGISTER_RDX: return context->Rdx;
    case ZYDIS_REGISTER_RSI: return context->Rsi;
    case ZYDIS_REGISTER_RDI: return context->Rdi;
    case ZYDIS_REGISTER_RBP: return context->Rbp;
    case ZYDIS_REGISTER_RSP: return context->Rsp;
    case ZYDIS_REGISTER_R8:  return context->R8;
    case ZYDIS_REGISTER_R9:  return context->R9;
    case ZYDIS_REGISTER_R10: return context->R10;
    case ZYDIS_REGISTER_R11: return context->R11;
    case ZYDIS_REGISTER_R12: return context->R12;
    case ZYDIS_REGISTER_R13: return context->R13;
    case ZYDIS_REGISTER_R14: return context->R14;
    case ZYDIS_REGISTER_R15: return context->R15;
    case ZYDIS_REGISTER_EAX: return context->Rax & 0xFFFFFFFF;
    case ZYDIS_REGISTER_EBX: return context->Rbx & 0xFFFFFFFF;
    case ZYDIS_REGISTER_ECX: return context->Rcx & 0xFFFFFFFF;
    case ZYDIS_REGISTER_EDX: return context->Rdx & 0xFFFFFFFF;
    case ZYDIS_REGISTER_ESI: return context->Rsi & 0xFFFFFFFF;
    case ZYDIS_REGISTER_EDI: return context->Rdi & 0xFFFFFFFF;
    case ZYDIS_REGISTER_EBP: return context->Rbp & 0xFFFFFFFF;
    case ZYDIS_REGISTER_ESP: return context->Rsp & 0xFFFFFFFF;
    case ZYDIS_REGISTER_R8D: return context->R8 & 0xFFFFFFFF;
    case ZYDIS_REGISTER_R9D: return context->R9 & 0xFFFFFFFF;
    case ZYDIS_REGISTER_R10D: return context->R10 & 0xFFFFFFFF;
    case ZYDIS_REGISTER_R11D: return context->R11 & 0xFFFFFFFF;
    case ZYDIS_REGISTER_R12D: return context->R12 & 0xFFFFFFFF;
    case ZYDIS_REGISTER_R13D: return context->R13 & 0xFFFFFFFF;
    case ZYDIS_REGISTER_R14D: return context->R14 & 0xFFFFFFFF;
    case ZYDIS_REGISTER_R15D: return context->R15 & 0xFFFFFFFF;
    default: return 0;
    }
}

// 设置寄存器值的辅助函数
void SetRegisterValue(PCONTEXT context, ZydisRegister reg, uintptr_t value) {
    std::cout << "SetRegisterValue: " << value << "\n";
    switch (reg) {
    case ZYDIS_REGISTER_RAX: context->Rax = value; break;
    case ZYDIS_REGISTER_RBX: context->Rbx = value; break;
    case ZYDIS_REGISTER_RCX: context->Rcx = value; break;
    case ZYDIS_REGISTER_RDX: context->Rdx = value; break;
    case ZYDIS_REGISTER_RSI: context->Rsi = value; break;
    case ZYDIS_REGISTER_RDI: context->Rdi = value; break;
    case ZYDIS_REGISTER_RBP: context->Rbp = value; break;
    case ZYDIS_REGISTER_RSP: context->Rsp = value; break;
    case ZYDIS_REGISTER_R8:  context->R8 = value; break;
    case ZYDIS_REGISTER_R9:  context->R9 = value; break;
    case ZYDIS_REGISTER_R10: context->R10 = value; break;
    case ZYDIS_REGISTER_R11: context->R11 = value; break;
    case ZYDIS_REGISTER_R12: context->R12 = value; break;
    case ZYDIS_REGISTER_R13: context->R13 = value; break;
    case ZYDIS_REGISTER_R14: context->R14 = value; break;
    case ZYDIS_REGISTER_R15: context->R15 = value; break;
    case ZYDIS_REGISTER_EAX: context->Rax = (context->Rax & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_EBX: context->Rbx = (context->Rbx & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_ECX: context->Rcx = (context->Rcx & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_EDX: context->Rdx = (context->Rdx & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_ESI: context->Rsi = (context->Rsi & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_EDI: context->Rdi = (context->Rdi & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_EBP: context->Rbp = (context->Rbp & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_ESP: context->Rsp = (context->Rsp & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_R8D: context->R8 = (context->R8 & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_R9D: context->R9 = (context->R9 & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_R10D: context->R10 = (context->R10 & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_R11D: context->R11 = (context->R11 & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_R12D: context->R12 = (context->R12 & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_R13D: context->R13 = (context->R13 & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_R14D: context->R14 = (context->R14 & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    case ZYDIS_REGISTER_R15D: context->R15 = (context->R15 & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); break;
    default: break;
    }
}

bool FixBaseDisplacementMemoryAccess(PCONTEXT context, uintptr_t value) {
    uint8_t* instructionPointer = reinterpret_cast<uint8_t*>(context->Rip);

    // 解码指令
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    if (ZYAN_FAILED(ZydisDecoderDecodeFull(&g_decoder, instructionPointer, ZYDIS_MAX_INSTRUCTION_LENGTH,
        &instruction, operands))) {
        return false;
    }

    std::cout << "解码指令: ";
    char buffer[256];
    ZydisFormatterFormatInstruction(&g_formatter, &instruction, operands,
        instruction.operand_count_visible, buffer, sizeof(buffer),
        reinterpret_cast<ZyanU64>(instructionPointer), nullptr);
    std::cout << buffer << std::endl;


    // 处理 MOV 指令
    if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV && instruction.operand_count_visible > 1 &&
        operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        ZydisRegister destReg = operands[0].reg.value;
        std::cout << "目标寄存器: " << ZydisRegisterGetString(destReg) << std::endl;
        if (operands[0].size == 64)
        {
            value |= MAGIC;
        }
        SetRegisterValue(context, destReg, value);
        context->Rip += instruction.length;
        return true;
    }

    // 处理 MOVZX 指令（零扩展移动）
    if (instruction.mnemonic == ZYDIS_MNEMONIC_MOVZX && instruction.operand_count_visible > 1 &&
        operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        ZydisRegister destReg = operands[0].reg.value;

        // 获取源操作数的大小（通常是第二个操作数）
        ZyanU16 srcSize = operands[1].size;

        std::cout << "MOVZX 目标寄存器: " << ZydisRegisterGetString(destReg)
            << ", 源大小: " << srcSize << " 位, 目标大小: " << operands[0].size << " 位" << std::endl;

        // 根据源操作数大小进行零扩展
        uintptr_t extendedValue;
        switch (srcSize) {
        case 8:  // 从8位零扩展到目标大小
            extendedValue = value & 0xFF;
            break;
        case 16: // 从16位零扩展到目标大小
            extendedValue = value & 0xFFFF;
            break;
        case 32: // 从32位零扩展到64位
            extendedValue = value & 0xFFFFFFFF;
            break;
        default:
            std::cout << "不支持的源操作数大小: " << srcSize << std::endl;
            return false;
        }

        std::cout << std::hex << "MOVZX 操作: " << value << " -> " << extendedValue << std::endl;

        SetRegisterValue(context, destReg, extendedValue);
        context->Rip += instruction.length;
        return true;
    }

    // 处理 ADD 指令
    if (instruction.mnemonic == ZYDIS_MNEMONIC_ADD && instruction.operand_count_visible > 1 &&
        operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        ZydisRegister destReg = operands[0].reg.value;
        std::cout << "ADD 目标寄存器: " << ZydisRegisterGetString(destReg) << std::endl;

        // 获取目标寄存器的当前值
        uintptr_t currentValue = GetRegisterValue(context, destReg);

        // 计算新的值：当前值 + 从内存读取的值
        uintptr_t newValue;

        // 根据操作数大小进行处理
        switch (operands[0].size) {
        case 8:  // 8位操作数
            newValue = (currentValue & 0xFFFFFFFFFFFFFF00) | ((currentValue + value) & 0xFF);
            break;
        case 16: // 16位操作数
            newValue = (currentValue & 0xFFFFFFFFFFFF0000) | ((currentValue + value) & 0xFFFF);
            break;
        case 32: // 32位操作数
            newValue = (currentValue & 0xFFFFFFFF00000000) | ((currentValue + value) & 0xFFFFFFFF);
            break;
        case 64: // 64位操作数
            newValue = currentValue + value;
            break;
        default:
            std::cout << "不支持的操作数大小: " << operands[0].size << std::endl;
            return false;
        }

        std::cout << std::hex << "ADD 操作: " << currentValue << " + " << value
            << " = " << newValue << std::endl;

        SetRegisterValue(context, destReg, newValue);
        context->Rip += instruction.length;
        return true;
    }

    // 处理 SUB 指令
    if (instruction.mnemonic == ZYDIS_MNEMONIC_SUB && instruction.operand_count_visible > 1 &&
        operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        ZydisRegister destReg = operands[0].reg.value;
        std::cout << "SUB 目标寄存器: " << ZydisRegisterGetString(destReg) << std::endl;

        // 获取目标寄存器的当前值
        uintptr_t currentValue = GetRegisterValue(context, destReg);

        // 计算新的值：当前值 - 从内存读取的值
        uintptr_t newValue;

        // 根据操作数大小进行处理
        switch (operands[0].size) {
        case 8:  // 8位操作数
            newValue = (currentValue & 0xFFFFFFFFFFFFFF00) | ((currentValue - value) & 0xFF);
            break;
        case 16: // 16位操作数
            newValue = (currentValue & 0xFFFFFFFFFFFF0000) | ((currentValue - value) & 0xFFFF);
            break;
        case 32: // 32位操作数
            newValue = (currentValue & 0xFFFFFFFF00000000) | ((currentValue - value) & 0xFFFFFFFF);
            break;
        case 64: // 64位操作数
            newValue = currentValue - value;
            break;
        default:
            std::cout << "不支持的操作数大小: " << operands[0].size << std::endl;
            return false;
        }

        std::cout << std::hex << "SUB 操作: " << currentValue << " - " << value
            << " = " << newValue << std::endl;

        SetRegisterValue(context, destReg, newValue);
        context->Rip += instruction.length;
        return true;
    }

    // 处理 IMUL 指令（三操作数形式）
    if (instruction.mnemonic == ZYDIS_MNEMONIC_IMUL && instruction.operand_count_visible == 3) {
        // 检查操作数类型：寄存器，内存，立即数
        if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            operands[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {

            ZydisRegister destReg = operands[0].reg.value;
            int64_t immediate = operands[2].imm.value.s;

            std::cout << "IMUL 目标寄存器: " << ZydisRegisterGetString(destReg)
                << ", 立即数: " << std::hex << immediate << std::endl;

            // 执行有符号乘法：目标寄存器 = 内存值 * 立即数
            int64_t result;

            // 根据操作数大小进行处理
            switch (operands[0].size) {
            case 8:  // 8位操作数
                result = (int8_t)value * (int8_t)immediate;
                break;
            case 16: // 16位操作数
                result = (int16_t)value * (int16_t)immediate;
                break;
            case 32: // 32位操作数
                result = (int32_t)value * (int32_t)immediate;
                break;
            case 64: // 64位操作数
                result = (int64_t)value * immediate;
                break;
            default:
                std::cout << "不支持的操作数大小: " << operands[0].size << std::endl;
                return false;
            }

            std::cout << std::hex << "IMUL 操作: " << value << " * " << immediate
                << " = " << result << std::endl;

            SetRegisterValue(context, destReg, (uintptr_t)result);
            context->Rip += instruction.length;
            return true;
        }
    }

    // 处理 IMUL 指令（两操作数形式）
    if (instruction.mnemonic == ZYDIS_MNEMONIC_IMUL && instruction.operand_count_visible == 2) {
        // 检查操作数类型：寄存器，内存
        if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {

            ZydisRegister destReg = operands[0].reg.value;

            std::cout << "IMUL 目标寄存器: " << ZydisRegisterGetString(destReg) << std::endl;

            // 获取目标寄存器的当前值
            int64_t currentValue = (int64_t)GetRegisterValue(context, destReg);

            // 执行有符号乘法：目标寄存器 = 当前值 * 内存值
            int64_t result;

            // 根据操作数大小进行处理
            switch (operands[0].size) {
            case 8:  // 8位操作数
                result = (int8_t)currentValue * (int8_t)value;
                break;
            case 16: // 16位操作数
                result = (int16_t)currentValue * (int16_t)value;
                break;
            case 32: // 32位操作数
                result = (int32_t)currentValue * (int32_t)value;
                break;
            case 64: // 64位操作数
                result = currentValue * (int64_t)value;
                break;
            default:
                std::cout << "不支持的操作数大小: " << operands[0].size << std::endl;
                return false;
            }

            std::cout << std::hex << "IMUL 操作: " << currentValue << " * " << value
                << " = " << (uintptr_t)result << std::endl;

            SetRegisterValue(context, destReg, (uintptr_t)result);
            context->Rip += instruction.length;
            return true;
        }
    }

    // 处理 AND 指令
    if (instruction.mnemonic == ZYDIS_MNEMONIC_AND && instruction.operand_count_visible > 1 &&
        operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        ZydisRegister destReg = operands[0].reg.value;
        std::cout << "AND 目标寄存器: " << ZydisRegisterGetString(destReg) << std::endl;

        // 获取目标寄存器的当前值
        uintptr_t currentValue = GetRegisterValue(context, destReg);

        // 计算新的值：当前值 AND 从内存读取的值
        uintptr_t newValue = currentValue & value;

        std::cout << std::hex << "AND 操作: " << currentValue << " & " << value
            << " = " << newValue << std::endl;

        SetRegisterValue(context, destReg, newValue);
        context->Rip += instruction.length;
        return true;
    }
    if (instruction.mnemonic == ZYDIS_MNEMONIC_MOVSXD && instruction.operand_count_visible > 1 &&
        operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
    {
        ZydisRegister destReg = operands[0].reg.value;
        ZyanU16 srcSize = operands[1].size; // 源操作数大小 (来自内存)
        ZyanU16 destSize = operands[0].size; // 目标寄存器大小

        std::cout << "MOVSXD 目标寄存器: " << ZydisRegisterGetString(destReg)
            << ", 源大小: " << srcSize << " 位, 目标大小: " << destSize << " 位" << std::endl;

        // 'value' 是我们从 VEH 传递过来的、已经从“魔法”地址读取的 64 位值
        uintptr_t extendedValue = 0;

        // 这是最常见的情况: movsxd r64, r/m32
        if (srcSize == 32 && destSize == 64)
        {
            // 1. 将 value 截断为 32 位，并解释为有符号整数
            int32_t signedSrcValue = (int32_t)(value & 0xFFFFFFFF);

            // 2. 将有符号 32 位整数转换为有符号 64 位整数 (C++ 自动处理符号扩展)
            int64_t signedExtendedValue = (int64_t)signedSrcValue;

            // 3. 转换为 uintptr_t 以便 SetRegisterValue
            extendedValue = (uintptr_t)signedExtendedValue;

            std::cout << std::hex << "MOVSXD 操作 (32->64): 0x" << (value & 0xFFFFFFFF)
                << " -> 0x" << extendedValue << std::endl;
        }
        // 也处理一下其他可能的变种
        else if (srcSize == 16)
        {
            int16_t signedSrcValue = (int16_t)(value & 0xFFFF);
            int64_t signedExtendedValue = (int64_t)signedSrcValue;
            extendedValue = (uintptr_t)signedExtendedValue;

            std::cout << std::hex << "MOVSXD 操作 (16->" << destSize << "): 0x" << (value & 0xFFFF)
                << " -> 0x" << extendedValue << std::endl;
        }
        else if (srcSize == 8)
        {
            int8_t signedSrcValue = (int8_t)(value & 0xFF);
            int64_t signedExtendedValue = (int64_t)signedSrcValue;
            extendedValue = (uintptr_t)signedExtendedValue;

            std::cout << std::hex << "MOVSXD 操作 (8->" << destSize << "): 0x" << (value & 0xFF)
                << " -> 0x" << extendedValue << std::endl;
        }
        else
        {
            std::cout << "不支持的 MOVSXD 操作数大小组合: "
                << "Src=" << srcSize << ", Dest=" << destSize << std::endl;
            return false;
        }

        // 设置目标寄存器
        SetRegisterValue(context, destReg, extendedValue);
        // 跳过当前指令
        context->Rip += instruction.length;
        return true;
    }
    // 处理 OR 指令
    if (instruction.mnemonic == ZYDIS_MNEMONIC_OR && instruction.operand_count_visible > 1 &&
        operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        ZydisRegister destReg = operands[0].reg.value;
        std::cout << "OR 目标寄存器: " << ZydisRegisterGetString(destReg) << std::endl;

        // 获取目标寄存器的当前值
        uintptr_t currentValue = GetRegisterValue(context, destReg);

        // 计算新的值：当前值 OR 从内存读取的值
        uintptr_t newValue = currentValue | value;

        std::cout << std::hex << "OR 操作: " << currentValue << " | " << value
            << " = " << newValue << std::endl;

        SetRegisterValue(context, destReg, newValue);
        context->Rip += instruction.length;
        return true;
    }

    // 处理 XOR 指令
    if (instruction.mnemonic == ZYDIS_MNEMONIC_XOR && instruction.operand_count_visible > 1 &&
        operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        ZydisRegister destReg = operands[0].reg.value;
        std::cout << "XOR 目标寄存器: " << ZydisRegisterGetString(destReg) << std::endl;

        // 获取目标寄存器的当前值
        uintptr_t currentValue = GetRegisterValue(context, destReg);

        // 计算新的值：当前值 XOR 从内存读取的值
        uintptr_t newValue = currentValue ^ value;

        std::cout << std::hex << "XOR 操作: " << currentValue << " ^ " << value
            << " = " << newValue << std::endl;

        SetRegisterValue(context, destReg, newValue);
        context->Rip += instruction.length;
        return true;
    }

    if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL && instruction.operand_count_visible == 1 &&
        operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {

        std::cout << "处理间接 CALL 指令" << std::endl;

        // 从内存中读取的是函数指针
        uintptr_t functionPointer = value;

        std::cout << "函数指针: " << std::hex << functionPointer << std::endl;

        // 获取返回地址（下一条指令）
        uintptr_t returnAddress = context->Rip + instruction.length;

        // 将返回地址压入栈中
        context->Rsp -= 8; // 64位系统，栈是8字节对齐
        SIZE_T bytesWritten;
        if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID)context->Rsp, &returnAddress, 8, &bytesWritten)) {
            std::cout << "压入返回地址失败" << std::endl;
            return false;
        }

        std::cout << "压入返回地址: " << std::hex << returnAddress
            << " 到栈地址: " << context->Rsp << std::endl;

        // 设置指令指针为函数地址
        context->Rip = functionPointer;

        std::cout << "跳转到函数: " << std::hex << functionPointer << std::endl;

        return true;
    }

    std::cout << "不支持的指令: " << ZydisMnemonicGetString(instruction.mnemonic) << std::endl;
    return false;
}

LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    PEXCEPTION_RECORD exceptionRecord = ExceptionInfo->ExceptionRecord;
    PCONTEXT context = ExceptionInfo->ContextRecord;

    // 我们只处理访问违规 (Access Violation)
    if (exceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
    {
        uintptr_t faultAddress = (uintptr_t)exceptionRecord->ExceptionInformation[1];
        DWORD operationType = exceptionRecord->ExceptionInformation[0]; // 0=Read, 1=Write

        // -----------------------------------------------------------------
        // 方案 A：动态修复由 dump 引起的 GS Cookie 加载失败 (最终版)
        // -----------------------------------------------------------------

        // 检查: 是否是 *读取* *特定* 的无效GS Cookie地址？
        if (faultAddress == 0x154694280 && operationType == 0 /* Read */)
        {
            //std::cout << "[GS Cookie 修复] 检测到损坏的 GS Cookie 访问。" << std::endl;
            //std::cout << "  -> 故障 RIP: 0x" << std::hex << context->Rip << std::endl;

            // 声明 Zydis 结构体
            ZydisDecodedInstruction insn;
            ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
            char buffer[256]; // 用于打印指令

            try
            {
                // 首先，解码当前导致异常的指令
                if (ZYAN_FAILED(ZydisDecoderDecodeFull(&g_decoder, (void*)context->Rip, ZYDIS_MAX_INSTRUCTION_LENGTH, &insn, ops))) {
                    throw std::runtime_error("无法解码故障指令");
                }

                // 格式化并打印我们找到的指令
                ZydisFormatterFormatInstruction(&g_formatter, &insn, ops, insn.operand_count_visible, buffer, sizeof(buffer), context->Rip, nullptr);
                //std::cout << "  -> 捕获到指令: " << buffer << std::endl;

                // --- 
                // --- 情况 1：这是函数序言 (Prologue) ---
                // ---
                if (insn.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[0].reg.value == ZYDIS_REGISTER_RAX &&
                    ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    std::cout << "  -> 识别为 Prologue (mov rax, ...). 正在验证 3-指令模式..." << std::endl;

                    uintptr_t rip2 = context->Rip + insn.length;
                    uintptr_t rip3 = 0;

                    // 声明用于验证的指令
                    ZydisDecodedInstruction insn2, insn3;
                    ZydisDecodedOperand ops2[ZYDIS_MAX_OPERAND_COUNT], ops3[ZYDIS_MAX_OPERAND_COUNT];

                    // --- 验证指令 2 (xor rax, rsp) ---
                    if (ZYAN_FAILED(ZydisDecoderDecodeFull(&g_decoder, (void*)rip2, ZYDIS_MAX_INSTRUCTION_LENGTH, &insn2, ops2))) {
                        throw std::runtime_error("无法解码指令 2 (xor)");
                    }
                    rip3 = rip2 + insn2.length;
                    if (insn2.mnemonic != ZYDIS_MNEMONIC_XOR ||
                        ops2[0].type != ZYDIS_OPERAND_TYPE_REGISTER || ops2[0].reg.value != ZYDIS_REGISTER_RAX ||
                        ops2[1].type != ZYDIS_OPERAND_TYPE_REGISTER || ops2[1].reg.value != ZYDIS_REGISTER_RSP) {
                        throw std::runtime_error("Prologue 模式失败: 指令 2 不是 xor rax, rsp");
                    }

                    // --- 验证指令 3 (mov [rbp+...], rax) ---
                    if (ZYAN_FAILED(ZydisDecoderDecodeFull(&g_decoder, (void*)rip3, ZYDIS_MAX_INSTRUCTION_LENGTH, &insn3, ops3))) {
                        throw std::runtime_error("无法解码指令 3 (mov)");
                    }
                    if (insn3.mnemonic != ZYDIS_MNEMONIC_MOV ||
                        ops3[0].type != ZYDIS_OPERAND_TYPE_MEMORY || ops3[0].mem.base != ZYDIS_REGISTER_RBP ||
                        ops3[1].type != ZYDIS_OPERAND_TYPE_REGISTER || ops3[1].reg.value != ZYDIS_REGISTER_RAX) {
                        throw std::runtime_error("Prologue 模式失败: 指令 3 不是 mov [rbp+...], rax");
                    }

                    // --- Prologue 验证成功 ---
                    //std::cout << "  -> Prologue 模式匹配成功! 动态跳过3条指令." << std::endl;
                    context->Rip = rip3 + insn3.length; // 设置为第三条指令之后的地址
                    //std::cout << "  -> RIP 已修改为 0x" << std::hex << context->Rip << std::endl;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                // --- 
                // --- 情况 2：这是函数结尾 (Epilogue) ---
                // ---
                else if (insn.mnemonic == ZYDIS_MNEMONIC_CMP &&
                    ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[0].reg.value == ZYDIS_REGISTER_RCX &&
                    ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    //std::cout << "  -> 识别为 Epilogue (cmp rcx, ...). 正在验证 2-指令模式..." << std::endl;

                    uintptr_t rip2 = context->Rip + insn.length;

                    // 验证指令 2 (jne)
                    ZydisDecodedInstruction insn2;
                    ZydisDecodedOperand ops2[ZYDIS_MAX_OPERAND_COUNT];
                    if (ZYAN_FAILED(ZydisDecoderDecodeFull(&g_decoder, (void*)rip2, ZYDIS_MAX_INSTRUCTION_LENGTH, &insn2, ops2))) {
                        throw std::runtime_error("无法解码指令 2 (jne)");
                    }

                    ZydisFormatterFormatInstruction(&g_formatter, &insn2, ops2, insn2.operand_count_visible, buffer, sizeof(buffer), rip2, nullptr);
                    //std::cout << "  -> 验证 2 (OK): " << buffer << std::endl;

                    // --- Epilogue 验证成功 ---
                    //std::cout << "[GS Cookie 修复] Epilogue 模式匹配成功! 动态跳过2条指令." << std::endl;
                    context->Rip = rip2 + insn2.length; // 设置为 jne 之后的地址
                    //std::cout << "  -> RIP 已修改为 0x" << std::hex << context->Rip << std::endl;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                // --- 如果两种模式都不是 ---
                else {
                    throw std::runtime_error("指令既不是 mov rax,... 也不是 cmp rcx,...");
                }
            }
            catch (const std::exception& e)
            {
                std::cout << "  !! [GS Cookie 修复] 模式匹配失败: " << e.what() << std::endl;
            }
        } // 结束 方案 A (GS Cookie)

        if (operationType == 8 /* Execute */ && ((uintptr_t)faultAddress & MAGIC_MASK) == MAGIC)
        {
            uintptr_t realCodeAddress = faultAddress ^ MAGIC;
            context->Rip = realCodeAddress;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        if (((uintptr_t)faultAddress & MAGIC_MASK) == MAGIC)
        {
            //std::cout << "[VM 模拟] 访问违规在地址: " << std::hex << faultAddress << std::endl;

            // --- 新增代码：打印导致异常的指令地址 (RIP) ---
            //std::cout << "[VM 模拟] 故障指令地址 (RIP): 0x" << std::hex << context->Rip << std::endl;
            // --- 结束新增代码 ---

            faultAddress ^= MAGIC; // 移除魔法标记，获取真实地址
            uintptr_t remote_value = Driver.Read<uintptr_t>(faultAddress);
            //std::cout << "[VM 模拟] 远程内容: " << remote_value << std::endl;

            // 调用你的指令模拟函数
            if (FixBaseDisplacementMemoryAccess(context, remote_value)) {
                //std::cout << "[VM 模拟] 修复成功，继续执行" << std::endl;
                return EXCEPTION_CONTINUE_EXECUTION; // 继续执行
            }
            else {
                //std::cout << "[VM 模拟] 修复失败 (不支持的指令?)" << std::endl;
                // ... 修复失败, 落到下面的“未处理异常”报告并崩溃
            }
        }
    }
    std::ios_base::fmtflags oldFlags = std::cout.flags();
    char oldFill = std::cout.fill();
    std::cout << std::hex << std::uppercase << std::setfill('0');

    std::cout << "\n============================================================\n";
    std::cout << "[VEH] 捕获到未处理的异常! (将交由系统处理)\n";
    std::cout << "============================================================\n";

    std::cout << "  --- 异常信息 (EXCEPTION_RECORD) ---\n";
    std::cout << "  异常代码 (Code): 0x" << exceptionRecord->ExceptionCode << "\n";
    std::cout << "  异常地址 (RIP):  0x" << std::setw(16) << (uintptr_t)exceptionRecord->ExceptionAddress << "\n";

    if (exceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
    {
        std::cout << "  异常类型: 访问违规 (Access Violation)\n";
        std::cout << "  操作类型 (Type): ";
        switch (exceptionRecord->ExceptionInformation[0])
        {
        case 0: std::cout << "Read (读取)\n"; break;
        case 1: std::cout << "Write (写入)\n"; break;
        case 8: std::cout << "Execute (DEP)\n"; break;
        default: std::cout << "Unknown\n"; break;
        }
        std::cout << "  目标地址 (Addr): 0x" << std::setw(16) << exceptionRecord->ExceptionInformation[1] << "\n";
    }

    std::cout << "\n  --- 上下文寄存器 (CONTEXT) ---\n";
    std::cout << "  RAX: 0x" << std::setw(16) << context->Rax << "  RBX: 0x" << std::setw(16) << context->Rbx << "\n";
    std::cout << "  RCX: 0x" << std::setw(16) << context->Rcx << "  RDX: 0x" << std::setw(16) << context->Rdx << "\n";
    std::cout << "  RSI: 0x" << std::setw(16) << context->Rsi << "  RDI: 0x" << std::setw(16) << context->Rdi << "\n";
    std::cout << "  RSP: 0x" << std::setw(16) << context->Rsp << "  RBP: 0x" << std::setw(16) << context->Rbp << "\n";
    std::cout << "  R8:  0x" << std::setw(16) << context->R8 << "  R9:  0x" << std::setw(16) << context->R9 << "\n";
    std::cout << "  R10: 0x" << std::setw(16) << context->R10 << "  R11: 0x" << std::setw(16) << context->R11 << "\n";
    std::cout << "  R12: 0x" << std::setw(16) << context->R12 << "  R13: 0x" << std::setw(16) << context->R13 << "\n";
    std::cout << "  R14: 0x" << std::setw(16) << context->R14 << "  R15: 0x" << std::setw(16) << context->R15 << "\n";
    std::cout << "  RIP: 0x" << std::setw(16) << context->Rip << " (应与上面的异常地址相同)\n";
    std::cout << "============================================================\n\n";

    std::cout.flags(oldFlags);
    std::cout.fill(oldFill);

    return EXCEPTION_CONTINUE_SEARCH;
}




unsigned long GetPidByWindowTitle(const char* windowTitle) {
    HWND hwnd = FindWindowA(NULL, windowTitle);
    if (hwnd == NULL) {
        std::cerr << "[-] 辅助函数: 找不到窗口 '" << windowTitle << "'" << std::endl;
        return 0;
    }
    unsigned long pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == 0) {
        std::cerr << "[-] 辅助函数: 无法获取 PID" << std::endl;
        return 0;
    }
    return pid;
}




DWORD GetFirstPIDByName(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return 0;
}

// 辅助函数：用于暂停程序
void PauseAndExit(int exitCode) {
    std::cout << "\n按 Enter 键退出..." << std::endl;
    std::cin.ignore();
    exit(exitCode);
}


// void DumpMemory(DWORD pid) {
//     // 1. 定义起始和结束地址
//     ULONG64 startAddress = 0x140000000;
//     ULONG64 endAddress = 0x150000000;
//     size_t totalSize = endAddress - startAddress;
//
//     std::cout << "[Dump] 准备开始 Dump 内存..." << std::endl;
//     std::cout << "[Dump] 范围: 0x" << std::hex << startAddress << " - 0x" << endAddress << std::endl;
//     std::cout << "[Dump] 总大小: " << std::dec << (totalSize / 1024 / 1024) << " MB" << std::endl;
//
//     // 2. 打开文件 (二进制模式)
//     std::ofstream dumpFile("memory_dump.bin", std::ios::binary);
//     if (!dumpFile.is_open()) {
//         std::cerr << "[Dump] 错误: 无法创建 memory_dump.bin 文件!" << std::endl;
//         return;
//     }
//
//     // 3. 配置分块读取参数
//     // 建议每次读取 1MB (1024*1024) 或 4KB (4096)。如果驱动不稳定，请减小此值。
//     const size_t CHUNK_SIZE = 1024 * 1024;
//     std::vector<char> buffer(CHUNK_SIZE); // 预分配缓冲区
//
//     ULONG64 currentAddr = startAddress;
//     size_t bytesWritten = 0;
//
//     // 4. 循环读取
//     while (currentAddr < endAddress) {
//         // 计算本次需要读取的大小 (防止最后一块越界)
//         size_t readSize = (std::min)((size_t)(endAddress - currentAddr), CHUNK_SIZE);
//
//         // 调用驱动读取内存
//         // 注意：这里直接传 buffer.data() 指针，而不是使用模板 Read<T>
//         if (Driver.Read( currentAddr, buffer.data(), readSize)) {
//             // 读取成功，写入文件
//             dumpFile.write(buffer.data(), readSize);
//         }
//         else {
//             // 读取失败 (可能是该内存页未映射或受保护)
//             // 为了保持 Dump 文件偏移正确，建议填零
//             // std::cerr << "[Dump] 警告: 读取失败于 0x" << std::hex << currentAddr << " 填充 0" << std::endl;
//             std::vector<char> emptyBuffer(readSize, 0);
//             dumpFile.write(emptyBuffer.data(), readSize);
//         }
//
//         currentAddr += readSize;
//         bytesWritten += readSize;
//
//         // 5. 显示进度 (每读取 10MB 显示一次，避免刷屏)
//         if (bytesWritten % (10 * 1024 * 1024) == 0) {
//             float progress = (float)bytesWritten / totalSize * 100.0f;
//             std::cout << "[Dump] 进度: " << std::dec << (int)progress << "% \r" << std::flush;
//         }
//     }
//
//     dumpFile.close();
//     std::cout << std::endl << "[Dump] 完成! 已保存至 memory_dump.bin" << std::endl;
// }

int32_t GetXorKey(int32_t Length) {
    int32_t Mode = Length % 9;
    int32_t ret = 0;

    switch (Mode) {
    case 0:
        ret = (Length + (Length & 31) + 128) | 127;
        break;
    case 1:
        ret = (Length + (Length ^ 223) + 128) | 127;
        break;
    case 2:
        ret = (Length + (Length | 207) + 128) | 127;
        break;
    case 3:
        ret = (33 * Length + 128) | 127;
        break;
    case 4:
        ret = (Length + (Length >> 2) + 128) | 127;
        break;
    case 5:
        ret = (3 * Length + 133) | 127;
        break;
    case 6:
        ret = (Length + ((4 * Length) | 5) + 128) | 127;
        break;
    case 7:
        ret = (Length + ((Length >> 4) | 7) + 128) | 127;
        break;
    case 8:
        ret = (Length + (Length ^ 12) + 128) | 127;
        break;
    default:
        ret = 0;
        break;
    }

    return ret;
}



std::string IndexToString(uint32_t index, DWORD pid)
{
    char NameBuffer[1024]{};
    uint64_t ref = Driver.Read<uint64_t>(0x0000000154C08780 + (((uint32_t)(index >> 18) + 1) * 8));
    if (ref <= 0)
    {
        return "";
    }
    uint64_t NamePoolChunk = ref + (uint32_t)(2 * (index & 0x3FFFF));
    uint16_t Pool = Driver.Read<uint16_t>(NamePoolChunk);
    if (Pool <= 0)
    {
        return "";
    }
    int32_t Length = (Pool >> 6) * ((Pool & 1) != 0 ? 2 : 1);
    if (Length < sizeof(NameBuffer))
    {
        Driver.Read(uintptr_t(NamePoolChunk + 2), (UCHAR*)NameBuffer, Length);

        for (int i = 0; i < Length; ++i)
            NameBuffer[i] ^= GetXorKey(Length);

        NameBuffer[Length] = '\0';
    }
    return std::string(NameBuffer);
}


uintptr_t DecryptUEPointer(uintptr_t PackedPointer) {
    uintptr_t RealPointer = PackedPointer & 0xFFFFFFFFFFFF;
    if (RealPointer & 0x800000000000) {
        RealPointer |= 0xFFFF000000000000;
    }
    return RealPointer;
}




// 适配你现有驱动的辅助读取逻辑
// 使用你驱动的 bool Read(addr, buffer, size)
uint32_t GetFinalKey2_Debug(uint64_t GameBase, uint32_t encryptedValue)
{
    uint16_t targetID = (uint16_t)(encryptedValue & 0xFFFF);

    printf("\n============ [DEBUG START] ============\n");
    printf("Target ID: 0x%X (Dec: %d)\n", targetID, targetID);

    // 1. 处理静态 ID (Bit 13)
    if ((targetID & 0x2000) == 0) {
        printf("[DEBUG] Bit 13 is 0, returning static ID: 0x%X\n", targetID);
        return targetID;
    }

    // 2. 计算 Slot 地址
    unsigned int slotIndex = targetID >> 14;
    uint64_t globalArrayBase = GameBase + 0x1486E5C0;
    uint64_t slotAddr = globalArrayBase + (slotIndex * 704);

    printf("[DEBUG] SlotIndex: %d, SlotAddr: 0x%llX\n", slotIndex, slotAddr);

    // 3. 读取链表头
    uint64_t currentNode = Driver.Read<uint64_t>(slotAddr + 0x298);
    printf("[DEBUG] List Head: 0x%llX\n", currentNode);

    if (currentNode == 0) {
        printf("[DEBUG] List is EMPTY (NULL Head). Returning 0.\n");
        return 0;
    }

    int safetyCount = 0;
    int nodeIndex = 0;

    // --- 开始扫描 ---
    while (safetyCount++ < 100) // 只看前20个节点，通常就在前几个
    {
        // 【关键修改】：这里不用 ReadBytes，直接用你的 bool Read
        // 我们定义一个 64 字节的数组，一次把节点的前 64 字节都读下来
        uint8_t nodeBuffer[64];
        memset(nodeBuffer, 0, sizeof(nodeBuffer)); // 清空防止垃圾数据

        // 调用驱动读取：从 currentNode 读 64 字节到 nodeBuffer
        if (!Driver.Read(currentNode, nodeBuffer, sizeof(nodeBuffer))) {
            printf("[DEBUG] Failed to read node at 0x%llX\n", currentNode);
            break;
        }

        // --- 解析数据 ---
        // 直接从 buffer 里强转类型来看数值
        uint64_t nextNode = *(uint64_t*)(nodeBuffer + 0x00); // +0x00
        uint32_t val_0x04 = *(uint32_t*)(nodeBuffer + 0x04); // +0x04
        uint32_t val_0x08 = *(uint32_t*)(nodeBuffer + 0x08); // +0x08 (通常是 Key)
        uint32_t val_0x0C = *(uint32_t*)(nodeBuffer + 0x0C); // +0x0C (嫌疑最大)
        uint32_t val_0x10 = *(uint32_t*)(nodeBuffer + 0x10); // +0x10
        uint32_t val_0x14 = *(uint32_t*)(nodeBuffer + 0x14); // +0x14

        // --- 打印详细日志 ---
        printf("----------------------------------------\n");
        printf("[Node %d] Addr: 0x%llX\n", nodeIndex, currentNode);
        printf("    +0x00 (Next): 0x%llX\n", nextNode);
        printf("    +0x04 (Val ): 0x%08X\n", val_0x04);
        printf("    +0x08 (Key?): 0x%08X\n", val_0x08);
        printf("    +0x0C (ID? ): 0x%08X  <-- check 0x%X\n", val_0x0C, targetID);
        printf("    +0x10 (Val ): 0x%08X\n", val_0x10);

        // 自动高亮发现
        if ((uint16_t)val_0x04 == targetID) printf("    >>> [FOUND MATCH] ID found at offset +0x04 !!! <<<\n");
        if ((uint16_t)val_0x08 == targetID) printf("    >>> [FOUND MATCH] ID found at offset +0x08 (Key==ID?) !!! <<<\n");
        if ((uint16_t)val_0x0C == targetID) printf("    >>> [FOUND MATCH] ID found at offset +0x0C !!! <<<\n");
        if ((uint16_t)val_0x10 == targetID) printf("    >>> [FOUND MATCH] ID found at offset +0x10 !!! <<<\n");

        // 链表结束判断
        if (nextNode == 0) {
            printf("[DEBUG] End of List reached. Returning last key: 0x%X\n", val_0x08);
            printf("============ [DEBUG END] ============\n");
            return val_0x08;
        }

        currentNode = nextNode;
        nodeIndex++;
    }

    printf("[DEBUG] Loop limit reached.\n");
    return 0;
}


uint32_t GetFinalKey2(uint64_t GameBase, uint32_t encryptedValue)

{
    uint16_t id = (uint16_t)(encryptedValue & 0xFFFF);
    if ((id & 0x2000) == 0)
    {
        return id;
    }
    unsigned int slotIndex = id >> 14;
    uint64_t globalArrayBase = GameBase + 0x1486E5C0;
    uint64_t slotAddr = globalArrayBase + (slotIndex * 704);
    uint64_t currentNode = Driver.Read<uint64_t>(slotAddr + 0x298);

    if (currentNode == 0)
        return 0;
    int safetyCount = 0;
    while (safetyCount++ < 200)
    {

        uint64_t nextNode = Driver.Read<uint64_t>(currentNode);
        if (nextNode == 0)
            break;
        currentNode = nextNode;
    }
    uint32_t finalKey = Driver.Read<uint32_t>(currentNode + 0x08);
    return finalKey;

}


void Initialize(const std::string& key) {
    SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);

    if (!Driver.Initialize()) {
        std::cerr << "[!] Init Failed. Check Npcap/Driver." << std::endl;
    }
    printf("[EXIDDriver::Initialize] 驱动安装成功\n");
    std::wstring targetProcessNameW = L"DeltaForceClient-Win64-Shipping.exe";
    std::wcout << L"[Log] 辅助函数: 正在通过进程名 \"" << targetProcessNameW << L"\" 查找 PID..." << std::endl;
    g_targetPid = GetFirstPIDByName(targetProcessNameW);

    if (g_targetPid == 0) {
        std::cerr << "[Log] 辅助函数: 未能找到目标进程. 程序即将退出." << std::endl;
    }
    std::cout << "[Log] 辅助函数: 成功找到 PID: " << std::dec << g_targetPid << std::endl;

    if (!Driver.AttachProcess(g_targetPid)) {
        std::cerr << "[!] Attach Failed." << std::endl;

    }

    __int64 testValue = Driver.Read<__int64>(0x140000000);

    std::cout << "[Log] 测试读取成功: 位于 0x" << std::hex << 0x140000000
        << " 的值是: 0x" << testValue << std::endl;


    std::ifstream file("memory_dump.bin", std::ios::in | std::ios::binary);
    if (!file.is_open())
    {
        std::cout << "打开文件失败\n";
    }
    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    void* image = VirtualAlloc((void*)0x140000000, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!image)
    {
        std::cout << "申请内存失败\n";
    }
    if (image != (void*)0x140000000)
    {
        std::cout << "申请内存位置不匹配\n";
    }
    if (!file.read(reinterpret_cast<char*>(image), size))
    {
        std::cout << "读取文件\n";
    }
    if (!AddVectoredExceptionHandler(1, VectoredExceptionHandler))
    {
        std::cout << "注册异常失败\n";
    }
    ZydisDecoderInit(&g_decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatterInit(&g_formatter, ZYDIS_FORMATTER_STYLE_INTEL);


    std::cout << "系统初始化完成，异常处理器已注册" << std::endl;


    ULONG64 uWorld = Driver.Read<uint64_t>(0x00000001542F1148);
    std::cout << "uWorld: 0x" << std::hex << uWorld << std::dec << std::endl;

    ULONG64 uLevels = Driver.Read<uint64_t>(uWorld + 0x158);
    std::cout << "uLevels: 0x" << std::hex << uLevels << std::dec << std::endl;

    ULONG64 Ulevel = Driver.Read<uint64_t>(uLevels);
    std::cout << "Ulevel: 0x" << std::hex << Ulevel << std::dec << std::endl;

    ULONG32 count = Driver.Read<ULONG32>(Ulevel + 0xA0);
    std::cout << "count: " << count << std::endl;

    ULONG64 Actoradd = Driver.Read<uint64_t>(Ulevel + 0x98);
    std::cout << "Actoradd: 0x" << std::hex << Actoradd << std::dec << std::endl;

    for (ULONG32 i = 0; i < count; i++)
    {
        ULONG64 cplayer = Driver.Read<uint64_t>(Actoradd + i * 8);
        if (!cplayer)
        {
            continue;
        }

        ULONG32 playerid = Driver.Read<ULONG32>(cplayer + 0x1C);
        std::string playerName = IndexToString(playerid, g_targetPid);
        if (playerName != "BP_DFMCharacter_C")
        {
            continue;
        }
        //std::cout << "cplayer[" << i << "]: 0x" << std::hex << cplayer << std::dec << std::endl;

        //std::cout << "playerid: " << playerid << ", playerName: " << playerName << std::endl;

        ULONG64 actorAddress = cplayer;
        std::cout << "actorAddress: 0x" << std::hex << actorAddress << std::dec << std::endl;

        ULONG64 encrypted_ptr = Driver.Read<uint64_t>(actorAddress + 0x180);
        std::cout << "encrypted_ptr: 0x" << std::hex << encrypted_ptr << std::dec << std::endl;
        uintptr_t ptr = DecryptUEPointer(encrypted_ptr);
        std::cout << "DecryptUEPointer: 0x" << std::hex << ptr << std::dec << std::endl;


        c_vec3 position = Driver.Read<c_vec3>(ptr + 0x210 + 0x10);

  
        uintptr_t encHandler2 = ptr + 0x210 + 0x30;
        std::cout << "Target Address (Arg3): 0x" << std::hex << encHandler2 << std::dec << std::endl;
 
        uint16_t realID = Driver.Read<uint16_t>(encHandler2);
        std::cout << "Read ID from Address: 0x" << std::hex << realID << std::dec << std::endl;

        uint32_t final_key = GetFinalKey2(0x140000000, realID);

        std::cout << "Final Decrypted Key: 0x" << std::hex << final_key << std::dec << std::endl;

        uint64_t ManagerPtr = Driver.Read<uint64_t>(0x140000000 + 0x13A33CC8);


        uint64_t HiddenArg = Driver.Read<uint64_t>(ManagerPtr + 0x08);

        std::cout << "Hidden Arg: 0x" << std::hex << HiddenArg << std::dec << std::endl;

        printf("Position: X = %.6f  Y = %.6f  Z = %.6f\n", position.x, position.y, position.z);
        printf("EncHandler2 = 0x%X\n", final_key);

        printf("原坐标 %f %f %f %x\n", position.x, position.y, position.z, encHandler2);
        printf("原坐标 %x %x %x\n", *(int*)&position.x, *(int*)&position.y, *(int*)&position.z);
        if (encHandler2 != 0xffff)
        {
            DecFunc_t DecFunc2 = (DecFunc_t)0x14D96ACB0;

            DecFunc2(&position, 0xc, final_key, 0x00004A0000000000 | HiddenArg);
         
            printf("\n");
            printf("解密坐标 %f %f %f %x\n", position.x, position.y, position.z, encHandler2);
            printf("解密坐标 %x %x %x\n", *(int*)&position.x, *(int*)&position.y, *(int*)&position.z);
            printf("\n");
            printf("\n");
            printf("\n");
        }
    }
    std::cin.get();
    std::cout << "Hello World!\n";

}


int main() {
    Initialize("kD52MxWPiuUVSPeh");
}