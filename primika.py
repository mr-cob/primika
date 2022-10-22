#!/usr/bin/env python3

from subprocess import run
from sys import argv


iota_counter = 0


def iota(reset=False):
    global iota_counter
    if reset:
        iota_counter = 0
    iota_count = iota_counter
    iota_counter += 1
    return iota_count


OP_PUSH = iota(True)
OP_PLUS = iota()
OP_MINUS = iota()
OP_DUMP = iota()
OP_COUNT = iota()


def push(x):
    return (OP_PUSH, x)


def plus():
    return (OP_PLUS, )


def minus():
    return (OP_MINUS, )


def dump():
    return (OP_DUMP, )


def interpret_program(program):
    stack = []
    for op in program:
        assert OP_COUNT == 4, "Exhaustive handling of operation in `interpret_program`"
        if op[0] == OP_PUSH:
            stack.append(op[1])
        elif op[0] == OP_PLUS:
            a = stack.pop()
            b = stack.pop()
            stack.append(a + b)
        elif op[0] == OP_MINUS:
            a = stack.pop()
            b = stack.pop()
            stack.append(a - b)
        elif op[0] == OP_DUMP:
            a = stack.pop()
            print(a)
        else:
            assert False, "Unreachable"


def compile_program(program, output_path):
    with open(output_path, "w") as out:
        out.write("segment .text\n")
        out.write("dump:\n")
        out.write("    mov     r9, -3689348814741910323\n")
        out.write("    sub     rsp, 40\n")
        out.write("    mov     BYTE [rsp+31], 10\n")
        out.write("    lea     rcx, [rsp+30]\n")
        out.write(".L2:\n")
        out.write("    mov     rax, rdi\n")
        out.write("    lea     r8, [rsp+32]\n")
        out.write("    mul     r9\n")
        out.write("    mov     rax, rdi\n")
        out.write("    sub     r8, rcx\n")
        out.write("    shr     rdx, 3\n")
        out.write("    lea     rsi, [rdx+rdx*4]\n")
        out.write("    add     rsi, rsi\n")
        out.write("    sub     rax, rsi\n")
        out.write("    add     eax, 48\n")
        out.write("    mov     BYTE [rcx], al\n")
        out.write("    mov     rax, rdi\n")
        out.write("    mov     rdi, rdx\n")
        out.write("    mov     rdx, rcx\n")
        out.write("    sub     rcx, 1\n")
        out.write("    cmp     rax, 9\n")
        out.write("    ja      .L2\n")
        out.write("    lea     rax, [rsp+32]\n")
        out.write("    mov     edi, 1\n")
        out.write("    sub     rdx, rax\n")
        out.write("    xor     eax, eax\n")
        out.write("    lea     rsi, [rsp+32+rdx]\n")
        out.write("    mov     rdx, r8\n")
        out.write("    mov     rax, 1\n")
        out.write("    syscall\n")
        out.write("    add     rsp, 40\n")
        out.write("    ret\n")
        out.write("global   _start\n")
        out.write("_start:\n")
        for op in program:
            assert OP_COUNT == 4, "Exhaustive handling of operation in `compile_program`"
            if op[0] == OP_PUSH:
                out.write(f"    ;; push {op[1]}\n")
                out.write(f"    push {op[1]}\n")
            elif op[0] == OP_PLUS:
                out.write("    ;; plus\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    add rax, rbx\n")
                out.write("    push rax\n")
            elif op[0] == OP_MINUS:
                out.write("    ;; minus\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    sub rax, rbx\n")
                out.write("    push rax\n")
            elif op[0] == OP_DUMP:
                out.write("    ;; dump\n")
            else:
                assert False, "Unreachable"
        out.write("    mov rax, 60\n")
        out.write("    mov rdi, 0\n")
        out.write("    syscall\n")


program = [
    push(1),
    push(1),
    plus(),
    dump(),
    push(1),
    push(1),
    minus(),
    dump()
]


def usage():
    print("Usage: primika <SUBCOMMANDS> [ARGS]")
    print("SUBCOMMANDS:")
    print("    int        Interpret the program")
    print("    com        Compile the program")


def call_cmd(command):
    run(command.split(" "))
    print(f"+ {command}")


if __name__ == "__main__":
    if len(argv) < 2:
        usage()
        print(f"ERROR: no subcommand provided")
        exit(1)

    subcommand = argv[1]

    if subcommand == "int":
        interpret_program(program)
    elif subcommand == "com":
        compile_program(program, "output.asm")
        call_cmd("nasm -felf64 output.asm")
        call_cmd("ld -o output output.o")
    else:
        usage()
        print(f"ERROR: unknown subcommand {subcommand}")
        exit(1)