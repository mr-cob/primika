#!/usr/bin/env python3

from subprocess import run
from sys import argv


###################################
#            Operations           #
###################################

iota_counter = 0


def iota(reset=False):
    global iota_counter
    if reset:
        iota_counter = 0
    iota_count = iota_counter
    iota_counter += 1
    return iota_count


OP_PUSH = iota(True)    # 0
OP_PLUS = iota()        # 1
OP_MINUS = iota()       # 2
OP_DUMP = iota()        # 3
OP_EQUAL = iota()       # 4
OP_IF = iota()          # 5
OP_ELSE = iota()        # 6
OP_END = iota()         # 7
OP_COUNT = iota()       # 8


def push(x):
    return (OP_PUSH, x)


def plus():
    return (OP_PLUS, )


def minus():
    return (OP_MINUS, )


def dump():
    return (OP_DUMP, )


def equal():
    return (OP_EQUAL, )


def iff():
    return (OP_IF, )


def elze():
    return (OP_ELSE, )


def end():
    return (OP_END, )


###################################
#           Interpreter           #
###################################


def interpret_program(program):
    stack = []
    ip = 0

    while ip < len(program):
        assert OP_COUNT == 8, 'Exhaustive handling of operation in `interpret_program`'
        op = program[ip]

        if op[0] == OP_PUSH:
            stack.append(op[1])
            ip += 1
        elif op[0] == OP_PLUS:
            a = stack.pop()
            b = stack.pop()
            stack.append(a + b)
            ip += 1
        elif op[0] == OP_MINUS:
            a = stack.pop()
            b = stack.pop()
            stack.append(b - a)
            ip += 1
        elif op[0] == OP_DUMP:
            a = stack.pop()
            print(a)
            ip += 1
        elif op[0] == OP_EQUAL:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(a == b))
            ip += 1
        elif op[0] == OP_IF:
            a = stack.pop()
            if a == 0:
                assert len(
                    op) == 2, '`if` does not have reference to the end block'
                ip = op[1]
            else:
                ip += 1
        elif op[0] == OP_ELSE:
            assert len(
                op) == 2, '`else` does not have reference to the end block'
            ip = op[1]
        elif op[0] == OP_END:
            ip += 1
        else:
            assert False, 'Unreachable'


###################################
#            Compiling            #
###################################


def compile_program(program, output_path):
    with open(output_path, 'w') as out:
        out.write('segment .text\n')
        out.write('dump:\n')
        out.write('    mov     r9, -3689348814741910323\n')
        out.write('    sub     rsp, 40\n')
        out.write('    mov     BYTE [rsp+31], 10\n')
        out.write('    lea     rcx, [rsp+30]\n')
        out.write('.L2:\n')
        out.write('    mov     rax, rdi\n')
        out.write('    lea     r8, [rsp+32]\n')
        out.write('    mul     r9\n')
        out.write('    mov     rax, rdi\n')
        out.write('    sub     r8, rcx\n')
        out.write('    shr     rdx, 3\n')
        out.write('    lea     rsi, [rdx+rdx*4]\n')
        out.write('    add     rsi, rsi\n')
        out.write('    sub     rax, rsi\n')
        out.write('    add     eax, 48\n')
        out.write('    mov     BYTE [rcx], al\n')
        out.write('    mov     rax, rdi\n')
        out.write('    mov     rdi, rdx\n')
        out.write('    mov     rdx, rcx\n')
        out.write('    sub     rcx, 1\n')
        out.write('    cmp     rax, 9\n')
        out.write('    ja      .L2\n')
        out.write('    lea     rax, [rsp+32]\n')
        out.write('    mov     edi, 1\n')
        out.write('    sub     rdx, rax\n')
        out.write('    xor     eax, eax\n')
        out.write('    lea     rsi, [rsp+32+rdx]\n')
        out.write('    mov     rdx, r8\n')
        out.write('    mov     rax, 1\n')
        out.write('    syscall\n')
        out.write('    add     rsp, 40\n')
        out.write('    ret\n')
        out.write('global   _start\n')
        out.write('_start:\n')
        for ip in range(len(program)):
            assert OP_COUNT == 8, 'Exhaustive handling of operation in `compile_program`'
            op = program[ip]

            if op[0] == OP_PUSH:
                out.write(f'    ;; --- push --- {op[1]}\n')
                out.write(f'    push {op[1]}\n')
            elif op[0] == OP_PLUS:
                out.write('    ;; --- plus ---\n')
                out.write('    pop rax\n')
                out.write('    pop rbx\n')
                out.write('    add rax, rbx\n')
                out.write('    push rax\n')
            elif op[0] == OP_MINUS:
                out.write('    ;; --- minus ---\n')
                out.write('    pop rax\n')
                out.write('    pop rbx\n')
                out.write('    sub rbx, rax\n')
                out.write('    push rbx\n')
            elif op[0] == OP_DUMP:
                out.write('    ;; --- dump ---\n')
                out.write('    pop rdi\n')
                out.write('    call dump\n')
            elif op[0] == OP_EQUAL:
                out.write('    ;; --- equal ---\n')
                out.write('    mov rcx, 0\n')
                out.write('    mov rdx, 1\n')
                out.write('    pop rax\n')
                out.write('    pop rbx\n')
                out.write('    cmp rax, rbx\n')
                out.write('    cmove rcx, rdx\n')
                out.write('    push rcx\n')
            elif op[0] == OP_IF:
                assert len(
                    op) == 2, '`if` does not have reference to the `end` block'
                out.write('    ;; --- if ---\n')
                out.write('    pop rax\n')
                out.write('    test rax, rax\n')
                out.write(f'    jz addr_{op[1]}\n')
            elif op[0] == OP_ELSE:
                assert len(
                    op) == 2, '`else` does not have reference to the `end` block'
                out.write('    ;; --- else ---\n')
                out.write(f'    jmp addr_{op[1]}\n')
                out.write(f'addr_{ip + 1}:\n')
            elif op[0] == OP_END:
                out.write(f'addr_{ip}:\n')
            else:
                assert False, 'Unreachable'
        out.write('    mov rax, 60\n')
        out.write('    mov rdi, 0\n')
        out.write('    syscall\n')


###################################
#            Tokenizer            #
###################################


def crossreference_blocks(program):
    stack = []
    for ip in range(len(program)):
        op = program[ip]
        assert OP_COUNT == 8, 'Exhaustive handeling of ops in `crossreference_blocks`'
        if op[0] == OP_IF:
            stack.append(ip)
        elif op[0] == OP_ELSE:
            if_ip = stack.pop()
            assert program[if_ip][0] == OP_IF, '`else` can only use with `if`'
            program[if_ip] = (OP_IF, ip + 1)
            stack.append(ip)
        elif op[0] == OP_END:
            block_ip = stack.pop()
            if program[block_ip][0] == OP_IF or program[block_ip][0] == OP_ELSE:
                program[block_ip] = (program[block_ip][0], ip)
            else:
                assert False, '`end` can only close `if` and `else`'
    return program


def find_col(line, start, predicate):
    while start < len(line) and not predicate(line[start]):
        start += 1
    return start


def lex_line(line):
    col = find_col(line, 0, lambda x: not x.isspace())
    while col < len(line):
        col_end = find_col(line, col, lambda x: x.isspace())
        yield (col, line[col:col_end])
        col = find_col(line, col_end, lambda x: not x.isspace())


def lex_file(filepath):
    with open(filepath, 'r') as f:
        return [(filepath, row, col, token)
                for (row, line) in enumerate(f.readlines())
                for (col, token) in lex_line(line)]


def parse_token_as_op(token):
    (filepath, row, col, lexeme) = token
    assert OP_COUNT == 8, 'Exhaustive handling of operation in `parse_token_as_op`'
    if lexeme == '+':
        return plus()
    elif lexeme == '-':
        return minus()
    elif lexeme == '.':
        return dump()
    elif lexeme == '=':
        return equal()
    elif lexeme == 'if':
        return iff()
    elif lexeme == 'else':
        return elze()
    elif lexeme == 'end':
        return end()
    else:
        try:
            return push(int(lexeme))
        except:
            print(
                f'ERROR: Invalid Lexeme in file {filepath}, line {row}:{col}')
            exit(1)


def load_program_from_file(filepath):
    with open(filepath, 'r') as f:
        return crossreference_blocks(
            [parse_token_as_op(token) for token in lex_file(filepath)])


###################################
#               CMD               #
###################################


def usage():
    print('Usage: primika <SUBCOMMANDS> [ARGS]')
    print('SUBCOMMANDS:')
    print('    i <source_file>       Interpret the program')
    print('    c <source_file>       Compile the program')


def call_cmd(command):
    run(command.split(' '))
    print(f'[CMD] {command}')


def uncons(xs):
    return (xs[0], xs[1:])


if __name__ == '__main__':
    (_, argv) = uncons(argv)
    if len(argv) < 1:
        usage()
        print(f'ERROR: no subcommand provided')
        exit(1)

    (subcommand, argv) = uncons(argv)
    if subcommand == 'i':
        if len(argv) < 1:
            usage()
            print('ERROR: no input file provided.')
            exit(1)
        (filepath, argv) = uncons(argv)
        program = load_program_from_file(filepath)
        interpret_program(program)
    elif subcommand == 'c':
        if len(argv) < 1:
            usage()
            print('ERROR: no input file provided.')
            exit(1)
        (filepath, argv) = uncons(argv)
        program = load_program_from_file(filepath)
        compile_program(program, 'output.asm')
        call_cmd('nasm -felf64 output.asm')
        call_cmd('ld -o output output.o')
    else:
        usage()
        print(f'ERROR: unknown subcommand {subcommand}')
        exit(1)
