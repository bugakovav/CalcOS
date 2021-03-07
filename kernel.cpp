// Эта инструкция обязательно должна быть первой, т.к. этот код компилируется в бинарный,
// и загрузчик передает управление по адресу первой инструкции бинарного образа ядра ОС.
__asm("jmp kmain");

#define VIDEO_BUF_PTR (0xb8000)
#define IDT_TYPE_INTR (0x0E)
#define IDT_TYPE_TRAP (0x0F)
#define SYSTEM_COLOR (0x7e00)

#define GDT_CS (0x8)
#define PIC1_PORT (0x20)
#define CURSOR_PORT (0x3D4)
#define VIDEO_WIDTH (80)

#define DEFAULT_COLOR 0x0F

#define FAIL_EXIT -1
#define SUCCESS_EXIT 0
#define NULL 0
#define TRUE 1
#define FALSE 0

#define OR ||
#define AND &&

#define ENTER 28
#define L_SHIFT 42
#define R_SHIFT 54
#define BACKSPACE 14

#define HEX 16
#define DEC 10
#define BIN 2

#define INT_MAX 2147483647
#define INT_MIN -2147483648

#define BUF_SIZE 40

#define SYSTEM_NL 0
#define USER_NL 1

typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned char u_char;
typedef const char c_char;

// Структура описывает данные об обработчике прерывания
struct idt_entry
{
    unsigned short base_lo;
    // Младшие биты адреса обработчика
    unsigned short segm_sel;
    // Селектор сегмента кода
    unsigned char always0;
    // Этот байт всегда 0
    unsigned char flags;
    // Флаги тип. Флаги: P, DPL, Типы - это константы - IDT_TYPE...
    unsigned short base_hi;
    // Старшие биты адреса обработчика
} __attribute__((packed)); // Выравнивание запрещено

// Структура, адрес которой передается как аргумент команды lidt
struct idt_ptr
{
    unsigned short limit;
    unsigned int base;
} __attribute__((packed)); // Выравнивание запрещено

typedef void (*intr_handler)();

struct idt_entry g_idt[256]; // Реальная таблица IDT
struct idt_ptr g_idtp;       // Описатель таблицы для команды lidt

u_short g_color;
u_short g_strnum;
u_short g_pos;

u_char g_buf[BUF_SIZE];
u_short g_buf_pos;

u_char g_expr[BUF_SIZE];
u_short g_expr_pos;

enum cmd_n
{
    help = 0,
    info = 1,
    expr = 2,
    clear = 3,
    shutdown = 4,
    wrong_cmd = -1
};

struct info_t
{
    c_char *hello;
    c_char *name_os;
    c_char *name_comp;
    c_char *info_op;
    c_char *error_cmd;
    c_char *help;
} os_info;

u_char available[] = {"1234567890+/-*\0"};

char scan_codes[] =
    {
        0,
        0, // ESC(this button starts with number "1")
        '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=',
        0,    // BACKSPACE(14)
        '\t', // TAB(15)
        'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']',
        0, // ENTER(28)
        0, // CTRL(29)
        'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', '<', '>', '+',
        0, // left SHIFT(42)
        '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/',
        0,                            // right SHIFT(54)
        '*',                          // NUMPAD *
        0,                            // ALT
        0,                            // SPACE
        0,                            //CAPSLOCK
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //F1 - F10
        0,                            //NUMLOCK
        0,                            //SCROLLOCK
        0,                            //HOME
        0,
        0,   //PAGE UP
        '-', //NUMPAD
        0, 0,
        0,   //(r)
        '+', //NUMPAD
};

void default_intr_handler();
void intr_reg_handler(int num, unsigned short segm_sel, unsigned short flags, intr_handler hndlr);
void intr_init();
void intr_start();
void intr_enable();
void intr_disable();

static inline void outw(unsigned int port, unsigned int data);
static inline unsigned char inb(unsigned short port);             // Чтение из порта
static inline void outb(unsigned short port, unsigned char data); // Запись

void keyb_init();
void keyb_handler();
void keyb_process_keys();
void cursor_moveto(unsigned int strnum, unsigned int pos);

void write_char(u_char s);
void write_str(c_char *str);

bool strcmp_buf(u_char *s1, c_char *s2);
void clear_buf(u_char *str, u_int size);

void mv_cur_r(void);
void mv_cur_l(void);
void mv_cur_nl(bool user);

int read_command(void);
void handle_command(int num);
int handle_expr(void);

bool init()
{
    intr_disable();

    switch (*(char *)SYSTEM_COLOR)
    {
    case '1': // green
        g_color = 0x02;
        break;
    case '2': // blue
        g_color = 0x01;
        break;
    case '3': // red
        g_color = 0x04;
        break;
    case '4': // yellow
        g_color = 0x0E;
        break;
    case '5': // gray
        g_color = 0x07;
        break;
    case '6': // white
        g_color = 0x0F;
        break;
    default:
        g_color = DEFAULT_COLOR;
        break;
    }

    g_strnum = 0;
    g_pos = 0;

    os_info.hello = "Welcome CalcOS!\0";

    write_str(os_info.hello);
    mv_cur_nl(SYSTEM_NL);

    os_info.name_os = "Calc OS: v.01. Developer: Bugakov Artem, 54/1, SpbPU, 2021\0";
    os_info.name_comp = "Compilers: bootloader: YASM, kernel: gcc\0";

    os_info.info_op = "Bootloader parameters: green color.\0";

    os_info.error_cmd = "Error: command not recognized\0";

    os_info.help = "Not implemented\0";

    g_buf_pos = 0;
    clear_buf(g_buf, BUF_SIZE);

    g_expr_pos = 0;
    clear_buf(g_expr, BUF_SIZE);

    intr_init();
    keyb_init();
    intr_start();
    intr_enable();

    return true;
}

bool strcmp_buf(u_char *s1, c_char *s2)
{
    while (*s1 AND * s2 AND * s1 == *s2)
    {
        s1 += 1;
        s2 += 1;
    }

    if (*s1 != *s2)
        return false;
    else
        return true;
}

void write_str(c_char *str)
{
    u_char *video_buf = (u_char *)VIDEO_BUF_PTR;
    video_buf += (VIDEO_WIDTH * g_strnum + g_pos) * 2;

    while (*str)
    {
        video_buf[0] = (u_char)*str;
        video_buf[1] = (u_char)g_color;

        g_pos += 1;

        video_buf += 2;
        str += 1;
    }
}

void write_char(u_char s)
{
    u_char *video_buf = (u_char *)VIDEO_BUF_PTR;
    video_buf += (VIDEO_WIDTH * g_strnum + g_pos) * 2;

    video_buf[0] = s;
    video_buf[1] = (u_char)g_color;

    video_buf += 2;
}

void clear_buf(u_char *str, u_int size)
{
    for (int i = 0; i < size; i++)
        str[i] = '\0';
}

u_int strlen(c_char *str)
{
    int i;

    for (i = 0; str[i] != '\0' and i < BUF_SIZE; i++)
        ;

    if (i = BUF_SIZE)
        return 0;
    else
        return i;
}

void on_key(u_char scan_code) // Обработчик клавиши
{
    u_int index = (u_int)scan_code; // Индексация по таблице

    char sym = scan_codes[index]; // Символ по таблице

    if (index == L_SHIFT OR index == R_SHIFT) // Спец. клавиши
        return;

    if (index != BACKSPACE and index != ENTER) // Добавление в программный буфер
        g_buf[g_buf_pos++] = sym;

    write_char(sym); // Вывод символа

    switch (index) // Проверка индекса на спец. клавиши
    {
    case ENTER:
        mv_cur_nl(USER_NL);
        break;
    case BACKSPACE:
        mv_cur_l();
        break;
    default:
        mv_cur_r();
        break;
    }
}

void mv_cur_r(void)
{
    if (g_pos + 1 > VIDEO_WIDTH)
        return;

    g_pos += 1;
    cursor_moveto(g_strnum, g_pos);
}

void mv_cur_l(void)
{
    if (g_pos - 1 < 0)
        return;

    g_pos -= 1;
    g_buf_pos -= 1;

    write_char(NULL);
    cursor_moveto(g_strnum, g_pos);
}

void mv_cur_nl(bool user) // NEW LINE
{
    g_pos = 0;
    g_strnum += 1;
    cursor_moveto(g_strnum, g_pos);

    if (user)
    {
        intr_disable();
        handle_command(read_command());
        intr_enable();
    }
}

int read_command(void)
{
    if (strcmp_buf(g_buf, "info"))
        return info;
    if (strcmp_buf(g_buf, "expr"))
        return expr;

    return wrong_cmd;
}

void info_func(void)
{
    write_str(os_info.name_os);
    mv_cur_nl(SYSTEM_NL);
    write_str(os_info.name_comp);
    mv_cur_nl(SYSTEM_NL);
    write_str(os_info.info_op);
    mv_cur_nl(SYSTEM_NL);
}

void invalid_func(void)
{
    write_str(os_info.error_cmd);
    mv_cur_nl(SYSTEM_NL);
}

bool is_avilable(u_char sym)
{
    for (int i = 0; i < 16; i++)
        if (sym == available[i])
            return true;

    return false;
}

bool validate_expr_arg(void)
{
    for (int i = 5; i < BUF_SIZE; i++) // strlen("expr\0");
        if (!is_avilable(g_buf[i]))
            return false;

    return true;
}

void expr_func(void)
{
    if (!validate_expr_arg())
    {
        write_str("Incorrect argument\0");
        mv_cur_nl(SYSTEM_NL);
        return;
    }

    for (int i = 5; i < BUF_SIZE; i++) // write expr to buf for func
        if (g_buf[i] != '\0')
            g_expr[g_expr_pos++] = g_buf[i];

    handle_expr();

    clear_buf(g_expr, BUF_SIZE);
    g_expr_pos = 0;
}

void handle_command(int num)
{
    switch (num)
    {
    case info:
        info_func();
        break;
    case expr:
        expr_func();
        break;
    case wrong_cmd:
        invalid_func();
        break;
    }

    clear_buf(g_buf, BUF_SIZE);
    g_buf_pos = 0;
}

extern "C" int kmain()
{
    if (!init())
        return FAIL_EXIT;

    while (1)
    {
        asm("hlt");
    }

    return SUCCESS_EXIT;
}

// Пустой обработчик прерываний. Другие обработчики могут быть реализованы по этому шаблону
void default_intr_handler()
{
    asm("pusha");
    // ... (реализация обработки)
    asm("popa; leave; iret");
}

// Функция регистрации необходимых обработчиков (таймер, клавиатура, диск и т.д.)
void intr_reg_handler(int num, unsigned short segm_sel, unsigned short flags, intr_handler hndlr)
{
    unsigned int hndlr_addr = (unsigned int)hndlr;

    g_idt[num].base_lo = (unsigned short)(hndlr_addr & 0xFFFF);
    g_idt[num].segm_sel = segm_sel;
    g_idt[num].always0 = 0;
    g_idt[num].flags = flags;
    g_idt[num].base_hi = (unsigned short)(hndlr_addr >> 16);
}

// Функция инициализации системы прерываний: заполнение массива с адресами обработчиков
void intr_init()
{
    int i;
    int idt_count = sizeof(g_idt) / sizeof(g_idt[0]);

    for (i = 0; i < idt_count; i++)
        intr_reg_handler(i, GDT_CS, 0x80 | IDT_TYPE_INTR,
                         default_intr_handler); // segm_sel=0x8, P=1, DPL=0, Type=Intr
}

// Функция регистрации таблицы дескрипторов прерываний
void intr_start()
{
    int idt_count = sizeof(g_idt) / sizeof(g_idt[0]);

    g_idtp.base = (unsigned int)(&g_idt[0]);
    g_idtp.limit = (sizeof(struct idt_entry) * idt_count) - 1;

    asm("lidt %0"
        :
        : "m"(g_idtp));
}

void intr_enable()
{
    asm("sti");
}

void intr_disable()
{
    asm("cli");
}

// Чтение из порта
static inline unsigned char inb(unsigned short port)
{
    unsigned char data;
    asm volatile("inb %w1, %b0"
                 : "=a"(data)
                 : "Nd"(port));
    return data;
}

// Запись в порт
static inline void outb(unsigned short port, unsigned char data) // Запись
{
    asm volatile("outb %b0, %w1"
                 :
                 : "a"(data), "Nd"(port));
}

static inline void outw(unsigned int port, unsigned int data)
{
    asm volatile("outw %w0, %w1"
                 :
                 : "a"(data), "Nd"(port));
}

// регистрирует обработчик прерывания клавиатуры и разрешает контроллеру прерываний его вызывать в случае нажатия пользователем клавиши клавиатуры
void keyb_init()
{
    // Регистрация обработчика прерывания
    intr_reg_handler(0x09, GDT_CS, 0x80 | IDT_TYPE_INTR, keyb_handler);
    // segm_sel=0x8, P=1, DPL=0, Type=Intr
    // Разрешение только прерываний клавиатуры от контроллера 8259
    outb(PIC1_PORT + 1, 0xFF ^ 0x02); // 0xFF - все прерывания, 0x02 - бит IRQ1 (клавиатура).
    // Разрешены будут только прерывания, чьи биты установлены в 0
}

// обработчик прерываний
void keyb_handler()
{
    asm("pusha");
    // Обработка поступивших данных
    keyb_process_keys();
    // Отправка контроллеру 8259 нотификации о том, что прерывание обработано
    outb(PIC1_PORT, 0x20);
    asm("popa; leave; iret");
}

// считывает поступивший от пользователя символ
void keyb_process_keys()
{
    // Проверка что буфер PS/2 клавиатуры не пуст (младший бит присутствует)
    if (inb(0x64) & 0x01)
    {
        unsigned char scan_code;
        unsigned char state;
        scan_code = inb(0x60); // Считывание символа с PS/2 клавиатуры
        if (scan_code < 128)   // Скан-коды выше 128 - это отпускание клавиши
            on_key(scan_code);
    }
}

// Функция переводит курсор на строку strnum (0 – самая верхняя) в позицию pos на этой строке (0 – самое левое положение).
void cursor_moveto(unsigned int strnum, unsigned int pos)
{
    unsigned short new_pos = (strnum * VIDEO_WIDTH) + pos;
    outb(CURSOR_PORT, 0x0F);
    outb(CURSOR_PORT + 1, (unsigned char)(new_pos & 0xFF));
    outb(CURSOR_PORT, 0x0E);
    outb(CURSOR_PORT + 1, (unsigned char)((new_pos >> 8) & 0xFF));
}

int atoi(char *str)
{
    int sign = 1, base = 0, i = 0;

    while (str[i] == ' ')
    {
        i++;
    }

    if (str[i] == '-' || str[i] == '+')
    {
        sign = 1 - 2 * (str[i++] == '-');
    }

    while (str[i] >= '0' && str[i] <= '9')
    {
        if (base > INT_MAX / 10 || (base == INT_MAX / 10 && str[i] - '0' > 7))
        {
            if (sign == 1)
                return INT_MAX;
            else
                return INT_MIN;
        }
        base = 10 * base + (str[i++] - '0');
    }
    return base * sign;
}

char *itoa(int num, char *str, int base)
{
    int i = 0;
    bool isNegative = false;

    if (num == 0)
    {
        str[i++] = '0';
        str[i] = '\0';
        return str;
    }

    if (num < 0 && base == 10)
    {
        isNegative = true;
        num = -num;
    }

    while (num != 0)
    {
        int rem = num % base;
        str[i++] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
        num = num / base;
    }

    if (isNegative)
        str[i++] = '-';

    str[i] = '\0';

    int start = 0;
    int end = i - 1;
    char tmp;

    while (start < end)
    {
        tmp = *(str + start);
        *(str + start) = *(str + end);
        *(str + end) = tmp;

        start++;
        end--;
    }

    return str;
}

#define SIZE_BUF 40

//char available[] = {"1234567890-+/*\0"};
char digits[] = {"1234567890\0"};

int p_input = 0;
char input[SIZE_BUF];

bool isdigit(char sym)
{
    for (int i = 0; i < strlen(digits); i++)
    {
        if (digits[i] == sym)
            return true;
    }

    return false;
}

char limit_max[] = {"2147483647"};
char limit_min[] = {"-2147483648"};

bool validate_int_max(char *str)
{
    if (strlen(str) > strlen(limit_max))
        return false;
    else if (strlen(str) == strlen(limit_max))
    {
        for (int i = 0; i < strlen(str); i++)
        {
            if (str[i] - '0' < limit_max[i] - '0')
                return true;
            if (str[i] - '0' > limit_max[i] - '0')
                return false;
        }
    }
    else
        return true;

    return true;
}

bool validate_int_min(char *str)
{
    if (strlen(str) > strlen(limit_min))
        return false;
    else if (strlen(str) == strlen(limit_min))
    {
        for (int i = 1; i < strlen(str); i++)
        {
            if (str[i] - '0' < limit_min[i] - '0')
                return true;
            if (str[i] - '0' > limit_min[i] - '0')
                return false;
        }
    }
    else
        return true;

    return true;
}

bool validate_num(char *num)
{
    bool success;

    if (num[0] == '-')
        success = validate_int_min(num);
    else
        success = validate_int_max(num);

    return success;
}

struct elem_output
{
    char op;
    int num;
    bool select;
};

typedef struct elem_output elem_output;

elem_output output[256]; // Массив для ОПЗ

char stack[256]; // Стек для операций

int int_stack[256]; // Стек для результирующей функции calc

int p_stack = 0, p_output = 0;

void clean_str(char *str)
{
    for (int i = 0; i < strlen(str) and i < SIZE_BUF; i++)
        str[i] = 0;
}

int RESULT = -1;

bool calc(void)
{
    p_stack = 0;

    for (int i = 0; i < p_output; i++)
    {
        switch (output[i].select)
        {
        case 0:
            int_stack[p_stack++] = output[i].num;
            break;
        case 1:
        {
            int op1, op2;

            int no_overflow = 1;

            if (p_stack >= 1) // Для бинарной операции должно быть точно два операнда
            {
                op2 = int_stack[p_stack - 1];
                op1 = int_stack[p_stack - 2];

                p_stack -= 2;

                switch (output[i].op)
                {
                case '+':
                    int_stack[p_stack++] = op1 + op2;
                    asm("jno NO_OVERFLOW_SUM");
                    asm("mov $0x0, %0"
                        : "=r"(no_overflow));
                    asm("NO_OVERFLOW_SUM:");
                    break;
                case '-':
                    int_stack[p_stack++] = op1 - op2;
                    asm("jno NO_OVERFLOW_SUB");
                    asm("mov $0x0, %0"
                        : "=r"(no_overflow));
                    asm("NO_OVERFLOW_SUB:");
                    break;
                case '*':
                    int_stack[p_stack++] = op1 * op2;
                    asm("jno NO_OVERFLOW_MULT");
                    asm("mov $0x0, %0"
                        : "=r"(no_overflow));
                    asm("NO_OVERFLOW_MULT:");
                    break;
                case '/':
                    if (op2 == 0)
                    {
                        write_str("Error: division by 0");
                        mv_cur_nl(SYSTEM_NL);
                        return false;
                    }
                    int_stack[p_stack++] = op1 / op2;
                    asm("jno NO_OVERFLOW_DIV");
                    asm("mov $0x0, %0"
                        : "=r"(no_overflow));
                    asm("NO_OVERFLOW_DIV:");
                    break;
                }

                if (!no_overflow)
                {
                    write_str("Error: integer overflow");
                    mv_cur_nl(SYSTEM_NL);

                    return false;
                }
            }
            else
            {
                write_str("Error: ivalid expression");
                mv_cur_nl(SYSTEM_NL);

                return false;
            }
            break;
        }
        }
    }

    RESULT = int_stack[0];

    char res[SIZE_BUF] = {0};

    itoa(RESULT, res, 10);

    write_str((c_char *)res);
    mv_cur_nl(SYSTEM_NL);

    return true;
}

int handle_expr(void)
{
    int num_int = 0;
    char num_char[SIZE_BUF];
    int p_num = 0;

    for (int i = 0; i < strlen((c_char *)g_expr); i++)
    {
        if (isdigit(g_expr[i]))
        {
            while (isdigit(g_expr[i]))
            {
                num_char[p_num++] = g_expr[i++];
            }

            p_num = 0;
            i--;

            if (!validate_num(num_char))
            {
                write_str("Error: integer overflow");
                mv_cur_nl(SYSTEM_NL);

                return -1;
            }

            num_int = atoi(num_char);

            output[p_output].select = 0; // 0 - num, 1 - op
            output[p_output++].num = num_int;

            clean_str(num_char);
            continue;
        }

        switch (g_expr[i])
        {
        case '+':
        {
            while (i < SIZE_BUF - 1 and g_expr[i + 1] == '+')
                i++;

            if (i < SIZE_BUF - 1 and g_expr[i + 1] != '-' and g_expr[i + 1] != '+' and !isdigit(g_expr[i + 1]))
            {
                write_str("Next value is not digit or '('");
                mv_cur_nl(SYSTEM_NL);

                return -1;
            }

            while (p_stack > 0 and stack[p_stack - 1] == '*' or stack[p_stack - 1] == '/')
            {
                output[p_output].select = 1;
                output[p_output++].op = stack[p_stack - 1];
                p_stack--;
            }
            stack[p_stack++] = '+';
            break;
        }
        case '-':
        {
            int count_minus = 1; // Для подсчета унарных минусов
            while (i < SIZE_BUF - 1 and g_expr[i + 1] == '-')
            {
                i++;
                count_minus++;
            }
            if (i < SIZE_BUF - 1 and g_expr[i + 1] != '-' and g_expr[i + 1] != '+' and !isdigit(g_expr[i + 1]))
            {
                write_str("Next value is not digit or '('");
                mv_cur_nl(SYSTEM_NL);

                return -1;
            }
            while (p_stack > 0 and stack[p_stack - 1] == '*' or stack[p_stack - 1] == '/')
            {
                output[p_output].select = 1;
                output[p_output++].op = stack[p_stack - 1];
                p_stack--;
            }
            if (count_minus % 2 == 0)
                stack[p_stack++] = '+'; // Зависит от количества унарных минусов
            else
                stack[p_stack++] = '-';
            break;
        }
        case '*':
        {
            if (i < SIZE_BUF - 1 and g_expr[i + 1] != '-' and g_expr[i + 1] != '+' and !isdigit(g_expr[i + 1])) // Если после текущей операции стоит не число и не скобка
            {
                write_str("Next value is not digit or '('");
                mv_cur_nl(SYSTEM_NL);

                return -1;
            }
            while (p_stack > 0 and stack[p_stack - 1] == '*' or stack[p_stack - 1] == '/') // Если сверху стека операция приоритетнее текущей
            {
                output[p_output].select = 1;
                output[p_output++].op = stack[p_stack - 1];
                p_stack--;
            }
            stack[p_stack++] = '*';
            break;
        }
        case '/':
        {
            if (i < SIZE_BUF - 1 and g_expr[i + 1] != '-' and g_expr[i + 1] != '+' and !isdigit(g_expr[i + 1]))
            {
                write_str("Next value is not digit or '('");
                mv_cur_nl(SYSTEM_NL);

                return -1;
            }

            while (p_stack > 0 and stack[p_stack - 1] == '*' or stack[p_stack - 1] == '/')
            {
                output[p_output].select = 1;
                output[p_output++].op = stack[p_stack - 1];
                p_stack--;
            }
            stack[p_stack++] = '/';
            break;
        }
        default:
            write_str("Error: invalid expression");
            mv_cur_nl(SYSTEM_NL);

            return -1;
        }
    }

    for (int i = 0; i < p_stack; i++)
    {
        output[p_output].select = 1;
        output[p_output++].op = stack[i];
    }

    calc();

    return 0;
}