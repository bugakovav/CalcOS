// Эта инструкция обязательно должна быть первой, т.к. этот код компилируется в бинарный,
// и загрузчик передает управление по адресу первой инструкции бинарного образа ядра ОС.
__asm("jmp kmain");

#define VIDEO_BUF_PTR (0xb8000)
#define IDT_TYPE_INTR (0x0E)
#define IDT_TYPE_TRAP (0x0F)

#define GDT_CS (0x8)
#define PIC1_PORT (0x20)
#define CURSOR_PORT (0x3D4)
#define VIDEO_WIDTH (80)

#define DEFAULT_COLOR 0x0F
#define SIZE_BUF 40

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

u_char g_buf[256];
u_short g_buf_pos;

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
    c_char *name_os;
    c_char *name_comp;
    c_char *info_op;
    c_char *error_cmd;
    c_char *help;
} os_info;

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
        ' ',                          // SPACE
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
void out_str(int color, const char *ptr, unsigned int strnum);

void out_char(int color, unsigned char simbol);
void out_word(int color, const char *ptr);
void out_num(int num);
static inline void outw(unsigned int port, unsigned int data);

static inline unsigned char inb(unsigned short port);             // Чтение из порта
static inline void outb(unsigned short port, unsigned char data); // Запись
void keyb_init();
void keyb_handler();
void keyb_process_keys();
void cursor_moveto(unsigned int strnum, unsigned int pos);

bool strcmp(char *str, char *cmd);

void mv_cur_r(void);
void mv_cur_l(void);
void mv_cur_nl(bool user);

int read_command(void);
void handle_command(int num);

bool init()
{
    intr_disable();

    os_info.name_os = "Welcome to CalcOS\0";
    os_info.name_comp = "YASM & GCC\0";
    os_info.info_op = "The loader has a global color selection function\0";
    os_info.error_cmd = "Incorrect command\0";
    os_info.help = "Commads: info, expr, shutdown\0";

    g_color = DEFAULT_COLOR;
    g_strnum = 0;
    g_pos = 0;

    g_buf_pos = 0;

    intr_init();
    keyb_init();
    intr_start();
    intr_enable();

    return true;
}

bool strcmp(char *str, char *cmd)
{
    while (*str AND * cmd AND * str == *cmd AND * str != ' ')
    {
        str += 1;
        cmd += 1;
    }

    if (*str != *cmd)
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

void on_key(u_char scan_code) // Обработчик клавиши
{
    u_int index = (u_int)scan_code; // Индексация по таблице

    char sym = scan_codes[index]; // Символ по таблице

    if (index == L_SHIFT OR index == R_SHIFT) // Спец. клавиши
        return;

    if (index != BACKSPACE) // Добавление в программный буфер
        g_buf[g_buf_pos] = sym;

    write_char(sym); // Вывод символа

    switch (index) // Проверка индекса на спец. клавиши
    {
    case ENTER:
        mv_cur_nl(TRUE);
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
    if (g_pos + 1 >= VIDEO_WIDTH - 40)
        return;

    g_pos += 1;
    g_buf_pos += 1;

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
    if (strcmp((char *)g_buf, (char *)"help"))
        return help;
    if (strcmp((char *)g_buf, (char *)"info"))
        return info;
    if (strcmp((char *)g_buf, (char *)"expr"))
        return expr;

    return wrong_cmd;
}

void handle_command(int num)
{
    switch (num)
    {
    case help:
        write_str(os_info.help);
        mv_cur_nl(FALSE);
        break;
    case info:
        write_str(os_info.name_os);
        mv_cur_nl(FALSE);
        write_str(os_info.name_comp);
        mv_cur_nl(FALSE);
        write_str(os_info.info_op);
        mv_cur_nl(FALSE);
        break;
    case expr:
        write_str("Hello from expr");
        mv_cur_nl(FALSE);
        break;
    case wrong_cmd:
        write_str(os_info.error_cmd);
        mv_cur_nl(FALSE);
        break;
    }

    for (int i = 0; i < SIZE_BUF; i++) // Очистить программный буфер
        g_buf[i] = '\0';

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