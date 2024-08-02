#include <bear/fuzzer.h>

typedef enum { STATIC, FUZZY_INTEGER, FUZZY_STRING, BLOCK_SIZE } BearFuzzyValueType;

struct _BearFuzzyValue {
    GObject parent_instance;

    GBytes *reference_value;
    gsize max_string_length;

    BearFuzzyValueType value_type;
    GList *possible_values;
    gchar *my_block_name;
    gchar *referenced_block_name;

    GBytes *computed_data;
    gboolean computing;
};

G_DEFINE_TYPE(BearFuzzyValue, bear_fuzzy_value, G_TYPE_OBJECT)

static void bear_fuzzy_value_init(BearFuzzyValue *value) {
    value->value_type = FUZZY_INTEGER;
    value->max_string_length = 1024;
}

static void bear_fuzzy_value_finalize(GObject *object) {
    BearFuzzyValue *value = BEAR_FUZZY_VALUE(object);

    g_list_free_full(value->possible_values, (GDestroyNotify)g_bytes_unref);
    g_free(value->my_block_name);
    g_free(value->referenced_block_name);
    g_bytes_unref(value->reference_value);
    g_bytes_unref(value->computed_data);

    G_OBJECT_CLASS(bear_fuzzy_value_parent_class)->finalize(object);
}

static void bear_fuzzy_value_class_init(BearFuzzyValueClass *klass) { G_OBJECT_CLASS(klass)->finalize = bear_fuzzy_value_finalize; }

BearFuzzyValue *bear_fuzzy_value_new_sizeof_block(const gchar *block_name, gsize integer_size) {
    g_return_val_if_fail(block_name != NULL, NULL);
    g_return_val_if_fail(integer_size == 1 || integer_size == 2 || integer_size == 4, NULL);

    BearFuzzyValue *value = g_object_new(BEAR_TYPE_FUZZY_VALUE, NULL);
    value->referenced_block_name = g_strdup(block_name);
    guint32 dummy = 0xB5B5B5B5;
    value->reference_value = g_bytes_new(&dummy, integer_size);
    value->value_type = BLOCK_SIZE;

    return value;
}

BearFuzzyValue *bear_fuzzy_value_new_static(GBytes *data) {
    g_return_val_if_fail(data != NULL, NULL);
    BearFuzzyValue *value = g_object_new(BEAR_TYPE_FUZZY_VALUE, NULL);
    value->reference_value = g_bytes_ref(data);
    value->value_type = STATIC;
    return value;
}

BearFuzzyValue *bear_fuzzy_value_new_variable(GBytes *data) {
    BearFuzzyValue *value = bear_fuzzy_value_new_static(data);
    value->value_type = FUZZY_INTEGER;
    return value;
}

BearFuzzyValue *bear_fuzzy_value_new_variable_string(const gchar *initial_value) {
    g_autoptr(GBytes) data = g_bytes_new(initial_value, strlen(initial_value));
    BearFuzzyValue *value = bear_fuzzy_value_new_variable(data);
    value->value_type = FUZZY_STRING;
    return value;
}

BearFuzzyValue *bear_fuzzy_value_new_static_string(const gchar *string) {
    BearFuzzyValue *value = bear_fuzzy_value_new_variable_string(string);
    value->value_type = STATIC;
    return value;
}

static void add_unique_int(BearFuzzyValue *value, guint32 new_value) {
    gsize integer_size = g_bytes_get_size(value->reference_value);
    guint32 mask = 0;
    for (gsize i = 0; i < integer_size; i++)
        mask |= 0xFF << (i * 8);
    new_value &= mask;

    g_autoptr(GBytes) new_entry = g_bytes_new(&new_value, integer_size);
    for (GList *iter = value->possible_values; iter != NULL; iter = g_list_next(iter)) {
        GBytes *entry = iter->data;
        if (g_bytes_compare(entry, new_entry) == 0)
            return;
    }
    value->possible_values = g_list_append(value->possible_values, g_bytes_ref(new_entry));
}

static void add_fuzzy_int(BearFuzzyValue *value, guint32 v, int fuzz) {
    for (gint64 i = v - fuzz; i <= v + fuzz; i++)
        add_unique_int(value, i);
}

static void create_integers(BearFuzzyValue *value) {
    gconstpointer initial_data = g_bytes_get_data(value->reference_value, NULL);
    guint32 initial_value = *(guint32 *)initial_data;

    add_unique_int(value, initial_value);

    for (int i = -100; i <= 0xFF; i++)
        add_unique_int(value, i);

    add_unique_int(value, 0x7F000000);
    add_unique_int(value, 0x7F00);
    add_unique_int(value, 0x7EFFFFFF);
    add_unique_int(value, 0x7EFF);
    add_unique_int(value, 536870912);
    add_fuzzy_int(value, 256, 12);
    add_fuzzy_int(value, 512, 12);
    add_fuzzy_int(value, 1024, 12);
    add_fuzzy_int(value, 2048, 12);
    add_fuzzy_int(value, 4096, 12);
    add_fuzzy_int(value, 65535, 12);
}

static void add_string(BearFuzzyValue *value, const gchar *new_value) {
    gsize s = MIN(strlen(new_value), value->max_string_length);
    g_autoptr(GBytes) new_entry = g_bytes_new(new_value, s);

    for (GList *iter = value->possible_values; iter != NULL; iter = g_list_next(iter)) {
        GBytes *entry = iter->data;

        if (g_bytes_compare(entry, new_entry) == 0)
            return;
    }

    value->possible_values = g_list_append(value->possible_values, g_steal_pointer(&new_entry));
}

#define CHOP_AND_ADD(length)                                                                                                               \
    {                                                                                                                                      \
        if (len > length) {                                                                                                                \
            len = length;                                                                                                                  \
            buffer[len] = '\0';                                                                                                            \
            add_string(value, buffer);                                                                                                     \
        }                                                                                                                                  \
    }

static void add_string_chop(BearFuzzyValue *value, const gchar *new_value) {
    gsize len = MIN(strlen(new_value), value->max_string_length);

    g_autofree gchar *buffer = g_new0(gchar, len + 1);
    memcpy(buffer, new_value, len);

    add_string(value, buffer);

    CHOP_AND_ADD(value->max_string_length - 1);
    CHOP_AND_ADD(65535);
    CHOP_AND_ADD(65534);
    CHOP_AND_ADD(65533);
    CHOP_AND_ADD(40000);
    CHOP_AND_ADD(32767);
    CHOP_AND_ADD(32766);
    CHOP_AND_ADD(32765);
    CHOP_AND_ADD(30000);
    CHOP_AND_ADD(20000);
    CHOP_AND_ADD(10000);
    CHOP_AND_ADD(5000);
    CHOP_AND_ADD(4097);
    CHOP_AND_ADD(4096);
    CHOP_AND_ADD(4095);
    CHOP_AND_ADD(2048);
    CHOP_AND_ADD(2047);
    CHOP_AND_ADD(1024);
    CHOP_AND_ADD(1023);
    CHOP_AND_ADD(1022);
    CHOP_AND_ADD(512);
    CHOP_AND_ADD(511);
    CHOP_AND_ADD(510);
    CHOP_AND_ADD(256);
    CHOP_AND_ADD(255);
    CHOP_AND_ADD(254);
    CHOP_AND_ADD(128);
    CHOP_AND_ADD(127);
    CHOP_AND_ADD(126);
    CHOP_AND_ADD(64);
    CHOP_AND_ADD(63);
    CHOP_AND_ADD(62);
    CHOP_AND_ADD(32);
    CHOP_AND_ADD(31);
}

static void add_string_chop_suey(BearFuzzyValue *value, const gchar *new_value) {
    gsize len = MIN(strlen(new_value), value->max_string_length);

    add_string_chop(value, new_value);
    if (len > 2)
        add_string_chop(value, new_value + 1);
    if (len > 2)
        add_string_chop(value, new_value + 2);
}

static void fill_repeated(gchar *buffer, const gchar *fragment, gsize buffer_len) {
    memset(buffer, 0, buffer_len);
    gsize fragment_len = strlen(fragment);
    gsize i = 0;
    while (i < buffer_len) {
        gsize j = 0;
        while (j < fragment_len && i < buffer_len) {
            buffer[i] = fragment[j];
            i++;
            j++;
        }
    }
    buffer[buffer_len] = '\0';
}

#define CHAR(c)                                                                                                                            \
    {                                                                                                                                      \
        memset(buffer, c, value->max_string_length);                                                                                       \
        add_string_chop(value, buffer);                                                                                                    \
    }

#define REPEAT(fragment)                                                                                                                   \
    {                                                                                                                                      \
        fill_repeated(buffer, fragment, value->max_string_length);                                                                         \
        add_string_chop_suey(value, buffer);                                                                                               \
    }

static void create_strings(BearFuzzyValue *value) {
    const gchar *reference_string = g_bytes_get_data(value->reference_value, NULL);
    if (reference_string != NULL)
        add_string(value, reference_string);

    add_string(value, "");

    add_string_chop_suey(value, "C:\\");
    add_string_chop_suey(value, "C:");
    add_string_chop_suey(value, "C:\\$Mft");
    add_string_chop_suey(value, "../../../../../../../../../../../../etc/hosts%00");
    add_string_chop_suey(value, "../../../../../../../../../../../../etc/hosts");
    add_string_chop_suey(value, "../../../../../../../../../../../../etc/passwd%00");
    add_string_chop_suey(value, "../../../../../../../../../../../../etc/passwd");
    add_string_chop_suey(value, "../../../../../../../../../../../../etc/shadow%00");
    add_string_chop_suey(value, "../../../../../../../../../../../../etc/shadow");
    add_string_chop_suey(value, "../../../../../../../../../../../../boot.ini%00");
    add_string_chop_suey(value, "../../../../../../../../../../../../boot.ini");
    add_string_chop_suey(value, "../../../../../../../../../../../../localstart.asp%00");
    add_string_chop_suey(value, "../../../../../../../../../../../../localstart.asp");
    add_string_chop_suey(value, "//../../../../../../etc/passwd");
    add_string_chop_suey(value, "..:..:..:..:..:..:..:..");
    add_string_chop_suey(value, "../../../../../../../winnt/system32/ipconfig.exe");
    add_string_chop_suey(value, "../../../../../../../winnt/system32/");
    add_string_chop_suey(value, "/localstart.asp%20");
    add_string_chop_suey(value, "immunitysec.com");
    add_string_chop_suey(value, ".immunitysec.com");
    add_string_chop_suey(value, "\\\\*");
    add_string_chop_suey(value, "\\\\?\\");

    g_autofree gchar *buffer = g_new0(gchar, value->max_string_length + 1);

    CHAR('A');
    CHAR('B');
    CHAR('1');
    CHAR('<');
    CHAR('>');
    CHAR('"');
    CHAR('/');
    CHAR('\\');
    CHAR('?');
    CHAR('=');
    CHAR('&');
    CHAR('.');
    CHAR('(');
    CHAR(')');
    CHAR(']');
    CHAR('[');
    CHAR('%');
    CHAR('*');
    CHAR('-');
    CHAR('+');
    CHAR('{');
    CHAR('}');
    CHAR('\'');
    CHAR('\x14');

    CHAR('\xfe');
    CHAR('\xff');

    REPEAT("/\\");
    REPEAT("/.");
    REPEAT("/..");
    REPEAT("/...");
    REPEAT("/:");
    REPEAT(":\\");
    REPEAT("%25n");

    add_string(value, "%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%"
                      "25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%00");
    add_string(value, "%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c.."
                      "%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%255cetc%255chosts");
    add_string(value, "%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%"
                      "25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%255cboot.ini");
    add_string(value, "/%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c.."
                      "%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%00");
    add_string(value, "/%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c."
                      ".%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..winnt/desktop.ini");

    add_string(value, "%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n");
    add_string(value, "%.50000x");
    REPEAT("%n");

    add_string(value, "65536");
    add_string(value, "0xfffffff");
    add_string(value, "fffffff");
    add_string(value, "268435455");
    add_string(value, "1");
    add_string(value, "0");
    add_string(value, "-1");
    add_string(value, "-268435455");
    add_string(value, "4294967295");
    add_string(value, "-4294967295");
    add_string(value, "4294967294");
    add_string(value, "-20");
    add_string(value, "536870912");

    add_string(value, "localhost");

    add_string(value, "X");
    add_string(value, "*");
    add_string(value, ".");
    add_string(value, "/");
    add_string(value, "$");
    add_string(value, "&");
    add_string(value, "-");

    add_string(value, "/%00/");
    add_string(value, "%00/");
    add_string(value, "%00");
    add_string(value, "%u0000");
    add_string(value, "Select \"DAV:displayname\" from scope()");

    add_string(value, ";read;");
    add_string(value, ";netstat -a;");
    add_string(value, "\nnetstat -a\n");
    add_string(value, "\"hihihi");
    add_string(value, "|dir");
    add_string(value, "|ls");

    add_string(value, "%20$(sleep%2050)");
    add_string(value, "%20'sleep%2050'");
    add_string(value, "!@#$%%^#$%#$@#$%$$@#$%^^**(()");
    add_string(value, "%01%02%03%04%0a%0d%0aADSF");
}

static void fill_candidates(BearFuzzyValue *value) {
    if (value->possible_values != NULL)
        return;

    switch (value->value_type) {
    case STATIC:
    case BLOCK_SIZE:
        return;
    case FUZZY_INTEGER:
        create_integers(value);
        return;
    case FUZZY_STRING:
        create_strings(value);
        return;
    }
}

GBytes *get_entry(BearFuzzyValue *value, gsize variability) {
    fill_candidates(value);
    int n = MIN(variability, g_list_length(value->possible_values));
    return g_list_nth_data(value->possible_values, n);
}

static gboolean fuzzy_value_matches_block(BearFuzzyValue *value, const gchar *block_name) {
    if (value->my_block_name == NULL)
        return FALSE;

    if (g_strcmp0(value->my_block_name, block_name) == 0)
        return TRUE;

    g_autofree gchar *prefix = g_strdup_printf("%s.", block_name);
    return g_str_has_prefix(value->my_block_name, prefix);
}

gsize bear_fuzzy_value_size(BearFuzzyValue *value, GList *all_values, gsize variability) {
    g_return_val_if_fail(BEAR_IS_FUZZY_VALUE(value), 0);
    g_return_val_if_fail(value->computed_data != NULL, 0);

    if (value->value_type == BLOCK_SIZE)
        return g_bytes_get_size(value->reference_value);

    if (value->value_type == STATIC)
        return g_bytes_get_size(value->reference_value);

    GBytes *entry = get_entry(value, variability);
    return g_bytes_get_size(entry);
}

gsize bear_fuzzy_value_variability(BearFuzzyValue *value) {
    g_return_val_if_fail(BEAR_IS_FUZZY_VALUE(value), 0);

    if (value->value_type == BLOCK_SIZE)
        return 0;

    if (value->value_type == STATIC)
        return 0;

    fill_candidates(value);
    return g_list_length(value->possible_values);
}

static void fuzzy_value_compute_block_size(BearFuzzyValue *value, GList *all_values, gsize variability, GArray *all_variabilities) {
    g_return_if_fail(value->referenced_block_name != NULL);

    if (value->computed_data != NULL)
        return;

    gsize block_size = 0;

    for (gsize i = 0; i < g_list_length(all_values); i++) {
        BearFuzzyValue *nth_value = BEAR_FUZZY_VALUE(g_list_nth_data(all_values, i));
        if (!fuzzy_value_matches_block(nth_value, value->referenced_block_name))
            continue;
        gsize nth_variability = bear_fuzzy_value_variability(nth_value);

        bear_fuzzy_value_compute_recursive(nth_value, all_values, nth_variability, all_variabilities);
        g_autoptr(GBytes) nth_bytes = bear_fuzzy_value_get_computed_data(nth_value);

        gsize nth_size = g_bytes_get_size(nth_bytes);
        block_size += nth_size;
    }

    gsize initial_size = g_bytes_get_size(value->reference_value);
    if (initial_size == 2)
        block_size = GUINT16_TO_BE(block_size);
    else if (initial_size == 4)
        block_size = GUINT32_TO_BE(block_size);

    value->computed_data = g_bytes_new(&block_size, initial_size);
}

void bear_fuzzy_value_reset(BearFuzzyValue *value) {
    g_return_if_fail(BEAR_IS_FUZZY_VALUE(value));

    g_bytes_unref(value->computed_data);
    value->computed_data = NULL;
    value->computing = FALSE;
}

GBytes *bear_fuzzy_value_get_computed_data(BearFuzzyValue *value) {
    g_return_val_if_fail(BEAR_IS_FUZZY_VALUE(value), NULL);
    return g_bytes_ref(value->computed_data);
}

void bear_fuzzy_value_compute_recursive(BearFuzzyValue *value, GList *values, gsize variability, GArray *all_variabilities) {
    g_return_if_fail(BEAR_IS_FUZZY_VALUE(value));

    if (value->computed_data != NULL)
        return;

    if (value->computing) {
        g_error("Circular dependency detected in fuzzy value (block: %s)", value->my_block_name);
        return;
    }

    if (value->value_type == BLOCK_SIZE) {
        value->computing = TRUE;
        fuzzy_value_compute_block_size(value, values, variability, all_variabilities);
        value->computing = FALSE;
    }
}

void bear_fuzzy_value_compute_simple(BearFuzzyValue *value, gsize variability) {
    if (value->value_type == BLOCK_SIZE)
        return;

    if (value->value_type == STATIC) {
        value->computed_data = g_bytes_ref(value->reference_value);
        return;
    }

    GBytes *entry = get_entry(value, variability);
    value->computed_data = g_bytes_ref(entry);
}

gboolean bear_fuzzy_value_is_computed(BearFuzzyValue *value) {
    g_return_val_if_fail(BEAR_IS_FUZZY_VALUE(value), FALSE);
    return value->computed_data != NULL;
}

void bear_fuzzy_value_set_max_string_length(BearFuzzyValue *value, gsize max_length) {
    g_return_if_fail(BEAR_IS_FUZZY_VALUE(value));
    g_return_if_fail(value->possible_values == NULL);
    value->max_string_length = max_length;
}

gsize bear_fuzzy_value_get_max_string_length(BearFuzzyValue *value) {
    g_return_val_if_fail(BEAR_IS_FUZZY_VALUE(value), 0);
    return value->max_string_length;
}

void bear_fuzzy_value_set_strings(BearFuzzyValue *value, ...) {
    g_return_if_fail(BEAR_IS_FUZZY_VALUE(value));
    g_return_if_fail(value->possible_values == NULL);
    value->value_type = FUZZY_STRING;

    va_list args;
    va_start(args, value);

    const gchar *str;
    while ((str = va_arg(args, const gchar *)) != NULL)
        add_string(value, str);

    va_end(args);
}

void bear_fuzzy_value_set_block(BearFuzzyValue *value, const gchar *block_name) {
    g_return_if_fail(BEAR_IS_FUZZY_VALUE(value));
    value->my_block_name = g_strdup(block_name);
}
