#include <bear/generator.h>

struct _BearGenerator {
    GObject parent_instance;

    GList *values;
    gchar *start_vector;
    gchar *current_vector;
    gchar *last_vector;
    GArray *variabilities;
};

G_DEFINE_TYPE(BearGenerator, bear_generator, G_TYPE_OBJECT)

static void bear_generator_init(BearGenerator *generator) {}

static void bear_generator_finalize(GObject *object) {
    BearGenerator *generator = BEAR_GENERATOR(object);
    g_list_free_full(generator->values, g_object_unref);
    g_free(generator->start_vector);
    g_free(generator->current_vector);
    g_free(generator->last_vector);
    g_array_unref(generator->variabilities);
    G_OBJECT_CLASS(bear_generator_parent_class)->finalize(object);
}

static void bear_generator_class_init(BearGeneratorClass *klass) {
    GObjectClass *object_class = G_OBJECT_CLASS(klass);
    object_class->finalize = bear_generator_finalize;
}

static void bear_generator_calculate_variabilities(BearGenerator *generator) {
    if (generator->variabilities)
        return;
    GArray *variabilities = g_array_new(FALSE, FALSE, sizeof(gsize));
    for (GList *iterator = generator->values; iterator; iterator = iterator->next) {
        BearFuzzyValue *value = BEAR_FUZZY_VALUE(iterator->data);
        gsize v = bear_fuzzy_value_variability(value);
        g_array_append_val(variabilities, v);
    }
    generator->variabilities = variabilities;
}

const GArray *bear_generator_get_variabilities(BearGenerator *generator) {
    g_return_val_if_fail(BEAR_IS_GENERATOR(generator), NULL);
    return generator->variabilities;
}

BearGenerator *bear_generator_new(GList *values) {
    BearGenerator *generator = g_object_new(BEAR_TYPE_GENERATOR, NULL);
    generator->values = g_list_copy_deep(values, (GCopyFunc)g_object_ref, NULL);
    bear_generator_calculate_variabilities(generator);
    generator->current_vector = g_strdup(bear_generator_get_start_vector(generator));
    return generator;
}

gboolean bear_generator_set_vector(BearGenerator *generator, const gchar *vector) {
    g_return_val_if_fail(BEAR_IS_GENERATOR(generator), FALSE);
    g_return_val_if_fail(vector != NULL, FALSE);

    if (!bear_generator_validate_vector(generator, vector))
        return FALSE;
    g_free(generator->current_vector);
    generator->current_vector = g_strdup(vector);
    return TRUE;
}

const gchar *bear_generator_get_current_vector(BearGenerator *generator) {
    g_return_val_if_fail(BEAR_IS_GENERATOR(generator), NULL);

    return generator->current_vector;
}

const gchar *bear_generator_get_start_vector(BearGenerator *generator) {
    if (generator->start_vector)
        return generator->start_vector;

    GString *vector = g_string_new("");
    for (gsize i = 0; i < g_list_length(generator->values); i++) {
        g_string_append(vector, ":");
        if (g_array_index(generator->variabilities, gsize, i) > 0)
            g_string_append(vector, "0");
    }

    generator->start_vector = g_string_free(vector, FALSE);
    return generator->start_vector;
}

const gchar *bear_generator_get_last_vector(BearGenerator *generator) {
    if (generator->last_vector)
        return generator->last_vector;

    GString *vector = g_string_new("");
    for (gsize i = 0; i < g_list_length(generator->values); i++) {
        g_string_append(vector, ":");
        if (g_array_index(generator->variabilities, gsize, i) > 0)
            g_string_append_printf(vector, "%zu", g_array_index(generator->variabilities, gsize, i) - 1);
    }
    generator->last_vector = g_string_free(vector, FALSE);
    return generator->last_vector;
}

GArray *bear_generator_get_vector_values(const gchar *vector) {
    GArray *values = g_array_new(FALSE, FALSE, sizeof(gsize));
    gchar **tokens = g_strsplit(vector, ":", -1);
    for (gsize i = 1; tokens[i]; i++) {
        gsize v = g_ascii_strtoull(tokens[i], NULL, 10);
        g_array_append_val(values, v);
    }
    g_strfreev(tokens);
    return values;
}

gboolean bear_generator_validate_vector(BearGenerator *generator, const gchar *vector) {
    g_return_val_if_fail(BEAR_IS_GENERATOR(generator), FALSE);

    g_autoptr(GArray) vector_values = bear_generator_get_vector_values(vector);
    if (vector_values->len != g_list_length(generator->values))
        return FALSE;
    for (gsize i = 0; i < vector_values->len; i++) {
        gsize vector_value = g_array_index(vector_values, gsize, i);
        if (vector_value != 0 && vector_value >= g_array_index(generator->variabilities, gsize, i))
            return FALSE;
    }
    return TRUE;
}

const gchar *bear_generator_increment_vector(BearGenerator *generator) {
    g_return_val_if_fail(BEAR_IS_GENERATOR(generator), NULL);

    g_autoptr(GArray) vector_values = bear_generator_get_vector_values(generator->current_vector);

    if (vector_values->len != g_list_length(generator->values))
        return NULL;

    gboolean carry = TRUE;
    for (int i = vector_values->len - 1; i >= 0; i--) {
        if (g_array_index(generator->variabilities, gsize, i) > 0 && carry) {
            g_array_index(vector_values, gsize, i)++;
            carry = FALSE;
            if (g_array_index(vector_values, gsize, i) < g_array_index(generator->variabilities, gsize, i))
                break;

            carry = TRUE;
            g_array_index(vector_values, gsize, i) = 0;
        }
    }

    if (carry) {
        g_free(generator->current_vector);
        generator->current_vector = NULL;
        return NULL;
    }

    GString *next_vector = g_string_new("");
    for (gsize i = 0; i < vector_values->len; i++) {
        g_string_append(next_vector, ":");
        if (g_array_index(generator->variabilities, gsize, i) > 0)
            g_string_append_printf(next_vector, "%zu", g_array_index(vector_values, gsize, i));
    }
    g_free(generator->current_vector);
    generator->current_vector = g_string_free(next_vector, FALSE);
    return generator->current_vector;
}

gsize bear_generator_total_variability(BearGenerator *generator) {
    gsize total_variability = 1;
    for (gsize i = 0; i < generator->variabilities->len; i++) {
        gsize v = g_array_index(generator->variabilities, gsize, i);
        if (v > 0)
            total_variability *= v;
    }
    return total_variability;
}

GBytes *bear_generator_get_data(BearGenerator *generator, const gchar *vector) {
    g_return_val_if_fail(BEAR_IS_GENERATOR(generator), NULL);
    g_return_val_if_fail(vector != NULL, NULL);

    if (!bear_generator_validate_vector(generator, vector))
        return NULL;

    g_autoptr(GArray) vector_values = bear_generator_get_vector_values(vector);
    for (gsize i = 0; i < generator->variabilities->len; i++) {
        BearFuzzyValue *value = BEAR_FUZZY_VALUE(g_list_nth_data(generator->values, i));
        gsize variability = g_array_index(vector_values, gsize, i);
        bear_fuzzy_value_reset(value);
        bear_fuzzy_value_compute_simple(value, variability);
    }

    for (gsize i = 0; i < vector_values->len; i++) {
        gsize variability = g_array_index(vector_values, gsize, i);
        BearFuzzyValue *value = BEAR_FUZZY_VALUE(g_list_nth_data(generator->values, i));
        bear_fuzzy_value_compute_recursive(value, generator->values, variability, vector_values);
    }

    g_autoptr(GByteArray) array = g_byte_array_new();
    for (gsize i = 0; i < vector_values->len; i++) {
        BearFuzzyValue *value = BEAR_FUZZY_VALUE(g_list_nth_data(generator->values, i));
        g_autoptr(GBytes) bytes = bear_fuzzy_value_get_computed_data(value);

        gsize len;
        const guint8 *data = g_bytes_get_data(bytes, &len);
        g_byte_array_append(array, data, len);
    }

    return g_bytes_new(array->data, array->len);
}
